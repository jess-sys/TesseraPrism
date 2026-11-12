import Foundation
import CryptoKit
#if canImport(Security)
import Security
#endif
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// Encrypted local password cache (see README "Password cache").
//
//  - `password-cache.bin`  AES-256-GCM(snapshot JSON), in the app-group container.
//  - `password-cache.json` non-secret listing (ids, titles, usernames, urls, count, expiry).
//  - the 256-bit key lives in the Keychain behind biometrics / device passcode (`KeychainCacheKeyStore`).
// Everything is deleted at `expires_at` (checked on every read), on Off, on Forget and on NotPaired.

public struct CachedPassword: Codable, Equatable, Sendable {
    public var id: EntryId
    public var title: String
    public var username: String
    public var password: String
    public var url: String?
    public var modified: UInt64
    public init(id: EntryId, title: String, username: String, password: String, url: String?, modified: UInt64) {
        self.id = id; self.title = title; self.username = username; self.password = password; self.url = url; self.modified = modified
    }
}

public struct PasswordSnapshot: Codable, Equatable, Sendable {
    public var generatedAt: UInt64
    public var expiresAt: UInt64
    public var entries: [CachedPassword]
    enum CodingKeys: String, CodingKey { case generatedAt = "generated_at", expiresAt = "expires_at", entries }
    public init(generatedAt: UInt64, expiresAt: UInt64, entries: [CachedPassword]) {
        self.generatedAt = generatedAt; self.expiresAt = expiresAt; self.entries = entries
    }
}

/// Non-secret listing of the cache, readable without biometrics.
public struct PasswordCacheListing: Codable, Equatable, Sendable, Identifiable {
    public var id: EntryId
    public var title: String
    public var username: String
    public var url: String?
}

public struct PasswordCacheMetadata: Codable, Equatable, Sendable {
    public var generatedAt: UInt64
    public var expiresAt: UInt64
    public var entries: [PasswordCacheListing]
    public var count: Int { entries.count }
    public var expiryDate: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }
}

public protocol CacheKeyStoring: AnyObject {
    /// Replaces any stored key. Must not prompt.
    func save(_ key: Data) throws
    /// Reads the key; prompts for biometrics / passcode with `reason`.
    func load(reason: String) throws -> Data
    func delete()
}

public enum PasswordCacheError: Error, LocalizedError {
    case noCache, expired, keyUnavailable(String), corrupt
    public var errorDescription: String? {
        switch self {
        case .noCache: return "No local password cache"
        case .expired: return "The local password cache has expired"
        case .keyUnavailable(let s): return "Could not unlock the password cache: \(s)"
        case .corrupt: return "The local password cache is corrupt"
        }
    }
}

public final class PasswordCacheStore: @unchecked Sendable {
    public static let blobName = "password-cache.bin"
    public static let metaName = "password-cache.json"
    private static let aad = Data("prism-password-cache-v1".utf8)

    private let directory: URL
    private let keys: CacheKeyStoring
    private let now: () -> Date
    private let lock = NSLock()

    public init(directory: URL, keys: CacheKeyStoring, now: @escaping () -> Date = Date.init) {
        self.directory = directory; self.keys = keys; self.now = now
    }

    /// Cache in the shared app-group container (falls back to Application Support when the group is unavailable).
    public convenience init(keys: CacheKeyStoring? = nil, group: String = prismSharedGroup) {
        let fm = FileManager.default
        let dir = fm.containerURL(forSecurityApplicationGroupIdentifier: group)
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Prism", isDirectory: true)
        #if canImport(Security)
        let k: CacheKeyStoring = keys ?? KeychainCacheKeyStore()
        #else
        let k: CacheKeyStoring = keys ?? MemoryCacheKeyStore()
        #endif
        self.init(directory: dir, keys: k)
    }

    private var blobURL: URL { directory.appendingPathComponent(Self.blobName) }
    private var metaURL: URL { directory.appendingPathComponent(Self.metaName) }

    // MARK: write

    /// Encrypts and stores `snapshot` with a fresh random key (replacing any previous cache).
    public func store(_ snapshot: PasswordSnapshot) throws {
        lock.lock(); defer { lock.unlock() }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let key = SymmetricKey(size: .bits256)
        let plain = try PrismJSON.encoder.encode(snapshot)
        let sealed = try AES.GCM.seal(plain, using: key, authenticating: Self.aad)
        guard let combined = sealed.combined else { throw PasswordCacheError.corrupt }
        let meta = PasswordCacheMetadata(
            generatedAt: snapshot.generatedAt, expiresAt: snapshot.expiresAt,
            entries: snapshot.entries.map { PasswordCacheListing(id: $0.id, title: $0.title, username: $0.username, url: $0.url) })
        let keyData = key.withUnsafeBytes { Data($0) }
        try keys.save(keyData)
        try write(combined, to: blobURL)
        try write(try PrismJSON.encoder.encode(meta), to: metaURL)
    }

    private func write(_ data: Data, to url: URL) throws {
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
        var u = url
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try? u.setResourceValues(rv)
    }

    // MARK: read

    /// Listing metadata, or nil when there is no cache or it has expired (expired caches are deleted).
    public func metadata() -> PasswordCacheMetadata? {
        lock.lock(); defer { lock.unlock() }
        return metadataLocked()
    }

    private func metadataLocked() -> PasswordCacheMetadata? {
        guard let data = try? Data(contentsOf: metaURL),
              let meta = try? PrismJSON.decoder.decode(PasswordCacheMetadata.self, from: data) else {
            return nil
        }
        if UInt64(max(0, now().timeIntervalSince1970)) >= meta.expiresAt { clearLocked(); return nil }
        return meta
    }

    /// Decrypts the cache (prompts for the key) and returns the password of `id`, or nil if not cached.
    public func password(id: EntryId, reason: String) throws -> String? {
        try snapshot(reason: reason).entries.first { $0.id == id }?.password
    }

    public func snapshot(reason: String) throws -> PasswordSnapshot {
        lock.lock(); defer { lock.unlock() }
        guard metadataLocked() != nil, let blob = try? Data(contentsOf: blobURL) else { throw PasswordCacheError.noCache }
        let keyData: Data
        do { keyData = try keys.load(reason: reason) } catch { throw PasswordCacheError.keyUnavailable(error.localizedDescription) }
        guard keyData.count == 32 else { throw PasswordCacheError.corrupt }
        let box: AES.GCM.SealedBox
        let plain: Data
        do {
            box = try AES.GCM.SealedBox(combined: blob)
            plain = try AES.GCM.open(box, using: SymmetricKey(data: keyData), authenticating: Self.aad)
        } catch { throw PasswordCacheError.corrupt }
        let snap = try PrismJSON.decoder.decode(PasswordSnapshot.self, from: plain)
        if UInt64(max(0, now().timeIntervalSince1970)) >= snap.expiresAt { clearLocked(); throw PasswordCacheError.expired }
        return snap
    }

    // MARK: delete

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        clearLocked()
    }

    private func clearLocked() {
        try? FileManager.default.removeItem(at: blobURL)
        try? FileManager.default.removeItem(at: metaURL)
        keys.delete()
    }
}

public final class MemoryCacheKeyStore: CacheKeyStoring {
    public var key: Data?
    public init() {}
    public func save(_ key: Data) throws { self.key = key }
    public func load(reason: String) throws -> Data {
        guard let key else { throw PasswordCacheError.noCache }
        return key
    }
    public func delete() { key = nil }
}

#if canImport(Security)
/// Keychain key, shared app <-> AutoFill extension through the keychain access group; reading it requires
/// Touch ID / Face ID (or the device passcode as fallback): `SecAccessControl .userPresence`.
public final class KeychainCacheKeyStore: CacheKeyStoring {
    private let service = "ch.neutheria.prism.password-cache"
    private let account = "cache-key"
    private let accessGroup: String?

    public init(accessGroup: String? = prismKeychainGroup) { self.accessGroup = accessGroup }

    private func baseQuery() -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: account,
                                kSecAttrSynchronizable as String: false]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    public func save(_ key: Data) throws {
        delete()
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &err) else {
            throw HostKeyError.keychain(errSecParam)
        }
        var add = baseQuery()
        add[kSecValueData as String] = key
        add[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw HostKeyError.keychain(st) }
    }

    public func load(reason: String) throws -> Data {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        #if canImport(LocalAuthentication)
        let ctx = LAContext()
        ctx.localizedReason = reason
        q[kSecUseAuthenticationContext as String] = ctx
        #endif
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let data = out as? Data else { throw HostKeyError.keychain(st) }
        return data
    }

    public func delete() { SecItemDelete(baseQuery() as CFDictionary) }
}
#endif
