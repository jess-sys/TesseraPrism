import Foundation
#if canImport(Security)
import Security
#endif

/// Apple Developer Team ID injected at build time as `PrismTeamID` (= `$(DEVELOPMENT_TEAM)`) in the
/// Info.plist of the app and the AutoFill extension. `nil` when absent (e.g. SwiftPM tests).
public var prismTeamID: String? {
    guard let id = Bundle.main.object(forInfoDictionaryKey: "PrismTeamID") as? String,
          !id.isEmpty, !id.hasPrefix("$(") else { return nil }
    return id
}

/// App group shared by the app and its AutoFill extension (keychain access group for the host key
/// and the suite for non-secret state). macOS uses the team-prefixed form, iOS the `group.` form;
/// both must match `com.apple.security.application-groups` in project.yml.
public var prismSharedGroup: String {
    #if os(macOS)
    if let team = prismTeamID { return "\(team).ch.neutheria.prism" }
    return "ch.neutheria.prism"
    #else
    return "group.ch.neutheria.prism"
    #endif
}

public protocol HostKeyStoring: AnyObject {
    /// Returns the stored (private, public) host key, creating one with `core` if absent.
    func loadOrCreate(core: PrismCore) throws -> (privateKey: [UInt8], publicKey: [UInt8])
    func delete() throws
}

public enum HostKeyError: Error, LocalizedError {
    case keychain(OSStatus)
    case corrupt

    public var errorDescription: String? {
        switch self {
        case .keychain(let st):
            #if canImport(Security)
            let msg = (SecCopyErrorMessageString(st, nil) as String?) ?? "unknown"
            #else
            let msg = "unknown"
            #endif
            return "Keychain error \(st): \(msg)"
        case .corrupt:
            return "Stored host key is corrupt"
        }
    }
}

/// Keychain sharing group for the host key (`keychain-access-groups` entitlement), shared by the
/// app and its AutoFill extension. Team-prefixed on both platforms.
/// `nil` (no access group) when the team ID is unknown.
public var prismKeychainGroup: String? {
    prismTeamID.map { "\($0).ch.neutheria.prism.shared" }
}

/// In-memory store for tests/previews.
public final class MemoryHostKeyStore: HostKeyStoring {
    private var key: (privateKey: [UInt8], publicKey: [UInt8])?
    public init() {}
    public func loadOrCreate(core: PrismCore) throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        if let key { return key }
        let k = core.generateHostKey(); key = k; return k
    }
    public func delete() throws { key = nil }
}

#if canImport(Security)
/// Keychain-backed host key. Shared between app and AutoFill extension via the access group
/// `prismKeychainGroup` (listed in the keychain-access-groups entitlement).
public final class KeychainHostKeyStore: HostKeyStoring {
    private let service = "ch.neutheria.prism.hostkey"
    private let account = "host-static-key"
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

    public func loadOrCreate(core: PrismCore) throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecSuccess, let data = out as? Data {
            // layout: 32 private || 32 public
            guard data.count == 64 else { throw HostKeyError.corrupt }
            return (Array(data.prefix(32)), Array(data.suffix(32)))
        }
        guard st == errSecItemNotFound else { throw HostKeyError.keychain(st) }
        let k = core.generateHostKey()
        var add = baseQuery()
        add[kSecValueData as String] = Data(k.privateKey + k.publicKey)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let s2 = SecItemAdd(add as CFDictionary, nil)
        guard s2 == errSecSuccess else { throw HostKeyError.keychain(s2) }
        return k
    }

    public func delete() throws {
        let st = SecItemDelete(baseQuery() as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw HostKeyError.keychain(st) }
    }
}
#endif

/// Small non-secret state shared via the app group: last peripheral identifier (fast reconnect in the
/// short-lived AutoFill extension) and whether pairing completed with it.
public final class PairedDeviceStore: @unchecked Sendable {
    private let defaults: UserDefaults
    public init(suite: String = prismSharedGroup) { defaults = UserDefaults(suiteName: suite) ?? .standard }

    public var peripheralIdentifier: UUID? {
        get { defaults.string(forKey: "peripheralId").flatMap(UUID.init(uuidString:)) }
        set { defaults.set(newValue?.uuidString, forKey: "peripheralId") }
    }
    public var deviceName: String? {
        get { defaults.string(forKey: "deviceName") }
        set { defaults.set(newValue, forKey: "deviceName") }
    }
    public var isPaired: Bool {
        get { defaults.bool(forKey: "paired") }
        set { defaults.set(newValue, forKey: "paired") }
    }
    public func forget() { peripheralIdentifier = nil; deviceName = nil; isPaired = false }
}
