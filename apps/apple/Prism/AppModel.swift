import Foundation
import SwiftUI
import PrismKit
import AuthenticationServices

@MainActor
final class AppModel: ObservableObject {
    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case pairing(sas: String)
        case connected(DeviceInfo)
        case failed(String)
    }

    @Published var state: ConnectionState = .disconnected
    @Published var entries: [EntrySummary] = []
    @Published var sshKeys: [SshPublicKey] = []
    @Published var settings: DeviceSettings?
    @Published var pairedHosts: [PairedHost] = []
    @Published var busy: String?          // e.g. "Approve on your Prism"
    @Published var activity: PrismActivity?   // animated counterpart of `busy`
    @Published var lastError: String?
    /// Listing of the encrypted local password cache (nil = none / expired). No biometrics needed.
    @Published var cacheMeta: PasswordCacheMetadata?

    let cache = PasswordCacheStore()

    init() { refreshCacheState() }

    func refreshCacheState() { cacheMeta = cache.metadata() }

    func clearCache() { cache.clear(); cacheMeta = nil }

    /// Fetches a fresh snapshot from the device (tap) and stores it encrypted.
    func syncCache() async {
        guard let snap = await run("Approve password cache on your Prism", { try await $0.passwordSnapshot() }) else { return }
        do { try cache.store(snap) } catch { lastError = "Could not store the cache: \(error.localizedDescription)" }
        refreshCacheState()
    }

    /// Password from the local cache (asks for Touch ID / Face ID / passcode). Used while the Prism is not connected.
    func cachedPassword(id: EntryId, title: String) async -> String? {
        let cache = self.cache
        let reason = "Show password for \(title)"
        let result = await Task.detached { Result { try cache.password(id: id, reason: reason) } }.value
        refreshCacheState()
        switch result {
        case .success(let p): return p
        case .failure(let e):
            lastError = e.localizedDescription
            return nil
        }
    }

    let core: PrismCore = makeDefaultCore()
    private var client: PrismClient?
    private var store = PairedDeviceStore()
    var usingStub: Bool { isUsingStubCore }

    var isConnected: Bool { if case .connected = state { return true }; return false }
    var isPaired: Bool { store.isPaired }
    var deviceName: String? { store.deviceName }

    // MARK: connection

    func connect() async {
        guard state == .disconnected || { if case .failed = state { return true }; return false }() else { return }
        state = .connecting
        let made = PrismConnection.makeClient(core: core)
        client = made.client
        store = made.store
        do {
            let info = try await made.client.connect(needsPairing: !store.isPaired) { [weak self] sas in
                Task { @MainActor in self?.state = .pairing(sas: sas) }
            }
            store.isPaired = true
            state = .connected(info)
            lastUse = Date()
            await refreshAll()
        } catch {
            state = .failed(error.localizedDescription)
            client = nil
        }
    }

    func disconnect() async {
        await client?.disconnect()
        client = nil
        state = .disconnected
    }

    func forgetDevice() async {
        await disconnect()
        store.forget()
        try? KeychainHostKeyStore().delete()
        entries = []; sshKeys = []
        clearCache()
    }

    // MARK: operations

    private func run<T>(_ op: (PrismClient) async throws -> T) async -> T? { await run(nil, op) }

    private var lastUse = Date.distantPast
    private var idleTask: Task<Void, Never>?
    /// Release the BLE link after this much inactivity. On macOS the app, its AutoFill extension
    /// and any other Prism process share ONE BLE link to the device, which keeps a single session
    /// per link: holding it while idle would collide with the extension.
    private static let idleDisconnectSecs: UInt64 = 8

    /// Returns a connected client, reconnecting silently (already paired) if the link was released.
    private func ensureClient() async throws -> PrismClient {
        if let client { return client }
        guard store.isPaired else { throw PrismError.notConnected }
        let made = PrismConnection.makeClient(core: core)
        _ = try await made.client.connect(needsPairing: false)
        client = made.client
        store = made.store
        lastUse = Date()
        return made.client
    }

    private func scheduleIdleDisconnect() {
        idleTask?.cancel()
        idleTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.idleDisconnectSecs * 1_000_000_000)
            guard !Task.isCancelled, let self, self.busy == nil, let c = self.client else { return }
            self.client = nil
            await c.disconnect()
        }
    }

    private func run<T>(_ label: String?, _ op: (PrismClient) async throws -> T) async -> T? {
        guard isConnected else { lastError = "Not connected"; return nil }
        idleTask?.cancel()
        busy = label
        activity = label == nil ? nil : .approve
        defer { busy = nil; activity = nil; lastUse = Date(); scheduleIdleDisconnect() }
        do {
            let fresh = client == nil
            let client = try await ensureClient()
            // Another Prism process may have used the shared link since our last request, which
            // makes the device drop our session: refresh it if we have been idle.
            if !fresh, Date().timeIntervalSince(lastUse) > 5 { try await client.resync() }
            // Locked device (standby): it shows its PIN pad; wait for the user to unlock it.
            return try await untilUnlocked(onLocked: { busy = "Unlock your Tessera Prism to continue..."; activity = .unlock }) {
                try await op(client)
            }
        } catch let e as PrismError where Self.isSessionLoss(e) {
            // Session or link lost: reconnect once and retry.
            if let c = client { self.client = nil; await c.disconnect() }
            do {
                return try await op(try await ensureClient())
            } catch {
                noteDeviceError(error)
                lastError = error.localizedDescription
                return nil
            }
        } catch {
            noteDeviceError(error)
            lastError = error.localizedDescription
            return nil
        }
    }

    /// The device no longer knows this host: its password cache must go.
    private func noteDeviceError(_ error: Error) {
        if case PrismError.device(.notPaired) = error { clearCache() }
    }

    private static func isSessionLoss(_ e: PrismError) -> Bool {
        switch e {
        case .timeout, .disconnected, .protocolViolation, .notConnected: return true
        case .device: return false
        }
    }

    func refreshAll() async {
        if let e = await run({ try await $0.listEntries() }) {
            entries = e
            // Passkeys must be registered too, or Chrome won't offer the Prism for the site. Older
            // firmware lacks ListPasskeys: then leave the store alone rather than drop passkeys.
            var passkeys: [PasskeyIdentity]? = []
            if e.contains(where: { $0.kind == .passkey }) {
                do {
                    passkeys = try await client?.listPasskeys()
                } catch {
                    passkeys = nil
                    // Firmware before ListPasskeys drops the session on an unknown request (newer
                    // firmware answers Unsupported): reconnect on the next call.
                    if case PrismError.device(.unsupported) = error {} else if let c = client { client = nil; await c.disconnect() }
                }
            }
            if let passkeys { await updateCredentialStore(e, passkeys: passkeys) }
        }
        if let k = await run({ try await $0.sshListKeys() }) { sshKeys = k }
    }

    func reveal(_ id: EntryId, field: SecretField) async -> String? {
        await run("Approve on your Prism") { try await $0.getSecret(id: id, field: field, context: "Prism app") }?.text
    }

    func totp(_ id: EntryId) async -> (code: String, validUntil: UInt64)? {
        await run("Approve on your Prism") { try await $0.getTotp(id: id) }
    }

    func add(_ entry: Entry) async -> Bool {
        let ok = await run("Confirm on your Prism") { try await $0.addEntry(entry) } != nil
        if ok { await refreshAll() }
        return ok
    }

    func delete(_ id: EntryId) async {
        if await run("Confirm deletion on your Prism", { try await $0.deleteEntry(id: id) }) != nil { await refreshAll() }
    }

    func generateSshKey(name: String, comment: String, policy: ApprovalPolicy) async {
        if await run("Confirm on your Prism", { try await $0.generateSshKey(name: name, comment: comment, policy: policy) }) != nil {
            await refreshAll()
        }
    }

    func loadSettings() async {
        settings = await run { try await $0.getSettings() }
        pairedHosts = await run { try await $0.listPairedHosts() } ?? pairedHosts
    }

    func save(_ s: DeviceSettings) async {
        if await run({ try await $0.setSettings(s) }) != nil {
            settings = s
            if s.passwordCacheSecs == 0 { clearCache() }
        }
    }

    func setEntryPolicy(_ id: EntryId, _ policy: ApprovalPolicy) async -> Bool {
        let ok = await run("Confirm on your Prism", { try await $0.setEntryPolicy(id: id, policy: policy) }) != nil
        if ok { await refreshAll() }
        return ok
    }

    func renameHost(_ h: PairedHost, to label: String) async {
        if await run("Confirm on your Prism", { try await $0.renamePairedHost(publicKey: h.publicKey, label: label) }) != nil { await loadSettings() }
    }

    func removeHost(_ h: PairedHost) async {
        if await run("Confirm on your Prism", { try await $0.removePairedHost(publicKey: h.publicKey) }) != nil { await loadSettings() }
    }

    func lockDevice() async { _ = await run { try await $0.lock() } }

    func exportVault(passphrase: String) async -> Data? {
        await run("Approve export on your Prism") { try await $0.exportVault(passphrase: passphrase) }
    }

    func setRecoveryPassphrase(_ passphrase: String) async -> Bool {
        await run("Confirm on your Prism") { try await $0.setRecoveryPassphrase(passphrase) } != nil
    }

    func importVault(_ data: Data, passphrase: String, mode: ImportMode) async -> Bool {
        let ok = await run("Approve import on your Prism") { try await $0.importVault(data, passphrase: passphrase, mode: mode) } != nil
        if ok { await refreshAll() }
        return ok
    }

    func parseTotp(uri: String) -> Totp? {
        do { return try PrismJSON.decode(Totp.self, from: try core.parseOtpauth(uri)) }
        catch { lastError = error.localizedDescription; return nil }
    }

    // MARK: AutoFill identity store

    private func updateCredentialStore(_ list: [EntrySummary], passkeys: [PasskeyIdentity]) async {
        var identities: [ASCredentialIdentity] = list.filter { $0.kind == .password }.compactMap { e -> ASPasswordCredentialIdentity? in
            guard let url = e.url, !url.isEmpty else { return nil }
            let host = URL(string: url)?.host ?? url
            return ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: host, type: .domain),
                                                user: e.subtitle, recordIdentifier: e.id.hex)
        }
        identities += passkeys.map {
            ASPasskeyCredentialIdentity(relyingPartyIdentifier: $0.rpId, userName: $0.userName,
                                        credentialID: Data($0.credentialId), userHandle: Data($0.userHandle),
                                        recordIdentifier: $0.id.hex)
        }
        let s = ASCredentialIdentityStore.shared
        guard await s.state().isEnabled else { return }
        try? await s.replaceCredentialIdentities(identities)
    }
}

enum Clipboard {
    static func copy(_ s: String) {
        #if os(iOS)
        UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: s]], options: [.expirationDate: Date().addingTimeInterval(60), .localOnly: true])
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        #endif
    }
}
