import Foundation
import os

let clientLog = Logger(subsystem: "ch.neutheria.prism", category: "client")

public enum PrismError: Error, LocalizedError {
    case device(ErrorCode)
    case timeout
    case disconnected
    case protocolViolation(String)
    case notConnected
    public var errorDescription: String? {
        switch self {
        case .device(let c): return "Device error: \(c.rawValue)"
        case .timeout: return "The device did not answer in time"
        case .disconnected: return "Disconnected"
        case .protocolViolation(let s): return "Protocol error: \(s)"
        case .notConnected: return "Not connected"
        }
    }
}

public actor PrismClient {
    public static let defaultTimeout: TimeInterval = 60
    public static let importChunkSize = 4096

    private let core: PrismCore
    private let transport: PrismTransport
    private let hostKeys: HostKeyStoring
    private let timeout: TimeInterval

    private var session: PrismSession?
    private var readerTask: Task<Void, Never>?
    private var nextId: UInt32 = 1
    private var pending: [UInt32: CheckedContinuation<Response, Error>] = [:]
    private var handshake: CheckedContinuation<Void, Error>?
    public private(set) var isReady = false

    public init(core: PrismCore, transport: PrismTransport, hostKeys: HostKeyStoring, timeout: TimeInterval = PrismClient.defaultTimeout) {
        self.core = core; self.transport = transport; self.hostKeys = hostKeys; self.timeout = timeout
    }

    // MARK: connection

    /// Connects, runs the Noise handshake and (if `needsPairing`) reports the SAS so the UI can show it
    /// while the user confirms on the device. Returns the device info.
    /// - Parameters:
    ///   - needsPairing: true if this host is not yet paired; `onSAS` is called with the 6-digit code.
    @discardableResult
    public func connect(needsPairing: Bool = false,
                        syncTime: Bool = true,
                        onSAS: (@Sendable (String) -> Void)? = nil) async throws -> DeviceInfo {
        try await transport.connect()
        startReader()
        let s = try await runHandshake()
        if needsPairing, let sas = s.sas() { onSAS?(sas) }

        // First request. An unpaired host in pairing mode gets `Paired` once the user confirms on the device.
        var reply = try await request(.getInfo)
        if case .paired = reply { reply = try await request(.getInfo) }
        guard case .info(let info) = reply else { throw PrismError.protocolViolation("expected Info") }
        isReady = true
        if syncTime { _ = try? await request(.setTime(unix: UInt64(Date().timeIntervalSince1970))) }
        return info
    }

    /// Runs a fresh Noise handshake over the already-connected transport and makes it the current
    /// session. Needed on macOS, where the app and its AutoFill extension share one BLE link: when
    /// the other process opens a session, the device replaces ours (newest client wins).
    @discardableResult
    private func runHandshake() async throws -> PrismSession {
        let key = try hostKeys.loadOrCreate(core: core)
        let s = try core.makeSession(hostPrivateKey: key.privateKey)
        session = s
        clientLog.notice("handshake: start (host key \(key.publicKey.prefix(4).map { String(format: "%02x", $0) }.joined(), privacy: .public))")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            handshake = cont
            Task { [weak self] in
                do { try await self?.transport.send(try s.start()) }
                catch { await self?.failHandshake(error) }
            }
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                await self?.failHandshake(PrismError.timeout)
            }
        }
        return s
    }

    /// Re-establish the session (already paired host) without reconnecting the transport.
    public func resync() async throws {
        isReady = false
        let p = pending; pending = [:]
        p.values.forEach { $0.resume(throwing: PrismError.disconnected) }
        try await runHandshake()
        isReady = true
    }

    public func disconnect() {
        transport.disconnect()
        teardown(PrismError.disconnected)
    }

    private func failHandshake(_ e: Error) {
        if let h = handshake { handshake = nil; h.resume(throwing: e) }
    }

    private func teardown(_ error: Error) {
        isReady = false
        readerTask?.cancel(); readerTask = nil
        failHandshake(error)
        let p = pending; pending = [:]
        p.values.forEach { $0.resume(throwing: error) }
    }

    private func startReader() {
        readerTask?.cancel()
        let frames = transport.frames
        readerTask = Task { [weak self] in
            for await frame in frames {
                if Task.isCancelled { return }
                await self?.handle(frame)
            }
            await self?.teardown(PrismError.disconnected)
        }
    }

    private func handle(_ frame: [UInt8]) async {
        guard let session else { return }
        do {
            clientLog.debug("rx frame kind=\(frame.first ?? 0, privacy: .public) len=\(frame.count, privacy: .public)")
            let json = try session.onFrame(frame)
            let event = try PrismJSON.decode(SessionEvent.self, from: json)
            switch event {
            case .sendFrame: clientLog.notice("event: sendFrame (established=\(session.isEstablished(), privacy: .public))")
            case .established: clientLog.notice("event: established")
            case .plainError(let e): clientLog.error("event: plainError \(String(describing: e), privacy: .public)")
            case .response(let env): clientLog.notice("event: response id=\(env.id, privacy: .public)")
            }
            switch event {
            case .sendFrame(let f):
                try await transport.send(f)
                // Handshake msg3 sent: the Rust initiator is established now (it emits no
                // `Established` event), so complete the handshake here.
                if session.isEstablished(), let h = handshake { handshake = nil; h.resume() }
            case .established:
                if let h = handshake { handshake = nil; h.resume() }
            case .plainError(let e):
                let err = PrismError.protocolViolation("device: \(e)")
                if handshake != nil { failHandshake(err) } else { teardown(err) }
            case .response(let env):
                if let c = pending.removeValue(forKey: env.id) { c.resume(returning: env.body) }
                // else: unsolicited (e.g. late Paired) - ignored
            }
        } catch {
            clientLog.error("frame handling failed: \(String(describing: error), privacy: .public)")
            if handshake != nil { failHandshake(error) }
        }
    }

    // MARK: requests

    public func request(_ req: Request) async throws -> Response {
        guard let session else { throw PrismError.notConnected }
        let id = nextId; nextId &+= 1
        let json = try PrismJSON.string(Envelope(id: id, body: req))
        let frame = try session.encryptRequest(json: json)
        let timeout = self.timeout
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Response, Error>) in
            pending[id] = cont
            Task { [weak self] in
                do { try await self?.transport.send(frame) }
                catch { await self?.fail(id, error) }
            }
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                await self?.fail(id, PrismError.timeout)
            }
        }
    }

    private func fail(_ id: UInt32, _ error: Error) {
        if let c = pending.removeValue(forKey: id) { c.resume(throwing: error) }
    }

    private func expect<T>(_ req: Request, _ pick: (Response) -> T?) async throws -> T {
        let r = try await request(req)
        if case .error(let code) = r { throw PrismError.device(code) }
        guard let v = pick(r) else { throw PrismError.protocolViolation("unexpected response \(r)") }
        return v
    }

    private func expectOk(_ req: Request) async throws {
        try await expect(req) { if case .ok = $0 { return () } else { return nil } }
    }

    // MARK: typed API

    public func info() async throws -> DeviceInfo { try await expect(.getInfo) { if case .info(let i) = $0 { return i }; return nil } }
    public func setTime(_ date: Date = Date()) async throws { try await expectOk(.setTime(unix: UInt64(date.timeIntervalSince1970))) }
    public func unlock(passphrase: String) async throws { try await expectOk(.unlock(passphrase: passphrase)) }
    public func lock() async throws { try await expectOk(.lock) }

    public func listEntries(kind: EntryKind? = nil) async throws -> [EntrySummary] {
        try await expect(.listEntries(kind: kind)) { if case .entries(let e) = $0 { return e }; return nil }
    }
    public func getSecret(id: EntryId, field: SecretField, context: String? = nil) async throws -> SecretValue {
        try await expect(.getSecret(id: id, field: field, context: context)) { if case .secret(let s) = $0 { return s }; return nil }
    }
    public func getTotp(id: EntryId) async throws -> (code: String, validUntil: UInt64) {
        try await expect(.getTotp(id: id)) { if case .totp(let c, let v) = $0 { return (c, v) }; return nil }
    }
    @discardableResult
    public func addEntry(_ entry: Entry) async throws -> EntryId {
        try await expect(.addEntry(entry: entry)) {
            switch $0 { case .entryId(let i): return i; case .ok: return entry.id; default: return nil }
        }
    }
    public func updateEntry(_ entry: Entry) async throws { try await expectOk(.updateEntry(entry: entry)) }
    public func deleteEntry(id: EntryId) async throws { try await expectOk(.deleteEntry(id: id)) }
    @discardableResult
    public func generateSshKey(name: String, comment: String, policy: ApprovalPolicy = .always) async throws -> SshPublicKey {
        try await expect(.generateSshKey(name: name, comment: comment, policy: policy)) { if case .sshKeys(let k) = $0 { return k.first }; return nil }
    }
    public func getEntry(id: EntryId) async throws -> Entry {
        try await expect(.getEntry(id: id)) { if case .entry(let e) = $0 { return e }; return nil }
    }
    public func setRecoveryPassphrase(_ passphrase: String) async throws { try await expectOk(.setRecoveryPassphrase(passphrase: passphrase)) }
    public func sshListKeys() async throws -> [SshPublicKey] {
        try await expect(.sshListKeys) { if case .sshKeys(let k) = $0 { return k }; return nil }
    }
    public func ctap(cbor: [UInt8], originHint: String? = nil) async throws -> [UInt8] {
        try await expect(.ctap(cbor: cbor, originHint: originHint)) { if case .ctap(let d) = $0 { return d }; return nil }
    }
    public func listPairedHosts() async throws -> [PairedHost] {
        try await expect(.listPairedHosts) { if case .pairedHosts(let h) = $0 { return h }; return nil }
    }
    public func removePairedHost(publicKey: [UInt8]) async throws { try await expectOk(.removePairedHost(publicKey: publicKey)) }
    public func getSettings() async throws -> DeviceSettings {
        try await expect(.getSettings) { if case .settings(let s) = $0 { return s }; return nil }
    }
    public func setSettings(_ s: DeviceSettings) async throws { try await expectOk(.setSettings(settings: s)) }

    // MARK: export / import

    public func exportVault(passphrase: String, progress: (@Sendable (Double) -> Void)? = nil) async throws -> Data {
        let total = try await expect(.export(passphrase: passphrase)) { if case .exportReady(let t) = $0 { return Int(t) }; return nil }
        var out: [UInt8] = []
        out.reserveCapacity(total)
        while out.count < total {
            let (offset, data) = try await expect(.exportChunk(offset: UInt32(out.count))) {
                if case .chunk(let o, let d) = $0 { return (o, d) }; return nil
            }
            guard Int(offset) == out.count, !data.isEmpty else { throw PrismError.protocolViolation("bad export chunk") }
            out += data
            progress?(Double(out.count) / Double(max(total, 1)))
        }
        return Data(out)
    }

    public func importVault(_ file: Data, passphrase: String, mode: ImportMode,
                            progress: (@Sendable (Double) -> Void)? = nil) async throws {
        let bytes = [UInt8](file)
        try await expectOk(.importBegin(totalLen: UInt32(bytes.count)))
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + Self.importChunkSize, bytes.count)
            try await expectOk(.importChunk(offset: UInt32(offset), data: Array(bytes[offset..<end])))
            offset = end
            progress?(Double(offset) / Double(bytes.count))
        }
        try await expectOk(.importCommit(passphrase: passphrase, mode: mode))
    }
}
