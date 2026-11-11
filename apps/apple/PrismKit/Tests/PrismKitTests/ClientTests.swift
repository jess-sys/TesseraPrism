import XCTest
@testable import PrismKit

/// Loopback transport with a fake device speaking StubCore's plaintext framing.
final class FakeDevice: PrismTransport {
    let frames: AsyncStream<[UInt8]>
    private let cont: AsyncStream<[UInt8]>.Continuation
    var handler: (Request) -> Response?   // nil = never answer
    var sent: [Request] = []
    init(handler: @escaping (Request) -> Response?) {
        var c: AsyncStream<[UInt8]>.Continuation!
        frames = AsyncStream { c = $0 }; cont = c; self.handler = handler
    }
    func connect() async throws {}
    func disconnect() { cont.finish() }
    func send(_ frame: [UInt8]) async throws {
        if frame.first == FrameKind.handshake.rawValue { cont.yield([FrameKind.handshake.rawValue, 1]); return }
        let env = try StubCore.decodeTransport(Envelope<Request>.self, frame: frame)
        sent.append(env.body)
        if let r = handler(env.body) { cont.yield(try StubCore.transportFrame(Envelope(id: env.id, body: r))) }
    }
}

final class ClientTests: XCTestCase {
    static let info = DeviceInfo(fwVersion: "1", devicePubkey: [UInt8](repeating: 0, count: 32), locked: false, initialized: true,
                                 batteryPct: 50, charging: false, entryCount: 1, timeValid: true)

    func makeClient(_ dev: FakeDevice, timeout: TimeInterval = 5) -> PrismClient {
        PrismClient(core: StubCore(), transport: dev, hostKeys: MemoryHostKeyStore(), timeout: timeout)
    }

    func testConnectListAndSecret() async throws {
        let id = EntryId(bytes: Array(0..<16))
        let dev = FakeDevice { req in
            switch req {
            case .getInfo: return .info(Self.info)
            case .setTime: return .ok
            case .listEntries: return .entries([EntrySummary(id: id, kind: .password, title: "GH", subtitle: "me")])
            case .getSecret: return .secret(.text("pw"))
            default: return .error(.unsupported)
            }
        }
        let c = makeClient(dev)
        let info = try await c.connect()
        XCTAssertEqual(info.entryCount, 1)
        let list = try await c.listEntries(kind: .password)
        XCTAssertEqual(list.first?.title, "GH")
        let s = try await c.getSecret(id: id, field: .password)
        XCTAssertEqual(s.text, "pw")
    }

    func testPairingFlowShowsSAS() async throws {
        var first = true
        let dev = FakeDevice { req in
            if case .getInfo = req, first { first = false; return .paired(label: "mac") }
            if case .getInfo = req { return .info(Self.info) }
            return .ok
        }
        let c = makeClient(dev)
        let sas = Box()
        _ = try await c.connect(needsPairing: true) { sas.value = $0 }
        XCTAssertEqual(sas.value, "123456")
    }

    func testDeviceErrorMapped() async throws {
        let dev = FakeDevice { req in if case .getInfo = req { return .info(Self.info) }; return .error(.denied) }
        let c = makeClient(dev)
        _ = try await c.connect(syncTime: false)
        do { _ = try await c.getTotp(id: EntryId(bytes: [])); XCTFail() }
        catch PrismError.device(let code) { XCTAssertEqual(code, .denied) }
    }

    func testTimeout() async throws {
        let dev = FakeDevice { req in if case .getInfo = req { return .info(Self.info) }; return nil }
        let c = makeClient(dev, timeout: 0.3)
        _ = try await c.connect(syncTime: false)
        do { _ = try await c.listEntries(); XCTFail() } catch PrismError.timeout {}
    }

    func testExportImportChunking() async throws {
        let blob = (0..<10_000).map { UInt8(truncatingIfNeeded: $0) }
        var imported: [UInt8] = []
        var committed = false
        let dev = FakeDevice { req in
            switch req {
            case .getInfo: return .info(Self.info)
            case .export(let pw): XCTAssertEqual(pw, "pw"); return .exportReady(totalLen: UInt32(blob.count))
            case .exportChunk(let o): return .chunk(offset: o, data: Array(blob[Int(o)..<min(Int(o) + 4096, blob.count)]))
            case .importChunk(let o, let d): XCTAssertEqual(Int(o), imported.count); imported += d; return .ok
            case .importCommit: committed = true; return .ok
            default: return .ok
            }
        }
        let c = makeClient(dev)
        _ = try await c.connect(syncTime: false)
        let out = try await c.exportVault(passphrase: "pw")
        XCTAssertEqual([UInt8](out), blob)
        try await c.importVault(out, passphrase: "x", mode: .replace)
        XCTAssertEqual(imported, blob); XCTAssertTrue(committed)
    }

    func testStubOtpauth() throws {
        let j = try StubCore().parseOtpauth("otpauth://totp/Example:alice@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6")
        let t = try PrismJSON.decode(Totp.self, from: j)
        XCTAssertEqual(t.issuer, "Example"); XCTAssertEqual(t.account, "alice@x.com")
        XCTAssertEqual(t.secret, Array("Hello!\u{DE}\u{AD}\u{BE}\u{EF}".utf8.prefix(0)) + [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef])
    }
}

final class Box: @unchecked Sendable { var value = "" }
