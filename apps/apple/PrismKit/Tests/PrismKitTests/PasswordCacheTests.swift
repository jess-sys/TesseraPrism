import XCTest
@testable import PrismKit

final class PasswordCacheTests: XCTestCase {
    var dir: URL!
    var keys: MemoryCacheKeyStore!
    var clock = Date(timeIntervalSince1970: 1_000)

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("prism-cache-\(UUID().uuidString)")
        keys = MemoryCacheKeyStore()
        clock = Date(timeIntervalSince1970: 1_000)
    }
    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    func store() -> PasswordCacheStore { PasswordCacheStore(directory: dir, keys: keys, now: { [unowned self] in clock }) }
    let id = EntryId(bytes: Array(0..<16))
    func snap(expires: UInt64 = 2_000) -> PasswordSnapshot {
        PasswordSnapshot(generatedAt: 1_000, expiresAt: expires, entries: [
            CachedPassword(id: id, title: "GitHub", username: "me", password: "s3cret-pw", url: "https://github.com", modified: 5)])
    }

    func testRoundTripAndNoPlaintextOnDisk() throws {
        let c = store()
        try c.store(snap())
        XCTAssertEqual(c.metadata()?.count, 1)
        XCTAssertEqual(c.metadata()?.entries.first?.username, "me")
        XCTAssertEqual(try c.password(id: id, reason: "t"), "s3cret-pw")
        XCTAssertNil(try c.password(id: EntryId(bytes: [UInt8](repeating: 9, count: 16)), reason: "t"))
        let blob = try Data(contentsOf: dir.appendingPathComponent(PasswordCacheStore.blobName))
        let meta = try Data(contentsOf: dir.appendingPathComponent(PasswordCacheStore.metaName))
        XCTAssertNil(blob.range(of: Data("s3cret-pw".utf8)))
        XCTAssertNil(meta.range(of: Data("s3cret-pw".utf8)))
        XCTAssertEqual(keys.key?.count, 32)
    }

    func testExpiryDeletesEverything() throws {
        let c = store()
        try c.store(snap())
        clock = Date(timeIntervalSince1970: 2_000)
        XCTAssertNil(c.metadata())
        XCTAssertNil(keys.key)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(PasswordCacheStore.blobName).path))
        XCTAssertThrowsError(try c.password(id: id, reason: "t"))
    }

    func testClearAndRestore() throws {
        let c = store()
        try c.store(snap())
        c.clear()
        XCTAssertNil(c.metadata()); XCTAssertNil(keys.key)
        try c.store(snap())
        XCTAssertNotNil(c.metadata())
    }

    func testTamperedOrWrongKeyFails() throws {
        let c = store()
        try c.store(snap())
        keys.key = Data(repeating: 1, count: 32)
        XCTAssertThrowsError(try c.password(id: id, reason: "t"))
        try c.store(snap())
        let url = dir.appendingPathComponent(PasswordCacheStore.blobName)
        var blob = try Data(contentsOf: url); blob[blob.count - 1] ^= 1
        try blob.write(to: url)
        XCTAssertThrowsError(try c.password(id: id, reason: "t"))
    }

    func testKeyRotatesOnEachStore() throws {
        let c = store()
        try c.store(snap()); let k1 = keys.key
        try c.store(snap()); XCTAssertNotEqual(k1, keys.key)
    }

    func testSnapshotJSONFromFFI() throws {
        let json = #"{"generated_at":10,"expires_at":20,"entries":[{"id":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"title":"t","username":"u","password":"p","url":null,"modified":5}]}"#
        let s = try PrismJSON.decode(PasswordSnapshot.self, from: json)
        XCTAssertEqual(s.expiresAt, 20); XCTAssertEqual(s.entries[0].id, id); XCTAssertNil(s.entries[0].url)
    }

    func testClientPasswordSnapshotAndPolicy() async throws {
        let json = Array(#"{"generated_at":10,"expires_at":20,"entries":[{"id":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"title":"t","username":"u","password":"p","url":null,"modified":5}]}"#.utf8)
        let dev = FakeDevice { req in
            switch req {
            case .getInfo: return .info(ClientTests.info)
            case .passwordSnapshot: return .exportReady(totalLen: UInt32(json.count))
            case .exportChunk(let o): return .chunk(offset: o, data: Array(json[Int(o)..<min(Int(o) + 40, json.count)]))
            case .setEntryPolicy: return .ok
            default: return .ok
            }
        }
        let c = PrismClient(core: StubCore(), transport: dev, hostKeys: MemoryHostKeyStore(), timeout: 5)
        _ = try await c.connect(syncTime: false)
        let snap = try await c.passwordSnapshot()
        XCTAssertEqual(snap.entries.first?.password, "p")
        try await c.setEntryPolicy(id: id, policy: .never)
        XCTAssertEqual(dev.sent.last, .setEntryPolicy(id: id, policy: .never))
    }
}
