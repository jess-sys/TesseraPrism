import XCTest
@testable import PrismKit

final class ChunkingCBORTests: XCTestCase {
    func testChunkRoundTripAllSizes() throws {
        for mtu in [20, 23, 185, 512] {
            for len in [0, 1, 17, 18, 19, 20, 100, 1000, 8192, 65535] {
                let frame = (0..<len).map { UInt8(truncatingIfNeeded: $0 &* 31) }
                let chunks = BLEChunker.chunk(frame: frame, maxChunk: mtu)
                XCTAssertTrue(chunks.allSatisfy { $0.count <= mtu })
                var r = BLEReassembler()
                var out: [UInt8]?
                for (i, c) in chunks.enumerated() {
                    out = try r.push(c)
                    if i < chunks.count - 1 { XCTAssertNil(out) }
                }
                XCTAssertEqual(out, frame, "mtu \(mtu) len \(len)")
            }
        }
    }

    func testChunkHeaderLayout() {
        let c = BLEChunker.chunk(frame: [1, 2, 3, 4, 5], maxChunk: 5)
        // payload = 05 00 01 02 03 04 05 -> body 4 per chunk
        XCTAssertEqual(c[0], [0x80, 5, 0, 1, 2])
        XCTAssertEqual(c[1], [0x01, 3, 4, 5])
    }

    func testReassemblerResetsOnSeqZeroAndRejectsGap() throws {
        var r = BLEReassembler()
        XCTAssertNil(try r.push([0x80, 4, 0, 1]))       // first of a frame, abandoned
        XCTAssertEqual(try r.push([0x00, 2, 0, 9, 8]), [9, 8])
        XCTAssertNil(try r.push([0x80, 4, 0, 1]))
        XCTAssertThrowsError(try r.push([0x02, 1]))      // seq gap
    }

    func testCBORVectors() throws {
        // RFC 8949 appendix A
        XCTAssertEqual(CBOR.int(0).encode(), [0x00])
        XCTAssertEqual(CBOR.int(24).encode(), [0x18, 0x18])
        XCTAssertEqual(CBOR.int(1000).encode(), [0x19, 0x03, 0xe8])
        XCTAssertEqual(CBOR.int(1_000_000).encode(), [0x1a, 0x00, 0x0f, 0x42, 0x40])
        XCTAssertEqual(CBOR.int(-1).encode(), [0x20])
        XCTAssertEqual(CBOR.int(-7).encode(), [0x26])
        XCTAssertEqual(CBOR.int(-1000).encode(), [0x39, 0x03, 0xe7])
        XCTAssertEqual(CBOR.text("IETF").encode(), [0x64, 0x49, 0x45, 0x54, 0x46])
        XCTAssertEqual(CBOR.bytes([1, 2, 3, 4]).encode(), [0x44, 1, 2, 3, 4])
        XCTAssertEqual(CBOR.array([.int(1), .int(2), .int(3)]).encode(), [0x83, 1, 2, 3])
        XCTAssertEqual(CBOR.bool(true).encode(), [0xf5])
        XCTAssertEqual(CBOR.null.encode(), [0xf6])
        XCTAssertEqual(CBOR.map([(.int(1), .int(2)), (.int(3), .int(4))]).encode(), [0xa2, 1, 2, 3, 4])
    }

    func testCBORRoundTrip() throws {
        let v = CBOR.map([(.int(1), .text("example.com")), (.int(2), .bytes(Array(repeating: 7, count: 300))),
                          (.int(5), .map([(.text("up"), .bool(true)), (.text("n"), .null)])),
                          (.int(-3), .array([.int(Int64(Int32.max) + 5), .int(-70000)]))])
        XCTAssertEqual(try CBOR.decode(v.encode()), v)
        XCTAssertThrowsError(try CBOR.decode([0x44, 1]))
        XCTAssertThrowsError(try CBOR.decode([0x00, 0x00]))
    }

    func testCTAPGetAssertionRequestAndParse() throws {
        let req = CTAP.getAssertionRequest(rpId: "example.com", clientDataHash: Array(repeating: 1, count: 32), allowCredentialIds: [[9, 9]])
        XCTAssertEqual(req[0], 0x02)
        let m = try CBOR.decode(Array(req.dropFirst()))
        XCTAssertEqual(m[1]?.string, "example.com")
        XCTAssertEqual(m[3]?.arrayValue?.first?["id"]?.byteString, [9, 9])
        let resp = [UInt8(0)] + CBOR.map([(.int(1), .map([(.text("id"), .bytes([9, 9]))])), (.int(2), .bytes([1, 2])), (.int(3), .bytes([3])),
                                          (.int(4), .map([(.text("id"), .bytes([5]))]))]).encode()
        let a = try CTAP.parseAssertion(resp)
        XCTAssertEqual(a.credentialId, [9, 9]); XCTAssertEqual(a.signature, [3]); XCTAssertEqual(a.userHandle, [5])
        XCTAssertThrowsError(try CTAP.parseAssertion([0x2e]))
    }

    func testCTAPRegistrationParse() throws {
        var auth = [UInt8](repeating: 0, count: 32) + [0x45, 0, 0, 0, 0] + [UInt8](repeating: 0xAA, count: 16) + [0, 4, 1, 2, 3, 4]
        auth += CBOR.map([(.int(1), .int(2))]).encode()
        let resp = [UInt8(0)] + CBOR.map([(.int(1), .text("none")), (.int(2), .bytes(auth)), (.int(3), .map([]))]).encode()
        let r = try CTAP.parseRegistration(resp)
        XCTAssertEqual(r.credentialId, [1, 2, 3, 4])
        let att = try CBOR.decode(r.attestationObject)
        XCTAssertEqual(att["fmt"]?.string, "none")
        XCTAssertEqual(att["authData"]?.byteString, auth)
    }
}

final class ChunkingV2Tests: XCTestCase {
    func testV2RoundTripAllSizes() throws {
        for mtu in [20, 23, 185, 512] {
            for len in [0, 1, 17, 18, 100, 1000, 8192, 65535] {
                let frame = (0..<len).map { UInt8(truncatingIfNeeded: $0 &* 31) }
                let chunks = BLEChunker.chunkV2(frame: frame, maxChunk: mtu, chan: 0xAABBCCDD)
                XCTAssertTrue(chunks.allSatisfy { $0.count <= mtu })
                var r = BLEReassemblerV2(chan: 0xAABBCCDD)
                var out: [UInt8]?
                for (i, c) in chunks.enumerated() {
                    out = try r.push(c)
                    if i < chunks.count - 1 { XCTAssertNil(out) }
                }
                XCTAssertEqual(out, frame, "mtu \(mtu) len \(len)")
            }
        }
    }

    func testV2ByteVector() {
        // Hand-computed from the spec: chan 0x04030201, maxChunk 20 (first body 13, next body 15).
        // The same vector is asserted against the Rust FFI in PrismFFIKit's FFITests.
        let frame = (0..<20).map { UInt8($0) }
        let c = BLEChunker.chunkV2(frame: frame, maxChunk: 20, chan: 0x04030201)
        XCTAssertEqual(c, [[0xC0, 1, 2, 3, 4, 20, 0] + Array(0...12), [0x41, 1, 2, 3, 4] + Array(13...19)])
        // single chunk, no "more"
        XCTAssertEqual(BLEChunker.chunkV2(frame: [9, 8], maxChunk: 20, chan: 1), [[0x40, 1, 0, 0, 0, 2, 0, 9, 8]])
    }

    func testForeignChannelAndV1Ignored() throws {
        let a = (0..<300).map { UInt8(truncatingIfNeeded: $0) }
        let b = (0..<300).map { UInt8(truncatingIfNeeded: $0 &+ 7) }
        let ca = BLEChunker.chunkV2(frame: a, maxChunk: 50, chan: 11)
        let cb = BLEChunker.chunkV2(frame: b, maxChunk: 50, chan: 22)
        let v1 = BLEChunker.chunk(frame: b, maxChunk: 50)
        var r = BLEReassemblerV2(chan: 11)
        var got: [UInt8]?
        for i in 0..<max(ca.count, cb.count, v1.count) {
            if i < cb.count { XCTAssertNil(try r.push(cb[i])) }
            if i < v1.count { XCTAssertNil(try r.push(v1[i])) }
            if i < ca.count, let f = try r.push(ca[i]) { got = f }
        }
        XCTAssertEqual(got, a)
    }
}
