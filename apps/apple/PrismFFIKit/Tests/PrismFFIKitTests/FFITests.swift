import XCTest
@testable import PrismFFI

final class FFITests: XCTestCase {
    func testHostKeyAndHandshakeStart() throws {
        let k = generateHostKey()
        XCTAssertEqual(k.private.count, 32)
        XCTAssertEqual(k.public.count, 32)
        let s = try Session(hostPrivateKey: k.private)
        XCTAssertFalse(s.isEstablished())
        let first = try s.start()
        XCTAssertEqual(first.first, 0x01)
    }

    func testBleRoundTrip() throws {
        for mtu: UInt32 in [23, 64, 185, 517] {
            let frame = Data((0..<1500).map { UInt8($0 & 0xff) })
            let chunks = try bleChunk(frame: frame, mtu: mtu)
            XCTAssertTrue(chunks.allSatisfy { $0.count <= Int(mtu) - 3 })
            let r = BleReassembler()
            var out: Data?
            for c in chunks { out = try r.push(chunk: c) }
            XCTAssertEqual(out, frame)
        }
    }

    func testBleV2RoundTripAndChannelFilter() throws {
        let chan = randomChannel()
        XCTAssertNotEqual(chan, 0)
        let frame = Data((0..<1500).map { UInt8($0 & 0xff) })
        let other = Data((0..<1500).map { UInt8(($0 + 3) & 0xff) })
        for mtu: UInt32 in [23, 185, 517] {
            let mine = try bleChunkV2(frame: frame, mtu: mtu, chan: chan)
            let foreign = try bleChunkV2(frame: other, mtu: mtu, chan: chan &+ 1 == 0 ? 1 : chan &+ 1)
            XCTAssertTrue(mine.allSatisfy { $0.count <= Int(mtu) - 3 && $0[0] & 0x40 != 0 })
            let r = try BleReassembler.withChannel(chan: chan)
            var out: Data?
            for i in 0..<max(mine.count, foreign.count) {
                if i < foreign.count { XCTAssertNil(try r.push(chunk: foreign[i])) }
                if i < mine.count, let f = try r.push(chunk: mine[i]) { out = f }
            }
            XCTAssertEqual(out, frame)
        }
    }

    func testBleV2ByteVector() throws {
        let c = try bleChunkV2(frame: Data(0..<20), mtu: 23, chan: 0x04030201)
        XCTAssertEqual(c, [Data([0xC0, 1, 2, 3, 4, 20, 0] + Array(0...12)), Data([0x41, 1, 2, 3, 4] + Array(13...19))])
        XCTAssertEqual(try bleChunkV2(frame: Data([9, 8]), mtu: 23, chan: 1), [Data([0x40, 1, 0, 0, 0, 2, 0, 9, 8])])
    }

    func testCdcRoundTrip() throws {
        let frames = [Data([1, 2, 3]), Data(repeating: 0xAB, count: 300)]
        let d = CdcDecoder()
        var got: [Data] = []
        for f in frames { got += try d.push(bytes: cdcEncode(frame: f)) }
        XCTAssertEqual(got, frames)
    }

    func testTotpRFC6238() throws {
        let secret = Array("12345678901234567890".utf8)
        let json = #"{"issuer":"","account":"","secret":\#(secret),"algorithm":"Sha1","digits":8,"period":30}"#
        XCTAssertEqual(try totpNow(jsonTotp: json, unix: 59), "94287082")
    }

    func testParseOtpauth() throws {
        let j = try parseOtpauth(uri: "otpauth://totp/Example:alice@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        XCTAssertTrue(j.contains("Example"))
    }
}
