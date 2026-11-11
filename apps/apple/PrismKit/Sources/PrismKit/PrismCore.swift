import Foundation

// Swift view of the prism-ffi (UniFFI) JSON API of ARCHITECTURE.md §9.3. The app codes against
// these protocols; `PrismFFICore` (apps/apple/Shared) adapts the real xcframework, `StubCore` is a
// pure-Swift stand-in (no encryption!) used for tests, previews and builds without the xcframework.

public protocol PrismSession: AnyObject {
    /// First handshake frame (kind 0x01) to send.
    func start() throws -> [UInt8]
    /// Feed a received frame; returns JSON of a `SessionEvent`.
    func onFrame(_ frame: [UInt8]) throws -> String
    /// 6-digit SAS once the handshake finished.
    func sas() -> String?
    /// True once the Noise handshake completed. The Rust initiator never emits an `Established`
    /// event: after the device's msg2 it returns `SendFrame(msg3)` and is established from then on.
    func isEstablished() -> Bool
    /// `json` is a JSON `Envelope<Request>` ({"id":N,"body":Request}); returns a full frame (kind 0x02).
    func encryptRequest(json: String) throws -> [UInt8]
}

public protocol PrismReassembler {
    mutating func push(_ chunk: [UInt8]) throws -> [UInt8]?
}

public protocol PrismCore: AnyObject {
    func generateHostKey() -> (privateKey: [UInt8], publicKey: [UInt8])
    func makeSession(hostPrivateKey: [UInt8]) throws -> PrismSession
    /// BLE framing v2. `maxChunk` = max GATT payload per write/notify (ATT_MTU - 3); `chan` non-zero.
    func bleChunk(frame: [UInt8], maxChunk: Int, chan: UInt32) -> [[UInt8]]
    /// Reassembler that only accepts v2 chunks of channel `chan`.
    func makeReassembler(chan: UInt32) -> PrismReassembler
    /// Random non-zero channel id.
    func randomChannel() -> UInt32
    /// otpauth:// URI -> JSON `Totp`
    func parseOtpauth(_ uri: String) throws -> String
    /// JSON Totp + unix time -> code
    func totpNow(totpJSON: String, unix: UInt64) throws -> String
}

public enum PrismCoreError: Error, LocalizedError {
    case invalidOtpauth, unsupported(String), session(String)
    public var errorDescription: String? {
        switch self {
        case .invalidOtpauth: return "Invalid otpauth:// URI"
        case .unsupported(let s): return "Unsupported: \(s)"
        case .session(let s): return s
        }
    }
}

public enum FrameKind: UInt8 { case handshake = 0x01, transport = 0x02, plainError = 0x03 }

// MARK: - StubCore

/// Pure-Swift insecure stand-in. Handshake: host sends [0x01, "hello"], device answers [0x01,"ok"] and
/// the session is established. Requests travel as [0x02] + JSON (no encryption). A fake device in tests
/// can use `StubCore.decodeTransport` / `StubCore.transportFrame` to talk to it.
public final class StubCore: PrismCore {
    public init() {}
    public func generateHostKey() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let k = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return (k, k.reversed())
    }
    public func makeSession(hostPrivateKey: [UInt8]) throws -> PrismSession { StubSession() }
    public func bleChunk(frame: [UInt8], maxChunk: Int, chan: UInt32) -> [[UInt8]] {
        BLEChunker.chunkV2(frame: frame, maxChunk: maxChunk, chan: chan)
    }
    public func makeReassembler(chan: UInt32) -> PrismReassembler { BLEReassemblerV2(chan: chan) }
    public func randomChannel() -> UInt32 { UInt32.random(in: 1...UInt32.max) }

    public func parseOtpauth(_ uri: String) throws -> String {
        guard let u = URLComponents(string: uri), u.scheme == "otpauth", u.host == "totp" else { throw PrismCoreError.invalidOtpauth }
        let items = Dictionary((u.queryItems ?? []).compactMap { i in i.value.map { (i.name.lowercased(), $0) } }, uniquingKeysWith: { a, _ in a })
        guard let secretStr = items["secret"], let secret = Base32.decode(secretStr) else { throw PrismCoreError.invalidOtpauth }
        var label = String(u.path.dropFirst()).removingPercentEncoding ?? ""
        var issuer = items["issuer"] ?? ""
        if let idx = label.firstIndex(of: ":") {
            if issuer.isEmpty { issuer = String(label[..<idx]) }
            label = String(label[label.index(after: idx)...]).trimmingCharacters(in: .whitespaces)
        }
        let algo: TotpAlgorithm
        switch (items["algorithm"] ?? "SHA1").uppercased() {
        case "SHA256": algo = .sha256
        case "SHA512": algo = .sha512
        default: algo = .sha1
        }
        let t = Totp(issuer: issuer, account: label, secret: secret, algorithm: algo,
                     digits: UInt8(items["digits"] ?? "6") ?? 6, period: UInt32(items["period"] ?? "30") ?? 30)
        return try PrismJSON.string(t)
    }

    public func totpNow(totpJSON: String, unix: UInt64) throws -> String {
        throw PrismCoreError.unsupported("totpNow requires prism-ffi")
    }

    // Helpers for fake devices
    public static func transportFrame<T: Encodable>(_ v: T) throws -> [UInt8] {
        [FrameKind.transport.rawValue] + Array(try PrismJSON.encoder.encode(v))
    }
    public static func decodeTransport<T: Decodable>(_ type: T.Type, frame: [UInt8]) throws -> T {
        try PrismJSON.decoder.decode(T.self, from: Data(frame.dropFirst()))
    }
}

final class StubSession: PrismSession {
    var established = false
    func start() throws -> [UInt8] { [FrameKind.handshake.rawValue] + Array("hello".utf8) }
    func onFrame(_ frame: [UInt8]) throws -> String {
        guard let kind = frame.first else { throw PrismCoreError.session("empty frame") }
        switch FrameKind(rawValue: kind) {
        case .handshake:
            // Mirror the real (Rust) initiator: reply with msg3, never an `Established` event.
            established = true
            return try PrismJSON.string(SessionEvent.sendFrame([FrameKind.handshake.rawValue] + Array("msg3".utf8)))
        case .transport:
            let env = try PrismJSON.decoder.decode(Envelope<Response>.self, from: Data(frame.dropFirst()))
            return try PrismJSON.string(SessionEvent.response(env))
        case .plainError:
            return try PrismJSON.string(SessionEvent.plainError(.string("plain error")))
        case .none: throw PrismCoreError.session("bad frame kind")
        }
    }
    func sas() -> String? { established ? "123456" : nil }
    func isEstablished() -> Bool { established }
    func encryptRequest(json: String) throws -> [UInt8] { [FrameKind.transport.rawValue] + Array(json.utf8) }
}

enum Base32 {
    static func decode(_ s: String) -> [UInt8]? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, acc = 0
        var out: [UInt8] = []
        for ch in s.uppercased() where ch != " " && ch != "=" {
            guard let v = alphabet.firstIndex(of: ch) else { return nil }
            acc = (acc << 5) | v; bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> bits) & 0xff)) }
        }
        return out
    }
}
