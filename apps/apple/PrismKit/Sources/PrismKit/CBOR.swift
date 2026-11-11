import Foundation

/// Minimal CBOR (RFC 8949) encoder/decoder, enough for CTAP2.
public indirect enum CBOR: Equatable, Sendable {
    case int(Int64)            // major 0/1
    case bytes([UInt8])        // major 2
    case text(String)          // major 3
    case array([CBOR])         // major 4
    case map([(CBOR, CBOR)])   // major 5 (order preserved)
    case bool(Bool)
    case null
    case undefined

    public static func == (l: CBOR, r: CBOR) -> Bool {
        switch (l, r) {
        case (.int(let a), .int(let b)): return a == b
        case (.bytes(let a), .bytes(let b)): return a == b
        case (.text(let a), .text(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.map(let a), .map(let b)):
            return a.count == b.count && zip(a, b).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        case (.bool(let a), .bool(let b)): return a == b
        case (.null, .null), (.undefined, .undefined): return true
        default: return false
        }
    }

    public subscript(key: CBOR) -> CBOR? {
        if case .map(let pairs) = self { return pairs.first { $0.0 == key }?.1 }
        return nil
    }
    public subscript(key: Int64) -> CBOR? { self[.int(key)] }
    public subscript(key: String) -> CBOR? { self[.text(key)] }

    public var byteString: [UInt8]? { if case .bytes(let b) = self { return b }; return nil }
    public var string: String? { if case .text(let s) = self { return s }; return nil }
    public var integer: Int64? { if case .int(let i) = self { return i }; return nil }
    public var arrayValue: [CBOR]? { if case .array(let a) = self { return a }; return nil }

    // MARK: encode
    public func encode() -> [UInt8] {
        var out: [UInt8] = []
        write(&out)
        return out
    }

    private static func head(_ major: UInt8, _ n: UInt64, _ out: inout [UInt8]) {
        let m = major << 5
        switch n {
        case 0..<24: out.append(m | UInt8(n))
        case 24..<0x100: out += [m | 24, UInt8(n)]
        case 0x100..<0x10000: out += [m | 25, UInt8(n >> 8), UInt8(n & 0xff)]
        case 0x10000..<0x1_0000_0000: out.append(m | 26); for s in stride(from: 24, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xff)) }
        default: out.append(m | 27); for s in stride(from: 56, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xff)) }
        }
    }

    private func write(_ out: inout [UInt8]) {
        switch self {
        case .int(let i):
            if i >= 0 { CBOR.head(0, UInt64(i), &out) } else { CBOR.head(1, UInt64(-1 - i), &out) }
        case .bytes(let b): CBOR.head(2, UInt64(b.count), &out); out += b
        case .text(let s): let u = Array(s.utf8); CBOR.head(3, UInt64(u.count), &out); out += u
        case .array(let a): CBOR.head(4, UInt64(a.count), &out); a.forEach { $0.write(&out) }
        case .map(let m): CBOR.head(5, UInt64(m.count), &out); m.forEach { $0.0.write(&out); $0.1.write(&out) }
        case .bool(let b): out.append(b ? 0xf5 : 0xf4)
        case .null: out.append(0xf6)
        case .undefined: out.append(0xf7)
        }
    }

    // MARK: decode
    public enum DecodeError: Error { case truncated, unsupported(UInt8), trailingBytes, tooDeep }

    public static func decode(_ bytes: [UInt8]) throws -> CBOR {
        var pos = 0
        let v = try read(bytes, &pos, depth: 0)
        guard pos == bytes.count else { throw DecodeError.trailingBytes }
        return v
    }

    /// Decodes the first item and returns the number of bytes consumed.
    public static func decodePrefix(_ bytes: [UInt8]) throws -> (CBOR, Int) {
        var pos = 0
        let v = try read(bytes, &pos, depth: 0)
        return (v, pos)
    }

    private static func readUInt(_ b: [UInt8], _ pos: inout Int, info: UInt8) throws -> UInt64 {
        func take(_ n: Int) throws -> UInt64 {
            guard pos + n <= b.count else { throw DecodeError.truncated }
            var v: UInt64 = 0
            for i in 0..<n { v = v << 8 | UInt64(b[pos + i]) }
            pos += n
            return v
        }
        switch info {
        case 0..<24: return UInt64(info)
        case 24: return try take(1)
        case 25: return try take(2)
        case 26: return try take(4)
        case 27: return try take(8)
        default: throw DecodeError.unsupported(info)
        }
    }

    private static func read(_ b: [UInt8], _ pos: inout Int, depth: Int) throws -> CBOR {
        guard depth < 32 else { throw DecodeError.tooDeep }
        guard pos < b.count else { throw DecodeError.truncated }
        let initial = b[pos]; pos += 1
        let major = initial >> 5, info = initial & 0x1f
        switch major {
        case 0: return .int(Int64(truncatingIfNeeded: try readUInt(b, &pos, info: info)))
        case 1: return .int(-1 - Int64(truncatingIfNeeded: try readUInt(b, &pos, info: info)))
        case 2, 3:
            let n = Int(try readUInt(b, &pos, info: info))
            guard n >= 0, pos + n <= b.count else { throw DecodeError.truncated }
            let slice = Array(b[pos..<pos + n]); pos += n
            return major == 2 ? .bytes(slice) : .text(String(decoding: slice, as: UTF8.self))
        case 4:
            let n = Int(try readUInt(b, &pos, info: info))
            var a: [CBOR] = []
            for _ in 0..<n { a.append(try read(b, &pos, depth: depth + 1)) }
            return .array(a)
        case 5:
            let n = Int(try readUInt(b, &pos, info: info))
            var m: [(CBOR, CBOR)] = []
            for _ in 0..<n { let k = try read(b, &pos, depth: depth + 1); m.append((k, try read(b, &pos, depth: depth + 1))) }
            return .map(m)
        case 6:
            _ = try readUInt(b, &pos, info: info)   // ignore tag
            return try read(b, &pos, depth: depth + 1)
        default:
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: return .undefined
            default: throw DecodeError.unsupported(initial)
            }
        }
    }
}
