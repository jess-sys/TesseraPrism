import Foundation

/// Swift implementation of the BLE chunking of ARCHITECTURE.md §5.1.
/// Chunk = [hdr][body]; hdr bit7 = more chunks follow, bits0-6 = seq (mod 128).
/// First chunk body starts with u16 LE total frame length.
public enum BLEChunker {
    /// `maxChunk` is the maximum GATT payload (ATT_MTU - 3, i.e. CBPeripheral.maximumWriteValueLength).
    public static func chunk(frame: [UInt8], maxChunk: Int) -> [[UInt8]] {
        precondition(maxChunk >= 4, "MTU too small")
        var payload = [UInt8(frame.count & 0xff), UInt8((frame.count >> 8) & 0xff)] + frame
        var out: [[UInt8]] = []
        var seq: UInt8 = 0
        while true {
            let take = min(maxChunk - 1, payload.count)
            let body = Array(payload.prefix(take))
            payload.removeFirst(take)
            let more = !payload.isEmpty
            out.append([(more ? 0x80 : 0) | (seq & 0x7f)] + body)
            seq = (seq &+ 1) & 0x7f
            if !more { break }
        }
        return out
    }
}

public enum ReassemblyError: Error, Equatable { case emptyChunk, outOfSequence, tooShort, overflow }

public struct BLEReassembler: PrismReassembler {
    private var buf: [UInt8] = []
    private var expectedSeq: UInt8 = 0
    private var total: Int = 0
    private var count = 0   // chunks received for the current frame
    public init() {}

    /// Returns a complete frame once the last chunk arrives. A chunk with seq 0 resets state.
    public mutating func push(_ chunk: [UInt8]) throws -> [UInt8]? {
        guard let hdr = chunk.first else { throw ReassemblyError.emptyChunk }
        let seq = hdr & 0x7f, more = hdr & 0x80 != 0
        var body = Array(chunk.dropFirst())
        // seq 0 restarts a frame, except when the 7-bit sequence legitimately wrapped (>= 128 chunks).
        let wrapped = seq == 0 && count > 0 && expectedSeq == 0
        if seq == 0 && !wrapped {
            buf = []; expectedSeq = 0; count = 0
            guard body.count >= 2 else { throw ReassemblyError.tooShort }
            total = Int(body[0]) | Int(body[1]) << 8
            body.removeFirst(2)
        } else if seq != expectedSeq {
            buf = []; expectedSeq = 0; count = 0
            throw ReassemblyError.outOfSequence
        }
        buf += body
        count += 1
        expectedSeq = (seq &+ 1) & 0x7f
        if buf.count > total { buf = []; count = 0; throw ReassemblyError.overflow }
        if !more {
            defer { buf = []; expectedSeq = 0; count = 0 }
            guard buf.count == total else { throw ReassemblyError.tooShort }
            return buf
        }
        return nil
    }
}

// MARK: - Framing v2 (channels), ARCHITECTURE.md §5.1 / docs/plans/ble-client-channels.md
//
// first chunk: [hdr][chan u32 LE][total_len u16 LE][body…]; next: [hdr][chan u32 LE][body…]
// hdr: bit7 = more, bit6 = 1 (v2 marker), bits0-5 = seq (mod 64). Mirrors prism-proto `ble::chunk_v2`.

extension BLEChunker {
    /// `maxChunk` is the maximum GATT payload (ATT_MTU - 3). `chan` must be non-zero.
    public static func chunkV2(frame: [UInt8], maxChunk: Int, chan: UInt32) -> [[UInt8]] {
        precondition(maxChunk >= 20, "MTU too small")
        precondition(chan != 0, "channel 0 is reserved for v1")
        precondition(frame.count <= 0xffff, "frame too large")
        let chanLE = (0..<4).map { UInt8((chan >> (8 * UInt32($0))) & 0xff) }
        var out: [[UInt8]] = []
        var pos = 0
        var seq: UInt8 = 0
        while true {
            var c: [UInt8] = [0] + chanLE
            if out.isEmpty { c += [UInt8(frame.count & 0xff), UInt8(frame.count >> 8)] }
            let n = min(maxChunk - c.count, frame.count - pos)
            c += frame[pos..<pos + n]
            pos += n
            let more = pos < frame.count
            c[0] = (seq & 0x3f) | 0x40 | (more ? 0x80 : 0)
            out.append(c)
            if !more { break }
            seq = (seq &+ 1) & 0x3f
        }
        return out
    }
}

/// Host-side v2 reassembler for one channel. Chunks of other channels and v1 chunks are ignored
/// (`nil`) without touching the partial frame.
public struct BLEReassemblerV2: PrismReassembler {
    public let chan: UInt32
    private var buf: [UInt8] = []
    private var total = 0
    private var nextSeq: UInt8 = 0
    private var active = false
    private var count = 0
    public init(chan: UInt32) { self.chan = chan }

    private mutating func reset() { buf = []; total = 0; nextSeq = 0; active = false; count = 0 }

    public mutating func push(_ chunk: [UInt8]) throws -> [UInt8]? {
        guard !chunk.isEmpty else { throw ReassemblyError.emptyChunk }
        guard chunk.count >= 5, chunk[0] & 0x40 != 0 else { return nil }
        let c = UInt32(chunk[1]) | UInt32(chunk[2]) << 8 | UInt32(chunk[3]) << 16 | UInt32(chunk[4]) << 24
        guard c != 0, c == chan else { return nil }
        let hdr = chunk[0]
        var body = Array(chunk.dropFirst(5))
        do { return try pushInner(hdr, &body) } catch { reset(); throw error }
    }

    private mutating func pushInner(_ hdr: UInt8, _ body: inout [UInt8]) throws -> [UInt8]? {
        let seq = hdr & 0x3f, more = hdr & 0x80 != 0
        let wrapped = seq == 0 && active && count > 0 && count % 64 == 0
        if seq == 0 && !wrapped {
            reset()
            guard body.count >= 2 else { throw ReassemblyError.tooShort }
            total = Int(body[0]) | Int(body[1]) << 8
            body.removeFirst(2)
            active = true
        } else if !active || seq != nextSeq {
            throw ReassemblyError.outOfSequence
        }
        nextSeq = (seq &+ 1) & 0x3f
        count += 1
        if buf.count + body.count > total { throw ReassemblyError.overflow }
        buf += body
        let complete = buf.count == total
        switch (more, complete) {
        case (false, true): let f = buf; reset(); return f
        case (true, false): return nil
        default: throw ReassemblyError.tooShort
        }
    }
}
