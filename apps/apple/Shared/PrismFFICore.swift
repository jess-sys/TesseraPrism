import Foundation
import PrismKit

// Shared by the app and the AutoFill extension.
//
// Real core: adapter over the UniFFI-generated `PrismFFI` module (apps/apple/PrismFFIKit links
// crates/prism-ffi/out/PrismFFI.xcframework + PrismFFI.swift). When the module is not linked the apps
// fall back to the insecure StubCore.
#if canImport(PrismFFI)
import PrismFFI

final class FFISession: PrismSession {
    private let s: PrismFFI.Session
    init(_ s: PrismFFI.Session) { self.s = s }
    func start() throws -> [UInt8] { [UInt8](try s.start()) }
    func onFrame(_ frame: [UInt8]) throws -> String { try s.onFrame(frame: Data(frame)) }
    func sas() -> String? { s.sas() }
    func isEstablished() -> Bool { s.isEstablished() }
    func encryptRequest(json: String) throws -> [UInt8] { [UInt8](try s.encryptRequest(jsonEnvelope: json)) }
}

final class FFIReassembler: PrismReassembler {
    private let r: PrismFFI.BleReassembler
    init(chan: UInt32) throws { r = try PrismFFI.BleReassembler.withChannel(chan: chan) }
    func push(_ chunk: [UInt8]) throws -> [UInt8]? { try r.push(chunk: Data(chunk)).map { [UInt8]($0) } }
}

final class PrismFFICore: PrismCore {
    func generateHostKey() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let k = PrismFFI.generateHostKey()
        return ([UInt8](k.private), [UInt8](k.public))
    }
    func makeSession(hostPrivateKey: [UInt8]) throws -> PrismSession {
        FFISession(try PrismFFI.Session(hostPrivateKey: Data(hostPrivateKey)))
    }
    /// `maxChunk` is CoreBluetooth's maximumWriteValueLength (= ATT_MTU - 3); prism-ffi wants the ATT MTU
    /// and emits chunks of at most mtu - 3, hence the +3.
    func bleChunk(frame: [UInt8], maxChunk: Int, chan: UInt32) -> [[UInt8]] {
        let mtu = UInt32(max(maxChunk, 20) + 3)
        return ((try? PrismFFI.bleChunkV2(frame: Data(frame), mtu: mtu, chan: chan)) ?? []).map { [UInt8]($0) }
    }
    func makeReassembler(chan: UInt32) -> PrismReassembler {
        // Only fails for chan == 0; fall back to a fresh random channel rather than crash.
        (try? FFIReassembler(chan: chan)) ?? (try! FFIReassembler(chan: PrismFFI.randomChannel()))
    }
    func randomChannel() -> UInt32 { PrismFFI.randomChannel() }
    func parseOtpauth(_ uri: String) throws -> String { try PrismFFI.parseOtpauth(uri: uri) }
    func totpNow(totpJSON: String, unix: UInt64) throws -> String { try PrismFFI.totpNow(jsonTotp: totpJSON, unix: unix) }
    func decodePasswordSnapshot(bytes: Data) throws -> String { try PrismFFI.decodePasswordSnapshot(bytes: bytes) }
}
#endif

/// The core used by the apps: the real FFI when the xcframework is linked, else the insecure StubCore.
func makeDefaultCore() -> PrismCore {
    #if canImport(PrismFFI)
    return PrismFFICore()
    #else
    return StubCore()
    #endif
}

var isUsingStubCore: Bool {
    #if canImport(PrismFFI)
    return false
    #else
    return true
    #endif
}
