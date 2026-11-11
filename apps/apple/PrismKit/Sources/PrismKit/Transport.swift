import Foundation

/// Frame-level transport (chunking is the transport's business).
public protocol PrismTransport: AnyObject {
    /// Complete reassembled frames from the device. Finishes when the link drops.
    var frames: AsyncStream<[UInt8]> { get }
    func connect() async throws
    func send(_ frame: [UInt8]) async throws
    func disconnect()
}

public enum TransportError: Error, LocalizedError {
    case bluetoothUnavailable(String), notFound, connectionFailed(String), disconnected, timeout
    public var errorDescription: String? {
        switch self {
        case .bluetoothUnavailable(let s): return "Bluetooth unavailable: \(s)"
        case .notFound: return "No Prism device found nearby"
        case .connectionFailed(let s): return "Connection failed: \(s)"
        case .disconnected: return "Disconnected from device"
        case .timeout: return "Timed out"
        }
    }
}
