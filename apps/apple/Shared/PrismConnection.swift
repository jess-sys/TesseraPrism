import Foundation
import PrismKit

/// Builds a connected, ready `PrismClient` over BLE, reusing the cached peripheral for fast reconnect.
/// Used by both the app and the (short-lived) AutoFill extension.
enum PrismConnection {
    static func makeClient(core: PrismCore = makeDefaultCore(),
                           scanTimeout: TimeInterval = 15) -> (client: PrismClient, transport: BLETransport, store: PairedDeviceStore) {
        let store = PairedDeviceStore()
        let transport = BLETransport(core: core, store: store, scanTimeout: scanTimeout)
        let keys = KeychainHostKeyStore()
        return (PrismClient(core: core, transport: transport, hostKeys: keys), transport, store)
    }

    /// One-shot helper for the extension: connect (already paired), run `body`, disconnect.
    static func withClient<T>(_ body: (PrismClient) async throws -> T) async throws -> T {
        let (client, _, store) = makeClient(scanTimeout: 10)
        _ = try await client.connect(needsPairing: !store.isPaired, syncTime: false)
        store.isPaired = true
        defer { Task { await client.disconnect() } }
        return try await body(client)
    }
}
