import Foundation

/// Run `op`, retrying while the device answers `Locked`. In standby the device wakes to its PIN pad
/// when a request is refused as locked, so the caller only has to wait for the user to type the PIN.
/// `onLocked` is called once, the first time the device reports it is locked (show "Unlock your
/// Prism..."). Gives up after `timeout`; cancelling the surrounding task stops waiting immediately.
public func untilUnlocked<T>(
    timeout: TimeInterval = 120,
    retryEvery: TimeInterval = 2,
    onLocked: () -> Void,
    _ op: () async throws -> T
) async throws -> T {
    let start = Date()
    var notified = false
    while true {
        do {
            return try await op()
        } catch PrismError.device(.locked) {
            if !notified {
                notified = true
                onLocked()
            }
            if Date().timeIntervalSince(start) >= timeout { throw PrismError.device(.locked) }
            try await Task.sleep(nanoseconds: UInt64(retryEvery * 1_000_000_000))
        }
    }
}
