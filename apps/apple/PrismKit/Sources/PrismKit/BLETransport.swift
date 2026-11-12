#if canImport(CoreBluetooth)
import Foundation
import os

let bleLog = Logger(subsystem: "ch.neutheria.prism", category: "ble")
@preconcurrency import CoreBluetooth

public enum PrismBLE {
    public static let service = CBUUID(string: "9e5d0001-3c4a-4b8e-9f1a-5072736d0000")
    public static let rx = CBUUID(string: "9e5d0002-3c4a-4b8e-9f1a-5072736d0000")   // host -> device
    public static let tx = CBUUID(string: "9e5d0003-3c4a-4b8e-9f1a-5072736d0000")   // device -> host (notify)
}

/// CoreBluetooth central. Scans for the Prism service (or retrieves a cached peripheral by identifier
/// for fast reconnect), writes RX without response, subscribes to TX notifications.
public final class BLETransport: NSObject, PrismTransport, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    public let frames: AsyncStream<[UInt8]>
    private let continuation: AsyncStream<[UInt8]>.Continuation
    private let core: PrismCore
    private let store: PairedDeviceStore?
    private let scanTimeout: TimeInterval
    private let queue = DispatchQueue(label: "ch.neutheria.prism.ble")

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var rxChar: CBCharacteristic?
    /// Random per-transport (= per connection) BLE channel id; tags every chunk we send.
    private let chan: UInt32
    private var reassembler: PrismReassembler
    private var connectCont: CheckedContinuation<Void, Error>?
    /// Senders waiting for `peripheralIsReady(toSendWriteWithoutResponse:)`, by token.
    private var readyConts: [UInt64: CheckedContinuation<Bool, Never>] = [:]
    private var readyToken: UInt64 = 0
    private var stateWaiters: [CheckedContinuation<Void, Error>] = []
    private var timeoutWork: DispatchWorkItem?

    public init(core: PrismCore, store: PairedDeviceStore? = nil, scanTimeout: TimeInterval = 15) {
        var c: AsyncStream<[UInt8]>.Continuation!
        frames = AsyncStream { c = $0 }
        continuation = c
        self.core = core; self.store = store; self.scanTimeout = scanTimeout
        chan = core.randomChannel()
        reassembler = core.makeReassembler(chan: chan)
        super.init()
        central = CBCentralManager(delegate: self, queue: queue)
    }

    // MARK: PrismTransport

    public func connect() async throws {
        try await waitPoweredOn()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                self.connectCont = cont
                self.reassembler = self.core.makeReassembler(chan: self.chan)
                if let id = self.store?.peripheralIdentifier,
                   let p = self.central.retrievePeripherals(withIdentifiers: [id]).first {
                    self.peripheral = p
                    p.delegate = self
                    self.central.connect(p)
                } else {
                    self.central.scanForPeripherals(withServices: [PrismBLE.service])
                }
                let work = DispatchWorkItem { [weak self] in self?.fail(TransportError.notFound) }
                self.timeoutWork = work
                self.queue.asyncAfter(deadline: .now() + self.scanTimeout, execute: work)
            }
        }
    }

    public func send(_ frame: [UInt8]) async throws {
        guard let p = peripheral, let rx = rxChar else { throw TransportError.disconnected }
        let maxChunk = p.maximumWriteValueLength(for: .withoutResponse)
        let chunks = core.bleChunk(frame: frame, maxChunk: maxChunk, chan: chan)
        bleLog.debug("tx frame len=\(frame.count, privacy: .public) maxChunk=\(maxChunk, privacy: .public) chunks=\(chunks.count, privacy: .public)")
        bleLog.notice("tx frame len=\(frame.count, privacy: .public) chunks=\(chunks.count, privacy: .public) chan=\(self.chan, privacy: .public)")
        for chunk in chunks {
            // Acknowledged writes: the device confirms each chunk (logged in didWriteValueFor),
            // and no reliance on the write-without-response "ready" callback, which some
            // processes sharing the macOS link never get.
            p.writeValue(Data(chunk), for: rx, type: .withResponse)
        }
    }

    public func disconnect() {
        queue.async {
            self.central.stopScan()
            if let p = self.peripheral {
                // Unsubscribe explicitly before leaving: on macOS the link (and its notification
                // state) outlives this process's connection when other processes share it.
                if let tx = p.services?.first(where: { $0.uuid == PrismBLE.service })?
                    .characteristics?.first(where: { $0.uuid == PrismBLE.tx }), tx.isNotifying {
                    p.setNotifyValue(false, for: tx)
                }
                self.central.cancelPeripheralConnection(p)
            }
            self.finish()
        }
    }

    // MARK: helpers

    private func waitPoweredOn() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                switch self.central.state {
                case .poweredOn: cont.resume()
                case .unknown, .resetting: self.stateWaiters.append(cont)
                case .unauthorized: cont.resume(throwing: TransportError.bluetoothUnavailable("permission denied"))
                case .unsupported: cont.resume(throwing: TransportError.bluetoothUnavailable("unsupported"))
                default: self.stateWaiters.append(cont)   // poweredOff: wait for user
                }
            }
        }
    }

    /// True once write-without-response is possible, false after `timeout`.
    private func waitWritable(_ p: CBPeripheral, timeout: TimeInterval) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            queue.async {
                if p.canSendWriteWithoutResponse { return cont.resume(returning: true) }
                self.readyToken &+= 1
                let token = self.readyToken
                self.readyConts[token] = cont
                self.queue.asyncAfter(deadline: .now() + timeout) {
                    self.readyConts.removeValue(forKey: token)?.resume(returning: false)
                }
            }
        }
    }

    private func fail(_ error: Error) {
        timeoutWork?.cancel(); timeoutWork = nil
        central.stopScan()
        if let c = connectCont { connectCont = nil; c.resume(throwing: error) }
        if let p = peripheral { central.cancelPeripheralConnection(p) }
    }

    private func succeed() {
        timeoutWork?.cancel(); timeoutWork = nil
        if let c = connectCont { connectCont = nil; c.resume() }
    }

    private func finish() {
        let waiting = readyConts; readyConts = [:]
        waiting.values.forEach { $0.resume(returning: false) }
        continuation.finish()
    }

    // MARK: CBCentralManagerDelegate

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            let w = stateWaiters; stateWaiters = []; w.forEach { $0.resume() }
        case .unauthorized, .unsupported:
            let w = stateWaiters; stateWaiters = []
            w.forEach { $0.resume(throwing: TransportError.bluetoothUnavailable("not authorized")) }
        default: break
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover p: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        peripheral = p
        p.delegate = self
        store?.deviceName = p.name
        central.connect(p)
    }

    public func centralManager(_ central: CBCentralManager, didConnect p: CBPeripheral) {
        store?.peripheralIdentifier = p.identifier
        p.discoverServices([PrismBLE.service])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        fail(TransportError.connectionFailed(error?.localizedDescription ?? "unknown"))
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        if connectCont != nil { fail(TransportError.disconnected) }
        rxChar = nil
        finish()
    }

    // MARK: CBPeripheralDelegate

    public func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let s = p.services?.first(where: { $0.uuid == PrismBLE.service }) else {
            return fail(TransportError.connectionFailed(error?.localizedDescription ?? "service missing"))
        }
        p.discoverCharacteristics([PrismBLE.rx, PrismBLE.tx], for: s)
    }

    public func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        guard error == nil, let chars = s.characteristics,
              let rx = chars.first(where: { $0.uuid == PrismBLE.rx }),
              let tx = chars.first(where: { $0.uuid == PrismBLE.tx }) else {
            return fail(TransportError.connectionFailed(error?.localizedDescription ?? "characteristics missing"))
        }
        rxChar = rx
        p.setNotifyValue(true, for: tx)
    }

    public func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor c: CBCharacteristic, error: Error?) {
        if let error { return fail(TransportError.connectionFailed(error.localizedDescription)) }
        bleLog.notice("notify state \(c.uuid.uuidString, privacy: .public) on=\(c.isNotifying, privacy: .public)")
        if c.uuid == PrismBLE.tx, c.isNotifying { succeed() }
    }

    public func peripheral(_ p: CBPeripheral, didUpdateValueFor c: CBCharacteristic, error: Error?) {
        if let error { bleLog.error("value update error: \(error.localizedDescription, privacy: .public)") }
        guard error == nil, c.uuid == PrismBLE.tx, let data = c.value else { return }
        bleLog.notice("rx chunk len=\(data.count, privacy: .public) hdr=\(data.first ?? 0, privacy: .public)")
        do {
            if let frame = try reassembler.push([UInt8](data)) { continuation.yield(frame) }
        } catch {
            bleLog.error("reassembly error: \(String(describing: error), privacy: .public)")
            reassembler = core.makeReassembler(chan: chan)
        }
    }

    public func peripheralIsReady(toSendWriteWithoutResponse p: CBPeripheral) {
        let waiting = readyConts; readyConts = [:]
        waiting.values.forEach { $0.resume(returning: true) }
    }

    public func peripheral(_ p: CBPeripheral, didWriteValueFor c: CBCharacteristic, error: Error?) {
        if let error { bleLog.error("write error: \(error.localizedDescription, privacy: .public)") }
        else { bleLog.notice("write acknowledged") }
    }
}
#endif
