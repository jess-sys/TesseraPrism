import type { BleReassemblerLike, PrismCore } from '../core/types';
import { PRISM_RX_UUID, PRISM_SERVICE_UUID, PRISM_TX_UUID } from '../core/types';
import { Listeners, type Transport } from './types';

/** Default ATT MTU assumed when none is negotiated (Web Bluetooth does not expose MTU). */
export const DEFAULT_ATT_MTU = 185;

export interface BleOptions {
  /** ATT MTU used for chunking (max chunk = mtu - 3, ARCHITECTURE §5.1). */
  mtu?: number;
}

/**
 * Web Bluetooth transport. Writes go to RX (Write Without Response) and
 * frames arrive as notifications on TX. Chunking and reassembly are done by prism-wasm.
 *
 * Always uses BLE framing v2 (docs/plans/ble-client-channels.md): each connection picks a random
 * channel id, tags every chunk it sends with it, and reassembles only chunks tagged with it, so
 * other host processes sharing the same CoreBluetooth link cannot corrupt this client's frames.
 */
export class BleTransport implements Transport {
  readonly label = 'BLE';
  private readonly frames = new Listeners<[Uint8Array]>();
  private readonly disconnects = new Listeners<[string]>();
  private device: BluetoothDevice | null = null;
  private rx: BluetoothRemoteGATTCharacteristic | null = null;
  private readonly channel: number;
  private readonly reassembler: BleReassemblerLike;
  private queue: Promise<void> = Promise.resolve();
  private readonly mtu: number;
  private closed = false;

  private readonly onNotify = (ev: Event): void => {
    const value = (ev.target as BluetoothRemoteGATTCharacteristic).value;
    if (!value) return;
    const chunk = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    try {
      const frame = this.reassembler.push(chunk.slice());
      if (frame) this.frames.emit(frame);
    } catch (err) {
      console.warn('BLE reassembly error, dropping partial frame', err);
    }
  };

  private readonly onGattDisconnect = (): void => {
    if (this.closed) return;
    this.closed = true;
    this.disconnects.emit('BLE link lost');
  };

  private constructor(private readonly core: PrismCore, opts: BleOptions) {
    this.mtu = opts.mtu ?? DEFAULT_ATT_MTU;
    this.channel = core.randomChannel();
    this.reassembler = core.newBleReassemblerV2(this.channel);
  }

  static isSupported(): boolean {
    return typeof navigator !== 'undefined' && 'bluetooth' in navigator && !!navigator.bluetooth;
  }

  /** Shows the browser device picker (must be called from a user gesture) and connects. */
  static async request(core: PrismCore, opts: BleOptions = {}): Promise<BleTransport> {
    if (!BleTransport.isSupported()) {
      throw new Error('Web Bluetooth is not available in this browser.');
    }
    const t = new BleTransport(core, opts);
    // requestDevice must run synchronously within the click gesture: no awaits before it.
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [PRISM_SERVICE_UUID] }],
      optionalServices: [PRISM_SERVICE_UUID],
    });
    t.device = device;
    device.addEventListener('gattserverdisconnected', t.onGattDisconnect);
    const server = await device.gatt?.connect();
    if (!server) throw new Error('Could not open GATT server.');
    const service = await server.getPrimaryService(PRISM_SERVICE_UUID);
    t.rx = await service.getCharacteristic(PRISM_RX_UUID);
    const tx = await service.getCharacteristic(PRISM_TX_UUID);
    tx.addEventListener('characteristicvaluechanged', t.onNotify);
    await tx.startNotifications();
    return t;
  }

  send(frame: Uint8Array): Promise<void> {
    const rx = this.rx;
    if (!rx || this.closed) return Promise.reject(new Error('BLE not connected'));
    const chunks = this.core.bleChunkV2(frame, this.mtu, this.channel);
    // Serialize GATT writes: concurrent writeValue calls on one characteristic are not reliable.
    const job = this.queue.then(async () => {
      for (const c of chunks) {
        await rx.writeValueWithoutResponse(c as BufferSource);
      }
    });
    this.queue = job.catch(() => undefined);
    return job;
  }

  onFrame(cb: (frame: Uint8Array) => void): () => void {
    return this.frames.add(cb);
  }

  onDisconnect(cb: (reason: string) => void): () => void {
    return this.disconnects.add(cb);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      this.device?.gatt?.disconnect();
    } catch {
      /* already gone */
    }
  }
}
