import type { CdcDecoderLike, PrismCore } from '../core/types';
import { Listeners, type Transport } from './types';

/** Espressif test VID/PID used by the dev firmware (ARCHITECTURE §1). */
export const PRISM_USB_FILTER = { usbVendorId: 0x303a, usbProductId: 0x8360 };
export const SERIAL_BAUD = 115200;

/**
 * Web Serial transport over USB CDC-ACM. Frames are COBS-encoded, 0x00-terminated (§5.1).
 */
export class SerialTransport implements Transport {
  readonly label = 'USB';
  private readonly frames = new Listeners<[Uint8Array]>();
  private readonly disconnects = new Listeners<[string]>();
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private readonly decoder: CdcDecoderLike;
  private closed = false;

  private constructor(
    private readonly core: PrismCore,
    private readonly port: SerialPort,
  ) {
    this.decoder = core.newCdcDecoder();
  }

  static isSupported(): boolean {
    return typeof navigator !== 'undefined' && 'serial' in navigator && !!navigator.serial;
  }

  /** Shows the port picker (must be called from a user gesture) and opens the port. */
  static async request(core: PrismCore): Promise<SerialTransport> {
    if (!SerialTransport.isSupported()) {
      throw new Error('Web Serial is not available in this browser.');
    }
    // requestPort must run within the click gesture; no awaits before it.
    const port = await navigator.serial.requestPort({ filters: [PRISM_USB_FILTER] });
    await port.open({ baudRate: SERIAL_BAUD });
    const t = new SerialTransport(core, port);
    t.startReading();
    t.writer = port.writable?.getWriter() ?? null;
    return t;
  }

  private startReading(): void {
    const readable = this.port.readable;
    if (!readable) return;
    this.reader = readable.getReader();
    void (async () => {
      try {
        for (;;) {
          const { value, done } = await this.reader!.read();
          if (done) break;
          if (!value) continue;
          for (const frame of this.decoder.push(value)) this.frames.emit(frame);
        }
        this.lost('USB port closed');
      } catch (err) {
        this.lost(err instanceof Error ? err.message : 'USB read error');
      }
    })();
  }

  private lost(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.disconnects.emit(reason);
  }

  async send(frame: Uint8Array): Promise<void> {
    if (!this.writer || this.closed) throw new Error('USB not connected');
    await this.writer.write(this.core.cdcEncode(frame));
  }

  onFrame(cb: (frame: Uint8Array) => void): () => void {
    return this.frames.add(cb);
  }

  onDisconnect(cb: (reason: string) => void): () => void {
    return this.disconnects.add(cb);
  }

  async close(): Promise<void> {
    const wasClosed = this.closed;
    this.closed = true;
    try {
      await this.reader?.cancel();
    } catch {
      /* ignore */
    }
    try {
      this.writer?.releaseLock();
    } catch {
      /* ignore */
    }
    if (!wasClosed) {
      try {
        await this.port.close();
      } catch {
        /* ignore */
      }
    }
  }
}
