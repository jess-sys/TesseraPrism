/**
 * A byte pipe to a Prism device. Frames are the protocol frames of ARCHITECTURE §5.1
 * (`[kind][payload]`); chunking (BLE) and COBS (USB) are handled inside the transport.
 */
export interface Transport {
  /** Human-readable name, e.g. "BLE" or "USB". */
  readonly label: string;
  /** Sends one complete protocol frame. Resolves when handed to the OS/driver. */
  send(frame: Uint8Array): Promise<void>;
  /** Registers a frame listener. Returns an unsubscribe function. */
  onFrame(cb: (frame: Uint8Array) => void): () => void;
  /** Registers a disconnect listener. Returns an unsubscribe function. */
  onDisconnect(cb: (reason: string) => void): () => void;
  /** Closes the link. Idempotent. */
  close(): Promise<void>;
}

/** Simple synchronous listener set used by the transports. */
export class Listeners<T extends unknown[]> {
  private set = new Set<(...args: T) => void>();

  add(cb: (...args: T) => void): () => void {
    this.set.add(cb);
    return () => this.set.delete(cb);
  }

  emit(...args: T): void {
    for (const cb of [...this.set]) {
      try {
        cb(...args);
      } catch (err) {
        console.error('listener failed', err);
      }
    }
  }
}
