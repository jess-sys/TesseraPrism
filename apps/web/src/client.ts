import type {
  Entry,
  EntryIdBytes,
  EntryKind,
  EntrySummary,
  DeviceInfo,
  Envelope,
  ErrorCode,
  HostKeyPair,
  ImportMode,
  KeyboardLayout,
  PairedHost,
  PrismCore,
  ProtoError,
  ProtoSession,
  Request,
  Response,
  SecretField,
  SecretValue,
  Settings,
  SshPublicKeyInfo,
  SessionEvent,
  ApprovalPolicy,
} from './core/types';
import type { Transport } from './transport/types';
import { Listeners } from './transport/types';

/** Error returned by the device (`Response::Error`) or raised locally. `code` is an ErrorCode or a local code. */
export class PrismError extends Error {
  constructor(
    readonly code: ErrorCode | 'Timeout' | 'NotConnected' | 'Disconnected' | 'PlainError' | 'Unexpected' | string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'PrismError';
  }
}

/** The device does not know this browser's host key (ARCHITECTURE §5.2). */
export class NotPairedError extends PrismError {
  constructor() {
    super(
      'NotPaired',
      'This browser is not paired with the device. On the device, open Settings > Pair new host, then use Pair here.',
    );
    this.name = 'NotPairedError';
  }
}

export type ClientEvent =
  | { type: 'sas'; sas: string }
  | { type: 'paired'; label: string }
  | { type: 'disconnected'; reason: string };

export interface ClientOptions {
  /** Per-request timeout (ARCHITECTURE §5.3: host timeout = 60 s). */
  requestTimeoutMs?: number;
  handshakeTimeoutMs?: number;
}

/** Export/import chunk size (ARCHITECTURE §5.3: <= 8 KiB). */
export const TRANSFER_CHUNK = 8 * 1024;

const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 20_000;

/** Extracts the payload of a `{Variant: payload}` response, or throws on a mismatch. */
function field<K extends string>(r: Response, key: K): Extract<Response, Record<K, unknown>>[K] {
  if (typeof r === 'object' && r !== null && key in r) {
    return (r as unknown as Record<K, Extract<Response, Record<K, unknown>>[K]>)[key];
  }
  throw new PrismError('Unexpected', `expected ${key} response, got ${JSON.stringify(r)}`);
}

function expectOk(r: Response): void {
  if (r !== 'Ok') throw new PrismError('Unexpected', `expected Ok, got ${JSON.stringify(r)}`);
}

function isEnvelope(x: unknown): x is Envelope<Response> {
  return typeof x === 'object' && x !== null && 'id' in x && 'body' in x;
}

function plainErrorToException(p: ProtoError | string): PrismError {
  if (typeof p === 'string') {
    return p.includes('NotPaired') ? new NotPairedError() : new PrismError('PlainError', p);
  }
  const code = p.code ?? 'PlainError';
  if (code === 'NotPaired') return new NotPairedError();
  return new PrismError(code, p.message ?? code);
}

/**
 * High-level client: owns one transport and one Noise session.
 * Requests are serialized (the device handles one approval at a time) and matched by `id`.
 */
export class PrismClient {
  private session: ProtoSession | null = null;
  private established = false;
  private nextId = 1;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly pending = new Map<
    number,
    { resolve: (r: Response) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  >();
  private handshake: { resolve: () => void; reject: (e: Error) => void } | null = null;
  private readonly events = new Listeners<[ClientEvent]>();
  private readonly unsubscribe: Array<() => void>;
  private readonly requestTimeoutMs: number;
  private readonly handshakeTimeoutMs: number;

  constructor(
    private readonly core: PrismCore,
    private readonly transport: Transport,
    private readonly hostKey: HostKeyPair,
    opts: ClientOptions = {},
  ) {
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.handshakeTimeoutMs = opts.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    this.unsubscribe = [
      transport.onFrame((f) => this.onFrame(f)),
      transport.onDisconnect((reason) => this.onLost(reason)),
    ];
  }

  get transportLabel(): string {
    return this.transport.label;
  }

  get isEstablished(): boolean {
    return this.established;
  }

  /** Subscribes to SAS/pairing/disconnect events. Returns an unsubscribe function. */
  on(cb: (ev: ClientEvent) => void): () => void {
    return this.events.add(cb);
  }

  /**
   * Noise handshake, then `GetInfo` (which also completes pairing when the device is in
   * pairing mode), then clock sync. Throws NotPairedError if the device rejects this host.
   */
  async connect(opts: { pairing?: boolean } = {}): Promise<DeviceInfo> {
    try {
      await this.doHandshake();
    } catch (err) {
      await this.close();
      throw err;
    }
    const sas = this.session?.sas() ?? null;
    if (sas) this.events.emit({ type: 'sas', sas });
    try {
      // In pairing mode the device shows the SAS and answers after the user taps Confirm.
      let r = await this.call('GetInfo', opts.pairing ? 60_000 : undefined);
      if (typeof r === 'object' && 'Paired' in r) {
        this.events.emit({ type: 'paired', label: r.Paired.label });
        r = await this.call('GetInfo');
      }
      const info = field(r, 'Info');
      try {
        await this.setTime(Math.floor(Date.now() / 1000));
      } catch (err) {
        console.warn('SetTime failed (continuing)', err);
      }
      return info;
    } catch (err) {
      if (err instanceof PrismError && err.code === 'NotPaired') throw new NotPairedError();
      throw err;
    }
  }

  /** Closes the transport and rejects anything in flight. */
  async close(): Promise<void> {
    this.unsubscribe.forEach((u) => u());
    this.failAll(new PrismError('Disconnected', 'Disconnected'));
    this.established = false;
    this.session = null;
    await this.transport.close();
  }

  // ------------------------------------------------------------ handshake and framing

  private doHandshake(): Promise<void> {
    this.session?.free?.();
    const session = this.core.newSession(this.hostKey.private);
    this.session = session;
    this.established = false;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.handshake = null;
        reject(new PrismError('Timeout', 'Noise handshake timed out'));
      }, this.handshakeTimeoutMs);
      this.handshake = {
        resolve: () => {
          clearTimeout(timer);
          this.handshake = null;
          resolve();
        },
        reject: (e) => {
          clearTimeout(timer);
          this.handshake = null;
          reject(e);
        },
      };
      this.transport.send(session.start()).catch((err: unknown) => {
        this.handshake?.reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  private onFrame(frame: Uint8Array): void {
    const session = this.session;
    if (!session) return;
    let ev: SessionEvent;
    try {
      ev = session.onFrame(frame);
    } catch (err) {
      console.warn('dropping frame the session rejected', err);
      return;
    }
    if (typeof ev === 'object') {
      if ('SendFrame' in ev) {
        this.transport.send(Uint8Array.from(ev.SendFrame)).catch((err: unknown) => {
          this.handshake?.reject(err instanceof Error ? err : new Error(String(err)));
        });
      } else if ('Response' in ev) {
        this.deliver(ev.Response);
      } else if ('PlainError' in ev) {
        const err = plainErrorToException(ev.PlainError);
        if (this.handshake) this.handshake.reject(err);
        else this.failAll(err);
      }
    }
    // The Rust initiator never emits Established; check the session state after every frame.
    if (!this.established && (ev === 'Established' || session.isEstablished())) {
      this.established = true;
      this.handshake?.resolve();
    }
  }

  private deliver(raw: Envelope<Response> | Response): void {
    let id: number;
    let body: Response;
    if (isEnvelope(raw)) {
      id = raw.id;
      body = raw.body;
    } else {
      // Bare response (no id echoed): safe because requests are serialized.
      const first = this.pending.keys().next();
      if (first.done) return;
      id = first.value;
      body = raw;
    }
    const p = this.pending.get(id);
    if (!p) {
      console.warn('response for unknown or timed-out request', id);
      return;
    }
    this.pending.delete(id);
    clearTimeout(p.timer);
    if (typeof body === 'object' && body !== null && 'Error' in body) {
      p.reject(new PrismError(body.Error, `device error: ${body.Error}`));
    } else {
      p.resolve(body);
    }
  }

  private onLost(reason: string): void {
    this.established = false;
    this.failAll(new PrismError('Disconnected', reason));
    this.events.emit({ type: 'disconnected', reason });
  }

  private failAll(err: Error): void {
    this.handshake?.reject(err);
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
      this.pending.delete(id);
    }
  }

  /** Serialized request/response. */
  private call(body: Request, timeoutMs: number = this.requestTimeoutMs): Promise<Response> {
    const run = () => this.sendOne(body, timeoutMs);
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private sendOne(body: Request, timeoutMs: number): Promise<Response> {
    const session = this.session;
    if (!session || !this.established) {
      return Promise.reject(new PrismError('NotConnected', 'Not connected to a device'));
    }
    const id = this.nextId;
    this.nextId = id >= 0xffff_fffe ? 1 : id + 1;
    const envelope: Envelope<Request> = { id, body };
    let frame: Uint8Array;
    try {
      frame = session.encryptRequest(JSON.stringify(envelope));
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
    return new Promise<Response>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new PrismError('Timeout', 'No response from device (approval may have timed out)'));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.transport.send(frame).catch((err: unknown) => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  // ------------------------------------------------------------ typed API (§5.3)

  async getInfo(): Promise<DeviceInfo> {
    return field(await this.call('GetInfo'), 'Info');
  }

  async setTime(unix: number): Promise<void> {
    expectOk(await this.call({ SetTime: { unix } }));
  }

  async unlock(passphrase: string): Promise<void> {
    expectOk(await this.call({ Unlock: { passphrase } }));
  }

  async lock(): Promise<void> {
    expectOk(await this.call('Lock'));
  }

  async listEntries(kind?: EntryKind): Promise<EntrySummary[]> {
    return field(await this.call({ ListEntries: { kind: kind ?? null } }), 'Entries');
  }

  async getSecret(id: EntryIdBytes, secretField: SecretField, context: string | null = null): Promise<SecretValue> {
    return field(await this.call({ GetSecret: { id, field: secretField, context } }), 'Secret');
  }

  async getTotp(id: EntryIdBytes): Promise<{ code: string; valid_until: number }> {
    return field(await this.call({ GetTotp: { id } }), 'Totp');
  }

  /** Full entry including secrets (approval per policy). Used by the edit forms. */
  async getEntry(id: EntryIdBytes): Promise<Entry> {
    return field(await this.call({ GetEntry: { id } }), 'Entry');
  }

  /** Sets the recovery passphrase (device tap required). Minimum length enforced by the UI. */
  async setRecoveryPassphrase(passphrase: string): Promise<void> {
    expectOk(await this.call({ SetRecoveryPassphrase: { passphrase } }));
  }

  async addEntry(entry: Entry): Promise<EntryIdBytes> {
    return field(await this.call({ AddEntry: { entry } }), 'EntryId');
  }

  async updateEntry(entry: Entry): Promise<void> {
    expectOk(await this.call({ UpdateEntry: { entry } }));
  }

  async deleteEntry(id: EntryIdBytes): Promise<void> {
    expectOk(await this.call({ DeleteEntry: { id } }));
  }

  async markRecoveryCodeUsed(id: EntryIdBytes, index: number): Promise<void> {
    expectOk(await this.call({ MarkRecoveryCodeUsed: { id, index } }));
  }

  /** Derives a new Ed25519 key on the device (rev 2: responds with the new key, one element). */
  async generateSshKey(name: string, comment: string, policy: ApprovalPolicy): Promise<SshPublicKeyInfo> {
    const keys = field(await this.call({ GenerateSshKey: { name, comment, policy } }), 'SshKeys');
    const key = keys[0];
    if (!key) throw new PrismError('Unexpected', 'GenerateSshKey returned no key');
    return key;
  }

  async sshListKeys(): Promise<SshPublicKeyInfo[]> {
    return field(await this.call('SshListKeys'), 'SshKeys');
  }

  async sshSign(publicKey: number[], data: Uint8Array, flags: number, hostHint: string | null = null): Promise<Uint8Array> {
    const sig = field(
      await this.call({ SshSign: { public_key: publicKey, data: Array.from(data), flags, host_hint: hostHint } }),
      'SshSignature',
    );
    return Uint8Array.from(sig);
  }

  async ctap(cbor: Uint8Array, originHint: string | null = null): Promise<Uint8Array> {
    return Uint8Array.from(field(await this.call({ Ctap: { cbor: Array.from(cbor), origin_hint: originHint } }), 'Ctap'));
  }

  /** Types a secret over USB HID on the device (device must be on USB). */
  async typeEntry(id: EntryIdBytes, secretField: SecretField, layout: KeyboardLayout): Promise<void> {
    expectOk(await this.call({ TypeEntry: { id, field: secretField, layout } }));
  }

  /**
   * Exports the whole vault as an encrypted `.prism` file (8 KiB chunks). The device verifies
   * `passphrase` against the recovery slot and encrypts the export with it.
   */
  async exportVault(passphrase: string, onProgress?: (done: number, total: number) => void): Promise<Uint8Array> {
    const total = field(await this.call({ Export: { passphrase } }), 'ExportReady').total_len;
    const out = new Uint8Array(total);
    let off = 0;
    while (off < total) {
      const c = field(await this.call({ ExportChunk: { offset: off } }), 'Chunk');
      if (c.offset !== off || c.data.length === 0 || off + c.data.length > total) {
        throw new PrismError('Unexpected', `bad export chunk at offset ${off}`);
      }
      out.set(c.data, off);
      off += c.data.length;
      onProgress?.(off, total);
    }
    return out;
  }

  /** Imports a `.prism` file. The passphrase is the recovery passphrase of that export. */
  async importVault(
    bytes: Uint8Array,
    passphrase: string,
    mode: ImportMode,
    onProgress?: (done: number, total: number) => void,
  ): Promise<void> {
    expectOk(await this.call({ ImportBegin: { total_len: bytes.length } }));
    for (let off = 0; off < bytes.length; off += TRANSFER_CHUNK) {
      const data = Array.from(bytes.subarray(off, off + TRANSFER_CHUNK));
      expectOk(await this.call({ ImportChunk: { offset: off, data } }));
      onProgress?.(Math.min(off + TRANSFER_CHUNK, bytes.length), bytes.length);
    }
    expectOk(await this.call({ ImportCommit: { passphrase, mode } }));
  }

  async listPairedHosts(): Promise<PairedHost[]> {
    return field(await this.call('ListPairedHosts'), 'PairedHosts');
  }

  async removePairedHost(publicKey: number[]): Promise<void> {
    expectOk(await this.call({ RemovePairedHost: { public_key: publicKey } }));
  }

  async getSettings(): Promise<Settings> {
    return field(await this.call('GetSettings'), 'Settings');
  }

  async setSettings(settings: Settings): Promise<void> {
    expectOk(await this.call({ SetSettings: { settings } }));
  }
}

