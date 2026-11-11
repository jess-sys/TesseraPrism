/**
 * MOCK CORE: used only when `src/wasm/pkg` is missing (or `?mock` is in the URL).
 * It is a labelled, in-memory stand-in for prism-wasm and a fake Prism device, meant for
 * UI development. It does NOT implement the real Noise protocol or real cryptography:
 * the "session" is a plain framed JSON channel and TOTP codes are placeholders.
 */
import type {
  BleReassemblerLike,
  CdcDecoderLike,
  Entry,
  EntryIdBytes,
  EntrySummary,
  HostKeyPair,
  PairedHost,
  PrismCore,
  ProtoSession,
  Request,
  Response,
  Settings,
  SessionEvent,
  SshPublicKeyInfo,
  Totp,
} from './types';
import { FRAME_HANDSHAKE, FRAME_PLAIN_ERROR, FRAME_TRANSPORT } from './types';
import type { Transport } from '../transport/types';
import { Listeners } from '../transport/types';
import { encodeEd25519PublicBlob, formatOpenSshPublicKey } from '../keys/openssh';

const enc = new TextEncoder();
const dec = new TextDecoder();

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// ---------------------------------------------------------------- framing (real algorithms)

/** COBS encode + trailing 0x00 delimiter (ARCHITECTURE §5.1, USB CDC). */
export function cobsEncode(input: Uint8Array): Uint8Array {
  const out: number[] = [0];
  let codeIdx = 0;
  let code = 1;
  for (const b of input) {
    if (b === 0) {
      out[codeIdx] = code;
      codeIdx = out.length;
      out.push(0);
      code = 1;
    } else {
      out.push(b);
      code++;
      if (code === 0xff) {
        out[codeIdx] = code;
        codeIdx = out.length;
        out.push(0);
        code = 1;
      }
    }
  }
  out[codeIdx] = code;
  out.push(0);
  return Uint8Array.from(out);
}

function cobsDecodeBlock(enc: number[]): Uint8Array | null {
  const out: number[] = [];
  let i = 0;
  while (i < enc.length) {
    const code = enc[i]!;
    if (code === 0) return null;
    for (let j = 1; j < code; j++) {
      if (i + j >= enc.length) return null;
      out.push(enc[i + j]!);
    }
    i += code;
    if (code !== 0xff && i < enc.length) out.push(0);
  }
  return Uint8Array.from(out);
}

class MockCdcDecoder implements CdcDecoderLike {
  private buf: number[] = [];
  push(bytes: Uint8Array): Uint8Array[] {
    const frames: Uint8Array[] = [];
    for (const b of bytes) {
      if (b === 0) {
        if (this.buf.length > 0) {
          const f = cobsDecodeBlock(this.buf);
          if (f) frames.push(f);
        }
        this.buf = [];
      } else {
        this.buf.push(b);
      }
    }
    return frames;
  }
}

/** BLE chunking: hdr bit7 = more follow, bits0-6 = seq; first chunk carries u16 LE total_len. */
export function bleChunkJs(frame: Uint8Array, mtu: number): Uint8Array[] {
  const max = mtu - 3;
  if (max < 4) throw new Error('MTU too small');
  const out: Uint8Array[] = [];
  let offset = 0;
  let seq = 0;
  for (;;) {
    const first = seq === 0;
    const cap = first ? max - 3 : max - 1;
    const take = Math.min(cap, frame.length - offset);
    const more = offset + take < frame.length;
    const body = first ? 3 : 1;
    const chunk = new Uint8Array(body + take);
    chunk[0] = (seq & 0x7f) | (more ? 0x80 : 0);
    if (first) {
      chunk[1] = frame.length & 0xff;
      chunk[2] = (frame.length >> 8) & 0xff;
    }
    chunk.set(frame.subarray(offset, offset + take), body);
    out.push(chunk);
    offset += take;
    seq = (seq + 1) & 0x7f;
    if (!more) break;
  }
  return out;
}

class MockBleReassembler implements BleReassemblerLike {
  private buf: number[] = [];
  private total = 0;
  private expected = 0;
  push(chunk: Uint8Array): Uint8Array | null {
    const hdr = chunk[0];
    if (hdr === undefined) throw new Error('empty chunk');
    const more = (hdr & 0x80) !== 0;
    const seq = hdr & 0x7f;
    if (seq === 0) {
      if (chunk.length < 3) throw new Error('short first chunk');
      this.total = chunk[1]! | (chunk[2]! << 8);
      this.buf = [];
      this.expected = 0;
      this.append(chunk.subarray(3));
    } else {
      if (seq !== this.expected) {
        this.buf = [];
        throw new Error(`BLE seq gap: got ${seq}, expected ${this.expected}`);
      }
      this.append(chunk.subarray(1));
    }
    this.expected = (seq + 1) & 0x7f;
    if (more) return null;
    if (this.buf.length !== this.total) throw new Error('BLE frame length mismatch');
    const frame = Uint8Array.from(this.buf);
    this.buf = [];
    return frame;
  }
  private append(bytes: Uint8Array): void {
    for (const b of bytes) this.buf.push(b);
  }
}

// ---------------------------------------------------------------- BLE framing v2 (channels)

const V2_MARKER = 0x40;
const V2_MORE = 0x80;

/** Random non-zero u32 channel id (CSPRNG). Channel 0 is reserved for v1 framing. */
export function randomChannelJs(): number {
  const b = new Uint32Array(1);
  do {
    crypto.getRandomValues(b);
  } while (b[0] === 0);
  return b[0]!;
}

/**
 * v2 chunking: first chunk `[hdr][chan u32 LE][total_len u16 LE][body]`, later chunks
 * `[hdr][chan u32 LE][body]`; hdr = more(0x80) | v2 marker(0x40) | seq mod 64.
 */
export function bleChunkV2Js(frame: Uint8Array, mtu: number, chan: number): Uint8Array[] {
  if (!Number.isInteger(chan) || chan <= 0 || chan > 0xffffffff) throw new Error('BLE channel must be a non-zero u32');
  if (frame.length > 0xffff) throw new Error('frame too large for BLE framing');
  const max = mtu - 3;
  if (max < 8) throw new Error('MTU too small');
  const out: Uint8Array[] = [];
  let offset = 0;
  let seq = 0;
  for (;;) {
    const first = out.length === 0; // seq wraps mod 64; only the first chunk carries total_len
    const header = first ? 7 : 5; // hdr + chan + (total_len on first chunk)
    const take = Math.min(max - header, frame.length - offset);
    const more = offset + take < frame.length;
    const chunk = new Uint8Array(header + take);
    chunk[0] = (seq & 0x3f) | V2_MARKER | (more ? V2_MORE : 0);
    new DataView(chunk.buffer).setUint32(1, chan, true);
    if (first) new DataView(chunk.buffer).setUint16(5, frame.length, true);
    chunk.set(frame.subarray(offset, offset + take), header);
    out.push(chunk);
    offset += take;
    seq = (seq + 1) & 0x3f;
    if (!more) break;
  }
  return out;
}

/**
 * v2 reassembler for one channel. Mirrors `prism_proto::ble::Reassembler::new_channel`: chunks
 * for other channels (or v1 chunks) are ignored without touching the partial frame.
 */
class MockBleChannelReassembler implements BleReassemblerLike {
  private buf: number[] = [];
  private total = 0;
  private expected = 0;
  private count = 0;
  private active = false;

  constructor(private readonly chan: number) {}

  push(chunk: Uint8Array): Uint8Array | null {
    if (chunk.length < 5 || (chunk[0]! & V2_MARKER) === 0) return null;
    const chan = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getUint32(1, true);
    if (chan !== this.chan) return null;
    const hdr = chunk[0]!;
    const seq = hdr & 0x3f;
    const more = (hdr & V2_MORE) !== 0;
    let body = chunk.subarray(5);
    try {
      // seq 0 restarts reassembly, except as the wrap-around of a long frame (64 chunks received).
      const wrapped = seq === 0 && this.active && this.count > 0 && this.count % 64 === 0;
      if (seq === 0 && !wrapped) {
        this.reset();
        if (body.length < 2) throw new Error('first chunk too short');
        this.total = body[0]! | (body[1]! << 8);
        body = body.subarray(2);
        this.active = true;
      } else if (!this.active) {
        throw new Error('BLE chunk without start');
      } else if (seq !== this.expected) {
        throw new Error(`BLE seq gap: got ${seq}, expected ${this.expected}`);
      }
      this.expected = (seq + 1) & 0x3f;
      this.count++;
      if (this.buf.length + body.length > this.total) throw new Error('BLE chunk overflows frame length');
      for (const b of body) this.buf.push(b);
      if (more) return null;
      if (this.buf.length !== this.total) throw new Error('BLE frame length mismatch');
      const frame = Uint8Array.from(this.buf);
      this.reset();
      return frame;
    } catch (err) {
      this.reset();
      throw err;
    }
  }

  private reset(): void {
    this.buf = [];
    this.total = 0;
    this.expected = 0;
    this.count = 0;
    this.active = false;
  }
}

// ---------------------------------------------------------------- otpauth + totp (placeholder)

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32DecodeJs(input: string): Uint8Array {
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character "${ch}"`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function parseOtpauthJs(uri: string): Totp {
  const url = new URL(uri);
  if (url.protocol !== 'otpauth:' || url.host !== 'totp') throw new Error('not an otpauth://totp URI');
  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [issuerFromLabel, ...rest] = label.split(':');
  const account = rest.length ? rest.join(':').trim() : label;
  const p = url.searchParams;
  const secret = p.get('secret');
  if (!secret) throw new Error('missing secret');
  const algo = (p.get('algorithm') ?? 'SHA1').toUpperCase();
  const algorithm = algo === 'SHA256' ? 'Sha256' : algo === 'SHA512' ? 'Sha512' : 'Sha1';
  return {
    issuer: p.get('issuer') ?? (rest.length ? issuerFromLabel!.trim() : ''),
    account: account.trim(),
    secret: Array.from(base32DecodeJs(secret)),
    algorithm,
    digits: Number(p.get('digits') ?? 6),
    period: Number(p.get('period') ?? 30),
  };
}

// ---------------------------------------------------------------- mock session

class MockSession implements ProtoSession {
  private established = false;
  start(): Uint8Array {
    return Uint8Array.of(FRAME_HANDSHAKE);
  }
  onFrame(frame: Uint8Array): SessionEvent {
    switch (frame[0]) {
      case FRAME_HANDSHAKE:
        if (this.established) return { PlainError: 'unexpected handshake' };
        this.established = true;
        return 'Established';
      case FRAME_TRANSPORT: {
        const env = JSON.parse(dec.decode(frame.subarray(1)));
        return { Response: env };
      }
      case FRAME_PLAIN_ERROR:
        return { PlainError: dec.decode(frame.subarray(1)) };
      default:
        return { PlainError: 'unknown frame kind' };
    }
  }
  isEstablished(): boolean {
    return this.established;
  }
  sas(): string | null {
    return this.established ? '482913' : null;
  }
  encryptRequest(envelopeJson: string): Uint8Array {
    if (!this.established) throw new Error('session not established');
    const body = enc.encode(envelopeJson);
    const out = new Uint8Array(body.length + 1);
    out[0] = FRAME_TRANSPORT;
    out.set(body, 1);
    return out;
  }
}

// ---------------------------------------------------------------- mock device

const APPROVAL_DELAY_MS = 1100;
const FAST_DELAY_MS = 90;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function seedEntries(): Entry[] {
  const now = Math.floor(Date.now() / 1000);
  const ent = (title: string, tags: string[], data: Entry['data']): Entry => ({
    id: Array.from(randomBytes(16)),
    title,
    tags,
    created: now - 86400,
    modified: now - 3600,
    policy: 'Always',
    data,
  });
  return [
    ent('GitHub', ['work'], {
      Password: {
        username: 'jdoe@example.com',
        password: 'correct-horse-battery-staple',
        url: 'https://github.com',
        notes: 'Recovery codes in the other entry.',
        totp: null,
      },
    }),
    ent('Mailbox', ['personal'], {
      Password: { username: 'jane', password: 'Tr0ub4dor&3', url: 'https://mail.example.org', notes: '', totp: null },
    }),
    ent('Example 2FA', [], {
      Totp: {
        issuer: 'Example',
        account: 'jdoe@example.com',
        secret: Array.from(base32DecodeJs('JBSWY3DPEHPK3PXP')),
        algorithm: 'Sha1',
        digits: 6,
        period: 30,
      },
    }),
    ent('Google backup codes', [], {
      RecoveryCodes: {
        service: 'Google',
        codes: ['1111-2222', '3333-4444', '5555-6666'].map((code, i) => ({ code, used: i === 0 })),
        notes: '',
      },
    }),
    ent('example.com passkey', [], {
      Passkey: {
        rp_id: 'example.com',
        rp_name: 'Example',
        user_handle: [1, 2, 3],
        user_name: 'jdoe',
        user_display_name: 'J. Doe',
        credential_id: Array.from(randomBytes(32)),
        alg: 'Es256',
        key_nonce: Array.from(randomBytes(16)),
        created: now - 86400,
      },
    }),
    ent('work key', [], {
      SshKey: { comment: 'jdoe@work', source: { Derived: { index: 0 } }, public_key: Array.from(randomBytes(32)) },
    }),
  ];
}

/** In-memory fake device with the §5.3 request semantics (no real crypto). */
export class MockDevice {
  locked = false;
  time = 0;
  settings: Settings = {
    auto_lock_secs: 180,
    sleep_mode: 'PowerOff',
    keyboard_layout: 'Us',
    orientation: 'Portrait',
    buzzer: true,
    owner_info: 'Mock device - owner@example.com',
  };
  entries: Entry[] = seedEntries();
  hosts: PairedHost[] = [
    { public_key: Array.from(randomBytes(32)), label: 'Work laptop (mock)', paired_at: 1_700_000_000, last_seen: 1_765_000_000 },
  ];
  /** Mirrors the device recovery slot. Null = no recovery slot yet (Export is Unsupported). */
  recoveryPassphrase: string | null = null;
  private exportBuf: Uint8Array | null = null;
  private importBuf: number[] | null = null;

  private find(id: EntryIdBytes): Entry | undefined {
    return this.entries.find((e) => e.id.join(',') === id.join(','));
  }

  /** Non-secret projection only (mirrors Entry::summary in model.rs). */
  private summary(e: Entry): EntrySummary {
    const d = e.data;
    const base = { id: e.id, title: e.title, tags: e.tags, modified: e.modified, policy: e.policy };
    if ('Password' in d)
      return { ...base, kind: 'Password', subtitle: d.Password.username, url: d.Password.url, has_totp: d.Password.totp !== null };
    if ('Totp' in d) return { ...base, kind: 'Totp', subtitle: d.Totp.account, url: null, has_totp: true };
    if ('Passkey' in d)
      return { ...base, kind: 'Passkey', subtitle: d.Passkey.user_name, url: d.Passkey.rp_id, has_totp: false };
    if ('SshKey' in d) return { ...base, kind: 'SshKey', subtitle: d.SshKey.comment, url: null, has_totp: false };
    const left = d.RecoveryCodes.codes.filter((c) => !c.used).length;
    return {
      ...base,
      kind: 'RecoveryCodes',
      subtitle: `${left}/${d.RecoveryCodes.codes.length} left`,
      url: null,
      has_totp: false,
    };
  }

  private sshInfo(e: Entry): SshPublicKeyInfo {
    const k = (e.data as { SshKey: { comment: string; public_key: number[] } }).SshKey;
    const pub = Uint8Array.from(k.public_key);
    return {
      id: e.id,
      name: e.title,
      comment: k.comment,
      blob: Array.from(encodeEd25519PublicBlob(pub)),
      openssh: formatOpenSshPublicKey(pub, k.comment),
    };
  }

  async handle(req: Request): Promise<Response> {
    const name = typeof req === 'string' ? req : Object.keys(req)[0]!;
    const body = (typeof req === 'string' ? {} : (req as Record<string, Record<string, unknown>>)[name]) as Record<string, any>;
    const open = ['GetInfo', 'SetTime', 'Unlock'];
    if (!open.includes(name) && this.locked) return { Error: 'Locked' };
    await sleep(['GetSecret', 'GetTotp', 'TypeEntry', 'DeleteEntry'].includes(name) ? APPROVAL_DELAY_MS : FAST_DELAY_MS);

    switch (name) {
      case 'GetInfo':
        return {
          Info: {
            fw_version: 'mock-0.0.0',
            device_pubkey: Array.from(randomBytes(32)),
            locked: this.locked,
            initialized: true,
            battery_pct: 84,
            charging: false,
            entry_count: this.entries.length,
            time_valid: this.time > 0,
          },
        };
      case 'SetTime':
        this.time = body.unix as number;
        return 'Ok';
      case 'Unlock':
        if (body.passphrase === 'wrong') return { Error: 'BadPassphrase' };
        this.locked = false;
        return 'Ok';
      case 'Lock':
        this.locked = true;
        return 'Ok';
      case 'ListEntries': {
        const kind = body.kind as string | null;
        return {
          Entries: this.entries.map((e) => this.summary(e)).filter((s) => !kind || s.kind === kind),
        };
      }
      case 'GetSecret': {
        const e = this.find(body.id);
        if (!e) return { Error: 'NotFound' };
        const d = e.data as Record<string, any>;
        const field = body.field as string;
        if (field === 'Password' && 'Password' in d) return { Secret: { Text: d.Password.password } };
        if (field === 'Username' && 'Password' in d) return { Secret: { Text: d.Password.username } };
        if (field === 'Notes' && 'Password' in d) return { Secret: { Text: d.Password.notes } };
        if (field === 'TotpSecret' && 'Totp' in d) return { Secret: { Bytes: d.Totp.secret } };
        if (field === 'RecoveryCodes' && 'RecoveryCodes' in d)
          return { Secret: { List: d.RecoveryCodes.codes.map((c: { code: string }) => c.code) } };
        return { Error: 'InvalidRequest' };
      }
      case 'GetTotp': {
        const e = this.find(body.id);
        if (!e || !('Totp' in e.data)) return { Error: 'NotFound' };
        const t = e.data.Totp;
        const now = Math.floor(Date.now() / 1000);
        const step = Math.floor(now / t.period);
        return { Totp: { code: mockCode(t, step), valid_until: (step + 1) * t.period } };
      }
      case 'AddEntry': {
        const entry = body.entry as Entry;
        this.entries.push(entry);
        return { EntryId: entry.id };
      }
      case 'UpdateEntry': {
        const entry = body.entry as Entry;
        const i = this.entries.findIndex((e) => e.id.join(',') === entry.id.join(','));
        if (i < 0) return { Error: 'NotFound' };
        this.entries[i] = entry;
        return 'Ok';
      }
      case 'DeleteEntry': {
        const before = this.entries.length;
        this.entries = this.entries.filter((e) => e.id.join(',') !== body.id.join(','));
        return before === this.entries.length ? { Error: 'NotFound' } : 'Ok';
      }
      case 'MarkRecoveryCodeUsed': {
        const e = this.find(body.id);
        if (!e || !('RecoveryCodes' in e.data)) return { Error: 'NotFound' };
        const c = e.data.RecoveryCodes.codes[body.index as number];
        if (!c) return { Error: 'InvalidRequest' };
        c.used = true;
        return 'Ok';
      }
      case 'GenerateSshKey': {
        const pub = randomBytes(32);
        const entry: Entry = {
          id: Array.from(randomBytes(16)),
          title: body.name as string,
          tags: [],
          created: this.time,
          modified: this.time,
          policy: body.policy as Entry['policy'],
          data: {
            SshKey: {
              comment: body.comment as string,
              source: { Derived: { index: this.entries.filter((e) => 'SshKey' in e.data).length } },
              public_key: Array.from(pub),
            },
          },
        };
        this.entries.push(entry);
        return { SshKeys: [this.sshInfo(entry)] };
      }
      case 'SshListKeys': {
        const keys = this.entries.filter((e) => 'SshKey' in e.data).map((e) => this.sshInfo(e));
        return { SshKeys: keys };
      }
      case 'SshSign':
        // Mock signature: NOT a valid Ed25519 signature.
        return { SshSignature: Array.from(randomBytes(64)) };
      case 'Ctap':
        return { Error: 'Unsupported' };
      case 'TypeEntry':
        return 'Ok';
      case 'SetRecoveryPassphrase':
        this.recoveryPassphrase = body.passphrase as string;
        return 'Ok';
      case 'GetEntry': {
        const e = this.find(body.id);
        return e ? { Entry: e } : { Error: 'NotFound' };
      }
      case 'Export':
        if (this.recoveryPassphrase === null) return { Error: 'Unsupported' };
        if (body.passphrase !== this.recoveryPassphrase) return { Error: 'BadPassphrase' };
        this.exportBuf = enc.encode(`PRSMEXP1-MOCK\n${JSON.stringify(this.entries)}`);
        return { ExportReady: { total_len: this.exportBuf.length } };
      case 'ExportChunk': {
        if (!this.exportBuf) return { Error: 'InvalidRequest' };
        const off = body.offset as number;
        const data = Array.from(this.exportBuf.subarray(off, off + 8192));
        return { Chunk: { offset: off, data } };
      }
      case 'ImportBegin':
        this.importBuf = [];
        return 'Ok';
      case 'ImportChunk':
        if (!this.importBuf) return { Error: 'InvalidRequest' };
        this.importBuf.push(...(body.data as number[]));
        return 'Ok';
      case 'ImportCommit':
        if (!this.importBuf) return { Error: 'InvalidRequest' };
        if (body.passphrase === 'wrong') return { Error: 'BadPassphrase' };
        this.importBuf = null;
        return 'Ok';
      case 'ListPairedHosts':
        return { PairedHosts: this.hosts };
      case 'RemovePairedHost': {
        const pk = (body.public_key as number[]).join(',');
        this.hosts = this.hosts.filter((h) => h.public_key.join(',') !== pk);
        return 'Ok';
      }
      case 'GetSettings':
        return { Settings: this.settings };
      case 'SetSettings':
        this.settings = body.settings as Settings;
        return 'Ok';
      default:
        return { Error: 'Unsupported' };
    }
  }
}

/** Placeholder code (NOT RFC 6238): deterministic per secret and step. */
function mockCode(t: Totp, step: number): string {
  let h = step;
  for (const b of t.secret) h = (Math.imul(h, 31) + b) >>> 0;
  return String(h % 10 ** t.digits).padStart(t.digits, '0');
}

/** Fake transport that behaves as the device: answers handshake and requests. */
export class MockTransport implements Transport {
  readonly label = 'MOCK';
  readonly device = new MockDevice();
  private readonly frames = new Listeners<[Uint8Array]>();
  private readonly disconnects = new Listeners<[string]>();

  async send(frame: Uint8Array): Promise<void> {
    if (frame[0] === FRAME_HANDSHAKE) {
      await sleep(40);
      this.frames.emit(Uint8Array.of(FRAME_HANDSHAKE));
      return;
    }
    if (frame[0] === FRAME_TRANSPORT) {
      const env = JSON.parse(dec.decode(frame.subarray(1))) as { id: number; body: Request };
      const body = await this.device.handle(env.body);
      const json = enc.encode(JSON.stringify({ id: env.id, body }));
      const out = new Uint8Array(json.length + 1);
      out[0] = FRAME_TRANSPORT;
      out.set(json, 1);
      this.frames.emit(out);
    }
  }

  onFrame(cb: (frame: Uint8Array) => void): () => void {
    return this.frames.add(cb);
  }

  onDisconnect(cb: (reason: string) => void): () => void {
    return this.disconnects.add(cb);
  }

  async close(): Promise<void> {
    this.disconnects.emit('mock closed');
  }
}

// ---------------------------------------------------------------- mock core

export function createMockCore(): PrismCore {
  return {
    kind: 'mock',
    generateHostKey(): HostKeyPair {
      return { private: randomBytes(32), public: randomBytes(32) };
    },
    newSession: () => new MockSession(),
    bleChunk: bleChunkJs,
    newBleReassembler: () => new MockBleReassembler(),
    bleChunkV2: bleChunkV2Js,
    newBleReassemblerV2: (chan) => new MockBleChannelReassembler(chan),
    randomChannel: randomChannelJs,
    cdcEncode: cobsEncode,
    newCdcDecoder: () => new MockCdcDecoder(),
    parseOtpauth: parseOtpauthJs,
    totpNow: (t, unix) => mockCode(t, Math.floor(unix / t.period)),
  };
}
