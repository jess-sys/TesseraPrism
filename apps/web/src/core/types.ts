/**
 * TypeScript mirror of `crates/prism-core/src/model.rs` and the §5.3 messages of
 * `docs/ARCHITECTURE.md`, as they appear on the JSON bridge (§9.3).
 *
 * Encoding rules (serde_json defaults):
 *  - externally-tagged enums: struct/newtype variants are `{"Variant": payload}`,
 *    unit variants are plain strings `"GetInfo"`.
 *  - `EntryId([u8;16])` and every `[u8; N]` / `Vec<u8>` is a `number[]`.
 *  - `Option<T>` is `null` or the value (never omitted).
 *  - newtype structs are transparent (EntryId is just its 16-number array).
 */

/** 16 bytes as numbers, serialized form of `EntryId`. */
export type EntryIdBytes = number[];

/** Serialized `Envelope<T>` (ARCHITECTURE §5.3): the `id` is echoed by the response. */
export interface Envelope<T> {
  id: number;
  body: T;
}

// ---------------------------------------------------------------- model.rs

export type EntryKind = 'Password' | 'Totp' | 'Passkey' | 'SshKey' | 'RecoveryCodes';

export type ApprovalPolicy = 'Always' | 'Session' | 'Never';

export interface Entry {
  id: EntryIdBytes;
  title: string;
  tags: string[];
  created: number;
  modified: number;
  policy: ApprovalPolicy;
  data: EntryData;
}

export type EntryData =
  | { Password: Password }
  | { Totp: Totp }
  | { Passkey: Passkey }
  | { SshKey: SshKey }
  | { RecoveryCodes: RecoveryCodes };

export interface Password {
  username: string;
  password: string;
  url: string | null;
  notes: string;
  totp: Totp | null;
}

export type TotpAlgorithm = 'Sha1' | 'Sha256' | 'Sha512';

export interface Totp {
  issuer: string;
  account: string;
  /** Raw (base32-decoded) secret. */
  secret: number[];
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

export type CoseAlg = 'Es256' | 'EdDsa';

export interface Passkey {
  rp_id: string;
  rp_name: string;
  user_handle: number[];
  user_name: string;
  user_display_name: string;
  credential_id: number[];
  alg: CoseAlg;
  key_nonce: number[];
  created: number;
}

export type SshKeySource = { Derived: { index: number } } | { Imported: { secret: number[] } };

export interface SshKey {
  comment: string;
  source: SshKeySource;
  /** 32-byte raw Ed25519 public key. */
  public_key: number[];
}

export interface RecoveryCode {
  code: string;
  used: boolean;
}

export interface RecoveryCodes {
  service: string;
  codes: RecoveryCode[];
  notes: string;
}

export interface EntrySummary {
  id: EntryIdBytes;
  kind: EntryKind;
  title: string;
  subtitle: string;
  url: string | null;
  tags: string[];
  modified: number;
  has_totp: boolean;
  policy: ApprovalPolicy;
}

export type SecretField =
  | 'Password'
  | 'Username'
  | 'Notes'
  | 'TotpSecret'
  | 'RecoveryCodes'
  | 'SshPublicKey';

export type SecretValue = { Text: string } | { Bytes: number[] } | { List: string[] };

export interface SshPublicKeyInfo {
  id: EntryIdBytes;
  name: string;
  comment: string;
  /** SSH wire-format public key blob. */
  blob: number[];
  /** "ssh-ed25519 AAAA... comment" */
  openssh: string;
}

export type KeyboardLayout = 'Us' | 'FrAzerty';
export type SleepMode = 'PowerOff' | 'LightSleep';
export type Orientation = 'Portrait' | 'Landscape';

export interface Settings {
  auto_lock_secs: number;
  sleep_mode: SleepMode;
  keyboard_layout: KeyboardLayout;
  orientation: Orientation;
  buzzer: boolean;
  owner_info: string | null;
}

export type ImportMode = 'Replace' | 'Merge';

export interface PairedHost {
  public_key: number[];
  label: string;
  paired_at: number;
  last_seen: number;
}

export interface DeviceInfo {
  fw_version: string;
  device_pubkey: number[];
  locked: boolean;
  initialized: boolean;
  battery_pct: number;
  charging: boolean;
  entry_count: number;
  time_valid: boolean;
}

// ---------------------------------------------------------------- Request (§5.3)

export type Request =
  | 'GetInfo'
  | { SetTime: { unix: number } }
  | { Unlock: { passphrase: string } }
  | 'Lock'
  | { ListEntries: { kind: EntryKind | null } }
  | { GetSecret: { id: EntryIdBytes; field: SecretField; context: string | null } }
  | { GetTotp: { id: EntryIdBytes } }
  | { AddEntry: { entry: Entry } }
  | { UpdateEntry: { entry: Entry } }
  | { DeleteEntry: { id: EntryIdBytes } }
  | { MarkRecoveryCodeUsed: { id: EntryIdBytes; index: number } }
  | { GenerateSshKey: { name: string; comment: string; policy: ApprovalPolicy } }
  | 'SshListKeys'
  | { SshSign: { public_key: number[]; data: number[]; flags: number; host_hint: string | null } }
  | { Ctap: { cbor: number[]; origin_hint: string | null } }
  | { TypeEntry: { id: EntryIdBytes; field: SecretField; layout: KeyboardLayout } }
  | { Export: { passphrase: string } }
  | { ExportChunk: { offset: number } }
  | { SetRecoveryPassphrase: { passphrase: string } }
  | { GetEntry: { id: EntryIdBytes } }
  | { ImportBegin: { total_len: number } }
  | { ImportChunk: { offset: number; data: number[] } }
  | { ImportCommit: { passphrase: string; mode: ImportMode } }
  | 'ListPairedHosts'
  | { RemovePairedHost: { public_key: number[] } }
  | 'GetSettings'
  | { SetSettings: { settings: Settings } };

// ---------------------------------------------------------------- Response (§5.3)

export type ErrorCode =
  | 'Locked'
  | 'Denied'
  | 'Timeout'
  | 'NotFound'
  | 'NotPaired'
  | 'InvalidRequest'
  | 'BadPassphrase'
  | 'StorageFull'
  | 'Unsupported'
  | 'Busy'
  | 'Internal';

export type Response =
  | { Info: DeviceInfo }
  | 'Ok'
  | { Paired: { label: string } }
  | { Entries: EntrySummary[] }
  | { Secret: SecretValue }
  | { Totp: { code: string; valid_until: number } }
  | { Entry: Entry }
  | { EntryId: EntryIdBytes }
  | { SshKeys: SshPublicKeyInfo[] }
  | { SshSignature: number[] }
  | { Ctap: number[] }
  | { ExportReady: { total_len: number } }
  | { Chunk: { offset: number; data: number[] } }
  | { PairedHosts: PairedHost[] }
  | { Settings: Settings }
  | { Error: ErrorCode };

// ---------------------------------------------------------------- Session events (§9.3)

/** Protocol error from `PlainError` (before the session is established). */
export interface ProtoError {
  code?: string;
  message?: string;
}

/**
 * JSON `SessionEvent` as produced by `session.onFrame`:
 *  - `{"SendFrame": number[]}`  send these bytes to the device
 *  - `"Established"`
 *  - `{"Response": Envelope<Response>}` (id preserved by the bridge; a bare Response is also tolerated)
 *  - `{"PlainError": ProtoError}`
 */
export type SessionEvent =
  | { SendFrame: number[] }
  | 'Established'
  | { Response: Envelope<Response> | Response }
  | { PlainError: ProtoError | string };

export interface HostKeyPair {
  private: Uint8Array;
  public: Uint8Array;
}

// ---------------------------------------------------------------- Bridge (§9.3)

/** Noise session (initiator). Mirrors `new Session(hostPrivateKey)`. */
export interface ProtoSession {
  /** Full handshake frame (kind 0x01) to send first. */
  start(): Uint8Array;
  /** Feed a received frame; returns the parsed SessionEvent. */
  onFrame(frame: Uint8Array): SessionEvent;
  /**
   * True once the handshake is complete. Note: the Rust initiator does NOT emit an
   * `Established` event; completion is only visible here after the third handshake frame.
   */
  isEstablished(): boolean;
  /** 6-digit SAS once the handshake is complete, else null. */
  sas(): string | null;
  /** Encrypts a JSON `Envelope<Request>` (`{"id":n,"body":...}`); returns a kind 0x02 frame. */
  encryptRequest(envelopeJson: string): Uint8Array;
  free?(): void;
}

export interface BleReassemblerLike {
  /** Returns a complete frame or null. */
  push(chunk: Uint8Array): Uint8Array | null;
}

export interface CdcDecoderLike {
  /** Returns all complete frames found in `bytes`. */
  push(bytes: Uint8Array): Uint8Array[];
}

/**
 * The surface the web app codes against. `loadCore()` returns either the real
 * prism-wasm module (wrapped to this shape) or the labelled mock below.
 */
export interface PrismCore {
  readonly kind: 'wasm' | 'mock';
  generateHostKey(): HostKeyPair;
  newSession(hostPrivateKey: Uint8Array): ProtoSession;
  /** v1 BLE chunking (no channel tag). Kept for old firmware; Web Bluetooth uses v2. */
  bleChunk(frame: Uint8Array, mtu: number): Uint8Array[];
  newBleReassembler(): BleReassemblerLike;
  /**
   * v2 BLE chunking (ARCHITECTURE §5.1, docs/plans/ble-client-channels.md): every chunk carries
   * the non-zero channel id `chan`. Max chunk is `mtu - 3`.
   */
  bleChunkV2(frame: Uint8Array, mtu: number, chan: number): Uint8Array[];
  /**
   * v2 reassembler bound to `chan` (non-zero). Chunks tagged with any other channel, or with
   * v1 framing, are ignored (`push` returns null) and leave the partial frame untouched.
   */
  newBleReassemblerV2(chan: number): BleReassemblerLike;
  /** Random non-zero u32 BLE channel id (CSPRNG). Chosen once per client connection. */
  randomChannel(): number;
  cdcEncode(frame: Uint8Array): Uint8Array;
  newCdcDecoder(): CdcDecoderLike;
  /** Parses an `otpauth://totp/...` URI. Throws on invalid input. */
  parseOtpauth(uri: string): Totp;
  /** Current TOTP code for preview. */
  totpNow(totp: Totp, unix: number): string;
}

// ---------------------------------------------------------------- Frame kinds (§5.1)

export const FRAME_HANDSHAKE = 0x01;
export const FRAME_TRANSPORT = 0x02;
export const FRAME_PLAIN_ERROR = 0x03;

export const PRISM_SERVICE_UUID = '9e5d0001-3c4a-4b8e-9f1a-5072736d0000';
export const PRISM_RX_UUID = '9e5d0002-3c4a-4b8e-9f1a-5072736d0000';
export const PRISM_TX_UUID = '9e5d0003-3c4a-4b8e-9f1a-5072736d0000';
