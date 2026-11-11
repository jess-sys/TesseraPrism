/**
 * Minimal OpenSSH key support for Ed25519 only (ARCHITECTURE §1: SSH is Ed25519 only).
 *
 * Parses UNENCRYPTED `-----BEGIN OPENSSH PRIVATE KEY-----` (openssh-key-v1) files, as produced by
 *   ssh-keygen -t ed25519 -N ""
 * and returns the raw 32-byte seed + public key, which are then sent to the device in an
 * `AddEntry` with `SshKeySource::Imported`. Encrypted keys, RSA/ECDSA keys and other formats
 * are rejected with an explanatory error. Nothing here touches the network.
 *
 * Format reference (PROTOCOL.key):
 *   "openssh-key-v1\0" | string ciphername | string kdfname | string kdfoptions | u32 nkeys
 *   | string publickey(ssh-ed25519 blob) | string privatesection
 *   privatesection = u32 check | u32 check | string keytype | string pub(32)
 *                    | string priv(64 = seed||pub) | string comment | padding 1,2,3...
 */

const AUTH_MAGIC = 'openssh-key-v1\0';
const KEY_TYPE = 'ssh-ed25519';
const BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----';
const END = '-----END OPENSSH PRIVATE KEY-----';

export class OpenSshError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OpenSshError';
  }
}

export interface ParsedEd25519Key {
  /** 32-byte Ed25519 secret seed (the device's `SshKeySource::Imported.secret`). */
  seed: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Comment stored in the key file (may be empty). */
  comment: string;
}

class Reader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  u32(): number {
    if (this.remaining < 4) throw new OpenSshError('truncated key data');
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 4).getUint32(0, false);
    this.pos += 4;
    return v;
  }

  bytes(): Uint8Array {
    const len = this.u32();
    if (len > this.remaining) throw new OpenSshError('truncated key data');
    const out = this.buf.slice(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  string(): string {
    return new TextDecoder().decode(this.bytes());
  }

  raw(n: number): Uint8Array {
    if (n > this.remaining) throw new OpenSshError('truncated key data');
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

/** Extracts the base64 body between the PEM armor lines. */
export function pemBody(text: string): Uint8Array {
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  const start = lines.indexOf(BEGIN);
  const end = lines.indexOf(END);
  if (start < 0 || end < 0 || end <= start) {
    throw new OpenSshError('not an OpenSSH private key (missing BEGIN/END OPENSSH PRIVATE KEY lines)');
  }
  const b64 = lines.slice(start + 1, end).filter((l) => l.length > 0 && !l.includes(':')).join('');
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new OpenSshError('key body is not valid base64');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Parses an unencrypted OpenSSH Ed25519 private key file. Throws OpenSshError. */
export function parseOpenSshEd25519(text: string): ParsedEd25519Key {
  const raw = pemBody(text);
  const magic = new TextDecoder().decode(raw.subarray(0, AUTH_MAGIC.length));
  if (magic !== AUTH_MAGIC) throw new OpenSshError('not an openssh-key-v1 file (legacy PEM keys are not supported)');

  const r = new Reader(raw.subarray(AUTH_MAGIC.length));
  const cipher = r.string();
  const kdf = r.string();
  r.bytes(); // kdfoptions
  if (cipher !== 'none' || kdf !== 'none') {
    throw new OpenSshError(
      'this key is passphrase-encrypted; remove the passphrase first with: ssh-keygen -p -N "" -f <keyfile>',
    );
  }
  const nkeys = r.u32();
  if (nkeys !== 1) throw new OpenSshError(`expected exactly one key, found ${nkeys}`);

  const pubBlob = new Reader(r.bytes());
  const pubType = pubBlob.string();
  if (pubType !== KEY_TYPE) throw new OpenSshError(`unsupported key type "${pubType}" (only ssh-ed25519 is supported)`);
  const publicKey = pubBlob.bytes();
  if (publicKey.length !== 32) throw new OpenSshError('invalid Ed25519 public key length');

  const priv = new Reader(r.bytes());
  const check1 = priv.u32();
  const check2 = priv.u32();
  if (check1 !== check2) throw new OpenSshError('check integers differ: corrupt key file');
  const privType = priv.string();
  if (privType !== KEY_TYPE) throw new OpenSshError(`unsupported private key type "${privType}"`);
  const pubInPriv = priv.bytes();
  if (!equalBytes(pubInPriv, publicKey)) throw new OpenSshError('public key in private section does not match');
  const secret = priv.bytes();
  if (secret.length !== 64) throw new OpenSshError('invalid Ed25519 private key length');
  if (!equalBytes(secret.subarray(32), publicKey)) {
    throw new OpenSshError('key material inconsistent: embedded public key does not match the seed half');
  }
  const comment = priv.string();
  // Padding must be 1, 2, 3, ... (ARCHITECTURE: strict enough to catch truncation).
  let expect = 1;
  while (priv.remaining > 0) {
    const b = priv.raw(1)[0];
    if (b !== (expect & 0xff)) throw new OpenSshError('bad padding in private section');
    expect++;
  }

  return { seed: secret.slice(0, 32), publicKey: publicKey.slice(), comment };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function u32be(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function sshString(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.length);
  out.set(u32be(data.length), 0);
  out.set(data, 4);
  return out;
}

/** SSH wire-format public key blob for an Ed25519 key: string "ssh-ed25519" | string pub. */
export function encodeEd25519PublicBlob(publicKey: Uint8Array): Uint8Array {
  const type = new TextEncoder().encode(KEY_TYPE);
  const a = sshString(type);
  const b = sshString(publicKey);
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** "ssh-ed25519 AAAA... comment" */
export function formatOpenSshPublicKey(publicKey: Uint8Array, comment: string): string {
  const blob = encodeEd25519PublicBlob(publicKey);
  let bin = '';
  for (const b of blob) bin += String.fromCharCode(b);
  const line = `${KEY_TYPE} ${btoa(bin)}`;
  return comment ? `${line} ${comment}` : line;
}
