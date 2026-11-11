import { createPrivateKey, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  encodeEd25519PublicBlob,
  formatOpenSshPublicKey,
  OpenSshError,
  parseOpenSshEd25519,
} from '../src/keys/openssh';

// Test helpers: build openssh-key-v1 files from a known seed. No private key material is committed.

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function publicFromSeed(seed: Uint8Array): Uint8Array {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

function str(data: Uint8Array | string): Uint8Array {
  const b = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length);
  out.set(b, 4);
  return out;
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

interface BuildOpts {
  seed: Uint8Array;
  publicKey?: Uint8Array;
  comment?: string;
  cipher?: string;
  kdf?: string;
  keytype?: string;
  check1?: number;
  check2?: number;
  innerPublic?: Uint8Array;
  magic?: string;
}

function buildOpenSshFile(o: BuildOpts): string {
  const pub = o.publicKey ?? publicFromSeed(o.seed);
  const keytype = o.keytype ?? 'ssh-ed25519';
  const pubBlob = cat(str(keytype), str(pub));
  const priv = cat(
    u32(o.check1 ?? 0x01020304),
    u32(o.check2 ?? 0x01020304),
    str(keytype),
    str(o.innerPublic ?? pub),
    str(cat(o.seed, pub)),
    str(o.comment ?? ''),
  );
  // Pad to 8 bytes with 1, 2, 3, ...
  const padLen = (8 - (priv.length % 8)) % 8;
  const padding = Uint8Array.from({ length: padLen }, (_, i) => i + 1);
  const body = cat(
    new TextEncoder().encode(o.magic ?? 'openssh-key-v1\0'),
    str(o.cipher ?? 'none'),
    str(o.kdf ?? 'none'),
    str(new Uint8Array()),
    u32(1),
    str(pubBlob),
    str(cat(priv, padding)),
  );
  const b64 = Buffer.from(body).toString('base64').match(/.{1,70}/g)!.join('\n');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

const SEED = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);

describe('parseOpenSshEd25519', () => {
  it('parses an unencrypted Ed25519 key and returns seed, public key and comment', () => {
    const text = buildOpenSshFile({ seed: SEED, comment: 'jdoe@laptop' });
    const key = parseOpenSshEd25519(text);
    expect(Array.from(key.seed)).toEqual(Array.from(SEED));
    expect(Array.from(key.publicKey)).toEqual(Array.from(publicFromSeed(SEED)));
    expect(key.comment).toBe('jdoe@laptop');
  });

  it('accepts CRLF line endings and an empty comment', () => {
    const text = buildOpenSshFile({ seed: SEED }).replace(/\n/g, '\r\n');
    const key = parseOpenSshEd25519(text);
    expect(key.comment).toBe('');
    expect(key.seed.length).toBe(32);
  });

  it('rejects passphrase-encrypted keys with a remediation hint', () => {
    const text = buildOpenSshFile({ seed: SEED, cipher: 'aes256-ctr', kdf: 'bcrypt' });
    expect(() => parseOpenSshEd25519(text)).toThrow(/passphrase-encrypted.*ssh-keygen -p/);
  });

  it('rejects non-Ed25519 key types', () => {
    const text = buildOpenSshFile({ seed: SEED, keytype: 'ecdsa-sha2-nistp256', publicKey: new Uint8Array(65) });
    expect(() => parseOpenSshEd25519(text)).toThrow(OpenSshError);
    expect(() => parseOpenSshEd25519(text)).toThrow(/unsupported key type/);
  });

  it('rejects mismatched check integers (corrupt or wrong key)', () => {
    const text = buildOpenSshFile({ seed: SEED, check1: 1, check2: 2 });
    expect(() => parseOpenSshEd25519(text)).toThrow(/check integers differ/);
  });

  it('rejects a public key that does not match the seed half of the private section', () => {
    const otherPub = publicFromSeed(Uint8Array.from({ length: 32 }, () => 9));
    const text = buildOpenSshFile({ seed: SEED, innerPublic: otherPub });
    expect(() => parseOpenSshEd25519(text)).toThrow(/does not match/);
  });

  it('rejects legacy PEM and non-key input', () => {
    expect(() => parseOpenSshEd25519('-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----')).toThrow(
      /not an OpenSSH private key/,
    );
    const text = buildOpenSshFile({ seed: SEED, magic: 'not-openssh\0' });
    expect(() => parseOpenSshEd25519(text)).toThrow(/openssh-key-v1/);
  });

  it('rejects truncated data', () => {
    const text = buildOpenSshFile({ seed: SEED });
    const lines = text.split('\n');
    const cut = [lines[0], lines[1]!.slice(0, 20), lines[lines.length - 2], lines[lines.length - 1]].join('\n');
    expect(() => parseOpenSshEd25519(cut)).toThrow(OpenSshError);
  });
});

describe('public key encoding', () => {
  it('encodes the SSH wire blob as string "ssh-ed25519" then string(pub)', () => {
    const pub = publicFromSeed(SEED);
    const blob = encodeEd25519PublicBlob(pub);
    expect(blob.length).toBe(4 + 11 + 4 + 32);
    expect(new DataView(blob.buffer).getUint32(0)).toBe(11);
    expect(new TextDecoder().decode(blob.subarray(4, 15))).toBe('ssh-ed25519');
    expect(Array.from(blob.subarray(19))).toEqual(Array.from(pub));
  });

  it('formats an authorized_keys line with the comment', () => {
    const pub = publicFromSeed(SEED);
    const line = formatOpenSshPublicKey(pub, 'me@host');
    const [type, b64, comment] = line.split(' ');
    expect(type).toBe('ssh-ed25519');
    expect(Buffer.from(b64!, 'base64')).toEqual(Buffer.from(encodeEd25519PublicBlob(pub)));
    expect(comment).toBe('me@host');
  });
});
