import { describe, expect, it } from 'vitest';
import { bleChunkJs, cobsEncode, createMockCore, MockTransport } from '../src/core/mock';
import { PrismClient } from '../src/client';
import { generatePassword } from '../src/util/password';

// These check the framing algorithms the mock core uses; they mirror the wasm bridge contract
// (ARCHITECTURE §5.1) so the UI can be exercised without the wasm pkg.

describe('COBS (USB CDC framing)', () => {
  it('encodes without zero bytes and terminates with 0x00', () => {
    const frame = Uint8Array.from([0x01, 0x00, 0x02, 0x00, 0x00, 0x03]);
    const enc = cobsEncode(frame);
    expect(enc[enc.length - 1]).toBe(0);
    expect(Array.from(enc.subarray(0, -1)).every((b) => b !== 0)).toBe(true);
  });
});

describe('BLE chunking', () => {
  it('chunks with seq numbers and a u16 length prefix on the first chunk', () => {
    const frame = Uint8Array.from({ length: 400 }, (_, i) => i & 0xff);
    const chunks = bleChunkJs(frame, 185);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks[0]![0]! & 0x7f).toBe(0);
    expect(chunks[0]![0]! & 0x80).toBe(0x80);
    expect(chunks[0]![1]! | (chunks[0]![2]! << 8)).toBe(400);
    expect(chunks.every((c) => c.length <= 185 - 3)).toBe(true);
    expect(chunks.at(-1)![0]! & 0x80).toBe(0);
  });
});

describe('mock core end to end', () => {
  it('connects, lists entries and reveals a secret through the framed session', async () => {
    const core = createMockCore();
    const transport = new MockTransport();
    const hostKey = core.generateHostKey();
    const client = new PrismClient(core, transport, hostKey, { requestTimeoutMs: 10_000 });
    const info = await client.connect();
    expect(info.initialized).toBe(true);
    const entries = await client.listEntries();
    expect(entries.length).toBeGreaterThan(0);
    expect(entries.every((e) => !('data' in (e as object)))).toBe(true);
    const gh = entries.find((e) => e.title === 'GitHub')!;
    const secret = await client.getSecret(gh.id, 'Password');
    expect(secret).toEqual({ Text: 'correct-horse-battery-staple' });
    await client.close();
  }, 15_000);
});

describe('password generator', () => {
  it('honours length and includes every enabled class', () => {
    for (let i = 0; i < 25; i++) {
      const pw = generatePassword({ length: 20, lower: true, upper: true, digits: true, symbols: true });
      expect(pw.length).toBe(20);
      expect(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)).toBe(true);
    }
  });

  it('rejects impossible lengths and empty class sets', () => {
    expect(() => generatePassword({ length: 2, lower: true, upper: true, digits: true, symbols: false })).toThrow();
    expect(() => generatePassword({ length: 10, lower: false, upper: false, digits: false, symbols: false })).toThrow();
  });
});
