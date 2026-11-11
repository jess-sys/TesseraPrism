import { describe, expect, it } from 'vitest';
import { PrismClient, PrismError, NotPairedError, TRANSFER_CHUNK } from '../src/client';
import type { HostKeyPair, PrismCore, ProtoSession, Response, SessionEvent } from '../src/core/types';
import type { Transport } from '../src/transport/types';
import { Listeners } from '../src/transport/types';

/**
 * A fake device behind a fake core. The fake session records each encrypted request envelope
 * (the exact JSON that prism-wasm receives) and the fake transport answers with `respond`.
 */
function harness(respond: (body: unknown, id: number) => Response | 'silent' | Promise<Response | 'silent'>) {
  const sent: { id: number; body: unknown }[] = [];
  const frames = new Listeners<[Uint8Array]>();
  const disconnects = new Listeners<[string]>();
  let established = false;

  const session: ProtoSession = {
    start: () => Uint8Array.of(1),
    onFrame: (f: Uint8Array): SessionEvent => {
      if (f[0] === 1) {
        established = true;
        return 'Established';
      }
      const env = JSON.parse(new TextDecoder().decode(f.subarray(1)));
      return { Response: env };
    },
    isEstablished: () => established,
    sas: () => '000111',
    encryptRequest: (json: string) => {
      const env = JSON.parse(json) as { id: number; body: unknown };
      sent.push(env);
      return Uint8Array.of(2, ...new TextEncoder().encode(json));
    },
  };

  const core = {
    kind: 'mock',
    generateHostKey: () => ({ private: new Uint8Array(32), public: new Uint8Array(32) }),
    newSession: () => session,
  } as unknown as PrismCore;

  const transport: Transport = {
    label: 'TEST',
    send: async (frame: Uint8Array) => {
      if (frame[0] === 1) {
        queueMicrotask(() => frames.emit(Uint8Array.of(1)));
        return;
      }
      const env = JSON.parse(new TextDecoder().decode(frame.subarray(1))) as { id: number; body: unknown };
      const r = await respond(env.body, env.id);
      if (r === 'silent') return;
      const json = JSON.stringify({ id: env.id, body: r });
      queueMicrotask(() => frames.emit(Uint8Array.of(2, ...new TextEncoder().encode(json))));
    },
    onFrame: (cb) => frames.add(cb),
    onDisconnect: (cb) => disconnects.add(cb),
    close: async () => undefined,
  };

  const hostKey: HostKeyPair = { private: new Uint8Array(32), public: new Uint8Array(32) };
  return { core, transport, hostKey, sent };
}

describe('PrismClient request encoding', () => {
  it('encodes unit variants as bare strings in an envelope', async () => {
    const h = harness(() => ({ Info: fakeInfo() }));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect().catch(() => undefined);
    h.sent.length = 0;
    await c.getInfo();
    expect(JSON.stringify(h.sent[0])).toBe('{"id":' + h.sent[0]!.id + ',"body":"GetInfo"}');
    await c.close();
  });

  it('encodes GetSecret with a 16-number EntryId, field and null context', async () => {
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : { Secret: { Text: 'pw' } }));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    const id = Array.from({ length: 16 }, (_, i) => i);
    const got = await c.getSecret(id, 'Password');
    expect(got).toEqual({ Text: 'pw' });
    expect(JSON.parse(JSON.stringify(h.sent.at(-1))).body).toEqual({
      GetSecret: { id, field: 'Password', context: null },
    });
    await c.close();
  });

  it('encodes ListEntries kind as null or an EntryKind string', async () => {
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : { Entries: [] }));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    await c.listEntries();
    await c.listEntries('SshKey');
    expect(h.sent.slice(-2).map((e) => e.body)).toEqual([{ ListEntries: { kind: null } }, { ListEntries: { kind: 'SshKey' } }]);
    await c.close();
  });

  it('encodes Settings with snake_case fields and enum strings', async () => {
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : 'Ok'));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    await c.setSettings({
      auto_lock_secs: 120,
      sleep_mode: 'LightSleep',
      keyboard_layout: 'FrAzerty',
      orientation: 'Portrait',
      buzzer: false,
      owner_info: null,
    });
    expect(h.sent.at(-1)!.body).toEqual({
      SetSettings: {
        settings: {
          auto_lock_secs: 120,
          sleep_mode: 'LightSleep',
          keyboard_layout: 'FrAzerty',
          orientation: 'Portrait',
          buzzer: false,
          owner_info: null,
        },
      },
    });
    await c.close();
  });

  it('chunks export downloads at 8 KiB and reassembles the file', async () => {
    const total = TRANSFER_CHUNK * 2 + 123;
    const file = Uint8Array.from({ length: total }, (_, i) => i % 251);
    const offsets: number[] = [];
    const h = harness((body) => {
      if (body === 'GetInfo') return { Info: fakeInfo() };
      if (typeof body === 'object' && body !== null && 'Export' in body) return { ExportReady: { total_len: total } };
      const off = (body as { ExportChunk: { offset: number } }).ExportChunk.offset;
      offsets.push(off);
      return { Chunk: { offset: off, data: Array.from(file.subarray(off, off + TRANSFER_CHUNK)) } };
    });
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    const out = await c.exportVault('correct horse');
    expect(h.sent.find((e) => (e.body as Record<string, unknown>).Export)?.body).toEqual({ Export: { passphrase: 'correct horse' } });
    expect(offsets).toEqual([0, TRANSFER_CHUNK, TRANSFER_CHUNK * 2]);
    expect(Buffer.from(out)).toEqual(Buffer.from(file));
    await c.close();
  });

  it('splits imports into 8 KiB chunks with ImportBegin and ImportCommit', async () => {
    const bytes = new Uint8Array(TRANSFER_CHUNK + 10);
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : 'Ok'));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    h.sent.length = 0;
    await c.importVault(bytes, 'pass', 'Merge');
    const bodies = h.sent.map((e) => e.body as Record<string, unknown>);
    expect(bodies[0]).toEqual({ ImportBegin: { total_len: bytes.length } });
    expect((bodies[1] as { ImportChunk: { offset: number; data: number[] } }).ImportChunk.data.length).toBe(TRANSFER_CHUNK);
    expect((bodies[2] as { ImportChunk: { offset: number } }).ImportChunk.offset).toBe(TRANSFER_CHUNK);
    expect(bodies[3]).toEqual({ ImportCommit: { passphrase: 'pass', mode: 'Merge' } });
    await c.close();
  });

  it('maps device error responses to PrismError with the ErrorCode', async () => {
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : { Error: 'Locked' }));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    await expect(c.listEntries()).rejects.toMatchObject({ code: 'Locked' });
    await expect(c.listEntries()).rejects.toBeInstanceOf(PrismError);
    await c.close();
  });

  it('times out requests that get no answer', async () => {
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : 'silent'));
    const c = new PrismClient(h.core, h.transport, h.hostKey, { requestTimeoutMs: 30 });
    await c.connect();
    await expect(c.getTotp(new Array(16).fill(0))).rejects.toMatchObject({ code: 'Timeout' });
    await c.close();
  });

  it('encodes GetEntry, SetRecoveryPassphrase and returns the full entry', async () => {
    const id = new Array(16).fill(7);
    const entry = {
      id,
      title: 'Codes',
      tags: [],
      created: 1,
      modified: 2,
      policy: 'Always',
      data: { RecoveryCodes: { service: 'S', codes: [{ code: 'a', used: true }], notes: '' } },
    };
    const h = harness((body) => {
      if (body === 'GetInfo') return { Info: fakeInfo() };
      if (typeof body === 'object' && body !== null && 'GetEntry' in body) return { Entry: entry as never };
      return 'Ok';
    });
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    expect(await c.getEntry(id)).toEqual(entry);
    expect(h.sent.at(-1)!.body).toEqual({ GetEntry: { id } });
    await c.setRecoveryPassphrase('long enough');
    expect(h.sent.at(-1)!.body).toEqual({ SetRecoveryPassphrase: { passphrase: 'long enough' } });
    await c.close();
  });

  it('generateSshKey returns the single key from SshKeys', async () => {
    const key = { id: new Array(16).fill(1), name: 'n', comment: 'c', blob: [0], openssh: 'ssh-ed25519 AAAA c' };
    const h = harness((body) => (body === 'GetInfo' ? { Info: fakeInfo() } : { SshKeys: [key] }));
    const c = new PrismClient(h.core, h.transport, h.hostKey);
    await c.connect();
    expect(await c.generateSshKey('n', 'c', 'Always')).toEqual(key);
    expect(h.sent.at(-1)!.body).toEqual({ GenerateSshKey: { name: 'n', comment: 'c', policy: 'Always' } });
    await c.close();
  });

  it('reports NotPaired from the handshake as NotPairedError', async () => {
    const h = harness(() => ({ Info: fakeInfo() }));
    const frames = new Listeners<[Uint8Array]>();
    const transport: Transport = {
      label: 'TEST',
      // The device answers the first handshake frame with a PLAIN_ERROR frame (kind 0x03).
      send: async () => {
        queueMicrotask(() => frames.emit(Uint8Array.of(3)));
      },
      onFrame: (cb) => frames.add(cb),
      onDisconnect: () => () => undefined,
      close: async () => undefined,
    };
    const core = {
      ...h.core,
      newSession: (): ProtoSession => ({
        start: () => Uint8Array.of(1),
        onFrame: (): SessionEvent => ({ PlainError: { code: 'NotPaired', message: 'unknown host' } }),
        isEstablished: () => false,
        sas: () => null,
        encryptRequest: () => new Uint8Array(),
      }),
    } as unknown as PrismCore;
    const c = new PrismClient(core, transport, h.hostKey, { handshakeTimeoutMs: 1000 });
    await expect(c.connect()).rejects.toBeInstanceOf(NotPairedError);
  });
});

function fakeInfo() {
  return {
    fw_version: 'test',
    device_pubkey: new Array(32).fill(0),
    locked: false,
    initialized: true,
    battery_pct: 50,
    charging: false,
    entry_count: 0,
    time_valid: true,
  };
}
