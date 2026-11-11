import { describe, expect, it } from 'vitest';
import { createMockCore } from '../src/core/mock';

const payload = (n: number, salt: number) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + salt) & 0xff);

describe('BLE framing v2 (channels) through the mock core', () => {
  it('picks a non-zero channel', () => {
    const core = createMockCore();
    for (let i = 0; i < 50; i++) {
      const c = core.randomChannel();
      expect(Number.isInteger(c)).toBe(true);
      expect(c).toBeGreaterThan(0);
      expect(c).toBeLessThanOrEqual(0xffffffff);
    }
  });

  it('round-trips a frame that needs many chunks, tagging every chunk with the channel', () => {
    const core = createMockCore();
    const chan = core.randomChannel();
    const frame = payload(1000, 3); // with mtu 23 this exceeds 64 chunks, exercising seq wrap
    for (const mtu of [23, 185]) {
      const chunks = core.bleChunkV2(frame, mtu, chan);
      expect(chunks.length).toBeGreaterThan(1);
      for (const c of chunks) {
        expect(c.length).toBeLessThanOrEqual(mtu - 3);
        expect(c[0]! & 0x40).toBe(0x40); // v2 marker
        expect(new DataView(c.buffer, c.byteOffset, c.byteLength).getUint32(1, true)).toBe(chan);
      }
      const r = core.newBleReassemblerV2(chan);
      let out: Uint8Array | null = null;
      for (const c of chunks) out = r.push(c) ?? out;
      expect(out).toEqual(frame);
    }
  });

  it('ignores chunks from foreign channels and v1 chunks without disturbing the partial frame', () => {
    const core = createMockCore();
    const mine = core.randomChannel();
    let other = core.randomChannel();
    while (other === mine) other = core.randomChannel();

    const frameA = payload(600, 1);
    const frameB = payload(600, 2);
    const a = core.bleChunkV2(frameA, 185, mine);
    const b = core.bleChunkV2(frameB, 185, other);
    const v1 = core.bleChunk(payload(300, 9), 185);

    const r = core.newBleReassemblerV2(mine);
    let out: Uint8Array | null = null;
    // Interleave: foreign chunks and v1 chunks between each of ours.
    const len = Math.max(a.length, b.length, v1.length);
    for (let i = 0; i < len; i++) {
      if (i < a.length) out = r.push(a[i]!) ?? out;
      if (i < b.length) expect(r.push(b[i]!)).toBeNull();
      if (i < v1.length) expect(r.push(v1[i]!)).toBeNull();
    }
    expect(out).toEqual(frameA);

    // The other channel's reassembler is unaffected by our traffic.
    const rb = core.newBleReassemblerV2(other);
    let outB: Uint8Array | null = null;
    for (const c of b) outB = rb.push(c) ?? outB;
    expect(outB).toEqual(frameB);
  });
});
