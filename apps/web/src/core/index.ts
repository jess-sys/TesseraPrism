import type {
  BleReassemblerLike,
  CdcDecoderLike,
  HostKeyPair,
  PrismCore,
  ProtoSession,
  SessionEvent,
  Totp,
} from './types';
import { createMockCore } from './mock';

/**
 * Shape of the wasm-bindgen module built by `wasm-pack build --target web --out-dir src/wasm/pkg`
 * (ARCHITECTURE §9.3). JSON-returning functions return strings.
 */
interface WasmSession {
  start(): Uint8Array;
  onFrame(frame: Uint8Array): string;
  sas(): string | undefined;
  isEstablished(): boolean;
  encryptRequest(json: string): Uint8Array;
  free?(): void;
}

interface WasmBleReassembler {
  push(chunk: Uint8Array): Uint8Array | null | undefined;
}

interface WasmModule {
  default(input?: unknown): Promise<unknown>;
  generateHostKey(): { private: Uint8Array | number[]; public: Uint8Array | number[] };
  Session: new (hostPrivateKey: Uint8Array) => WasmSession;
  BleReassembler: (new () => WasmBleReassembler) & { newChannel(chan: number): WasmBleReassembler };
  CdcDecoder: new () => { push(bytes: Uint8Array): Uint8Array[] };
  bleChunk(frame: Uint8Array, mtu: number): Uint8Array[];
  bleChunkV2(frame: Uint8Array, mtu: number, chan: number): Uint8Array[];
  randomChannel(): number;
  cdcEncode(frame: Uint8Array): Uint8Array;
  parseOtpauth(uri: string): string | Totp;
  totpNow(totpJson: string, unix: number): string;
}

/**
 * `import.meta.glob` is resolved at build time: if `src/wasm/pkg/prism_wasm.js` is absent the
 * map is empty, the build still succeeds and the mock core is used.
 */
const wasmLoaders = import.meta.glob('../wasm/pkg/prism_wasm.js') as Record<string, () => Promise<unknown>>;

export const MOCK_BANNER =
  'MOCK CORE: running against an in-memory fake device (prism-wasm not loaded, or ?mock). No real crypto or pairing.';

/** Returns the real prism-wasm core when built, otherwise the labelled mock. Never throws. */
export async function loadCore(): Promise<PrismCore> {
  const forced = new URLSearchParams(location.search).has('mock');
  const key = Object.keys(wasmLoaders)[0];
  if (forced || !key) {
    if (!forced) console.warn('prism-wasm pkg missing; using mock core');
    return createMockCore();
  }
  try {
    const mod = (await wasmLoaders[key]!()) as WasmModule;
    await mod.default();
    return wrapWasm(mod);
  } catch (err) {
    console.error('prism-wasm failed to initialise; using mock core', err);
    return createMockCore();
  }
}

const toBytes = (x: Uint8Array | number[]): Uint8Array => (x instanceof Uint8Array ? x : Uint8Array.from(x));

function wrapWasm(mod: WasmModule): PrismCore {
  return {
    kind: 'wasm',
    generateHostKey(): HostKeyPair {
      const k = mod.generateHostKey();
      return { private: toBytes(k.private), public: toBytes(k.public) };
    },
    newSession(hostPrivateKey: Uint8Array): ProtoSession {
      const s = new mod.Session(hostPrivateKey);
      return {
        start: () => s.start(),
        onFrame: (f) => JSON.parse(s.onFrame(f)) as SessionEvent,
        sas: () => s.sas() ?? null,
        isEstablished: () => s.isEstablished(),
        encryptRequest: (json) => s.encryptRequest(json),
        free: () => s.free?.(),
      };
    },
    bleChunk: (frame, mtu) => mod.bleChunk(frame, mtu),
    newBleReassembler(): BleReassemblerLike {
      const r = new mod.BleReassembler();
      return { push: (c) => r.push(c) ?? null };
    },
    bleChunkV2: (frame, mtu, chan) => mod.bleChunkV2(frame, mtu, chan),
    newBleReassemblerV2(chan: number): BleReassemblerLike {
      const r = mod.BleReassembler.newChannel(chan);
      return { push: (c) => r.push(c) ?? null };
    },
    randomChannel: () => mod.randomChannel(),
    cdcEncode: (frame) => mod.cdcEncode(frame),
    newCdcDecoder(): CdcDecoderLike {
      const d = new mod.CdcDecoder();
      return { push: (b) => d.push(b) };
    },
    parseOtpauth(uri: string): Totp {
      const r = mod.parseOtpauth(uri);
      return typeof r === 'string' ? (JSON.parse(r) as Totp) : r;
    },
    totpNow: (t, unix) => mod.totpNow(JSON.stringify(t), unix),
  };
}
