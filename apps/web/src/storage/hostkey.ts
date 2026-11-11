import type { HostKeyPair, PrismCore } from '../core/types';

/**
 * The browser's Noise static key (X25519) is kept in IndexedDB so that the device keeps
 * recognising this browser across visits. Mock and real cores use separate keys.
 */
const DB_NAME = 'prism-web';
const STORE = 'kv';
const VERSION = 1;

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function withStore<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

/** Loads the host key for this core kind, creating and persisting one on first use. */
export async function loadOrCreateHostKey(core: PrismCore): Promise<HostKeyPair> {
  const key = `host-key/${core.kind}`;
  try {
    const stored = await withStore<HostKeyPair | undefined>('readonly', (s) => s.get(key));
    if (stored && stored.private.length === 32 && stored.public.length === 32) return stored;
  } catch (err) {
    console.warn('IndexedDB unavailable; host key will not persist', err);
  }
  const fresh = core.generateHostKey();
  const pair: HostKeyPair = { private: Uint8Array.from(fresh.private), public: Uint8Array.from(fresh.public) };
  try {
    await withStore('readwrite', (s) => s.put(pair, key));
  } catch (err) {
    console.warn('could not persist host key', err);
  }
  return pair;
}

/** Forgets the stored host key (the device will then need to be re-paired). */
export async function forgetHostKey(core: PrismCore): Promise<void> {
  await withStore('readwrite', (s) => s.delete(`host-key/${core.kind}`));
}
