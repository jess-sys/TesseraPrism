import { loadCore, MOCK_BANNER } from './core/index';
import type { DeviceInfo, PrismCore } from './core/types';
import { PrismClient, type ClientEvent } from './client';
import { BleTransport } from './transport/ble';
import { SerialTransport } from './transport/serial';
import { MockTransport } from './core/mock';
import type { Transport } from './transport/types';
import { loadOrCreateHostKey } from './storage/hostkey';
import { clear, describeError, h, toast } from './ui/dom';

export type TransportKind = 'ble' | 'usb' | 'mock';

/** Shared application state. Single-tab app: no store library needed. */
export const state = {
  core: null as PrismCore | null,
  client: null as PrismClient | null,
  info: null as DeviceInfo | null,
  transportLabel: '',
  fingerprint: '',
  mockTransport: null as MockTransport | null,
};

export function requireClient(): PrismClient {
  if (!state.client) throw new Error('Not connected');
  return state.client;
}

export function core(): PrismCore {
  if (!state.core) throw new Error('Core not loaded');
  return state.core;
}

/** Asks the router to re-render the current page. */
export function rerender(): void {
  window.dispatchEvent(new Event('prism:rerender'));
}

/**
 * Opens a transport (browser picker for BLE/USB), runs the handshake and GetInfo, and makes
 * it the active device. `onEvent` receives SAS/pairing events during the handshake.
 * Throws NotPairedError when the device rejects this browser.
 */
export async function connectDevice(
  kind: TransportKind,
  opts: { pairing?: boolean; onEvent?: (ev: ClientEvent) => void } = {},
): Promise<DeviceInfo> {
  await disconnectDevice();
  const c = core();
  // The browser pickers must run inside the click gesture, so they come first.
  let transport: Transport;
  if (kind === 'ble') transport = await BleTransport.request(c);
  else if (kind === 'usb') transport = await SerialTransport.request(c);
  else transport = (state.mockTransport ??= new MockTransport());

  const hostKey = await loadOrCreateHostKey(c);
  const client = new PrismClient(c, transport, hostKey);
  client.on((ev) => {
    if (ev.type === 'disconnected' && state.client === client) onLost(ev.reason);
    opts.onEvent?.(ev);
  });
  let info: DeviceInfo;
  try {
    info = await client.connect({ pairing: opts.pairing ?? false });
  } catch (err) {
    await client.close().catch(() => undefined);
    throw err;
  }
  state.client = client;
  state.info = info;
  state.transportLabel = transport.label;
  state.fingerprint = Array.from(hostKey.public.slice(0, 6), (b) => b.toString(16).padStart(2, '0')).join(':');
  renderChrome();
  return info;
}

export async function disconnectDevice(): Promise<void> {
  const c = state.client;
  state.client = null;
  state.info = null;
  if (c) await c.close().catch(() => undefined);
  renderChrome();
}

export async function refreshInfo(): Promise<DeviceInfo | null> {
  if (!state.client) return null;
  try {
    state.info = await state.client.getInfo();
  } catch (err) {
    toast(describeError(err), 'error');
  }
  renderChrome();
  return state.info;
}

function onLost(reason: string): void {
  state.client = null;
  state.info = null;
  renderChrome();
  toast(`Disconnected: ${reason}`, 'error', 6000);
  location.hash = '#/connect';
}

// ---------------------------------------------------------------- chrome (header, status, nav)

export function renderChrome(): void {
  const nav = document.getElementById('nav');
  const status = document.getElementById('status');
  if (!nav || !status) return;
  const connected = !!state.client && !!state.info;
  clear(nav);
  if (connected) {
    nav.append(
      h('a', { href: '#/entries', 'data-nav': 'entries' }, 'Entries'),
      h('a', { href: '#/transfer', 'data-nav': 'transfer' }, 'Export / Import'),
      h('a', { href: '#/hosts', 'data-nav': 'hosts' }, 'Paired hosts'),
      h('a', { href: '#/settings', 'data-nav': 'settings' }, 'Device'),
      h(
        'button',
        { class: 'btn small ghost', onclick: () => void disconnectDevice().then(() => (location.hash = '#/connect')) },
        'Disconnect',
      ),
    );
  }
  const battery = state.info ? ` · ${state.info.battery_pct}%` : '';
  status.textContent = connected
    ? `${state.transportLabel} · ${state.info!.locked ? 'locked' : 'unlocked'}${battery}`
    : 'Not connected';
  status.classList.toggle('on', connected);
}

/** Adds the banner that makes the mock core impossible to mistake for the real thing. */
export function renderBanner(c: PrismCore): void {
  if (c.kind !== 'mock') return;
  document.querySelector('.topbar')?.insertAdjacentElement('afterend', h('div', { class: 'banner warn', role: 'note' }, MOCK_BANNER));
}

export async function init(): Promise<PrismCore> {
  const c = await loadCore();
  state.core = c;
  renderBanner(c);
  return c;
}
