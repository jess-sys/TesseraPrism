import './styles/main.css';
import { init, refreshInfo, renderChrome, state } from './app';
import { h, clear } from './ui/dom';
import { renderConnect } from './pages/connect';
import { renderPair } from './pages/pair';
import { renderEntries } from './pages/entries';
import { renderEntryDetail } from './pages/entry-detail';
import { renderNewEntry, renderEditEntry } from './pages/entry-forms';
import { renderTransfer } from './pages/transfer';
import { renderSettings, renderHosts } from './pages/settings';

const app = (): HTMLElement => document.getElementById('app')!;
let routeToken = 0;

type Handler = (root: HTMLElement, args: string[], query: URLSearchParams, isCurrent: () => boolean) => void | Promise<void>;

/** Route table. `protected` routes need a live, handshaken client. */
const routes: Record<string, { handler: Handler; protected: boolean }> = {
  connect: { handler: (r) => renderConnect(r), protected: false },
  pair: { handler: (r) => renderPair(r), protected: false },
  entries: { handler: (r, _a, q, c) => renderEntries(r, q, c), protected: true },
  entry: { handler: (r, [id], _q, c) => renderEntryDetail(r, id!, c), protected: true },
  new: { handler: (r, [kind]) => renderNewEntry(r, kind ?? 'password'), protected: true },
  edit: { handler: (r, [id], _q, c) => renderEditEntry(r, id!, c), protected: true },
  transfer: { handler: (r) => renderTransfer(r), protected: true },
  settings: { handler: (r, _a, _q, c) => renderSettings(r, c), protected: true },
  hosts: { handler: (r, _a, _q, c) => renderHosts(r, c), protected: true },
};

async function route(): Promise<void> {
  const token = ++routeToken;
  const raw = location.hash.replace(/^#\/?/, '');
  const [pathPart = '', queryPart = ''] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean);
  const name = segments[0] ?? 'entries';
  const entry = routes[name];
  const root = app();
  clear(root);

  if (!entry) {
    location.hash = '#/connect';
    return;
  }
  if (entry.protected && !state.client) {
    location.hash = '#/connect';
    return;
  }
  document.querySelectorAll('nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('data-nav') === name));
  renderChrome();
  try {
    await entry.handler(root, segments.slice(1), new URLSearchParams(queryPart), () => token === routeToken);
  } catch (err) {
    if (token !== routeToken) return;
    console.error(err);
    clear(root);
    root.append(h('div', { class: 'card error', role: 'alert' }, String(err instanceof Error ? err.message : err)));
  }
  if (token === routeToken) root.focus({ preventScroll: true });
}

async function boot(): Promise<void> {
  await init();
  renderChrome();
  window.addEventListener('hashchange', () => void route());
  window.addEventListener('prism:rerender', () => void route());
  if (!location.hash) location.hash = state.client ? '#/entries' : '#/connect';
  await route();
  // Keep the status line fresh while connected (lock state, battery).
  setInterval(() => {
    if (state.client) void refreshInfo();
  }, 60_000);
}

void boot();
