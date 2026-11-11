import { requireClient } from '../app';
import type { EntryKind, EntrySummary } from '../core/types';
import { PrismError } from '../client';
import { clear, describeError, h, hex, input, toast } from '../ui/dom';
import { pageHead, unlockPanel } from './shared';

const KIND_TABS: [EntryKind | '', string][] = [
  ['', 'All'],
  ['Password', 'Passwords'],
  ['Totp', 'One-time codes'],
  ['Passkey', 'Passkeys'],
  ['SshKey', 'SSH keys'],
  ['RecoveryCodes', 'Recovery'],
];

export const KIND_LABEL: Record<EntryKind, string> = {
  Password: 'Password',
  Totp: 'TOTP',
  Passkey: 'Passkey',
  SshKey: 'SSH key',
  RecoveryCodes: 'Recovery',
};

export async function renderEntries(root: HTMLElement, query: URLSearchParams, isCurrent: () => boolean): Promise<void> {
  const kind = (query.get('kind') ?? '') as EntryKind | '';
  const q0 = query.get('q') ?? '';

  const search = input({ type: 'search', placeholder: 'Search title, user, site, tag', 'aria-label': 'Search entries', value: q0 });
  const list = h('ul', { class: 'entry-list', 'aria-label': 'Entries' });
  const status = h('p', { class: 'muted', role: 'status' }, 'Loading entries...');
  const tabs = h(
    'nav',
    { class: 'tabs', 'aria-label': 'Filter by type' },
    KIND_TABS.map(([k, label]) =>
      h('a', { href: `#/entries${k ? `?kind=${k}` : ''}`, class: k === kind ? 'tab active' : 'tab', 'aria-current': k === kind ? 'page' : null }, label),
    ),
  );
  const newMenu = h(
    'div',
    { class: 'actions' },
    h('a', { class: 'btn small', href: '#/new/password' }, '+ Password'),
    h('a', { class: 'btn small', href: '#/new/totp' }, '+ One-time code'),
    h('a', { class: 'btn small', href: '#/new/recovery' }, '+ Recovery codes'),
    h('a', { class: 'btn small', href: '#/new/ssh' }, '+ SSH key'),
  );
  clear(root);
  root.append(pageHead('Entries', newMenu), tabs, h('div', { class: 'toolbar' }, search), status, list);

  let all: EntrySummary[] = [];
  const paint = (): void => {
    const needle = search.value.trim().toLowerCase();
    const rows = all.filter((e) => {
      if (kind && e.kind !== kind) return false;
      if (!needle) return true;
      return [e.title, e.subtitle, e.url ?? '', ...e.tags].some((s) => s.toLowerCase().includes(needle));
    });
    list.replaceChildren(...rows.map(entryRow));
    status.textContent = rows.length === 0 ? (all.length === 0 ? 'No entries yet.' : 'No matches.') : `${rows.length} of ${all.length}`;
  };
  search.addEventListener('input', () => {
    paint();
    const url = new URL(location.href);
    history.replaceState(null, '', `${url.pathname}${url.search}#/entries${kind ? `?kind=${kind}` : ''}`);
  });

  try {
    all = await requireClient().listEntries(undefined);
  } catch (err) {
    if (!isCurrent()) return;
    if (err instanceof PrismError && err.code === 'Locked') {
      status.remove();
      list.remove();
      root.append(unlockPanel());
      return;
    }
    status.textContent = describeError(err);
    toast(describeError(err), 'error');
    return;
  }
  paint();
}

function entryRow(e: EntrySummary): HTMLElement {
  return h(
    'li',
    null,
    h(
      'a',
      { class: 'entry-row', href: `#/entry/${hex(e.id)}` },
      h('span', { class: `kind kind-${e.kind}` }, KIND_LABEL[e.kind]),
      h(
        'span',
        { class: 'entry-main' },
        h('span', { class: 'entry-title' }, e.title),
        h('span', { class: 'entry-sub muted' }, [e.subtitle, e.url].filter(Boolean).join(' · ')),
      ),
      e.has_totp ? h('span', { class: 'badge', title: 'Has a one-time code' }, 'OTP') : null,
      e.policy === 'Always' ? h('span', { class: 'badge subtle', title: 'Needs a tap on the device every time' }, 'tap') : null,
    ),
  );
}
