import { requireClient, rerender } from '../app';
import type { EntrySummary, RecoveryCode, SecretField, SecretValue, SshPublicKeyInfo } from '../core/types';
import type { PrismClient } from '../client';
import { copySecret, CLIPBOARD_CLEAR_SECONDS } from '../util/clipboard';
import { clear, describeError, h, hex, nowUnix, toast } from '../ui/dom';
import { approve, confirmDialog, pageHead } from './shared';
import { KIND_LABEL } from './entries';

const REVEAL_MS = 30_000;

export function hexToId(s: string): number[] | null {
  if (!/^[0-9a-f]{32}$/i.test(s)) return null;
  return Array.from({ length: 16 }, (_, i) => parseInt(s.slice(i * 2, i * 2 + 2), 16));
}

function asText(v: SecretValue): string {
  if ('Text' in v) return v.Text;
  if ('List' in v) return v.List.join('\n');
  return Array.from(v.Bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function groupCode(code: string): string {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

export async function renderEntryDetail(root: HTMLElement, idHex: string, isCurrent: () => boolean): Promise<void> {
  const id = hexToId(idHex);
  const client = requireClient();
  if (!id) throw new Error('Invalid entry id');
  const list = await client.listEntries();
  if (!isCurrent()) return;
  const e = list.find((x) => hex(x.id) === idHex);
  clear(root);
  if (!e) {
    root.append(h('div', { class: 'card' }, h('p', null, 'That entry was not found on the device.'), h('a', { href: '#/entries' }, 'Back to entries')));
    return;
  }

  const actions = h(
    'div',
    { class: 'actions' },
    e.kind === 'Passkey' ? null : h('a', { class: 'btn small', href: `#/edit/${idHex}` }, 'Edit'),
    h('button', { class: 'btn small danger', onclick: () => void deleteEntry(e) }, 'Delete'),
  );
  root.append(
    pageHead(e.title, actions),
    h(
      'p',
      { class: 'muted' },
      h('span', { class: `kind kind-${e.kind}` }, KIND_LABEL[e.kind]),
      ' ',
      `Approval: ${policyText(e.policy)}`,
      e.tags.length ? ` · tags: ${e.tags.join(', ')}` : '',
    ),
  );

  const body = h('section', { class: 'card detail' });
  root.append(body);
  switch (e.kind) {
    case 'Password':
      await passwordBody(body, client, e, idHex);
      break;
    case 'Totp':
      body.append(totpPanel(client, id, e));
      break;
    case 'Passkey':
      body.append(
        dl([
          ['Site', e.url ?? '-'],
          ['User', e.subtitle || '-'],
        ]),
        h('p', { class: 'hint' }, 'Passkeys are used from the browser or the Prism credential provider. The private key never leaves the device.'),
      );
      break;
    case 'SshKey':
      await sshBody(body, client, id, e, isCurrent);
      break;
    case 'RecoveryCodes':
      body.append(recoveryBody(client, id, e));
      break;
  }
}

function policyText(p: EntrySummary['policy']): string {
  return p === 'Always' ? 'a tap on the device every time' : p === 'Session' ? 'once per unlock' : 'none (device must be unlocked)';
}

function dl(rows: [string, string][]): HTMLElement {
  return h(
    'dl',
    { class: 'dl' },
    ...rows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]),
  );
}

/** A secret row: Reveal (approve on device) and Copy (approve, then auto-clear). */
function secretRow(label: string, fetchValue: () => Promise<string>, opts: { revealable: boolean }): HTMLElement {
  const value = h('code', { class: 'secret', 'aria-label': `${label} value` }, '••••••••');
  let shown = false;
  let hideTimer: ReturnType<typeof setTimeout> | null = null;
  const row = h('div', { class: 'secret-row' });
  const revealBtn = h('button', { class: 'btn small' }, 'Reveal');
  const copyBtn = h('button', { class: 'btn small' }, 'Copy');

  const hide = (): void => {
    shown = false;
    value.textContent = '••••••••';
    revealBtn.textContent = 'Reveal';
    if (hideTimer) clearTimeout(hideTimer);
  };

  revealBtn.addEventListener('click', async () => {
    if (shown) return hide();
    const v = await approve(row, 'Approve on device…', fetchValue);
    if (v === undefined) return;
    shown = true;
    value.textContent = v;
    revealBtn.textContent = 'Hide';
    hideTimer = setTimeout(hide, REVEAL_MS);
  });
  copyBtn.addEventListener('click', async () => {
    const v = await approve(row, 'Approve on device…', fetchValue);
    if (v === undefined) return;
    await copySecret(v, () => toast('Clipboard cleared'));
    toast(`${label} copied. Clipboard clears in ${CLIPBOARD_CLEAR_SECONDS} s.`, 'ok');
  });

  row.append(h('span', { class: 'secret-label' }, label), value, h('span', { class: 'row gap' }, opts.revealable ? revealBtn : null, copyBtn));
  return row;
}

async function passwordBody(body: HTMLElement, client: PrismClient, e: EntrySummary, idHex: string): Promise<void> {
  const id = hexToId(idHex)!;
  const fetchField = (f: SecretField) => async () => asText(await client.getSecret(id, f));
  body.append(
    dl([['Site', e.url ?? '-']]),
    h('div', { class: 'secret-list' },
      secretRow('Username', fetchField('Username'), { revealable: false }),
      secretRow('Password', fetchField('Password'), { revealable: true }),
      secretRow('Notes', fetchField('Notes'), { revealable: true }),
    ),
  );
  if (e.has_totp) {
    body.append(h('h2', null, 'One-time code'), totpPanel(client, id, e));
  }
  if (e.url) {
    body.append(h('p', { class: 'muted' }, h('a', { href: e.url, target: '_blank', rel: 'noopener noreferrer' }, 'Open site')));
  }
}

/**
 * TOTP with countdown. With policy Always the device asks for a tap on every fetch, so the
 * next code is fetched on demand rather than automatically at each period boundary.
 */
function totpPanel(client: PrismClient, id: number[], e: EntrySummary): HTMLElement {
  const codeEl = h('div', { class: 'totp-code', 'aria-live': 'off' }, '--- ---');
  const meta = h('p', { class: 'muted', role: 'status' }, '');
  const nextBtn = h('button', { class: 'btn primary' }, 'Get code');
  const copyBtn = h('button', { class: 'btn small', disabled: true }, 'Copy code');
  let code = '';
  let validUntil = 0;
  let timer: ReturnType<typeof setInterval> | null = null;
  const area = h('div', { class: 'totp' }, codeEl, meta, h('div', { class: 'actions' }, nextBtn, copyBtn));

  const stop = (): void => {
    if (timer) clearInterval(timer);
    timer = null;
  };
  const tick = (): void => {
    if (!area.isConnected) return stop();
    const left = validUntil - nowUnix();
    if (left > 0) {
      meta.textContent = `Expires in ${left} s`;
      return;
    }
    stop();
    code = '';
    codeEl.textContent = '--- ---';
    copyBtn.disabled = true;
    meta.textContent = 'Expired. Get the next code.';
    nextBtn.textContent = 'Get next code';
    nextBtn.disabled = false;
    if (e.policy !== 'Always') void fetchCode();
  };
  const fetchCode = async (): Promise<void> => {
    nextBtn.disabled = true;
    const r = await approve(area, 'Approve on device…', () => client.getTotp(id));
    nextBtn.disabled = false;
    if (!r) return;
    code = r.code;
    validUntil = r.valid_until;
    codeEl.textContent = groupCode(code);
    copyBtn.disabled = false;
    nextBtn.textContent = 'Refresh';
    stop();
    timer = setInterval(tick, 1000);
    tick();
  };
  nextBtn.addEventListener('click', () => void fetchCode());
  copyBtn.addEventListener('click', async () => {
    if (!code) return;
    await copySecret(code, () => toast('Clipboard cleared'));
    toast(`Code copied. Clipboard clears in ${CLIPBOARD_CLEAR_SECONDS} s.`, 'ok');
  });
  return area;
}

async function sshBody(body: HTMLElement, client: PrismClient, id: number[], e: EntrySummary, isCurrent: () => boolean): Promise<void> {
  const keys: SshPublicKeyInfo[] = await client.sshListKeys();
  if (!isCurrent()) return;
  const key = keys.find((k) => hex(k.id) === hex(id));
  if (!key) {
    body.append(h('p', null, 'Public key not available.'));
    return;
  }
  body.append(
    dl([
      ['Comment', key.comment || '-'],
      ['Algorithm', 'ssh-ed25519'],
    ]),
    h('p', { class: 'strong' }, 'Public key'),
    h('pre', { class: 'code-block' }, key.openssh),
    h(
      'div',
      { class: 'actions' },
      h(
        'button',
        {
          class: 'btn',
          onclick: async () => {
            await navigator.clipboard.writeText(key.openssh);
            toast('Public key copied', 'ok');
          },
        },
        'Copy public key',
      ),
    ),
    h('p', { class: 'hint' }, `Add it to ~/.ssh/authorized_keys on servers, or to GitHub settings. Entry: ${e.title}.`),
  );
}

function recoveryBody(client: PrismClient, id: number[], e: EntrySummary): HTMLElement {
  const out = h('ol', { class: 'codes' });
  const meta = h('p', { class: 'muted' }, e.subtitle);
  const area = h('div', null, meta, out);
  const show = h('button', { class: 'btn primary' }, 'Show codes');

  const render = (codes: RecoveryCode[]): void => {
    meta.textContent = `${codes.filter((c) => !c.used).length}/${codes.length} left`;
    out.replaceChildren(
      ...codes.map((c, index) =>
        h(
          'li',
          { class: c.used ? 'used' : null },
          h('code', { class: 'secret' }, c.code),
          ' ',
          h('button', { class: 'btn small', onclick: () => void copySecret(c.code, () => toast('Clipboard cleared')) }, 'Copy'),
          ' ',
          h(
            'button',
            {
              class: 'btn small ghost',
              disabled: c.used,
              onclick: async () => {
                try {
                  await client.markRecoveryCodeUsed(id, index);
                  c.used = true;
                  toast('Marked as used', 'ok');
                  render(codes);
                } catch (err) {
                  toast(describeError(err), 'error');
                }
              },
            },
            c.used ? 'Used' : 'Mark used',
          ),
        ),
      ),
    );
  };

  show.addEventListener('click', async () => {
    const full = await approve(area, 'Approve on device…', () => client.getEntry(id));
    if (!full || !('RecoveryCodes' in full.data)) return;
    show.remove();
    render(full.data.RecoveryCodes.codes);
  });
  area.append(show);
  return area;
}

async function deleteEntry(e: EntrySummary): Promise<void> {
  if (!confirmDialog(`Delete "${e.title}"? The device will ask for a tap to confirm.`)) return;
  try {
    await requireClient().deleteEntry(e.id);
    toast('Deleted', 'ok');
    location.hash = '#/entries';
  } catch (err) {
    toast(describeError(err), 'error', 6000);
    rerender();
  }
}

