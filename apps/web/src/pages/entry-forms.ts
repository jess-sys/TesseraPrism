import jsQR from 'jsqr';
import { core, requireClient } from '../app';
import type { ApprovalPolicy, Entry, EntryData, Totp } from '../core/types';
import type { PrismClient } from '../client';
import { formatOpenSshPublicKey, parseOpenSshEd25519, OpenSshError } from '../keys/openssh';
import { generatePassword, strengthLabel } from '../util/password';
import { clear, describeError, field, h, hex, input, nowUnix, randomId, select, textarea, toast, withBusy } from '../ui/dom';
import { approve, pageHead } from './shared';
import { hexToId } from './entry-detail';

const POLICY_OPTIONS: [ApprovalPolicy, string][] = [
  ['Always', 'Always: tap on device every use'],
  ['Session', 'Session: tap once per unlock'],
  ['Never', 'Never: no tap (device unlocked)'],
];

/** `entry` is set only for edit mode; it is the full entry returned by GetEntry. */
interface FormOpts {
  mode: 'new' | 'edit';
  entry?: Entry;
}

function splitTags(s: string): string[] {
  return s.split(',').map((t) => t.trim()).filter(Boolean);
}

function buildEntry(
  base: { id?: number[]; created?: number; policy: ApprovalPolicy; title: string; tags: string[] },
  data: EntryData,
): Entry {
  const now = nowUnix();
  return {
    id: base.id ?? randomId(),
    title: base.title,
    tags: base.tags,
    created: base.created ?? now,
    modified: now,
    policy: base.policy,
    data,
  };
}

/** Carries the existing id/created/policy/tags through an edit. */
function baseFrom(opts: FormOpts, policy: ApprovalPolicy, title: string, tags: string[]) {
  return { id: opts.entry?.id, created: opts.entry?.created, policy, title, tags };
}

async function save(entry: Entry, isNew: boolean): Promise<void> {
  const client = requireClient();
  if (isNew) await client.addEntry(entry);
  else await client.updateEntry(entry);
  toast(isNew ? 'Saved to device' : 'Updated on device', 'ok');
  location.hash = `#/entry/${hex(entry.id)}`;
}

export async function renderNewEntry(root: HTMLElement, kind: string): Promise<void> {
  clear(root);
  switch (kind) {
    case 'password':
      root.append(pageHead('New password'), passwordForm({ mode: 'new' }));
      return;
    case 'totp':
      root.append(pageHead('New one-time code'), totpForm({ mode: 'new' }));
      return;
    case 'recovery':
      root.append(pageHead('New recovery codes'), recoveryForm({ mode: 'new' }));
      return;
    case 'ssh':
      root.append(pageHead('New SSH key'), sshPage());
      return;
    default:
      throw new Error(`Unknown entry type "${kind}"`);
  }
}

export async function renderEditEntry(root: HTMLElement, idHex: string, isCurrent: () => boolean): Promise<void> {
  const client = requireClient();
  const id = hexToId(idHex);
  if (!id) throw new Error('Invalid entry id');
  const list = await client.listEntries();
  if (!isCurrent()) return;
  const e = list.find((x) => hex(x.id) === idHex);
  clear(root);
  if (!e) {
    root.append(h('p', null, 'Entry not found.'));
    return;
  }
  root.append(pageHead(`Edit: ${e.title}`));
  if (e.kind === 'SshKey' || e.kind === 'Passkey') {
    root.append(h('p', { class: 'banner' }, `${e.kind === 'SshKey' ? 'SSH keys' : 'Passkeys'} cannot be edited. Delete and create a new one.`));
    return;
  }
  root.append(editLoader(client, id));
}

/** One tap: GetEntry returns the full entry, which pre-fills the right form for its kind. */
function editLoader(client: PrismClient, id: number[]): HTMLElement {
  const area = h('div', { class: 'card' });
  const btn = h('button', { class: 'btn primary' }, 'Load from device');
  btn.addEventListener('click', async () => {
    const full = await approve(area, 'Approve on device…', () => client.getEntry(id));
    if (!full) return;
    clear(area);
    area.append(formForEntry(full));
  });
  area.append(h('p', null, 'Loads the full entry from the device (one tap).'), h('div', { class: 'actions' }, btn));
  return area;
}

function formForEntry(entry: Entry): HTMLElement {
  const d = entry.data;
  if ('Password' in d) return passwordForm({ mode: 'edit', entry });
  if ('Totp' in d) return totpForm({ mode: 'edit', entry });
  if ('RecoveryCodes' in d) return recoveryForm({ mode: 'edit', entry });
  return h('p', null, 'This entry type cannot be edited.');
}

// ---------------------------------------------------------------- password

function passwordForm(opts: FormOpts): HTMLElement {
  const e = opts.entry;
  const p = e && 'Password' in e.data ? e.data.Password : null;
  const title = input({ required: true, value: e?.title ?? '', 'aria-required': 'true' });
  const user = input({ value: p?.username ?? '' });
  const pass = input({ id: 'pw', type: 'password', autocomplete: 'new-password', value: p?.password ?? '' });
  const url = input({ type: 'url', placeholder: 'https://example.com', value: p?.url ?? '' });
  const notes = textarea({ value: p?.notes ?? '' });
  const tags = input({ value: e?.tags.join(', ') ?? '' });
  const policy = select(POLICY_OPTIONS, e?.policy ?? 'Always');
  const strength = h('span', { class: 'hint', role: 'status' }, '');
  const updateStrength = () => (strength.textContent = pass.value ? `Strength: ${strengthLabel(pass.value)}` : '');
  pass.addEventListener('input', updateStrength);
  updateStrength();

  let show = false;
  const toggle = h('button', { type: 'button', class: 'btn small ghost' }, 'Show');
  toggle.addEventListener('click', () => {
    show = !show;
    pass.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Hide' : 'Show';
  });

  const len = input({ type: 'number', min: 8, max: 128, value: 20, 'aria-label': 'Length' });
  const cls = {
    lower: h('input', { type: 'checkbox', checked: true }),
    upper: h('input', { type: 'checkbox', checked: true }),
    digits: h('input', { type: 'checkbox', checked: true }),
    symbols: h('input', { type: 'checkbox', checked: true }),
  };
  const gen = h(
    'details',
    { class: 'gen' },
    h('summary', null, 'Password generator'),
    h(
      'div',
      { class: 'gen-grid' },
      field('Length', len),
      h('label', { class: 'check' }, cls.lower, ' a-z'),
      h('label', { class: 'check' }, cls.upper, ' A-Z'),
      h('label', { class: 'check' }, cls.digits, ' 0-9'),
      h('label', { class: 'check' }, cls.symbols, ' symbols'),
    ),
    h(
      'button',
      {
        type: 'button',
        class: 'btn small',
        onclick: () => {
          try {
            pass.value = generatePassword({
              length: Number(len.value),
              lower: cls.lower.checked,
              upper: cls.upper.checked,
              digits: cls.digits.checked,
              symbols: cls.symbols.checked,
            });
            updateStrength();
          } catch (err) {
            toast(describeError(err), 'error');
          }
        },
      },
      'Generate',
    ),
  );

  const saveBtn = h('button', { class: 'btn primary', type: 'submit' }, opts.mode === 'new' ? 'Save to device' : 'Save changes');
  return h(
    'form',
    {
      class: 'form card',
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        if (!title.value.trim()) return toast('Title is required', 'error');
        if (!pass.value) return toast('Password is required', 'error');
        await withBusy(saveBtn, 'Approve on device...', async () => {
          const entry = buildEntry(baseFrom(opts, policy.value as ApprovalPolicy, title.value.trim(), splitTags(tags.value)), {
            Password: {
              username: user.value,
              password: pass.value,
              url: url.value.trim() || null,
              notes: notes.value,
              // Keep an attached one-time code exactly as the device returned it.
              totp: p?.totp ?? null,
            },
          });
          await save(entry, opts.mode === 'new');
        });
      },
    },
    field('Title', title),
    field('Username', user),
    h('div', { class: 'field' }, h('label', { for: 'pw' }, 'Password'), h('div', { class: 'row gap' }, pass, toggle), strength),
    gen,
    field('Website', url),
    field('Notes', notes),
    field('Tags', tags, 'Comma separated'),
    field('Approval policy', policy),
    h('div', { class: 'actions' }, saveBtn),
  );
}

// ---------------------------------------------------------------- TOTP

function uriFromSecret(secret: string, issuer: string, account: string): string {
  const enc = encodeURIComponent;
  const label = issuer ? `${enc(issuer)}:${enc(account)}` : enc(account);
  const params = [`secret=${enc(secret.replace(/\s+/g, '').toUpperCase())}`];
  if (issuer) params.push(`issuer=${enc(issuer)}`);
  return `otpauth://totp/${label}?${params.join('&')}`;
}

async function decodeQr(file: File): Promise<string> {
  const bmp = await createImageBitmap(file);
  const canvas = document.createElement('canvas');
  canvas.width = bmp.width;
  canvas.height = bmp.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('Canvas not available');
  ctx.drawImage(bmp, 0, 0);
  const img = ctx.getImageData(0, 0, bmp.width, bmp.height);
  const res = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
  if (!res) throw new Error('No QR code found in that image.');
  if (!res.data.startsWith('otpauth://')) throw new Error('The QR code is not an otpauth:// code.');
  return res.data;
}

function totpForm(opts: FormOpts): HTMLElement {
  const e = opts.entry;
  const existing: Totp | null = e && 'Totp' in e.data ? e.data.Totp : null;
  const method = select(
    [
      ['uri', 'Paste otpauth:// URI'],
      ['secret', 'Enter base32 secret'],
      ['qr', 'Upload QR code image'],
    ],
    'uri',
  );
  const title = input({ required: true, value: e?.title ?? '' });
  const uri = textarea({ rows: 2, placeholder: 'otpauth://totp/Example:me@example.com?secret=...' });
  const secret = input({ placeholder: 'JBSW Y3DP EHPK 3PXP', autocomplete: 'off', spellcheck: false });
  const issuer = input({ placeholder: 'Example' });
  const account = input({ placeholder: 'me@example.com' });
  const qr = input({ type: 'file', accept: 'image/*' });
  const policy = select(POLICY_OPTIONS, e?.policy ?? 'Always');
  const preview = h('div', { class: 'preview', role: 'status' });
  const saveBtn = h('button', { class: 'btn primary', type: 'submit' }, 'Save to device');
  const hint = existing && opts.mode === 'edit'
    ? h('p', { class: 'hint' }, 'Leave the inputs empty to keep the current secret. Enter a new one to replace it.')
    : null;

  const sections: Record<string, HTMLElement> = {
    uri: field('otpauth URI', uri),
    secret: h('div', { class: 'grid-3' }, field('Secret (base32)', secret), field('Issuer', issuer), field('Account', account)),
    qr: field('QR image', qr, 'Decoded in your browser; the image is not uploaded anywhere.'),
  };
  const sectionBox = h('div', null, ...Object.values(sections));
  const showSection = () => {
    for (const [k, el] of Object.entries(sections)) el.hidden = k !== method.value;
  };
  showSection();

  let parsed: Totp | null = null;
  /** Resolves the current input to a parsed TOTP config. Edit mode keeps the stored secret when blank. */
  const resolve = async (): Promise<Totp> => {
    let text: string;
    if (method.value === 'uri') text = uri.value.trim();
    else if (method.value === 'secret') {
      text = secret.value.trim() ? uriFromSecret(secret.value, issuer.value.trim(), account.value.trim()) : '';
    } else {
      const file = qr.files?.[0];
      if (file) {
        text = await decodeQr(file);
        uri.value = text;
      } else text = '';
    }
    if (!text) {
      if (existing) return existing;
      throw new Error(method.value === 'qr' ? 'Choose a QR image first.' : 'Enter the code details first.');
    }
    return core().parseOtpauth(text);
  };
  const doPreview = async () => {
    preview.replaceChildren();
    try {
      parsed = await resolve();
      const code = core().totpNow(parsed, nowUnix());
      if (!title.value && parsed.issuer) title.value = parsed.issuer;
      preview.append(
        h('dl', { class: 'dl' },
          h('dt', null, 'Issuer'), h('dd', null, parsed.issuer || '-'),
          h('dt', null, 'Account'), h('dd', null, parsed.account || '-'),
          h('dt', null, 'Digits / period'), h('dd', null, `${parsed.digits} / ${parsed.period}s`),
          h('dt', null, 'Algorithm'), h('dd', null, parsed.algorithm.replace('Sha', 'SHA-')),
        ),
        h('p', { class: 'hint' }, `Preview code: ${code} (the device computes the real code)`),
      );
    } catch (err) {
      parsed = null;
      preview.append(h('p', { class: 'banner error', role: 'alert' }, describeError(err)));
    }
  };
  method.addEventListener('change', () => {
    showSection();
    void doPreview();
  });
  for (const el of [uri, secret, issuer, account]) el.addEventListener('change', () => void doPreview());
  qr.addEventListener('change', () => void doPreview());
  if (existing) void doPreview();

  return h(
    'form',
    {
      class: 'form card',
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        await withBusy(saveBtn, 'Approve on device...', async () => {
          const totp = parsed ?? (await resolve());
          if (!title.value.trim()) throw new Error('Title is required');
          await save(buildEntry(baseFrom(opts, policy.value as ApprovalPolicy, title.value.trim(), e?.tags ?? []), { Totp: totp }), opts.mode === 'new');
        });
      },
    },
    field('Title', title),
    field('Input method', method),
    hint,
    sectionBox,
    preview,
    field('Approval policy', policy),
    h('div', { class: 'actions' }, saveBtn),
  );
}

// ---------------------------------------------------------------- recovery codes

function recoveryForm(opts: FormOpts): HTMLElement {
  const e = opts.entry;
  const rc = e && 'RecoveryCodes' in e.data ? e.data.RecoveryCodes : null;
  // Used flags are keyed by code text: unchanged codes keep their state on save.
  const usedByCode = new Map((rc?.codes ?? []).map((c) => [c.code, c.used] as const));
  const title = input({ required: true, value: e?.title ?? '' });
  const service = input({ value: rc?.service ?? '' });
  const codes = textarea({ rows: 8, placeholder: 'One code per line', value: (rc?.codes ?? []).map((c) => c.code).join('\n') });
  const notes = textarea({ rows: 2, value: rc?.notes ?? '' });
  const tags = input({ value: e?.tags.join(', ') ?? '' });
  const policy = select(POLICY_OPTIONS, e?.policy ?? 'Always');
  const usedCount = rc ? rc.codes.filter((c) => c.used).length : 0;
  const saveBtn = h('button', { class: 'btn primary', type: 'submit' }, opts.mode === 'new' ? 'Save to device' : 'Save changes');
  return h(
    'form',
    {
      class: 'form card',
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        const list = codes.value.split('\n').map((c) => c.trim()).filter(Boolean);
        if (!title.value.trim()) return toast('Title is required', 'error');
        if (list.length === 0) return toast('Paste at least one code', 'error');
        await withBusy(saveBtn, 'Approve on device...', async () => {
          await save(
            buildEntry(baseFrom(opts, policy.value as ApprovalPolicy, title.value.trim(), splitTags(tags.value)), {
              RecoveryCodes: {
                service: service.value.trim() || title.value.trim(),
                codes: list.map((code) => ({ code, used: usedByCode.get(code) ?? false })),
                notes: notes.value,
              },
            }),
            opts.mode === 'new',
          );
        });
      },
    },
    field('Title', title),
    field('Service', service, 'Optional. Defaults to the title.'),
    field('Codes', codes, rc ? `${usedCount} of ${rc.codes.length} used. Used state is kept for codes you do not change.` : 'Paste the list from the site, one per line.'),
    field('Notes', notes),
    field('Tags', tags, 'Comma separated'),
    field('Approval policy', policy),
    h('div', { class: 'actions' }, saveBtn),
  );
}

// ---------------------------------------------------------------- SSH

function sshPage(): HTMLElement {
  return h('div', { class: 'stack' }, generateSshCard(), importSshCard());
}

function generateSshCard(): HTMLElement {
  const name = input({ required: true, placeholder: 'work-github' });
  const comment = input({ placeholder: 'you@laptop' });
  const policy = select(POLICY_OPTIONS, 'Always');
  const out = h('div', { role: 'status' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Generate on device');
  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'Generate on the device'),
    h('p', { class: 'muted' }, 'The private key is derived from the device seed and never leaves the device.'),
    h(
      'form',
      {
        class: 'form',
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          if (!name.value.trim()) return toast('Name is required', 'error');
          const client = requireClient();
          await withBusy(btn, 'Approve on device...', async () => {
            const key = await client.generateSshKey(name.value.trim(), comment.value.trim(), policy.value as ApprovalPolicy);
            out.replaceChildren(
              h('p', { class: 'strong' }, 'Public key'),
              h('pre', { class: 'code-block' }, key.openssh),
              h('a', { href: `#/entry/${hex(key.id)}` }, 'Open key entry'),
            );
            toast('SSH key generated', 'ok');
          });
        },
      },
      field('Name', name),
      field('Comment', comment),
      field('Approval policy', policy),
      h('div', { class: 'actions' }, btn),
    ),
    out,
  );
}

function importSshCard(): HTMLElement {
  const file = input({ type: 'file', accept: '.key,.pem,.txt,*/*', 'aria-label': 'OpenSSH private key file' });
  const name = input({ placeholder: 'Defaults to the key comment' });
  const policy = select(POLICY_OPTIONS, 'Always');
  const preview = h('div', { role: 'status' });
  const btn = h('button', { class: 'btn primary', type: 'submit', disabled: true }, 'Import to device');
  let parsed: ReturnType<typeof parseOpenSshEd25519> | null = null;

  file.addEventListener('change', async () => {
    parsed = null;
    btn.disabled = true;
    preview.replaceChildren();
    const f = file.files?.[0];
    if (!f) return;
    try {
      const key = parseOpenSshEd25519(await f.text());
      parsed = key;
      name.value ||= key.comment || f.name;
      preview.append(
        h('p', { class: 'strong' }, 'Parsed: unencrypted Ed25519 key'),
        h('pre', { class: 'code-block' }, formatOpenSshPublicKey(key.publicKey, key.comment)),
      );
      btn.disabled = false;
    } catch (err) {
      preview.append(h('p', { class: 'banner error', role: 'alert' }, err instanceof OpenSshError ? err.message : describeError(err)));
    }
  });

  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'Import an existing key'),
    h('p', { class: 'muted' }, 'Supports unencrypted Ed25519 keys in OpenSSH format. Remove a passphrase first with ssh-keygen -p -N "".'),
    h(
      'form',
      {
        class: 'form',
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          if (!parsed) return;
          const key = parsed;
          const title = name.value.trim() || key.comment || 'imported key';
          await withBusy(btn, 'Approve on device...', async () => {
            const seed = Array.from(key.seed);
            const publicKey = Array.from(key.publicKey);
            try {
              await requireClient().addEntry(
                buildEntry(
                  { policy: policy.value as ApprovalPolicy, title, tags: [] },
                  { SshKey: { comment: key.comment, source: { Imported: { secret: seed } }, public_key: publicKey } },
                ),
              );
            } finally {
              key.seed.fill(0);
              seed.fill(0);
            }
            toast('Imported', 'ok');
            location.hash = '#/entries';
          });
        },
      },
      field('Key file', file),
      preview,
      field('Name', name),
      field('Approval policy', policy),
      h('div', { class: 'actions' }, btn),
    ),
  );
}
