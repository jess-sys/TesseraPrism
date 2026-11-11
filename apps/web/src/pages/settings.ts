import { refreshInfo, requireClient, rerender, state } from '../app';
import type { KeyboardLayout, Orientation, Settings, SleepMode } from '../core/types';
import { clear, describeError, field, formatTime, h, hex, input, nowUnix, select, toast, withBusy } from '../ui/dom';
import { strengthLabel } from '../util/password';
import { confirmDialog, pageHead, unlockPanel } from './shared';

/** Device info, lock/clock actions and the settings form (ARCHITECTURE §5.3 GetSettings/SetSettings). */
export async function renderSettings(root: HTMLElement, isCurrent: () => boolean): Promise<void> {
  const client = requireClient();
  const info = (await refreshInfo()) ?? state.info;
  const settings = await client.getSettings();
  if (!isCurrent()) return;
  clear(root);
  root.append(pageHead('Device'));

  if (info?.locked) root.append(unlockPanel());

  const rows: [string, string][] = info
    ? [
        ['Firmware', info.fw_version],
        ['Battery', `${info.battery_pct}%${info.charging ? ' (charging)' : ''}`],
        ['Entries', String(info.entry_count)],
        ['Initialized', info.initialized ? 'yes' : 'no'],
        ['Clock', info.time_valid ? 'valid' : 'not set'],
        ['Device key', hex(info.device_pubkey, 24)],
      ]
    : [];
  const lockBtn = h('button', { class: 'btn', onclick: () => void lockNow() }, 'Lock now');
  const clockBtn = h(
    'button',
    {
      class: 'btn',
      onclick: async (ev: Event) => {
        await withBusy(ev.currentTarget as HTMLButtonElement, 'Setting...', async () => {
          await client.setTime(nowUnix());
          await refreshInfo();
          toast('Clock set from this computer', 'ok');
        });
      },
    },
    'Set clock',
  );
  root.append(
    h(
      'section',
      { class: 'card' },
      h('h2', null, 'Status'),
      h('dl', { class: 'dl' }, ...rows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
      h('div', { class: 'actions' }, lockBtn, clockBtn, h('span', { class: 'muted' }, `Updated ${formatTime(nowUnix())}`)),
    ),
  );

  const autoLock = input({ type: 'number', min: 30, max: 3600, value: settings.auto_lock_secs, 'aria-describedby': 'al-hint' });
  const sleep = select<SleepMode>(
    [
      ['PowerOff', 'Power off when idle (default)'],
      ['LightSleep', 'Light sleep (stays Bluetooth-reachable)'],
    ],
    settings.sleep_mode,
  );
  const layout = select<KeyboardLayout>(
    [
      ['Us', 'US'],
      ['FrAzerty', 'French AZERTY'],
    ],
    settings.keyboard_layout,
  );
  const orientation = select<Orientation>(
    [
      ['Portrait', 'Portrait'],
      ['Landscape', 'Landscape'],
    ],
    settings.orientation,
  );
  const buzzer = h('input', { type: 'checkbox', checked: settings.buzzer });
  const owner = input({ value: settings.owner_info ?? '', maxlength: 120, placeholder: 'Shown on the lock screen' });
  const saveBtn = h('button', { class: 'btn primary', type: 'submit' }, 'Save settings');

  root.append(
    h(
      'section',
      { class: 'card' },
      h('h2', null, 'Settings'),
      h(
        'form',
        {
          class: 'form',
          onsubmit: async (ev: Event) => {
            ev.preventDefault();
            const secs = Number(autoLock.value);
            if (!Number.isInteger(secs) || secs < 30 || secs > 3600) return toast('Auto-lock must be 30 to 3600 seconds', 'error');
            const next: Settings = {
              auto_lock_secs: secs,
              sleep_mode: sleep.value as SleepMode,
              keyboard_layout: layout.value as KeyboardLayout,
              orientation: orientation.value as Orientation,
              buzzer: buzzer.checked,
              owner_info: owner.value.trim() || null,
            };
            await withBusy(saveBtn, 'Saving...', async () => {
              await client.setSettings(next);
              toast('Settings saved', 'ok');
              rerender();
            });
          },
        },
        field('Auto-lock after (seconds)', autoLock, 'Between 30 and 3600. Default 180.'),
        field('When idle', sleep),
        field('USB keyboard layout', layout, 'Used when typing entries over USB.'),
        field('Screen orientation', orientation),
        h('label', { class: 'check' }, buzzer, ' Buzzer on approvals and key presses'),
        field('Owner info', owner, 'Optional contact shown on the lock screen.'),
        h('div', { class: 'actions' }, saveBtn),
      ),
    ),
  );

  root.append(recoveryPassphraseCard());
}

/** Sets the recovery passphrase (device tap). Required before the device can export. */
function recoveryPassphraseCard(): HTMLElement {
  const pass = input({ type: 'password', autocomplete: 'new-password', minlength: 8, required: true });
  const again = input({ type: 'password', autocomplete: 'new-password', minlength: 8, required: true });
  const strength = h('p', { class: 'hint', role: 'status' }, '');
  pass.addEventListener('input', () => (strength.textContent = pass.value ? `Strength: ${strengthLabel(pass.value)}` : ''));
  const btn = h('button', { class: 'btn', type: 'submit' }, 'Set recovery passphrase');
  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'Recovery passphrase'),
    h(
      'p',
      { class: 'muted' },
      'Used to encrypt exports and to unlock with the companion. Use at least 8 characters, and store it somewhere safe: without it you cannot restore an export.',
    ),
    h(
      'form',
      {
        class: 'form',
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          if (pass.value.length < 8) return toast('Use at least 8 characters', 'error');
          if (pass.value !== again.value) return toast('The two passphrases do not match', 'error');
          await withBusy(btn, 'Approve on device...', async () => {
            await requireClient().setRecoveryPassphrase(pass.value);
            pass.value = '';
            again.value = '';
            strength.textContent = '';
            toast('Recovery passphrase set', 'ok');
          });
        },
      },
      field('New passphrase', pass),
      strength,
      field('Repeat passphrase', again),
      h('div', { class: 'actions' }, btn),
    ),
  );
}

async function lockNow(): Promise<void> {
  try {
    await requireClient().lock();
    await refreshInfo();
    toast('Locked', 'ok');
    rerender();
  } catch (err) {
    toast(describeError(err), 'error');
  }
}

/** Paired hosts (ARCHITECTURE §5.2: max 16 hosts). */
export async function renderHosts(root: HTMLElement, isCurrent: () => boolean): Promise<void> {
  const client = requireClient();
  const hosts = await client.listPairedHosts();
  if (!isCurrent()) return;
  clear(root);
  root.append(
    pageHead('Paired hosts'),
    h(
      'section',
      { class: 'card' },
      h('p', { class: 'muted' }, `This browser's key starts with ${state.fingerprint}. Removing a host means it must pair again before use.`),
      hosts.length === 0
        ? h('p', null, 'No paired hosts.')
        : h(
            'ul',
            { class: 'host-list' },
            ...hosts.map((host) =>
              h(
                'li',
                { class: 'host' },
                h('div', null, h('strong', null, host.label || 'Unnamed host'), h('div', { class: 'muted small' }, `key ${hex(host.public_key, 16)}`)),
                h('div', { class: 'muted small' }, `paired ${formatTime(host.paired_at)} · last seen ${formatTime(host.last_seen)}`),
                h(
                  'button',
                  {
                    class: 'btn small danger',
                    onclick: async () => {
                      if (!confirmDialog(`Remove "${host.label}"?`)) return;
                      try {
                        await client.removePairedHost(host.public_key);
                        toast('Host removed', 'ok');
                        rerender();
                      } catch (err) {
                        toast(describeError(err), 'error');
                      }
                    },
                  },
                  'Remove',
                ),
              ),
            ),
          ),
    ),
  );
}
