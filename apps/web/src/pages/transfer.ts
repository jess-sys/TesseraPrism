import { requireClient } from '../app';
import type { ImportMode } from '../core/types';
import { describeError, field, h, input, toast, withBusy, clear } from '../ui/dom';
import { pageHead, confirmDialog } from './shared';

/** Export/import of the encrypted `.prism` file (ARCHITECTURE §3.3). The file stays encrypted. */
export function renderTransfer(root: HTMLElement): void {
  clear(root);
  root.append(pageHead('Export / Import'), h('div', { class: 'stack' }, exportCard(), importCard()));
}

function exportCard(): HTMLElement {
  const pass = input({ type: 'password', autocomplete: 'off', required: true });
  const progress = h('progress', { max: 100, value: 0, hidden: true, 'aria-label': 'Export progress' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Export vault');
  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'Export'),
    h(
      'p',
      { class: 'muted' },
      'Downloads an encrypted .prism backup. The device checks the recovery passphrase and encrypts the file with it. The device asks for a tap before exporting.',
    ),
    h(
      'form',
      {
        class: 'form',
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          await withBusy(btn, 'Approve on device...', async () => {
            progress.hidden = false;
            const bytes = await requireClient().exportVault(pass.value, (done, total) => {
              progress.value = Math.round((done / total) * 100);
            });
            const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = h('a', { href: url, download: `prism-${new Date().toISOString().slice(0, 10)}.prism` });
            document.body.append(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 10_000);
            toast(`Exported ${bytes.length.toLocaleString()} bytes`, 'ok');
          });
          progress.hidden = true;
        },
      },
      field('Recovery passphrase', pass, 'Required to encrypt the export.'),
      progress,
      h('div', { class: 'actions' }, btn),
    ),
  );
}

function importCard(): HTMLElement {
  const file = input({ type: 'file', accept: '.prism,application/octet-stream', 'aria-label': 'Export file to import' });
  const pass = input({ type: 'password', autocomplete: 'off', required: true });
  const merge = h('input', { type: 'radio', name: 'mode', value: 'Merge', checked: true });
  const replace = h('input', { type: 'radio', name: 'mode', value: 'Replace' });
  const progress = h('progress', { max: 100, value: 0, hidden: true, 'aria-label': 'Import progress' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Import');
  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'Import'),
    h(
      'form',
      {
        class: 'form',
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          const f = file.files?.[0];
          if (!f) return toast('Choose a .prism file', 'error');
          const mode: ImportMode = replace.checked ? 'Replace' : 'Merge';
          if (mode === 'Replace' && !confirmDialog('Replace ALL entries and the device seed with this file? This cannot be undone.')) return;
          await withBusy(btn, 'Importing...', async () => {
            progress.hidden = false;
            try {
              const bytes = new Uint8Array(await f.arrayBuffer());
              await requireClient().importVault(bytes, pass.value, mode, (done, total) => {
                progress.value = Math.round((done / total) * 100);
              });
              toast('Import complete', 'ok');
            } catch (err) {
              toast(describeError(err), 'error', 6000);
            } finally {
              progress.hidden = true;
            }
          });
        },
      },
      field('Backup file', file),
      field('Recovery passphrase', pass, 'The passphrase the export was made with.'),
      h(
        'fieldset',
        { class: 'choices' },
        h('legend', null, 'Mode'),
        h('label', { class: 'check' }, merge, ' Merge: add or update entries, keep this device seed'),
        h('label', { class: 'check' }, replace, ' Replace: overwrite everything with the backup'),
      ),
      progress,
      h('div', { class: 'actions' }, btn),
    ),
  );
}
