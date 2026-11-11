import { requireClient, refreshInfo, rerender } from '../app';
import { describeError, field, h, input, spinner, toast, withBusy } from '../ui/dom';

export function pageHead(title: string, ...actions: (Node | null)[]): HTMLElement {
  return h('header', { class: 'page-head' }, h('h1', null, title), h('div', { class: 'actions' }, ...actions));
}

/** Shows a spinner while a device-approved operation runs; returns undefined on failure. */
export async function approve<T>(
  container: HTMLElement,
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  const s = spinner(label);
  container.append(s);
  try {
    return await fn();
  } catch (err) {
    toast(describeError(err), 'error', 6000);
    return undefined;
  } finally {
    s.remove();
  }
}

/** Passphrase unlock (companion path). Used when the device is locked. */
export function unlockPanel(): HTMLElement {
  const pass = input({ type: 'password', autocomplete: 'current-password', required: true });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Unlock');
  const form = h(
    'form',
    {
      class: 'card',
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        await withBusy(btn, 'Unlocking...', async () => {
          await requireClient().unlock(pass.value);
          await refreshInfo();
          toast('Unlocked', 'ok');
          rerender();
        });
      },
    },
    h('h2', null, 'Device is locked'),
    h('p', null, 'Unlock it on its touchscreen with your PIN, or enter the recovery passphrase here.'),
    field('Recovery passphrase', pass),
    h('div', { class: 'actions' }, btn),
  );
  return form;
}

export function confirmDialog(message: string): boolean {
  return window.confirm(message);
}
