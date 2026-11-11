import { connectDevice, type TransportKind } from '../app';
import { NotPairedError } from '../client';
import { browserSupport } from './connect';
import { clear, describeError, h, spinner, toast, withBusy } from '../ui/dom';

/**
 * Pairing = Noise handshake in pairing mode. Both screens show the same 6-digit SAS; the user
 * compares them and taps Confirm on the device (ARCHITECTURE §5.2).
 */
export function renderPair(root: HTMLElement): void {
  const sup = browserSupport();
  const sasBox = h('div', { class: 'sas', 'aria-live': 'polite', 'aria-label': 'Pairing code' });
  const progress = h('div', null);

  const start = (kind: TransportKind) => async (ev: Event) => {
    const b = ev.currentTarget as HTMLButtonElement;
    await withBusy(b, 'Pairing...', async () => {
      sasBox.replaceChildren();
      progress.replaceChildren(spinner('Connecting. Enable pairing on the device first.'));
      try {
        await connectDevice(kind, {
          pairing: true,
          onEvent: (ev) => {
            if (ev.type === 'sas') {
              sasBox.replaceChildren(ev.sas.slice(0, 3), ' ', ev.sas.slice(3));
              progress.replaceChildren(
                h('p', { class: 'strong' }, 'Confirm on the device: the same digits must be shown there.'),
                spinner('Waiting for Confirm on the device...'),
              );
            }
            if (ev.type === 'paired') toast(`Paired with ${ev.label}`, 'ok');
          },
        });
        toast('Paired and connected', 'ok');
        location.hash = '#/entries';
      } catch (err) {
        sasBox.replaceChildren();
        progress.replaceChildren();
        if (err instanceof NotPairedError) {
          progress.append(h('div', { class: 'banner error', role: 'alert' }, err.message));
        } else {
          progress.append(h('div', { class: 'banner error', role: 'alert' }, describeError(err)));
        }
      }
    });
  };

  const btn = (kind: TransportKind, label: string, enabled: boolean) =>
    h('button', { class: 'btn primary', disabled: !enabled, onclick: start(kind) }, label);

  clear(root);
  root.append(
    h(
      'section',
      { class: 'card narrow' },
      h('h1', null, 'Pair this browser'),
      h('ol', { class: 'steps' },
        h('li', null, 'On the device, open Settings and choose Pair new host.'),
        h('li', null, 'Choose the connection below. A 6-digit code appears here and on the device.'),
        h('li', null, 'Check the digits match, then tap Confirm on the device.'),
      ),
      h('div', { class: 'actions' },
        btn('ble', 'Pair over Bluetooth', sup.ble && sup.secure),
        btn('usb', 'Pair over USB', sup.usb && sup.secure),
      ),
      sasBox,
      progress,
      h('p', { class: 'muted' }, h('a', { href: '#/connect' }, 'Back to connect')),
    ),
  );
}
