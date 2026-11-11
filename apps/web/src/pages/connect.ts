import { connectDevice, type TransportKind } from '../app';
import { NotPairedError } from '../client';
import { BleTransport } from '../transport/ble';
import { SerialTransport } from '../transport/serial';
import { clear, describeError, h, toast, withBusy } from '../ui/dom';

/** Feature detection with an actionable message (Web Bluetooth / Web Serial are Chromium-only). */
export function browserSupport(): { ble: boolean; usb: boolean; secure: boolean } {
  return {
    ble: BleTransport.isSupported(),
    usb: SerialTransport.isSupported(),
    secure: window.isSecureContext,
  };
}

export function renderConnect(root: HTMLElement): void {
  const sup = browserSupport();
  const anySupported = (sup.ble || sup.usb) && sup.secure;

  const connectButton = (kind: TransportKind, label: string, hint: string, enabled: boolean): HTMLElement => {
    const btn = h(
      'button',
      {
        class: 'btn primary big',
        disabled: !enabled,
        onclick: async (ev: Event) => {
          const b = ev.currentTarget as HTMLButtonElement;
          await withBusy(b, 'Connecting...', async () => {
            try {
              await connectDevice(kind);
              toast('Connected', 'ok');
              location.hash = '#/entries';
            } catch (err) {
              if (err instanceof NotPairedError) {
                toast(err.message, 'error', 8000);
                location.hash = '#/pair';
                return;
              }
              throw err;
            }
          });
        },
      },
      label,
    );
    return h('div', { class: 'choice' }, btn, h('p', { class: 'hint' }, hint));
  };

  const unsupported = !sup.secure
    ? 'This page must be served over https:// or http://localhost to use device connections.'
    : 'Web Bluetooth and Web Serial are only available in Chrome or Edge (desktop, or Android for Bluetooth).';

  clear(root);
  root.append(
    h(
      'section',
      { class: 'card narrow' },
      h('h1', null, 'Connect to your Prism'),
      h(
        'p',
        null,
        'Pick how this browser reaches the device. Bluetooth works wirelessly; USB needs the cable and is the fallback.',
      ),
      anySupported
        ? null
        : h('div', { class: 'banner error', role: 'alert' }, `${unsupported} Use Chrome or Edge.`),
      h(
        'div',
        { class: 'grid-2' },
        connectButton('ble', 'Bluetooth', 'Recommended. Chrome/Edge only.', sup.ble && sup.secure),
        connectButton('usb', 'USB cable', 'Plug the device in with USB-C. Chrome/Edge only.', sup.usb && sup.secure),
      ),
      h(
        'p',
        { class: 'muted' },
        'New browser or never paired? ',
        h('a', { href: '#/pair' }, 'Pair this browser'),
        '.',
      ),
      h(
        'details',
        { class: 'muted small' },
        h('summary', null, 'No device handy?'),
        h(
          'p',
          null,
          'Try the demo, which uses an in-memory fake device. ',
          h(
            'button',
            {
              class: 'link',
              onclick: () => void connectDevice('mock').then(() => (location.hash = '#/entries')).catch((e) => toast(describeError(e), 'error')),
            },
            'Start demo device',
          ),
        ),
      ),
    ),
  );
}
