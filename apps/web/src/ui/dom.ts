/** Tiny DOM helpers. Text is always inserted as text (no innerHTML with data). */

export type Child = Node | string | number | null | undefined | false | readonly Child[];

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, unknown> | null = null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = String(v);
      else if (k.startsWith('on') && typeof v === 'function') {
        el.addEventListener(k.slice(2), v as EventListener);
      } else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') {
        (el as unknown as Record<string, unknown>)[k] = v;
      } else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  append(el, children);
  return el;
}

function append(parent: Node, children: readonly Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(parent, c as readonly Child[]);
    else if (typeof c === 'string' || typeof c === 'number') parent.appendChild(document.createTextNode(String(c)));
    else parent.appendChild(c as Node);
  }
}

export function clear(el: Element): void {
  el.replaceChildren();
}

/** Short-lived status message in the toast region. */
export function toast(message: string, kind: 'info' | 'error' | 'ok' = 'info', ms = 4000): void {
  const region = document.getElementById('toasts');
  if (!region) return;
  const el = h('div', { class: `toast toast-${kind}` }, message);
  region.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

/** Maps a thrown error to a message a user can act on. */
export function describeError(err: unknown): string {
  const code = typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : '';
  const msg = err instanceof Error ? err.message : String(err);
  switch (code) {
    case 'Locked':
      return 'The device is locked. Unlock it on its touchscreen, or unlock with the recovery passphrase (Settings).';
    case 'Denied':
      return 'Denied on the device.';
    case 'Timeout':
      return 'No response from the device. Check it is awake and try again.';
    case 'NotFound':
      return 'That entry no longer exists on the device.';
    case 'NotPaired':
      return 'This browser is not paired with the device.';
    case 'BadPassphrase':
      return 'Wrong passphrase.';
    case 'StorageFull':
      return 'The device storage is full.';
    case 'Busy':
      return 'The device is busy. Try again in a moment.';
    case 'Unsupported':
      return 'The device does not support this operation.';
    case 'Disconnected':
      return 'The connection to the device was lost.';
    default:
      return msg || 'Something went wrong.';
  }
}

/** Runs `fn` with the button disabled and `busyLabel` shown; re-enables afterwards. */
export async function withBusy<T>(btn: HTMLButtonElement, busyLabel: string, fn: () => Promise<T>): Promise<T | undefined> {
  const original = btn.textContent;
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.textContent = busyLabel;
  try {
    return await fn();
  } catch (err) {
    toast(describeError(err), 'error', 6000);
    return undefined;
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.textContent = original;
  }
}

export function spinner(label: string): HTMLElement {
  return h('div', { class: 'approval', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), h('span', null, label));
}

export function field(label: string, control: HTMLElement, hint?: string): HTMLElement {
  const id = control.id || `f-${Math.random().toString(36).slice(2, 8)}`;
  control.id = id;
  return h(
    'div',
    { class: 'field' },
    h('label', { for: id }, label),
    control,
    hint ? h('p', { class: 'hint' }, hint) : null,
  );
}

export function input(attrs: Record<string, unknown> = {}): HTMLInputElement {
  return h('input', { type: 'text', autocomplete: 'off', ...attrs });
}

export function textarea(attrs: Record<string, unknown> = {}): HTMLTextAreaElement {
  return h('textarea', { rows: 4, ...attrs });
}

export function select<T extends string>(options: readonly [T, string][], value: T): HTMLSelectElement {
  const s = h('select', null, ...options.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
  s.value = value;
  return s;
}

export function formatTime(unix: number): string {
  if (!unix) return '-';
  return new Date(unix * 1000).toLocaleString();
}

export function hex(bytes: ArrayLike<number>, max = Infinity): string {
  const s = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

export function randomId(): number[] {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b);
}

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}
