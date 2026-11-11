const CLEAR_AFTER_MS = 30_000;
let clearTimer: ReturnType<typeof setTimeout> | null = null;
let lastCopied: string | null = null;

/**
 * Copies a secret and clears it after 30 s, but only if nothing else was copied meanwhile.
 * Browsers cannot read the clipboard silently, so the check is "we were the last writer".
 */
export async function copySecret(text: string, onCleared?: () => void): Promise<void> {
  await navigator.clipboard.writeText(text);
  lastCopied = text;
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    clearTimer = null;
    if (lastCopied !== text) return;
    lastCopied = null;
    navigator.clipboard.writeText('').catch(() => undefined);
    onCleared?.();
  }, CLEAR_AFTER_MS);
}

export const CLIPBOARD_CLEAR_SECONDS = CLEAR_AFTER_MS / 1000;
