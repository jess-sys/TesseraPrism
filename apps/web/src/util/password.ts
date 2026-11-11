export interface PasswordOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

export const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?/';

/** Uniform random index in [0, n) using rejection sampling. */
function randomIndex(n: number): number {
  const max = 0x1_0000_0000 - (0x1_0000_0000 % n);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < max) return buf[0]! % n;
  }
}

/** Generates a password with at least one character from each enabled class. */
export function generatePassword(opts: PasswordOptions): string {
  const classes: string[] = [];
  if (opts.lower) classes.push('abcdefghijkmnopqrstuvwxyz');
  if (opts.upper) classes.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (opts.digits) classes.push('23456789');
  if (opts.symbols) classes.push(SYMBOLS);
  if (classes.length === 0) throw new Error('Select at least one character class.');
  if (opts.length < classes.length || opts.length > 256) {
    throw new Error(`Length must be between ${classes.length} and 256.`);
  }
  const all = classes.join('');
  const out: string[] = [];
  // One from each class first, then fill; shuffle so the guaranteed ones are not positional.
  for (const c of classes) out.push(c[randomIndex(c.length)]!);
  while (out.length < opts.length) out.push(all[randomIndex(all.length)]!);
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out.join('');
}

/** Rough strength estimate for display only. */
export function strengthLabel(pw: string): 'weak' | 'fair' | 'strong' {
  const pool =
    (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/\d/.test(pw) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pw) ? 32 : 0);
  const bits = pool > 0 ? pw.length * Math.log2(pool) : 0;
  if (bits < 50) return 'weak';
  if (bits < 80) return 'fair';
  return 'strong';
}
