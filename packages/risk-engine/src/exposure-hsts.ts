/** Inspect only the supplied HSTS value. No HTTP requests or posture scoring. */
export function extractHstsMaxAge(value: string | null | undefined): number | null {
  if (!value) return null;
  const directives = value.split(";").map((part) => part.trim());
  const entries = directives.filter((part) => /^max-age\s*=/i.test(part));
  if (entries.length !== 1) return null;
  const match = /^max-age\s*=\s*([0-9]+)$/i.exec(entries[0]!);
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isSafeInteger(seconds) ? seconds : null;
}
