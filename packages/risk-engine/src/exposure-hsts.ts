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

/** Inspect HSTS flag directives only after finding one valid max-age. */
export function inspectHstsFlags(value: string | null | undefined): { includeSubDomains: boolean; preload: boolean } | null {
  if (extractHstsMaxAge(value) === null || !value) return null;
  const directives = value.split(";").map((part) => part.trim().toLowerCase());
  const check = (name: string) => {
    const tokens = directives.filter((part) => part === name || part.startsWith(name + "="));
    return tokens.length <= 1 && (tokens.length === 0 || tokens[0] === name);
  };
  if (!check("includesubdomains") || !check("preload")) return null;
  return { includeSubDomains: directives.includes("includesubdomains"), preload: directives.includes("preload") };
}
