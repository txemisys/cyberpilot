/** Analyze caller-supplied response headers without contacting any host. */
export type HttpSecurityHeaderInventory = {
  strictTransportSecurity: "PRESENT" | "MISSING";
  contentSecurityPolicy: "PRESENT" | "MISSING";
  xContentTypeOptions: "PRESENT" | "MISSING";
  referrerPolicy: "PRESENT" | "MISSING";
};

export function inventoryHttpSecurityHeaders(
  headers: Readonly<Record<string, string | undefined>>,
): HttpSecurityHeaderInventory {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  const status = (name: string): "PRESENT" | "MISSING" =>
    normalized.get(name)?.trim() ? "PRESENT" : "MISSING";
  return {
    strictTransportSecurity: status("strict-transport-security"),
    contentSecurityPolicy: status("content-security-policy"),
    xContentTypeOptions: status("x-content-type-options"),
    referrerPolicy: status("referrer-policy"),
  };
}

export function inspectXContentTypeOptions(value: string | null | undefined): "NOSNIFF" | "MISSING" | "INVALID" {
  if (value == null || value.trim() === "") return "MISSING";
  return value.trim().toLowerCase() === "nosniff" ? "NOSNIFF" : "INVALID";
}

/** Read the final valid policy token from a supplied Referrer-Policy value. */
export function inspectReferrerPolicy(value: string | null | undefined): string | null {
  if (!value?.trim()) return null;
  const policies = new Set([
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
  ]);
  const tokens = value.split(",").map((token) => token.trim().toLowerCase());
  for (let i = tokens.length - 1; i >= 0; i--) {
    if (policies.has(tokens[i]!)) return tokens[i]!;
  }
  return null;
}

/** Inventory names of explicitly supplied CSP directives, without evaluating browser enforcement. */
export function inventoryCspDirectives(value: string | null | undefined): string[] | null {
  if (!value?.trim()) return null;
  const directives = value.split(";").map((part) => part.trim()).filter(Boolean);
  if (directives.length === 0) return null;
  const names = directives.map((directive) => directive.split(/\s+/)[0]!.toLowerCase());
  if (names.some((name) => !/^[a-z][a-z0-9-]*$/.test(name)) || new Set(names).size !== names.length) return null;
  return names;
}

/** Read literal script-src source expressions; no browser policy evaluation is implied. */
export function extractCspScriptSources(value: string | null | undefined): string[] | null {
  if (!value?.trim() || inventoryCspDirectives(value) === null) return null;
  const directive = value.split(";").map((part) => part.trim())
    .find((part) => /^script-src(?:\s|$)/i.test(part));
  if (!directive) return null;
  return directive.split(/\s+/).slice(1);
}

/** Inventory explicit default-src expressions; do not infer effective fallback policies. */
export function extractCspDefaultSources(value: string | null | undefined): string[] | null {
  if (!value?.trim() || inventoryCspDirectives(value) === null) return null;
  const directive = value.split(";").map((part) => part.trim())
    .find((part) => /^default-src(?:\s|$)/i.test(part));
  if (!directive) return null;
  return directive.split(/\s+/).slice(1);
}
