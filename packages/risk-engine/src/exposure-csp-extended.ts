/** Passive CSP inspection of explicitly supplied headers. No browser enforcement is asserted. */
export type CspDirectiveObservation = { name: string; tokens: string[] };
export function parseCspDirectives(value: string | null | undefined): CspDirectiveObservation[] | null {
  if (!value?.trim()) return null;
  const parts = value.split(";").map((part) => part.trim()).filter(Boolean);
  const result: CspDirectiveObservation[] = [];
  const seen = new Set<string>();
  for (const part of parts) {
    const [name, ...tokens] = part.split(/\s+/);
    if (!name || !/^[a-z][a-z0-9-]*$/i.test(name) || seen.has(name.toLowerCase())) return null;
    seen.add(name.toLowerCase());
    result.push({ name: name.toLowerCase(), tokens });
  }
  return result.length ? result : null;
}
export function extractCspSources(value: string | null | undefined, name: "form-action" | "connect-src" | "img-src" | "style-src"): string[] | null {
  return parseCspDirectives(value)?.find((part) => part.name === name)?.tokens ?? null;
}
export function inspectCspFlag(value: string | null | undefined, name: "upgrade-insecure-requests" | "block-all-mixed-content"): "PRESENT" | "MISSING" | "UNKNOWN" | "INVALID" {
  if (!value?.trim()) return "UNKNOWN";
  const items = parseCspDirectives(value);
  if (!items) return "INVALID";
  const directive = items.find((item) => item.name === name);
  return !directive ? "MISSING" : directive.tokens.length === 0 ? "PRESENT" : "INVALID";
}
export function inventoryCspUnsafeSources(value: string | null | undefined): { unsafeInline: string[]; unsafeEval: string[] } | null {
  const items = parseCspDirectives(value);
  if (!items) return null;
  const unsafeInline = items.filter((item) => item.tokens.includes("'unsafe-inline'")).map((item) => item.name);
  const unsafeEval = items.filter((item) => item.tokens.includes("'unsafe-eval'")).map((item) => item.name);
  return { unsafeInline, unsafeEval };
}
export type CspEvidence = { policy: string | null; source: "DECLARED" | "OBSERVED"; observedAt?: string | null };
export function inspectCspEvidence(evidence: CspEvidence): { source: CspEvidence["source"]; state: "UNKNOWN" | "DECLARED" | "OBSERVED" | "INVALID"; directives: string[] } {
  const parsed = parseCspDirectives(evidence.policy);
  if (!parsed) return { source: evidence.source, state: "UNKNOWN", directives: [] };
  if (evidence.source === "OBSERVED" && (!evidence.observedAt || !Number.isFinite(Date.parse(evidence.observedAt))))
    return { source: evidence.source, state: "INVALID", directives: [] };
  return { source: evidence.source, state: evidence.source, directives: parsed.map((item) => item.name) };
}
