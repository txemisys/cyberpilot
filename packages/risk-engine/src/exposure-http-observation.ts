/** Pure, offline HTTP observation helpers. No fetches, trust decisions or scoring. */
export type HttpObservation = {
  url?: string | null;
  status?: number | null;
  location?: string | null;
  headers?: ReadonlyArray<readonly [string, string]> | null;
};
export function classifyHttpStatus(status: number | null | undefined): "UNKNOWN" | "INFORMATIONAL" | "SUCCESS" | "REDIRECT" | "CLIENT_ERROR" | "SERVER_ERROR" | "INVALID" {
  if (status == null) return "UNKNOWN";
  if (!Number.isInteger(status) || status < 100 || status > 599) return "INVALID";
  return status < 200 ? "INFORMATIONAL" : status < 300 ? "SUCCESS" : status < 400 ? "REDIRECT" : status < 500 ? "CLIENT_ERROR" : "SERVER_ERROR";
}
export function inspectHttpScheme(raw: string | null | undefined): "HTTPS" | "HTTP" | "OTHER" | "UNKNOWN" {
  if (!raw) return "UNKNOWN";
  try {
    const protocol = new URL(raw).protocol;
    return protocol === "https:" ? "HTTPS" : protocol === "http:" ? "HTTP" : "OTHER";
  } catch { return "UNKNOWN"; }
}
export function inspectRedirect(observation: HttpObservation): { state: "NOT_REDIRECT" | "MISSING_TARGET" | "VALID_TARGET" | "INVALID_TARGET" | "UNKNOWN"; target: string | null; crossOrigin: boolean | null; downgrade: boolean | null } {
  const kind = classifyHttpStatus(observation.status);
  const empty = (state: "NOT_REDIRECT" | "MISSING_TARGET" | "UNKNOWN") => ({ state, target: null, crossOrigin: null, downgrade: null });
  if (kind === "UNKNOWN" || kind === "INVALID") return empty("UNKNOWN");
  if (kind !== "REDIRECT") return empty("NOT_REDIRECT");
  if (!observation.location?.trim()) return empty("MISSING_TARGET");
  try {
    if (!observation.url) return { state: "INVALID_TARGET", target: null, crossOrigin: null, downgrade: null };
    const current = new URL(observation.url);
    const next = new URL(observation.location, current);
    if (!["http:", "https:"].includes(next.protocol)) return { state: "INVALID_TARGET", target: null, crossOrigin: null, downgrade: null };
    return { state: "VALID_TARGET", target: next.href, crossOrigin: current.origin !== next.origin, downgrade: current.protocol === "https:" && next.protocol === "http:" };
  } catch { return { state: "INVALID_TARGET", target: null, crossOrigin: null, downgrade: null }; }
}
export function inventoryResponseHeaders(headers: HttpObservation["headers"]): {
  state: "UNKNOWN" | "COLLECTED"; names: string[]; emptyNames: string[]; duplicateNames: string[];
} {
  if (headers == null) return { state: "UNKNOWN", names: [], emptyNames: [], duplicateNames: [] };
  const counts = new Map<string, number>();
  const empty = new Set<string>();
  for (const [key, value] of headers) {
    const name = key.trim().toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) continue;
    counts.set(name, (counts.get(name) ?? 0) + 1);
    if (!value.trim()) empty.add(name);
  }
  return {
    state: "COLLECTED",
    names: [...counts.keys()].sort(),
    emptyNames: [...empty].sort(),
    duplicateNames: [...counts].filter(([, n]) => n > 1).map(([name]) => name).sort(),
  };
}
export function inspectPermissionsPolicy(value: string | null | undefined): string[] | null {
  if (!value?.trim()) return null;
  const names = value.split(",").map((entry) => /^([a-z][a-z0-9-]*)\s*=/.exec(entry.trim())?.[1] ?? "");
  return names.some((name) => !name) || new Set(names).size !== names.length ? null : names;
}
export function inspectXFrameOptions(value: string | null | undefined): "DENY" | "SAMEORIGIN" | "MISSING" | "INVALID" {
  if (!value?.trim()) return "MISSING";
  const token = value.trim().toUpperCase();
  return token === "DENY" || token === "SAMEORIGIN" ? token : "INVALID";
}
