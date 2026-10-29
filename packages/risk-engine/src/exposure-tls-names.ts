/** Offline validation of observed TLS metadata; never establishes chain trust. */
export function normalizeTlsDnsNames(names: readonly string[] | null | undefined): string[] | null {
  if (names == null) return null;
  const normalized: string[] = [];
  for (const raw of names) {
    const value = raw.trim().toLowerCase().replace(/\.$/, "");
    const wildcard = value.startsWith("*.");
    const host = wildcard ? value.slice(2) : value;
    if (!host || host.length > 253 || !host.split(".").every((label) =>
      label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    )) return null;
    normalized.push(wildcard ? "*." + host : host);
  }
  return [...new Set(normalized)].sort();
}
export function tlsNameMatches(hostname: string, dnsNames: readonly string[] | null | undefined): "MATCH" | "NO_MATCH" | "UNKNOWN" {
  const names = normalizeTlsDnsNames(dnsNames);
  const host = normalizeTlsDnsNames([hostname])?.[0];
  if (!names || !host || host.startsWith("*.")) return "UNKNOWN";
  for (const name of names) {
    if (name === host) return "MATCH";
    if (name.startsWith("*.")) {
      const suffix = name.slice(2);
      if (host.endsWith("." + suffix) && host.split(".").length === suffix.split(".").length + 1) return "MATCH";
    }
  }
  return "NO_MATCH";
}
export type TlsTransportMetadata = { version?: string | null; cipher?: string | null; handshakeVerified?: boolean | null };
export function inspectTlsTransport(meta: TlsTransportMetadata): {
  version: string | null; cipher: string | null; handshakeVerified: "TRUE" | "FALSE" | "UNKNOWN";
  inconsistent: boolean;
} {
  const version = meta.version?.trim() || null;
  const cipher = meta.cipher?.trim() || null;
  const verified = meta.handshakeVerified == null ? "UNKNOWN" : meta.handshakeVerified ? "TRUE" : "FALSE";
  return { version, cipher, handshakeVerified: verified, inconsistent: meta.handshakeVerified === true && (!version || !cipher) };
}
