/** Passive TLS metadata inspection from caller-supplied, synthetic or observed evidence.
 * Never performs a handshake and never claims a certificate was verified.
 */
export type TlsCertificateMetadata = {
  notBefore?: string | null;
  notAfter?: string | null;
  subject?: string | null;
  issuer?: string | null;
  dnsNames?: readonly string[] | null;
};
export type TlsCertificateInventory = {
  validity: "UNKNOWN" | "VALID_AT_OBSERVATION" | "NOT_YET_VALID" | "EXPIRED" | "INVALID_DATES";
  daysUntilExpiry: number | null;
  hasSubject: boolean;
  hasIssuer: boolean;
  dnsNameCount: number | null;
};
function parseTimestamp(value: string | null | undefined): number | null {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}
export function inventoryTlsCertificate(
  metadata: TlsCertificateMetadata,
  observedAt: string,
): TlsCertificateInventory {
  const now = parseTimestamp(observedAt);
  const start = parseTimestamp(metadata.notBefore);
  const end = parseTimestamp(metadata.notAfter);
  let validity: TlsCertificateInventory["validity"] = "UNKNOWN";
  let daysUntilExpiry: number | null = null;
  if (metadata.notBefore != null || metadata.notAfter != null) {
    if (now === null || start === null || end === null || start > end) validity = "INVALID_DATES";
    else {
      validity = now < start ? "NOT_YET_VALID" : now > end ? "EXPIRED" : "VALID_AT_OBSERVATION";
      daysUntilExpiry = Math.floor((end - now) / 86400000);
    }
  }
  return {
    validity,
    daysUntilExpiry,
    hasSubject: Boolean(metadata.subject?.trim()),
    hasIssuer: Boolean(metadata.issuer?.trim()),
    dnsNameCount: metadata.dnsNames == null ? null : metadata.dnsNames.length,
  };
}
