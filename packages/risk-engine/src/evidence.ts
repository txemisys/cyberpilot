/**
 * Provider-neutral evidence contract (v1).
 * This does not replace persisted Microsoft 365 findings or the existing
 * CyberScore model. Adapters and database migrations follow separately.
 */
export type EvidenceSource = "MICROSOFT_365" | "DOMAIN" | "BASELINE" | "ASSETS" | "GOOGLE_WORKSPACE" | "LAB";
export type EvidenceDomain = "IDENTITY" | "EMAIL" | "WEB" | "ENDPOINT" | "BACKUP" | "GOVERNANCE";
export type EvidenceState = "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type EvidenceCoverage = "COMPLETE" | "PARTIAL" | "UNASSESSED";

export type SecurityEvidenceV1 = {
  schemaVersion: 1;
  organizationId: string;
  source: EvidenceSource;
  domain: EvidenceDomain;
  controlId: string;
  state: EvidenceState;
  observedAt: Date | null;
  /** Explicitly scoped evidence; a declaration is not an observation. */
  scope: string;
  details: Record<string, string | number | boolean | null>;
};

export function summarizeEvidenceCoverage(
  evidence: readonly SecurityEvidenceV1[],
  expectedDomains: readonly EvidenceDomain[],
): { coverage: EvidenceCoverage; assessedDomains: EvidenceDomain[]; unassessedDomains: EvidenceDomain[] } {
  const domains = [...new Set(expectedDomains)];
  const assessedDomains = domains.filter((domain) =>
    evidence.some((item) => item.domain === domain && item.state === "OBSERVED" && item.observedAt !== null),
  );
  const unassessedDomains = domains.filter((domain) => !assessedDomains.includes(domain));
  return {
    coverage: domains.length === 0 || assessedDomains.length === 0
      ? "UNASSESSED"
      : unassessedDomains.length === 0 ? "COMPLETE" : "PARTIAL",
    assessedDomains,
    unassessedDomains,
  };
}
