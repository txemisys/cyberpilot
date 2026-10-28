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

function isValidObservation(item: SecurityEvidenceV1): boolean {
  return item.state === "OBSERVED" && item.observedAt instanceof Date && Number.isFinite(item.observedAt.getTime());
}

export function summarizeEvidenceCoverage(
  evidence: readonly SecurityEvidenceV1[],
  expectedDomains: readonly EvidenceDomain[],
): { coverage: EvidenceCoverage; assessedDomains: EvidenceDomain[]; unassessedDomains: EvidenceDomain[] } {
  const domains = [...new Set(expectedDomains)];
  const assessedDomains = domains.filter((domain) =>
    evidence.some((item) => item.domain === domain && isValidObservation(item)),
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

/**
 * Precise control coverage: one observed control must never imply that every
 * required control in its domain was evaluated.
 */
export function summarizeEvidenceControlCoverage(
  evidence: readonly SecurityEvidenceV1[],
  expectedControls: readonly { domain: EvidenceDomain; controlId: string; scope?: string; source?: EvidenceSource }[],
) {
  const unique = [...new Map(expectedControls.map((control) =>
    [JSON.stringify([control.domain, control.controlId, control.scope ?? null, control.source ?? null]), control],
  )).values()];
  const assessed = unique.filter((control) => evidence.some((item) =>
    item.domain === control.domain &&
    item.controlId === control.controlId &&
    (control.source === undefined || item.source === control.source) &&
    (control.scope === undefined || item.scope === control.scope) &&
    isValidObservation(item),
  ));
  return {
    coverage: (unique.length === 0 || assessed.length === 0
      ? "UNASSESSED"
      : assessed.length === unique.length ? "COMPLETE" : "PARTIAL") as EvidenceCoverage,
    assessedCount: assessed.length,
    expectedCount: unique.length,
    missingControls: unique.filter((control) => !assessed.includes(control)),
  };
}
