import type { EvidenceDomain, EvidenceSource, EvidenceState, SecurityEvidenceV1 } from "./evidence";
/** Provider-neutral report summary; no existing CyberScore changes or external calls. */
export type EvidenceReportRow = { controlId: string; domain: EvidenceDomain; source: EvidenceSource; scope: string; state: EvidenceState; observedAt: string | null };
export type EvidenceReport = {
  schemaVersion: 1; organizationId: string;
  total: number; observed: number; declared: number; unknown: number; errors: number;
  byDomain: Partial<Record<EvidenceDomain, number>>;
  bySource: Partial<Record<EvidenceSource, number>>;
  rows: EvidenceReportRow[];
  coverage: "UNASSESSED" | "PARTIAL" | "COMPLETE";
};
export function buildEvidenceReport(
  organizationId: string,
  evidence: readonly SecurityEvidenceV1[],
  expectedControls: readonly { domain: EvidenceDomain; controlId: string; source?: EvidenceSource; scope?: string }[],
): EvidenceReport {
  const items = evidence.filter((item) => item.organizationId === organizationId && item.schemaVersion === 1);
  const byDomain: EvidenceReport["byDomain"] = {};
  const bySource: EvidenceReport["bySource"] = {};
  for (const item of items) {
    byDomain[item.domain] = (byDomain[item.domain] ?? 0) + 1;
    bySource[item.source] = (bySource[item.source] ?? 0) + 1;
  }
  const rows: EvidenceReportRow[] = items.map((item) => ({
    controlId: item.controlId, domain: item.domain, source: item.source, scope: item.scope, state: item.state,
    observedAt: item.state === "OBSERVED" && item.observedAt instanceof Date && Number.isFinite(item.observedAt.getTime()) ? item.observedAt.toISOString() : null,
  })).sort((a,b) => (a.domain + a.controlId + a.source + a.scope).localeCompare(b.domain + b.controlId + b.source + b.scope));
  const expected = [...new Map(expectedControls.map((item) => [JSON.stringify([item.domain,item.controlId,item.source ?? "",item.scope ?? ""]),item])).values()];
  const covered = expected.filter((control) => items.some((item) =>
    item.state === "OBSERVED" && item.observedAt instanceof Date && Number.isFinite(item.observedAt.getTime()) &&
    item.domain === control.domain && item.controlId === control.controlId &&
    (control.source === undefined || control.source === item.source) &&
    (control.scope === undefined || control.scope === item.scope),
  )).length;
  const coverage = covered === 0 ? "UNASSESSED" : covered === expected.length ? "COMPLETE" : "PARTIAL";
  return {
    schemaVersion:1, organizationId, total:items.length,
    observed:items.filter(x=>x.state==="OBSERVED" && x.observedAt instanceof Date && Number.isFinite(x.observedAt.getTime())).length,
    declared:items.filter(x=>x.state==="DECLARED").length,
    unknown:items.filter(x=>x.state==="UNKNOWN" || (x.state==="OBSERVED" && !(x.observedAt instanceof Date && Number.isFinite(x.observedAt.getTime())))).length,
    errors:items.filter(x=>x.state==="ERROR").length,
    byDomain, bySource, rows, coverage,
  };
}
