import type { EvidenceReport } from "./evidence-report";
/** Reconcile totals in a report without interpreting evidence as a security score. */
export type ReportIntegrityIssue = "NEGATIVE_COUNT" | "NON_INTEGER_COUNT" | "STATE_TOTAL_MISMATCH" | "ROW_TOTAL_MISMATCH" | "DOMAIN_TOTAL_MISMATCH" | "SOURCE_TOTAL_MISMATCH" | "ROW_STATE_MISMATCH" | "ROW_DOMAIN_MISMATCH" | "ROW_SOURCE_MISMATCH" | "INVALID_OBSERVATION_TIMESTAMP";
export function auditEvidenceReport(report: EvidenceReport): ReportIntegrityIssue[] {
  const issues = new Set<ReportIntegrityIssue>();
  const counts = [report.total,report.observed,report.declared,report.unknown,report.errors,
    ...Object.values(report.byDomain),...Object.values(report.bySource)];
  if (counts.some(x=>x!==undefined && (!Number.isInteger(x)))) issues.add("NON_INTEGER_COUNT");
  if (counts.some(x=>x!==undefined && x<0)) issues.add("NEGATIVE_COUNT");
  if (report.total !== report.observed+report.declared+report.unknown+report.errors) issues.add("STATE_TOTAL_MISMATCH");
  if (report.rows.length !== report.total) issues.add("ROW_TOTAL_MISMATCH");
  const domainCount = Object.values(report.byDomain).reduce((a,b)=>a+(b??0),0);
  const sourceCount = Object.values(report.bySource).reduce((a,b)=>a+(b??0),0);
  if (domainCount !== report.total) issues.add("DOMAIN_TOTAL_MISMATCH");
  if (sourceCount !== report.total) issues.add("SOURCE_TOTAL_MISMATCH");
  const actual = {
    observed:report.rows.filter(row=>row.state==="OBSERVED" && row.observedAt!==null).length,
    declared:report.rows.filter(row=>row.state==="DECLARED").length,
    unknown:report.rows.filter(row=>row.state==="UNKNOWN" || (row.state==="OBSERVED" && row.observedAt===null)).length,
    errors:report.rows.filter(row=>row.state==="ERROR").length,
  };
  if (actual.observed!==report.observed||actual.declared!==report.declared||actual.unknown!==report.unknown||actual.errors!==report.errors) issues.add("ROW_STATE_MISMATCH");
  for(const [domain,count] of Object.entries(report.byDomain)) if(report.rows.filter(row=>row.domain===domain).length!==count) issues.add("ROW_DOMAIN_MISMATCH");
  for(const [source,count] of Object.entries(report.bySource)) if(report.rows.filter(row=>row.source===source).length!==count) issues.add("ROW_SOURCE_MISMATCH");
  if(report.rows.some(row=>row.observedAt!==null && (row.state!=="OBSERVED" || !Number.isFinite(Date.parse(row.observedAt))))) issues.add("INVALID_OBSERVATION_TIMESTAMP");
  return [...issues].sort();
}
