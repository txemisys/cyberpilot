import type { EvidenceReport } from "./evidence-report";
import { auditEvidenceReport } from "./evidence-report-audit";
/** Deterministic, tenant-bound offline export of evidence summaries. No private details or scores. */
export type ExportResult = { ok: true; filename: string; mimeType: string; content: string } | { ok: false; error: "TENANT_MISMATCH" | "INVALID_REPORT" | "INVALID_FILENAME" };
export function exportEvidenceCsv(report: EvidenceReport, organizationId: string, filename = "evidence-report.csv"): ExportResult {
  if (!organizationId || report.organizationId !== organizationId) return {ok:false,error:"TENANT_MISMATCH"};
  if (!/^[a-zA-Z0-9._-]{1,128}\.csv$/.test(filename)) return {ok:false,error:"INVALID_FILENAME"};
  if (auditEvidenceReport(report).length) return {ok:false,error:"INVALID_REPORT"};
  const headers = ["domain","controlId","source","scope","state","observedAt"];
  const protect = (raw: string): string => {
    const value = /^[\s]*[=+@\-]/.test(raw) ? "'"+raw : raw;
    return '"' + value.replace(/"/g,'""') + '"';
  };
  const rows = report.rows.map(row=>[
    row.domain,row.controlId,row.source,row.scope,row.state,row.observedAt ?? "",
  ].map(protect).join(","));
  return {ok:true,filename,mimeType:"text/csv; charset=utf-8",content:[headers.join(","),...rows].join("\r\n")+"\r\n"};
}
export function exportEvidenceJson(report: EvidenceReport, organizationId: string): ExportResult {
  if (!organizationId || report.organizationId !== organizationId) return {ok:false,error:"TENANT_MISMATCH"};
  if (auditEvidenceReport(report).length) return {ok:false,error:"INVALID_REPORT"};
  const safe = {
    schemaVersion: report.schemaVersion, organizationId: report.organizationId,
    total:report.total,observed:report.observed,declared:report.declared,unknown:report.unknown,errors:report.errors,
    coverage:report.coverage,byDomain:report.byDomain,bySource:report.bySource,rows:report.rows.map(row=>({
      domain:row.domain,controlId:row.controlId,source:row.source,scope:row.scope,state:row.state,observedAt:row.observedAt,
    })),
  };
  return {ok:true,filename:"evidence-report.json",mimeType:"application/json",content:JSON.stringify(safe)};
}
