import type { ActionTrendManifest } from "./evidence-action-trend-manifest";
import type { ActionTrendReportExport } from "./evidence-action-trend-report-export";
/** Validate offline report manifest against its exported payload. */
export type ActionTrendManifestAudit={ok:boolean;issues:("TENANT_MISMATCH"|"INVALID_MANIFEST"|"EXPORT_MISMATCH"|"INVALID_DATES")[]};
const date=(s:string)=>/^\d{4}-\d{2}-\d{2}$/.test(s)&&Number.isFinite(Date.parse(s+"T00:00:00Z"))&&new Date(s+"T00:00:00Z").toISOString().slice(0,10)===s;
export function auditActionTrendManifest(manifest:ActionTrendManifest,output:ActionTrendReportExport,organizationId:string):ActionTrendManifestAudit {
 const issues:ActionTrendManifestAudit["issues"]=[];
 if(!organizationId||manifest.organizationId!==organizationId)issues.push("TENANT_MISMATCH");
 if(manifest.schemaVersion!==1||!Number.isSafeInteger(manifest.snapshotCount)||manifest.snapshotCount<1||manifest.snapshotCount>366||
 !Number.isSafeInteger(manifest.contentLength)||manifest.contentLength<1||!Array.isArray(manifest.snapshotDates)||
 manifest.snapshotDates.length!==manifest.snapshotCount||!Array.isArray(manifest.reportSignals)||manifest.reportSignals.length===0)
 issues.push("INVALID_MANIFEST");
 if(!Array.isArray(manifest.snapshotDates)||manifest.snapshotDates.some(d=>!date(d))||
 !date(manifest.reportFrom)||!date(manifest.reportTo)||
 manifest.snapshotDates[0]!==manifest.reportFrom||
 manifest.snapshotDates[manifest.snapshotDates.length-1]!==manifest.reportTo||
 manifest.snapshotDates.some((d,i)=>i>0&&manifest.snapshotDates[i-1]!>=d))issues.push("INVALID_DATES");
 if(!output.ok||output.format!==manifest.format||output.filename!==manifest.filename||output.content.length!==manifest.contentLength)
 issues.push("EXPORT_MISMATCH");
 return {ok:issues.length===0,issues};
}
