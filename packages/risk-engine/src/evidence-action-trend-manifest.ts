import type { ActionWorkspaceSnapshot } from "./evidence-action-workspace-snapshot";
import { createActionTrendReportPackage } from "./evidence-action-trend-report-pipeline";
/** Offline report manifest for traceable, same-tenant report inputs. No persistence. */
export type ActionTrendManifest = {
  organizationId:string; schemaVersion:1; format:"csv"|"json";
  snapshotDates:string[]; snapshotCount:number; reportFrom:string; reportTo:string;
  filename:string; contentLength:number; reportSignals:string[];
};
export function createActionTrendManifest(snapshots:readonly ActionWorkspaceSnapshot[],organizationId:string,format:"csv"|"json"):ActionTrendManifest|null {
  const pkg=createActionTrendReportPackage(snapshots,organizationId,format);
  if(!pkg||pkg.output.content.length===0)return null;
  const dates=snapshots.map(s=>s.asOf);
  if(dates.length!==pkg.report.period.points||dates[0]!==pkg.report.period.from||dates[dates.length-1]!==pkg.report.period.to)return null;
  return {organizationId,schemaVersion:1,format,snapshotDates:dates,snapshotCount:dates.length,
    reportFrom:pkg.report.period.from,reportTo:pkg.report.period.to,
    filename:pkg.output.filename,contentLength:pkg.output.content.length,reportSignals:[...pkg.report.signals]};
}
