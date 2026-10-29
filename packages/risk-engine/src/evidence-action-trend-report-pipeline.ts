import type { ActionWorkspaceSnapshot } from "./evidence-action-workspace-snapshot";
import { summarizeActionWorkspaceTrend } from "./evidence-action-workspace-trend";
import { buildActionTrendReport } from "./evidence-action-trend-report";
import { auditActionTrendReport } from "./evidence-action-trend-report-audit";
import { exportActionTrendReport } from "./evidence-action-trend-report-export";
/** Single tenant-bound offline workflow for an executive trend report. */
export function createActionTrendReportPackage(snapshots:readonly ActionWorkspaceSnapshot[],organizationId:string,format:"csv"|"json") {
 const trend=summarizeActionWorkspaceTrend(snapshots,organizationId);
 if(!trend)return null;
 const report=buildActionTrendReport(trend,organizationId);
 if(!report)return null;
 const audit=auditActionTrendReport(report,organizationId);
 if(!audit.ok)return null;
 const output=exportActionTrendReport(report,organizationId,format);
 if(!output.ok)return null;
 return {organizationId,report,audit,output};
}
