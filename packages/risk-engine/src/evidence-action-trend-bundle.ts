import type { ActionWorkspaceSnapshot } from "./evidence-action-workspace-snapshot";
import { createActionTrendManifest } from "./evidence-action-trend-manifest";
import { createActionTrendReportPackage } from "./evidence-action-trend-report-pipeline";
import { auditActionTrendManifest } from "./evidence-action-trend-manifest-audit";
/** Validated, read-only report bundle. The content is never delivered or persisted automatically. */
export function createValidatedActionTrendBundle(snapshots:readonly ActionWorkspaceSnapshot[],organizationId:string,format:"csv"|"json") {
 const pkg=createActionTrendReportPackage(snapshots,organizationId,format);
 if(!pkg)return null;
 const manifest=createActionTrendManifest(snapshots,organizationId,format);
 if(!manifest)return null;
 const audit=auditActionTrendManifest(manifest,pkg.output,organizationId);
 if(!audit.ok)return null;
 return {organizationId,manifest,report:pkg.report,output:pkg.output,audit};
}
