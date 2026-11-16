import {randomUUID} from "node:crypto";
import {collectIntegratedRiskDigest,
  type IntegratedReviewer} from "./integrated-risk-service";
import {readIntegratedActions} from "./integrated-action-service";
import {buildExecutiveCockpit,verifyExecutiveCockpit,
  type ExecutiveCockpitReport} from "./integrated-executive-cockpit";

/**
 * One tenant-scoped, read-only composition across the existing persisted
 * evidence and the new follow-up registry. This is an on-demand
 * ephemeral report: the digest is integrity metadata, not a signature.
 */
export async function collectExecutiveCockpit(
  actor:IntegratedReviewer,
  asOf=new Date().toISOString(),
):Promise<ExecutiveCockpitReport>{
  const [risk,actions]=await Promise.all([
    collectIntegratedRiskDigest(actor,asOf),
    readIntegratedActions(actor,asOf),
  ]);
  if(risk.organizationId!==actor.organizationId||
    actions.organizationId!==actor.organizationId)
    throw Error("EXECUTIVE_TENANT_BOUNDARY");
  const report=buildExecutiveCockpit({
    organizationId:actor.organizationId,
    generatedAt:asOf,
    reportId:randomUUID(),
    riskDigest:risk,
    actions:actions.actions,
    auditIssues:actions.issues,
    actionsTruncated:actions.truncated,
    includeResolved:false,
  });
  if(!verifyExecutiveCockpit(report,actor.organizationId).valid)
    throw Error("EXECUTIVE_REPORT_INTEGRITY_FAILURE");
  return report;
}
