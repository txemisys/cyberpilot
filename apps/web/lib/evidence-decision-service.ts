import type {IntegratedReviewer} from "./integrated-risk-service";
import {collectIntegratedRiskDigest} from "./integrated-risk-service";
import {buildEvidenceDecisionReport,verifyEvidenceDecisionReport,
  exportEvidenceDecisions} from "./evidence-decision-engine";
export async function collectEvidenceDecisionReport(actor:IntegratedReviewer){
  const source=await collectIntegratedRiskDigest(actor);
  const report=buildEvidenceDecisionReport(source);
  if(!verifyEvidenceDecisionReport(report,actor.organizationId).valid)
    throw Error("EVIDENCE_TRIAGE_INTEGRITY_FAILED");
  return report;
}
export {exportEvidenceDecisions};
