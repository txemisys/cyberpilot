import type { IntegratedReviewer } from "./integrated-risk-service";
import { collectIntegratedRiskDigest } from "./integrated-risk-service";
import { verifyIntegratedRiskDigest } from "./integrated-risk-engine";
import { readEvidenceDecisionCases } from "./evidence-decision-case-service";
import { readIntegratedActions } from "./integrated-action-service";
import {
  buildCaseActionHandoffBoard,
  selectCaseActionHandoffRows,
  exportCaseActionHandoffBoard,
  verifyCaseActionHandoffBoard,
  type HandoffBoardQuery,
} from "./case-action-handoff-domain";

/**
 * Read model for the two independently persisted workflows.
 * This service never assumes a case action link proves remediation;
 * it re-checks current source risk identities and audit boundaries.
 */
export class HandoffReviewError extends Error {
  constructor(public readonly code:string){
    super(code);
    this.name="HandoffReviewError";
  }
}
function fail(code:string):never {throw new HandoffReviewError(code);}
const identifier=(x:unknown)=>
  typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
export type ReadCaseActionHandoff={
  filters?:HandoffBoardQuery;
  format?:"JSON"|"CSV"|"MARKDOWN";
};
export async function readCaseActionHandoffReview(
  actor:IntegratedReviewer,
  request:ReadCaseActionHandoff={},
){
  if(!identifier(actor.organizationId)||!identifier(actor.userId)||
    !["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("HANDOFF_REVIEW_ACTOR_INVALID");
  if(request.format!==undefined&&
    !["JSON","CSV","MARKDOWN"].includes(request.format))
    fail("HANDOFF_REVIEW_FORMAT_INVALID");
  const [caseResult,actionResult,riskReport]=await Promise.all([
    readEvidenceDecisionCases(actor),
    readIntegratedActions(actor),
    collectIntegratedRiskDigest(actor),
  ]);
  if(caseResult.organizationId!==actor.organizationId||
    actionResult.organizationId!==actor.organizationId||
    riskReport.organizationId!==actor.organizationId)
    fail("HANDOFF_REVIEW_TENANT_MISMATCH");
  if(!verifyIntegratedRiskDigest(riskReport,actor.organizationId).valid)
    fail("HANDOFF_REVIEW_RISK_REPORT_INVALID");
  const board=buildCaseActionHandoffBoard({
    organizationId:actor.organizationId,
    evaluatedAt:new Date().toISOString(),
    cases:caseResult.board.cases,
    actions:actionResult.actions,
    report:riskReport,
    sourceTruncated:caseResult.sourceTruncated||
      actionResult.truncated||
      riskReport.state==="INCOMPLETE",
  });
  if(!verifyCaseActionHandoffBoard(board,actor.organizationId).valid)
    fail("HANDOFF_REVIEW_DIGEST_INVALID");
  let page;
  try{
    page=selectCaseActionHandoffRows(board,request.filters??{});
  }catch{fail("HANDOFF_REVIEW_QUERY_INVALID");}
  const artifact=request.format?
    exportCaseActionHandoffBoard(board,request.format):null;
  return{
    schema:"cyberpilot.case.action.review.v1" as const,
    organizationId:actor.organizationId,
    board,page,artifact,
    sourceSnapshots:{
      evidenceCases:caseResult.board.cases.length,
      riskActions:actionResult.actions.length,
      availableRisks:riskReport.risks.length,
      sourceTruncated:board.sourceTruncated,
      riskReportDigest:riskReport.digest,
    },
    providerCalls:0 as const,
    independentRemediationConfirmed:false as const,
    LIVEPermissionGranted:false as const,
    customerConsentCreated:false as const,
    cyberScoreV1Writes:0 as const,
  };
}
