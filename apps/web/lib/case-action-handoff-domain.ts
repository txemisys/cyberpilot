import { createHash } from "node:crypto";
import type { DecisionCaseSnapshot } from "./evidence-decision-case-domain";
import type { ActionSnapshot, ActionPriority } from "./integrated-action-domain";
import type { IntegratedRiskDigest } from "./integrated-risk-engine";

/**
 * Read-only action handoff planning from persisted, tenant-bound sources.
 * This does not accept a caller-supplied risk title, arbitrary finding,
 * source override, security waiver or externally claimed remediation.
 */
export type CaseActionCandidate={
  riskKey:string;
  title:string;
  severity:string;
  sourceFindingIds:string[];
  sourceEvidenceIds:string[];
  sharedFindingIds:string[];
  sharedEvidenceIds:string[];
  existingActionId:string|null;
  existingActionStatus:string|null;
  existingActionRevision:number|null;
  suggestedPriority:ActionPriority;
  sourceComplete:boolean;
  supportsAtomicHandoff:boolean;
  unsupportedReason:string|null;
};
export type CaseActionHandoffRow={
  caseId:string;
  decisionKey:string;
  organizationId:string;
  caseRevision:number;
  caseStatus:DecisionCaseSnapshot["status"];
  casePriority:DecisionCaseSnapshot["priority"];
  caseOwnerUserId:string|null;
  caseDueAt:string|null;
  decisionSourceDigest:string;
  originalFindingCount:number;
  originalEvidenceCount:number;
  relatedActionId:string|null;
  candidates:CaseActionCandidate[];
  candidateCount:number;
  actionableCandidates:number;
  linkedActionExists:boolean;
  linkedActionRiskKey:string|null;
  linkedActionSourceMatched:boolean;
  orphanedRelatedAction:boolean;
  ambiguousSources:boolean;
  noOriginalFinding:boolean;
  riskSourceIncomplete:boolean;
  sourceUnavailable:boolean;
  safeForHandoff:boolean;
  legalRemediationCertified:false;
};
export type CaseActionHandoffBoard={
  schema:"cyberpilot.case.action.handoff.board.v1";
  organizationId:string;
  evaluatedAt:string;
  riskReportDigest:string;
  riskSourceComplete:boolean;
  sourceTruncated:boolean;
  rows:CaseActionHandoffRow[];
  totals:{
    cases:number;unlinked:number;linked:number;
    orphanedLinks:number;sourceMismatches:number;
    withCandidates:number;readyForHandoff:number;
    blockedCases:number;ambiguousSources:number;
    withoutOriginalFindings:number;
    existingActionsReusable:number;
    actionsNeedingCreation:number;
    unsupportedSourceRows:number;
  };
  status:"READY"|"PARTIAL"|"BLOCKED";
  issues:string[];
  independentRemediationVerified:false;
  LIVEProviderCalls:0;
  customerConsentEstablished:false;
  scoreV1Writes:0;
  digest:string;
};
export type HandoffBoardQuery={
  kind?:"ALL"|"READY"|"BLOCKED"|"LINKED"|"UNLINKED";
  search?:string;
  ownerUserId?:string|null;
  minPriority?:"P0"|"P1"|"P2"|"P3";
  offset?:number;
  limit?:number;
  includeCandidates?:boolean;
};
export type HandoffBoardPage={
  schema:"cyberpilot.case.action.handoff.page.v1";
  organizationId:string;
  boardDigest:string;
  total:number;offset:number;limit:number;
  nextOffset:number|null;
  rows:CaseActionHandoffRow[];
  sourceTruncated:boolean;
  noProvidersContacted:true;
};
const id=(x:unknown):x is string=>
  typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso=(x:unknown):x is string=>
  typeof x==="string"&&Number.isFinite(Date.parse(x))&&
  new Date(x).toISOString()===x;
const hash=(x:string)=>createHash("sha256").update(x).digest("hex");
const unique=<T>(items:readonly T[])=>[...new Set(items)];
const urgency:Record<DecisionCaseSnapshot["priority"],number>={
  P0:0,P1:1,P2:2,P3:3,
};
const severityPriority=(severity:string):ActionPriority=>{
  switch(severity.toUpperCase()){
  case"CRITICAL":return"URGENT";
  case"HIGH":return"HIGH";
  case"MEDIUM":return"NORMAL";
  default:return"LOW";
  }
};
function shared(a:readonly string[],b:readonly string[]):string[]{
  const accepted=new Set(b);
  return unique(a.filter(x=>accepted.has(x))).sort();
}
function safeText(x:unknown):string{
  return typeof x==="string"?x:"";
}
function rowFor(
  item:DecisionCaseSnapshot,
  risks:IntegratedRiskDigest["risks"],
  actions:ActionSnapshot[],
  sourceComplete:boolean,
):CaseActionHandoffRow{
  const existing=item.relatedActionId===null?null:
    actions.find(x=>x.actionId===item.relatedActionId)??null;
  const originalFindingIds=Array.isArray(item.findingIds)?
    item.findingIds.filter(id):[];
  const originalEvidenceIds=Array.isArray(item.evidenceIds)?
    item.evidenceIds.filter(id):[];
  const byRiskKey=new Map(actions.map(x=>[x.riskKey,x]));
  const candidates:CaseActionCandidate[]=risks.flatMap(risk=>{
    const sourceFindings=Array.isArray(risk.sourceFindingIds)?
      risk.sourceFindingIds.filter(id):[];
    const sourceEvidence=Array.isArray(risk.sourceEvidenceIds)?
      risk.sourceEvidenceIds.filter(id):[];
    const sharedFindingIds=shared(originalFindingIds,sourceFindings);
    if(sharedFindingIds.length===0)return[];
    const prior=byRiskKey.get(risk.key);
    const valid=sourceComplete&&risk.status==="OPEN"&&
      sharedFindingIds.length>0;
    const unsupportedReason=!sourceComplete?"SOURCE_INCOMPLETE":
      risk.status!=="OPEN"?"RISK_NOT_OPEN":
      originalFindingIds.length===0?"ORIGINAL_FINDINGS_MISSING":null;
    return[{
      riskKey:risk.key,title:risk.title,
      severity:risk.severity,
      sourceFindingIds:sourceFindings,
      sourceEvidenceIds:sourceEvidence,
      sharedFindingIds,
      sharedEvidenceIds:shared(originalEvidenceIds,sourceEvidence),
      existingActionId:prior?.actionId??null,
      existingActionStatus:prior?.status??null,
      existingActionRevision:prior?.revision??null,
      suggestedPriority:severityPriority(risk.severity),
      sourceComplete,supportsAtomicHandoff:valid,
      unsupportedReason,
    }];
  }).sort((a,b)=>
    b.sharedFindingIds.length-a.sharedFindingIds.length||
    b.sharedEvidenceIds.length-a.sharedEvidenceIds.length||
    a.riskKey.localeCompare(b.riskKey));
  const linkedCandidate=existing?
    candidates.find(x=>x.riskKey===existing.riskKey):undefined;
  const orphanedRelatedAction=item.relatedActionId!==null&&!existing;
  const linkedActionSourceMatched=Boolean(existing&&linkedCandidate);
  const unlinked=item.relatedActionId===null;
  const safeForHandoff=unlinked&&sourceComplete&&
    candidates.some(x=>x.supportsAtomicHandoff);
  return{
    caseId:item.caseId,decisionKey:item.decisionKey,
    organizationId:item.organizationId,
    caseRevision:item.revision,caseStatus:item.status,
    casePriority:item.priority,
    caseOwnerUserId:item.ownerUserId,caseDueAt:item.dueAt,
    decisionSourceDigest:item.sourceReportDigest,
    originalFindingCount:originalFindingIds.length,
    originalEvidenceCount:originalEvidenceIds.length,
    relatedActionId:item.relatedActionId,
    candidates,candidateCount:candidates.length,
    actionableCandidates:candidates.filter(x=>
      x.supportsAtomicHandoff).length,
    linkedActionExists:Boolean(existing),
    linkedActionRiskKey:existing?.riskKey??null,
    linkedActionSourceMatched,
    orphanedRelatedAction,
    ambiguousSources:candidates.length>1,
    noOriginalFinding:originalFindingIds.length===0,
    riskSourceIncomplete:!sourceComplete,
    sourceUnavailable:candidates.length===0,
    safeForHandoff,
    legalRemediationCertified:false,
  };
}
export function buildCaseActionHandoffBoard(input:{
  organizationId:string;
  evaluatedAt:string;
  cases:DecisionCaseSnapshot[];
  actions:ActionSnapshot[];
  report:IntegratedRiskDigest;
  sourceTruncated:boolean;
}):CaseActionHandoffBoard{
  const{organizationId,evaluatedAt,cases,actions,report}=input;
  if(!id(organizationId)||!iso(evaluatedAt)||
    !Array.isArray(cases)||cases.length>500||
    !Array.isArray(actions)||actions.length>500||
    report.organizationId!==organizationId||
    cases.some(x=>x.organizationId!==organizationId)||
    actions.some(x=>x.organizationId!==organizationId))
    throw Error("CASE_HANDOFF_BOARD_SCOPE_INVALID");
  if(new Set(cases.map(x=>x.caseId)).size!==cases.length)
    throw Error("CASE_HANDOFF_DUPLICATE_CASE");
  if(new Set(actions.map(x=>x.actionId)).size!==actions.length)
    throw Error("CASE_HANDOFF_DUPLICATE_ACTION");
  const sourceComplete=report.state!=="INCOMPLETE"&&
    !input.sourceTruncated;
  const rows=cases.map(item=>rowFor(item,report.risks,actions,
    sourceComplete)).sort((a,b)=>
    urgency[a.casePriority]-urgency[b.casePriority]||
    (a.caseDueAt??"9999").localeCompare(b.caseDueAt??"9999")||
    a.caseId.localeCompare(b.caseId));
  const issues:string[]=[];
  if(input.sourceTruncated)issues.push("HANDOFF_SOURCE_TRUNCATED");
  if(report.state==="INCOMPLETE")issues.push("HANDOFF_RISK_SOURCE_INCOMPLETE");
  if(rows.some(x=>x.orphanedRelatedAction))
    issues.push("HANDOFF_ORPHANED_ACTION_LINK");
  if(rows.some(x=>x.relatedActionId&&!x.linkedActionSourceMatched))
    issues.push("HANDOFF_LINKED_SOURCE_MISMATCH");
  if(rows.some(x=>x.ambiguousSources))
    issues.push("HANDOFF_MULTIPLE_SOURCE_RISKS");
  if(rows.some(x=>x.noOriginalFinding))
    issues.push("HANDOFF_CASE_WITHOUT_FINDING");
  const totals={
    cases:rows.length,
    unlinked:rows.filter(x=>!x.relatedActionId).length,
    linked:rows.filter(x=>x.relatedActionId).length,
    orphanedLinks:rows.filter(x=>x.orphanedRelatedAction).length,
    sourceMismatches:rows.filter(x=>x.relatedActionId&&
      !x.linkedActionSourceMatched).length,
    withCandidates:rows.filter(x=>x.candidateCount>0).length,
    readyForHandoff:rows.filter(x=>x.safeForHandoff).length,
    blockedCases:rows.filter(x=>!x.safeForHandoff&&!x.relatedActionId).length,
    ambiguousSources:rows.filter(x=>x.ambiguousSources).length,
    withoutOriginalFindings:rows.filter(x=>x.noOriginalFinding).length,
    existingActionsReusable:rows.filter(x=>x.safeForHandoff&&
      x.candidates.some(c=>c.existingActionId)).length,
    actionsNeedingCreation:rows.filter(x=>x.safeForHandoff&&
      x.candidates.some(c=>!c.existingActionId)).length,
    unsupportedSourceRows:rows.filter(x=>x.riskSourceIncomplete||
      x.sourceUnavailable).length,
  };
  const status:CaseActionHandoffBoard["status"]=!sourceComplete?"BLOCKED":
    issues.length?"PARTIAL":"READY";
  const base={
    schema:"cyberpilot.case.action.handoff.board.v1" as const,
    organizationId,evaluatedAt,riskReportDigest:report.digest,
    riskSourceComplete:sourceComplete,
    sourceTruncated:input.sourceTruncated,
    rows,totals,status,issues:unique(issues),
    independentRemediationVerified:false as const,
    LIVEProviderCalls:0 as const,
    customerConsentEstablished:false as const,
    scoreV1Writes:0 as const,
  };
  return{...base,digest:hash(JSON.stringify(base))};
}
export function verifyCaseActionHandoffBoard(
  board:CaseActionHandoffBoard,organizationId:string,
){
  const issues:string[]=[];
  if(board.organizationId!==organizationId||
    board.schema!=="cyberpilot.case.action.handoff.board.v1")
    issues.push("HANDOFF_BOARD_TENANT");
  const{digest,...base}=board;
  if(hash(JSON.stringify(base))!==digest)
    issues.push("HANDOFF_BOARD_DIGEST");
  if(board.rows.some(x=>x.organizationId!==organizationId))
    issues.push("HANDOFF_BOARD_ROW_TENANT");
  if(board.totals.cases!==board.rows.length||
    board.totals.readyForHandoff!==board.rows.filter(x=>
      x.safeForHandoff).length)
    issues.push("HANDOFF_BOARD_METRIC_INVALID");
  if(board.independentRemediationVerified!==false||
    board.LIVEProviderCalls!==0||
    board.customerConsentEstablished!==false||board.scoreV1Writes!==0)
    issues.push("HANDOFF_BOARD_FALSE_SECURITY_CLAIM");
  if(board.sourceTruncated&&board.riskSourceComplete)
    issues.push("HANDOFF_BOARD_TRUNCATION_DOWNGRADED");
  return{valid:issues.length===0,issues:unique(issues)};
}
export function selectCaseActionHandoffRows(
  board:CaseActionHandoffBoard,query:HandoffBoardQuery={},
):HandoffBoardPage{
  const kind=query.kind??"ALL";
  const offset=query.offset??0,limit=query.limit??50;
  if(!["ALL","READY","BLOCKED","LINKED","UNLINKED"].includes(kind)||
    !Number.isSafeInteger(offset)||offset<0||offset>100000||
    !Number.isSafeInteger(limit)||limit<1||limit>200||
    (query.search!==undefined&&
      (typeof query.search!=="string"||query.search.length>200))||
    (query.minPriority!==undefined&&
      !Object.keys(urgency).includes(query.minPriority)))
    throw Error("HANDOFF_BOARD_QUERY_INVALID");
  const search=query.search?.trim().toLowerCase()??"";
  const filtered=board.rows.filter(x=>
    (kind==="ALL"||
      kind==="READY"&&x.safeForHandoff||
      kind==="BLOCKED"&&!x.safeForHandoff&&!x.relatedActionId||
      kind==="LINKED"&&x.relatedActionId!==null||
      kind==="UNLINKED"&&x.relatedActionId===null)&&
    (query.ownerUserId===undefined||
      x.caseOwnerUserId===query.ownerUserId)&&
    (query.minPriority===undefined||
      urgency[x.casePriority]<=urgency[query.minPriority])&&
    (!search||[
      x.caseId,x.decisionKey,
      ...x.candidates.flatMap(c=>[c.riskKey,c.title,c.severity]),
    ].join(" ").toLowerCase().includes(search)));
  const rows=filtered.slice(offset,offset+limit).map(x=>
    query.includeCandidates===false?{...x,candidates:[]}:x);
  return{
    schema:"cyberpilot.case.action.handoff.page.v1",
    organizationId:board.organizationId,
    boardDigest:board.digest,total:filtered.length,offset,limit,
    nextOffset:offset+limit<filtered.length?offset+limit:null,
    rows,sourceTruncated:board.sourceTruncated,
    noProvidersContacted:true,
  };
}
export function exportCaseActionHandoffBoard(
  board:CaseActionHandoffBoard,
  format:"JSON"|"CSV"|"MARKDOWN",
){
  if(!verifyCaseActionHandoffBoard(board,board.organizationId).valid)
    throw Error("HANDOFF_EXPORT_SOURCE_INVALID");
  const filename="case-action-handoffs-"+board.evaluatedAt.slice(0,10);
  if(format==="JSON")return{
    filename:filename+".json",mime:"application/json",
    content:JSON.stringify(board,null,2),
  };
  const quote=(v:unknown)=>'"'+safeText(v??"")
    .replaceAll('"','""').replace(/^[=+@\-]/,x=>"'"+x)+'"';
  if(format==="CSV")return{
    filename:filename+".csv",mime:"text/csv",
    content:[
      "caseId,priority,caseRevision,relatedActionId,ready,candidates,blocked",
      ...board.rows.map(x=>[
        x.caseId,x.casePriority,x.caseRevision,x.relatedActionId,
        x.safeForHandoff,x.candidateCount,
        x.orphanedRelatedAction||x.riskSourceIncomplete||
          x.noOriginalFinding,
      ].map(quote).join(",")),
    ].join("\n"),
  };
  if(format!=="MARKDOWN")throw Error("HANDOFF_EXPORT_FORMAT_INVALID");
  return{
    filename:filename+".md",mime:"text/markdown",
    content:[
      "# Offline evidence case and risk action handoffs",
      "Organization: "+board.organizationId,
      "Evaluated: "+board.evaluatedAt,
      "Status: "+board.status,
      "Source truncated: "+board.sourceTruncated,
      "Ready for human follow-up: "+board.totals.readyForHandoff,
      "Unlinked: "+board.totals.unlinked,
      "Linked: "+board.totals.linked,
      "Orphaned action links: "+board.totals.orphanedLinks,
      "Issues: "+board.issues.join(", "),
      "",
      ...board.rows.map(x=>"- "+x.caseId+" "+x.casePriority+
        " / candidates "+x.candidateCount+
        " / ready "+x.safeForHandoff),
      "",
      "No LIVE remediation, customer certification or historical score write.",
    ].join("\n"),
  };
}
