import type {ReviewFinding,ReviewAction} from "./finding-evidence-review";
import {buildControlChronology} from "./control-chronology";
export type ReconciliationOutcome="aligned-verified"|"aligned-open"|"resolved-separately"|"verified-but-open"|"completed-not-verified"|"failed-work"|"pending-work"|"unaddressed"|"unknown";
export type ReconciliationEntry={
 id:string;findingId:string;findingTitle:string;severity:string;
 findingStatus:string;actionId:string|null;actionTitle:string|null;
 actionStatus:string|null;outcome:ReconciliationOutcome;
 explanation:string;nextAction:string;warnings:string[];
 lastFindingAt:Date;lastWorkAt:Date|null;lastObservationAt:Date|null;
 verifiedAt:Date|null;resolvedAt:Date|null;needsReviewer:boolean;
};
export type ReconciliationPortfolio={
 entries:ReconciliationEntry[];total:number;affectedFindings:number;
 aligned:number;requiresReview:number;verifiedOpen:number;
 completedNotVerified:number;failed:number;unaddressed:number;
};
const severityOrder:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const outcomeOrder:Record<ReconciliationOutcome,number>={
 "verified-but-open":0,"completed-not-verified":1,"failed-work":2,
 "pending-work":3,unaddressed:4,unknown:5,"resolved-separately":6,
 "aligned-open":7,"aligned-verified":8,
};
const outcomeDescriptions:Record<ReconciliationOutcome,[string,string]>={
 "verified-but-open":[
  "A linked remediation has a verified workflow timestamp, while the finding remains open.",
  "Inspect the verification scope and request a new finding assessment where appropriate.",
 ],
 "completed-not-verified":[
  "Recorded remediation work is complete, but evidence-based verification is not recorded.",
  "Collect a fresh control observation and use the existing verification workflow.",
 ],
 "failed-work":[
  "The recorded remediation attempt failed.",
  "Investigate the failure and determine whether a retry or different action is warranted.",
 ],
 "pending-work":[
  "A remediation is proposed, approved or running, without a verified outcome.",
  "Continue the authorized workflow and record the results for subsequent verification.",
 ],
 unaddressed:[
  "No remediation workflow is linked to this finding.",
  "Review the finding and plan a suitable action or document independent resolution.",
 ],
 unknown:[
  "The stored workflow does not conclusively describe a verified remediation result.",
  "Review the action state, observation lineage and control scope.",
 ],
 "resolved-separately":[
  "The finding is recorded resolved without a linked verified action.",
  "Review its source resolution evidence; independent detection may resolve a finding.",
 ],
 "aligned-open":[
  "The finding remains open and no linked remediation has achieved verification.",
  "Continue remediation or investigate the latest observed control outcome.",
 ],
 "aligned-verified":[
  "The finding is resolved and a linked action has a recorded verification timestamp.",
  "Confirm that the action verification and finding resolution cover the same control scope.",
 ],
};
function reconcileAction(finding:ReviewFinding,action:ReviewAction|null):ReconciliationEntry{
 const chronology=buildControlChronology(finding);
 const verified=Boolean(action?.status==="VERIFIED"&&action.verifiedAt);
 const completed=Boolean(action?.status==="SUCCEEDED"||action?.completedAt);
 const resolved=finding.status==="RESOLVED";
 let outcome:ReconciliationOutcome;
 if(!action)outcome=resolved?"resolved-separately":"unaddressed";
 else if(verified)outcome=resolved?"aligned-verified":"verified-but-open";
 else if(action.status==="FAILED")outcome="failed-work";
 else if(completed)outcome="completed-not-verified";
 else if(["PROPOSED","APPROVED","EXECUTING"].includes(action.status))
  outcome=resolved?"resolved-separately":"pending-work";
 else outcome=resolved?"resolved-separately":"unknown";
 const [explanation,nextAction]=outcomeDescriptions[outcome];
 const warnings:string[]=[];
 if(chronology.workAfterObservation)warnings.push(
  "The latest matched observed evidence does not follow the recorded work.",
 );
 if(finding.evidence.length===0)warnings.push(
  "No exact control identifier evidence was matched; source mapping may be incomplete.",
 );
 if(finding.evidence.some(e=>e.source==="DECLARED"))warnings.push(
  "Declared records do not independently establish effective remediation.",
 );
 if(finding.evidence.some(e=>e.source==="ERROR"||e.source==="UNKNOWN"))warnings.push(
  "Unknown or errored source evidence requires separate investigation.",
 );
 if(outcome==="aligned-verified")warnings.push(
  "Recorded agreement of status and timestamps does not independently certify the control.",
 );
 const needsReviewer=outcome!=="aligned-verified"&&outcome!=="aligned-open";
 return {
  id:finding.id+":"+(action?.id??"no-action"),findingId:finding.id,
  findingTitle:finding.title,severity:finding.severity,
  findingStatus:finding.status,actionId:action?.id??null,
  actionTitle:action?.title??null,actionStatus:action?.status??null,
  outcome,explanation,nextAction,warnings,
  lastFindingAt:finding.lastSeenAt,lastWorkAt:chronology.lastWorkAt,
  lastObservationAt:chronology.lastObservationAt,
  verifiedAt:verified?action?.verifiedAt??null:null,
  resolvedAt:resolved?finding.resolvedAt:null,
  needsReviewer,
 };
}
export function reconcileFinding(finding:ReviewFinding):ReconciliationEntry[]{
 if(!finding.actions.length)return [reconcileAction(finding,null)];
 return finding.actions.map(action=>reconcileAction(finding,action));
}
export function buildReconciliationPortfolio(findings:readonly ReviewFinding[]):ReconciliationPortfolio{
 const entries=findings.flatMap(reconcileFinding).sort((a,b)=>
  outcomeOrder[a.outcome]-outcomeOrder[b.outcome]||
  (severityOrder[a.severity]??5)-(severityOrder[b.severity]??5)||
  a.findingId.localeCompare(b.findingId)||a.id.localeCompare(b.id));
 return {
  entries,total:entries.length,
  affectedFindings:new Set(entries.map(x=>x.findingId)).size,
  aligned:entries.filter(x=>x.outcome==="aligned-verified"||x.outcome==="aligned-open").length,
  requiresReview:entries.filter(x=>x.needsReviewer).length,
  verifiedOpen:entries.filter(x=>x.outcome==="verified-but-open").length,
  completedNotVerified:entries.filter(x=>x.outcome==="completed-not-verified").length,
  failed:entries.filter(x=>x.outcome==="failed-work").length,
  unaddressed:entries.filter(x=>x.outcome==="unaddressed").length,
 };
}
export function reconciliationCsv(portfolio:ReconciliationPortfolio):string{
 const safe=(value:string):string=>{
  const text=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
  return '"'+text.replaceAll('"','""')+'"';
 };
 const header=["Finding ID","Finding","Severity","Finding status","Action ID",
  "Action status","Reconciliation","Explanation","Next action",
  "Last finding UTC","Last remediation UTC","Last observed evidence UTC",
  "Verified UTC","Resolved UTC","Warnings"];
 const rows=portfolio.entries.map(x=>[
  x.findingId,x.findingTitle,x.severity,x.findingStatus,x.actionId??"",
  x.actionStatus??"",x.outcome,x.explanation,x.nextAction,
  x.lastFindingAt.toISOString(),x.lastWorkAt?.toISOString()??"",
  x.lastObservationAt?.toISOString()??"",x.verifiedAt?.toISOString()??"",
  x.resolvedAt?.toISOString()??"",x.warnings.join(" | "),
 ]);
 return "\uFEFF"+[header,...rows].map(row=>row.map(safe).join(",")).join("\r\n")+"\r\n";
}
export function reconciliationText(portfolio:ReconciliationPortfolio):string{
 const lines=[
  "CYBERPILOT — REMEDIATION OUTCOME RECONCILIATION",
  "Review of stored states, not an attestation of security effectiveness.",
  "Workflow records: "+portfolio.total,
  "Records requiring review: "+portfolio.requiresReview,
  "Verified actions with open findings: "+portfolio.verifiedOpen,
  "Completed but not verified: "+portfolio.completedNotVerified,"",
 ];
 for(const [index,item] of portfolio.entries.entries()){
  lines.push(
   `${index+1}. ${item.findingTitle}`,
   "Severity: "+item.severity,
   "Finding state: "+item.findingStatus,
   "Action: "+(item.actionTitle??"No linked action"),
   "Action state: "+(item.actionStatus??"Not recorded"),
   "Reconciliation: "+item.outcome,
   "Explanation: "+item.explanation,
   "Next step: "+item.nextAction,
   "Last observed: "+(item.lastObservationAt?.toISOString()??"Not recorded"),
   "Last work: "+(item.lastWorkAt?.toISOString()??"Not recorded"),
   "Limitations:",
   ...(item.warnings.length?item.warnings.map(x=>" - "+x):
    [" - Review source provenance and affected scope."]),
   "",
  );
 }
 return lines.join("\n")+"\n";
}
