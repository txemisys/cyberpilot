import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
import {assessControlAssurance} from "./control-assurance";
import {buildControlChronology} from "./control-chronology";

export type VerificationGate=
 "finding-scope"|"action-record"|"work-finished"|"fresh-observation"|
 "evidence-quality"|"verification-checklist"|"workflow-verification"|"finding-closure";
export type GateResult="met"|"not-met"|"needs-review"|"not-applicable";
export type ReadinessGate={
 id:VerificationGate;
 label:string;
 result:GateResult;
 explanation:string;
 reviewerInstruction:string;
 evidenceReferences:string[];
};
export type ClosureReadiness={
 findingId:string;title:string;severity:string;findingStatus:string;
 gates:ReadinessGate[];met:number;notMet:number;needsReview:number;
 notApplicable:number;readyForHumanReview:boolean;
 blockedBy:string[];warnings:string[];
 lastObservationAt:Date|null;lastWorkAt:Date|null;
};
const gateMeta:Record<VerificationGate,{label:string;instruction:string}>={
 "finding-scope":{
  label:"Confirm the affected control scope",
  instruction:"Compare evidence control IDs and affected asset scope against the original finding.",
 },
 "action-record":{
  label:"Record an applicable remediation",
  instruction:"Review the action details or document the independent resolution process.",
 },
 "work-finished":{
  label:"Confirm work was completed",
  instruction:"Inspect completed work and its scope; acknowledgement alone is not verification.",
 },
 "fresh-observation":{
  label:"Collect an observation after work",
  instruction:"Request an authorized new control observation after the relevant remediation.",
 },
 "evidence-quality":{
  label:"Review the evidence provenance and outcome",
  instruction:"Check observed versus declared sources, errors and the actual control result.",
 },
 "verification-checklist":{
  label:"Apply recorded verification criteria",
  instruction:"Check every recorded verification criterion against the latest relevant evidence.",
 },
 "workflow-verification":{
  label:"Review recorded verification",
  instruction:"Use the existing verification workflow; the checklist must not auto-verify.",
 },
 "finding-closure":{
  label:"Confirm finding closure status",
  instruction:"Review current finding state and resolution evidence before communicating closure.",
 },
};
function makeGate(
 id:VerificationGate,result:GateResult,explanation:string,
 evidenceReferences:string[]=[],
):ReadinessGate{
 return {
  id,label:gateMeta[id].label,
  reviewerInstruction:gateMeta[id].instruction,
  result,explanation,evidenceReferences,
 };
}
function verified(action:ReviewAction):boolean{
 return action.status==="VERIFIED"&&action.verifiedAt!==null;
}
function complete(action:ReviewAction):boolean{
 return action.status==="SUCCEEDED"||verified(action)||
  (action.mode==="GUIDED"&&action.steps.length>0&&
  action.steps.every((_,index)=>action.acknowledgedSteps.has(index)));
}
function evidenceFromObserved(records:readonly ReviewEvidence[]):ReviewEvidence[]{
 return records.filter(x=>x.source==="OBSERVED");
}
export function assessClosureReadiness(finding:ReviewFinding):ClosureReadiness{
 const assurance=assessControlAssurance(finding);
 const timeline=buildControlChronology(finding);
 const actions=finding.actions;
 const observed=evidenceFromObserved(finding.evidence);
 const matched=finding.evidence.length>0;
 const completeWork=actions.some(complete);
 const verifiedWork=actions.some(verified);
 const hasChecklist=actions.some(a=>a.verification.length>0);
 const freshObserved=Boolean(timeline.lastObservationAt&&
  timeline.lastWorkAt&&timeline.lastObservationAt>=timeline.lastWorkAt);
 const noWork=actions.length===0;
 const scopeReferences=observed.map(x=>x.id);
 const gates:ReadinessGate[]=[
  makeGate("finding-scope",matched?"needs-review":"not-met",
   matched?"Exact control ID matches were found; reviewer must confirm scope.":
    "No exact control-matched evidence is available.",scopeReferences),
  makeGate("action-record",noWork?"not-met":"met",
   noWork?"No linked remediation is recorded. An independently resolved finding may need separate review.":
    `${actions.length} remediation workflows are recorded.`,actions.map(a=>a.id)),
  makeGate("work-finished",noWork?"not-applicable":completeWork?"needs-review":"not-met",
   completeWork?"Completed or acknowledged work is recorded but must be independently reviewed.":
    "No workflow shows completed or fully acknowledged work."),
  makeGate("fresh-observation",noWork?"not-applicable":freshObserved?"needs-review":"not-met",
   freshObserved?"An observation follows the latest recorded work; its scope and result require review.":
    "The available data does not establish an observation after the latest work.",
   observed.map(x=>x.id)),
  makeGate("evidence-quality",observed.length===0?"not-met":"needs-review",
   observed.length===0?"No observed records matched; declarations cannot replace observation.":
    `${observed.length} observed records matched. Their conclusions remain to be reviewed.`,
   observed.map(x=>x.id)),
  makeGate("verification-checklist",noWork?"not-applicable":hasChecklist?"needs-review":"not-met",
   hasChecklist?"A stored verification checklist is available for human assessment.":
    "No verification checklist was recorded on a linked remediation.",
   actions.filter(a=>a.verification.length>0).map(a=>a.id)),
  makeGate("workflow-verification",noWork?"not-applicable":verifiedWork?"met":"not-met",
   verifiedWork?"A workflow verification timestamp is recorded; verify its affected scope.":
    "No linked action combines VERIFIED state with a verification timestamp.",
   actions.filter(verified).map(a=>a.id)),
  makeGate("finding-closure",finding.status==="RESOLVED"?"needs-review":"not-met",
   finding.status==="RESOLVED"?"Resolution is recorded; confirm provenance and scope.":
    "The finding has not been recorded as RESOLVED."),
 ];
 const count=(value:GateResult)=>gates.filter(x=>x.result===value).length;
 const warnings:string[]=[...assurance.limitations,...timeline.warnings];
 if(finding.status==="RESOLVED"&&noWork)warnings.push(
  "An independently resolved finding may have no linked remediation; review its original evidence.",
 );
 if(freshObserved)warnings.push(
  "Evidence recorded after work is not automatically evidence of a successful control test.",
 );
 return {
  findingId:finding.id,title:finding.title,severity:finding.severity,
  findingStatus:finding.status,gates,
  met:count("met"),notMet:count("not-met"),
  needsReview:count("needs-review"),notApplicable:count("not-applicable"),
  readyForHumanReview:gates.some(x=>x.result==="needs-review")||
    gates.some(x=>x.result==="met"),
  blockedBy:gates.filter(x=>x.result==="not-met").map(x=>x.label),
  warnings:[...new Set(warnings)],
  lastObservationAt:timeline.lastObservationAt,
  lastWorkAt:timeline.lastWorkAt,
 };
}
export function buildClosureReadinessPortfolio(findings:readonly ReviewFinding[]):{
 items:ClosureReadiness[];findings:number;blocked:number;
 reviewable:number;fullyRecorded:number;missingObservation:number;
}{
 const items=findings.map(assessClosureReadiness);
 const severityRanks:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 items.sort((a,b)=>b.notMet-a.notMet||
  (severityRanks[a.severity]??5)-(severityRanks[b.severity]??5)||
  a.findingId.localeCompare(b.findingId));
 return {
  items,findings:items.length,
  blocked:items.filter(x=>x.notMet>0).length,
  reviewable:items.filter(x=>x.readyForHumanReview).length,
  fullyRecorded:items.filter(x=>x.notMet===0).length,
  missingObservation:items.filter(x=>x.gates.some(g=>
   g.id==="evidence-quality"&&g.result==="not-met")).length,
 };
}
export function closureReadinessCsv(items:readonly ClosureReadiness[]):string{
 const cell=(value:string):string=>{
  const safe=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
  return '"'+safe.replaceAll('"','""')+'"';
 };
 const header=["Finding ID","Finding","Severity","Finding status","Met gates",
  "Missing gates","Human review gates","Not applicable","Missing requirements",
  "Last observation UTC","Last remediation UTC","Review limitations"];
 const rows=items.map(x=>[x.findingId,x.title,x.severity,x.findingStatus,
  String(x.met),String(x.notMet),String(x.needsReview),
  String(x.notApplicable),x.blockedBy.join(" | "),
  x.lastObservationAt?.toISOString()??"",x.lastWorkAt?.toISOString()??"",
  x.warnings.join(" | ")]);
 return "\uFEFF"+[header,...rows].map(row=>row.map(cell).join(",")).join("\r\n")+"\r\n";
}
