import type {ReviewFinding} from "./finding-evidence-review";
import {buildControlChronology} from "./control-chronology";
import {assessControlAssurance} from "./control-assurance";

export type ReviewExceptionKind =
 "open-after-verification" | "resolved-without-verification" |
 "work-newer-than-observation" | "declared-only" |
 "source-error" | "missing-control-match" | "incomplete-approval" |
 "completed-without-evidence" | "workflow-without-progress";

export type ReviewException={
 id:string;
 findingId:string;
 findingTitle:string;
 severity:string;
 kind:ReviewExceptionKind;
 priority:number;
 title:string;
 explanation:string;
 recommendation:string;
 factualContext:string[];
 recordedAt:Date;
 remediationId:string|null;
};
const severityRank:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const priorityRank:Record<ReviewExceptionKind,number>={
 "work-newer-than-observation":0,
 "completed-without-evidence":1,
 "open-after-verification":2,
 "source-error":3,
 "missing-control-match":4,
 "resolved-without-verification":5,
 "declared-only":6,
 "incomplete-approval":7,
 "workflow-without-progress":8,
};
const descriptions:Record<ReviewExceptionKind,{title:string;explanation:string;recommendation:string}>={
 "open-after-verification":{
  title:"Action verified while finding remains open",
  explanation:"A remediation has a recorded verification timestamp, but its associated finding is still open.",
  recommendation:"Check whether the verification covers the same control and whether a fresh finding assessment is required.",
 },
 "resolved-without-verification":{
  title:"Finding resolved without a linked verified action",
  explanation:"The finding is marked resolved, but none of the available linked remediations has a verified workflow record.",
  recommendation:"Review the finding resolution provenance. Some controls may be resolved through independent rescans rather than a remediation.",
 },
 "work-newer-than-observation":{
  title:"Evidence predates recorded remediation",
  explanation:"The last matched observed signal is older than recorded remediation work.",
  recommendation:"Request fresh observed evidence before evaluating the effect of the change.",
 },
 "declared-only":{
  title:"Evidence is declaration-only",
  explanation:"The matched records are declarations, not independent observations of security controls.",
  recommendation:"Obtain an authorized observed signal or document the manual review limitation.",
 },
 "source-error":{
  title:"Source evidence is inconclusive",
  explanation:"The evidence includes unknown or errored records that cannot establish an effective control.",
  recommendation:"Review collection errors, access permissions and the affected control identifier.",
 },
 "missing-control-match":{
  title:"No exact control-matched evidence",
  explanation:"No stored evidence matched the finding control identifier.",
  recommendation:"Confirm the control mapping or obtain an authoritative observation.",
 },
 "incomplete-approval":{
  title:"Remediation proposed but not approved",
  explanation:"A proposed remediation has not progressed to an approved work plan.",
  recommendation:"Have an authorized manager review and approve the plan before execution.",
 },
 "completed-without-evidence":{
  title:"Completed work has no verified security result",
  explanation:"An action was completed or succeeded without a recorded verification outcome.",
  recommendation:"Collect fresh evidence and apply the existing verification checklist.",
 },
 "workflow-without-progress":{
  title:"Approved guided work has no acknowledged steps",
  explanation:"A guided remediation is approved but none of its recorded steps has been acknowledged.",
  recommendation:"Review assigned work and begin the first relevant guided instruction.",
 },
};
export function collectFindingReviewExceptions(finding:ReviewFinding):ReviewException[]{
 const assurance=assessControlAssurance(finding);
 const chronology=buildControlChronology(finding);
 const exceptions:ReviewException[]=[];
 const include=(kind:ReviewExceptionKind,context:string[],remediationId:string|null=null)=>{
  const description=descriptions[kind];
  exceptions.push({
   id:finding.id+":"+kind+(remediationId?":"+remediationId:""),
   findingId:finding.id,
   findingTitle:finding.title,
   severity:finding.severity,
   kind,
   title:description.title,
   explanation:description.explanation,
   recommendation:description.recommendation,
   priority:priorityRank[kind]*10+(severityRank[finding.severity]??5),
   factualContext:context,
   recordedAt:finding.lastSeenAt,
   remediationId,
  });
 };
 if(finding.status==="OPEN"&&assurance.verifiedWorkflows>0){
  include("open-after-verification",[
   "Finding status: OPEN",
   "Verified workflow records: "+assurance.verifiedWorkflows,
  ]);
 }
 if(finding.status==="RESOLVED"&&assurance.verifiedWorkflows===0){
  include("resolved-without-verification",[
   "Finding status: RESOLVED",
   "Verified workflow records: 0",
  ]);
 }
 if(chronology.workAfterObservation){
  include("work-newer-than-observation",[
   "Last work: "+(chronology.lastWorkAt?.toISOString()??"Unknown"),
   "Last observation: "+(chronology.lastObservationAt?.toISOString()??"Unknown"),
  ]);
 }
 if(finding.evidence.length===0){
  include("missing-control-match",["Matched evidence records: 0"]);
 }else if(assurance.observations===0&&assurance.declarations>0){
  include("declared-only",[
   "Matched declarations: "+assurance.declarations,
   "Matched observations: 0",
  ]);
 }
 if(assurance.errors>0||assurance.unknown>0){
  include("source-error",[
   "Unknown records: "+assurance.unknown,
   "Error records: "+assurance.errors,
  ]);
 }
 for(const action of finding.actions){
  if(action.status==="PROPOSED"&&finding.status==="OPEN"){
   include("incomplete-approval",[
    "Action status: PROPOSED",
    "Action title: "+action.title,
   ],action.id);
  }
  const unverified=action.status!=="VERIFIED"||!action.verifiedAt;
  if(unverified&&(action.status==="SUCCEEDED"||
   (action.completedAt!==null&&finding.status==="OPEN"))){
   include("completed-without-evidence",[
    "Action status: "+action.status,
    "Completed: "+(action.completedAt?.toISOString()??"Unknown"),
   ],action.id);
  }
  if(action.mode==="GUIDED"&&action.status==="APPROVED"&&
    action.steps.length>0&&action.acknowledgedSteps.size===0){
   include("workflow-without-progress",[
    "Recorded guided steps: "+action.steps.length,
    "Acknowledged steps: 0",
   ],action.id);
  }
 }
 return exceptions.sort((a,b)=>a.priority-b.priority||a.id.localeCompare(b.id));
}
export function buildReviewExceptionRegister(findings:readonly ReviewFinding[]):{
 items:ReviewException[];
 count:number;
 affectedFindings:number;
 critical:number;
 high:number;
 reviewEvidence:number;
 needsWork:number;
}{
 const items=findings.flatMap(collectFindingReviewExceptions)
  .sort((a,b)=>a.priority-b.priority||a.id.localeCompare(b.id));
 const reviewEvidence=items.filter(x=>[
  "work-newer-than-observation","completed-without-evidence",
  "source-error","missing-control-match","declared-only",
 ].includes(x.kind)).length;
 return {
  items,count:items.length,
  affectedFindings:new Set(items.map(x=>x.findingId)).size,
  critical:items.filter(x=>x.severity==="CRITICAL").length,
  high:items.filter(x=>x.severity==="HIGH").length,
  reviewEvidence,
  needsWork:items.length-reviewEvidence,
 };
}
export function exportExceptionRegister(items:readonly ReviewException[]):string{
 const cell=(value:string)=>{
  const safe=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
  return '"'+safe.replaceAll('"','""')+'"';
 };
 const header=["Finding ID","Finding","Severity","Exception","Explanation",
  "Recommendation","Remediation ID","Finding last seen","Context"];
 const values=items.map(item=>[
  item.findingId,item.findingTitle,item.severity,item.title,
  item.explanation,item.recommendation,item.remediationId??"",
  item.recordedAt.toISOString(),item.factualContext.join(" | "),
 ]);
 return "\uFEFF"+[header,...values].map(row=>row.map(cell).join(",")).join("\r\n")+"\r\n";
}

export type ExceptionCategoryCount = {
  kind: ReviewExceptionKind;
  count: number;
  critical: number;
  high: number;
  affectedFindings: number;
};
/** Give managers an actionable breakdown without hiding duplicate flags per finding. */
export function summarizeReviewExceptionKinds(
  exceptions: readonly ReviewException[],
): ExceptionCategoryCount[] {
  const kinds = new Map<ReviewExceptionKind, ReviewException[]>();
  for (const item of exceptions) {
    const group = kinds.get(item.kind) ?? [];
    group.push(item);
    kinds.set(item.kind, group);
  }
  return [...kinds.entries()].map(([kind, group]) => ({
    kind,
    count: group.length,
    critical: group.filter(item => item.severity === "CRITICAL").length,
    high: group.filter(item => item.severity === "HIGH").length,
    affectedFindings: new Set(group.map(item => item.findingId)).size,
  })).sort((a, b) =>
    b.critical - a.critical ||
    b.high - a.high ||
    b.count - a.count ||
    a.kind.localeCompare(b.kind));
}
