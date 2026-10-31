/**
 * Human review triage for explicitly attached evidence references.
 * This is a deterministic queue of review questions, not an automatic verification engine.
 */
import {assessLinkedEvidence,type EvidenceRecord,type FindingReference} from "./work-evidence-policy";
export type ReferenceTriageRow={
 linkId:string;workItemId:string;findingId:string;workStatus:string;
 assignedUserId:string|null;reason:string;
 evidence:EvidenceRecord;finding:FindingReference;
 linkedAt:Date;unlinkedAt:Date|null;
};
export type ReferenceIssueCode=
 |"REFERENCE_DETACHED"|"EVIDENCE_ERROR"|"EVIDENCE_UNKNOWN"
 |"DECLARED_ONLY"|"UNRECOGNIZED_STATE"|"CONTROL_MISMATCH"
 |"MISSING_OBSERVATION"|"FUTURE_OBSERVATION"|"STALE_OBSERVATION"
 |"AGING_OBSERVATION"|"WORK_DONE_UNVERIFIED";
export type ReferenceReview={
 linkId:string;workItemId:string;findingId:string;assignedUserId:string|null;
 severity:"URGENT"|"REVIEW"|"INFORMATION";
 issues:ReferenceIssueCode[];actions:string[];
 isActive:boolean;canBeUsedAsEvidence:boolean;
};
const actions:Record<ReferenceIssueCode,string>={
 REFERENCE_DETACHED:"Review historical link changes before relying on this record.",
 EVIDENCE_ERROR:"Investigate the source error and collect a new observation.",
 EVIDENCE_UNKNOWN:"Determine why the evidence source could not assess the control.",
 DECLARED_ONLY:"Request independent observation supporting the declaration.",
 UNRECOGNIZED_STATE:"Review the evidence schema and its recorded state.",
 CONTROL_MISMATCH:"Check control mapping and whether the scope genuinely applies.",
 MISSING_OBSERVATION:"Collect timestamped source evidence before a verification review.",
 FUTURE_OBSERVATION:"Investigate timestamp consistency and clock configuration.",
 STALE_OBSERVATION:"Collect fresh evidence for the current control state.",
 AGING_OBSERVATION:"Review freshness policy and consider a new observation.",
 WORK_DONE_UNVERIFIED:"Review completed work against current verification criteria."
};
export function reviewEvidenceReference(row:ReferenceTriageRow,now=new Date()):ReferenceReview{
 const assessment=assessLinkedEvidence(row.evidence,row.finding,now);
 const issues:ReferenceIssueCode[]=[];
 if(row.unlinkedAt!==null)issues.push("REFERENCE_DETACHED");
 if(assessment.state==="ERROR")issues.push("EVIDENCE_ERROR");
 if(assessment.state==="UNKNOWN")issues.push("EVIDENCE_UNKNOWN");
 if(assessment.state==="DECLARED")issues.push("DECLARED_ONLY");
 if(assessment.state==="OTHER")issues.push("UNRECOGNIZED_STATE");
 if(!assessment.isExplicitMatch)issues.push("CONTROL_MISMATCH");
 if(assessment.age==="NOT_OBSERVED")issues.push("MISSING_OBSERVATION");
 if(assessment.age==="FUTURE")issues.push("FUTURE_OBSERVATION");
 if(assessment.age==="STALE")issues.push("STALE_OBSERVATION");
 if(assessment.age==="AGING")issues.push("AGING_OBSERVATION");
 if(row.workStatus==="DONE"&&row.finding.status==="OPEN")
  issues.push("WORK_DONE_UNVERIFIED");
 const urgent=issues.some(x=>[
  "EVIDENCE_ERROR","CONTROL_MISMATCH","FUTURE_OBSERVATION","WORK_DONE_UNVERIFIED"
 ].includes(x));
 return {
  linkId:row.linkId,workItemId:row.workItemId,findingId:row.findingId,
  assignedUserId:row.assignedUserId,
  severity:urgent?"URGENT":issues.length?"REVIEW":"INFORMATION",
  issues,actions:issues.map(issue=>actions[issue]),
  isActive:row.unlinkedAt===null,
  canBeUsedAsEvidence:false
 };
}
export function prioritizeEvidenceReferences(rows:readonly ReferenceTriageRow[],now=new Date()){
 const rank={URGENT:0,REVIEW:1,INFORMATION:2};
 return rows.map(row=>reviewEvidenceReference(row,now)).sort((a,b)=>
  rank[a.severity]-rank[b.severity]||
  b.issues.length-a.issues.length||
  a.workItemId.localeCompare(b.workItemId)||
  a.linkId.localeCompare(b.linkId));
}
export function summarizeReferenceReview(rows:readonly ReferenceReview[]){
 const summary={
  total:rows.length,urgent:0,review:0,information:0,detached:0,
  workDoneButFindingOpen:0,evidenceError:0,controlMismatch:0,
  notFresh:0,requiresAction:0
 };
 for(const row of rows){
  if(row.severity==="URGENT")summary.urgent++;
  if(row.severity==="REVIEW")summary.review++;
  if(row.severity==="INFORMATION")summary.information++;
  if(!row.isActive)summary.detached++;
  if(row.issues.includes("WORK_DONE_UNVERIFIED"))summary.workDoneButFindingOpen++;
  if(row.issues.includes("EVIDENCE_ERROR"))summary.evidenceError++;
  if(row.issues.includes("CONTROL_MISMATCH"))summary.controlMismatch++;
  if(row.issues.some(issue=>[
   "MISSING_OBSERVATION","FUTURE_OBSERVATION","STALE_OBSERVATION","AGING_OBSERVATION"
  ].includes(issue)))summary.notFresh++;
  if(row.issues.length)summary.requiresAction++;
 }
 return {...summary,disclaimer:"Review questions are not an assurance conclusion."};
}
export function groupReviewsByAssignee(rows:readonly ReferenceReview[]){
 const groups=new Map<string,{workItems:Set<string>;links:number;urgent:number;review:number}>();
 for(const row of rows){
  const user=row.assignedUserId??"UNASSIGNED";
  const group=groups.get(user)??{workItems:new Set<string>(),links:0,urgent:0,review:0};
  group.workItems.add(row.workItemId);group.links++;
  if(row.severity==="URGENT")group.urgent++;
  if(row.severity==="REVIEW")group.review++;
  groups.set(user,group);
 }
 return [...groups].map(([assigneeUserId,group])=>({
  assigneeUserId,workItems:group.workItems.size,
  references:group.links,urgent:group.urgent,review:group.review
 })).sort((a,b)=>b.urgent-a.urgent||b.review-a.review||
  a.assigneeUserId.localeCompare(b.assigneeUserId));
}
