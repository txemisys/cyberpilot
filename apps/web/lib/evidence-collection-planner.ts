import type {ReviewFinding,ReviewEvidence,ReviewAction} from "./finding-evidence-review";

export type EvidenceCollectionState="available"|"declared-only"|"unavailable"|"needs-refresh"|"inconclusive";
export type EvidenceCollectionInstruction={
 id:string;findingId:string;findingTitle:string;severity:string;
 controlScope:string;state:EvidenceCollectionState;
 headline:string;purpose:string;instructions:string[];
 reviewCriteria:string[];cautions:string[];
 observationAt:Date|null;latestWorkAt:Date|null;
 observedRecordIds:string[];declaredRecordIds:string[];inconclusiveRecordIds:string[];
 needsNewObservation:boolean;linkedActionIds:string[];
};
export type EvidenceCollectionPlan={
 items:EvidenceCollectionInstruction[];total:number;refreshRequired:number;
 unavailable:number;declaredOnly:number;inconclusive:number;available:number;
 affectedCritical:number;affectedHigh:number;
};
function newest(values:readonly(Date|null)[]):Date|null{
 let latest:Date|null=null;
 for(const value of values){
  if(!value||!Number.isFinite(value.getTime()))continue;
  if(!latest||value>latest)latest=value;
 }
 return latest;
}
function evidenceTimestamp(record:ReviewEvidence):Date|null{
 return newest([record.lastObservedAt,record.capturedAt]);
}
function workTimestamp(action:ReviewAction):Date|null{
 return newest([action.completedAt,action.startedAt,action.approvedAt]);
}
export function deriveEvidenceCollectionInstruction(finding:ReviewFinding):EvidenceCollectionInstruction{
 const observed=finding.evidence.filter(e=>e.source==="OBSERVED");
 const declared=finding.evidence.filter(e=>e.source==="DECLARED");
 const inconclusive=finding.evidence.filter(e=>e.source==="UNKNOWN"||e.source==="ERROR");
 const latestObservation=newest(observed.map(evidenceTimestamp));
 const latestWork=newest(finding.actions.map(workTimestamp));
 const needsRefresh=Boolean(latestWork&&(!latestObservation||latestWork>latestObservation));
 let state:EvidenceCollectionState;
 if(inconclusive.length&&!observed.length)state="inconclusive";
 else if(needsRefresh)state="needs-refresh";
 else if(observed.length)state="available";
 else if(declared.length)state="declared-only";
 else state="unavailable";
 const summaries:Record<EvidenceCollectionState,[string,string]>={
  available:["Observed evidence is recorded","Check whether the observed result covers the original finding and whether the control actually passed."],
  "needs-refresh":["An observation after remediation is required","The most recent stored observation does not establish the result after recorded work."],
  "declared-only":["Only declarations are available","A declaration needs an independent observation or a documented competent manual review."],
  unavailable:["No exact matching evidence was found","The evidence source or control mapping must be investigated before claiming a result."],
  inconclusive:["The available evidence is inconclusive","Review collection errors and unknown states before determining the actual control configuration."],
 };
 const instructions=[
  "Confirm the exact affected identity, resource, tenant and control scope from the finding.",
  "Check whether the connector and evidence source are authorized for this organization.",
  "Review the control identifier mapping; absence of an exact match is not proof of absence.",
  "Collect a fresh observation through an authorized source or document a manual verification process.",
  "Inspect the actual observation result rather than assuming that a timestamp means success.",
  "Compare the result against the security finding and linked remediation verification criteria.",
  "Use the existing verified workflow only after evidence and affected scope are independently reviewed.",
 ];
 const criteria=[
  "The collected record corresponds to the same affected control and organization.",
  "Its provenance and observation timestamp can be explained to an independent reviewer.",
  "The outcome of the security control is known, not merely the existence of an observation.",
  "If work was performed, the observation is later than the relevant remediation activity.",
  "Unknown, error and declared-only signals are not counted as verified remediation.",
  "Any remaining open finding or contradictory workflow is investigated before communicating closure.",
 ];
 const cautions:string[]=[];
 if(needsRefresh)cautions.push("The recorded work is newer than the last matched observed evidence.");
 if(declared.length)cautions.push(`${declared.length} declarations cannot independently verify the control.`);
 if(inconclusive.length)cautions.push(`${inconclusive.length} unknown or errored records need investigation.`);
 if(finding.status==="RESOLVED")cautions.push("The finding is recorded resolved; review its historical resolution provenance.");
 if(finding.actions.some(a=>a.status==="SUCCEEDED"&&a.verifiedAt===null))
  cautions.push("At least one completed execution lacks a recorded verification timestamp.");
 return {
  id:finding.id+":collection",findingId:finding.id,
  findingTitle:finding.title,severity:finding.severity,controlScope:finding.description,
  state,headline:summaries[state][0],purpose:summaries[state][1],
  instructions,reviewCriteria:criteria,cautions,
  observationAt:latestObservation,latestWorkAt:latestWork,
  observedRecordIds:observed.map(x=>x.id),
  declaredRecordIds:declared.map(x=>x.id),
  inconclusiveRecordIds:inconclusive.map(x=>x.id),
  needsNewObservation:state!=="available",
  linkedActionIds:finding.actions.map(a=>a.id),
 };
}
const priority:Record<EvidenceCollectionState,number>={
 "needs-refresh":0,inconclusive:1,"declared-only":2,unavailable:3,available:4,
};
const severity:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
export function buildEvidenceCollectionPlan(findings:readonly ReviewFinding[]):EvidenceCollectionPlan{
 const items=findings.map(deriveEvidenceCollectionInstruction);
 items.sort((a,b)=>priority[a.state]-priority[b.state]||
  (severity[a.severity]??5)-(severity[b.severity]??5)||
  a.findingId.localeCompare(b.findingId));
 const count=(state:EvidenceCollectionState)=>items.filter(x=>x.state===state).length;
 return {
  items,total:items.length,refreshRequired:count("needs-refresh"),
  unavailable:count("unavailable"),declaredOnly:count("declared-only"),
  inconclusive:count("inconclusive"),available:count("available"),
  affectedCritical:items.filter(x=>x.severity==="CRITICAL"&&x.needsNewObservation).length,
  affectedHigh:items.filter(x=>x.severity==="HIGH"&&x.needsNewObservation).length,
 };
}
export function evidenceCollectionPlanText(plan:EvidenceCollectionPlan):string{
 const lines=[
  "CYBERPILOT — EVIDENCE COLLECTION PREPARATION",
  "This document does not trigger a provider scan or verify a security control.",
  "Findings reviewed: "+plan.total,
  "Observation refresh recommended: "+plan.refreshRequired,
  "No matched evidence: "+plan.unavailable,
  "Declaration only: "+plan.declaredOnly,
  "Inconclusive: "+plan.inconclusive,
  "",
 ];
 for(const [index,item] of plan.items.entries()){
  lines.push(
   `${index+1}. ${item.findingTitle}`,
   "Severity: "+item.severity,"Evidence state: "+item.state,
   "Purpose: "+item.purpose,
   "Last observation: "+(item.observationAt?.toISOString()??"Not recorded"),
   "Latest remediation activity: "+(item.latestWorkAt?.toISOString()??"Not recorded"),
   "Preparation steps:",
   ...item.instructions.map((text,n)=>`  ${n+1}. ${text}`),
   "Independent review criteria:",
   ...item.reviewCriteria.map(text=>"  - "+text),
   "Cautions:",
   ...(item.cautions.length?item.cautions.map(text=>"  - "+text):["  - Verify the underlying observation result."]),
   "",
  );
 }
 return lines.join("\n")+"\n";
}
export function evidenceCollectionPlanCsv(plan:EvidenceCollectionPlan):string{
 const csv=(text:string)=>{
  const safe=/^[\s]*[=+@\-]/.test(text)?"'"+text:text;
  return '"'+safe.replaceAll('"','""')+'"';
 };
 const rows=[
  ["Finding ID","Finding title","Severity","Evidence state","Purpose",
   "Fresh observation required","Matched observed records","Declared records",
   "Inconclusive records","Last observation UTC","Latest work UTC",
   "Collection instructions","Verification criteria","Warnings"],
  ...plan.items.map(item=>[
   item.findingId,item.findingTitle,item.severity,item.state,item.purpose,
   item.needsNewObservation?"yes":"no",
   String(item.observedRecordIds.length),String(item.declaredRecordIds.length),
   String(item.inconclusiveRecordIds.length),
   item.observationAt?.toISOString()??"",item.latestWorkAt?.toISOString()??"",
   item.instructions.join(" | "),item.reviewCriteria.join(" | "),item.cautions.join(" | "),
  ]),
 ];
 return "\uFEFF"+rows.map(row=>row.map(csv).join(",")).join("\r\n")+"\r\n";
}
