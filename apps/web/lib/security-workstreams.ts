import type {ReviewFinding} from "./finding-evidence-review";
import {buildManagementDecisionBoard} from "./management-decision-board";
import {buildEvidenceGapReport} from "./evidence-gap-report";
import {buildClosureReadinessPortfolio} from "./closure-readiness";
export type Workstream="evidence"|"approval"|"investigation"|"execution"|"closure";
export type WorkstreamItem={
 id:string;findingId:string;findingTitle:string;severity:string;
 actionId:string|null;workstream:Workstream;
 state:string;title:string;instructions:string;
 criteria:string[];limitations:string[];
 timestamp:Date;ownerRole:string;
 urgency:number;
};
export type WorkstreamSummary={
 stream:Workstream;total:number;critical:number;high:number;
 affectedFindings:number;requiresEvidence:number;
 items:WorkstreamItem[];
};
export type WorkstreamPlan={
 total:number;findings:number;openFindings:number;
 streams:WorkstreamSummary[];items:WorkstreamItem[];
 unaddressedFindings:number;outdatedObservations:number;
 noMatchedEvidence:number;reviewGatesMissing:number;
};
const severityRank:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const streamOrder:Record<Workstream,number>={
 evidence:0,investigation:1,approval:2,execution:3,closure:4,
};
const descriptions:Record<Workstream,{role:string;criteria:string[];limitations:string[]}>={
 evidence:{
  role:"Evidence reviewer",
  criteria:[
   "The evidence source has authorization to observe the affected control.",
   "The new observation covers the same identity, asset or control scope as the finding.",
   "The observation result is reviewed, not just its timestamp.",
  ],
  limitations:[
   "Declaring work complete cannot substitute for an observation.",
   "Observations of a different scope cannot verify this finding.",
  ],
 },
 approval:{
  role:"Authorized approver",
  criteria:[
   "The proposed remediation scope is reviewed for impact.",
   "The appropriate manager uses the existing authenticated approval route.",
   "The reviewer confirms a suitable post-change validation method.",
  ],
  limitations:[
   "A management briefing cannot itself grant remediation approval.",
  ],
 },
 investigation:{
  role:"Security investigator",
  criteria:[
   "The relevant finding and its evidence provenance have been reviewed.",
   "Any source collection error or ambiguous control mapping has been investigated.",
   "Next actions are based on the affected asset and control scope.",
  ],
  limitations:[
   "An unmatched evidence identifier does not establish that a control is absent.",
  ],
 },
 execution:{
  role:"Authorized operator",
  criteria:[
   "Approved instructions have been performed with appropriate authorization.",
   "Implementation result and any failures are reviewed.",
   "Post-change evidence is requested before claiming security improvement.",
  ],
  limitations:[
   "Execution success is not equivalent to verification.",
  ],
 },
 closure:{
  role:"Security reviewer",
  criteria:[
   "Finding resolution status is reviewed against authoritative source evidence.",
   "The verification workflow and affected control scope are checked.",
   "Contradictions between an open finding and a verified action are investigated.",
  ],
  limitations:[
   "Resolution timestamps alone are not a compliance certification.",
  ],
 },
};
export function createWorkstreamPlan(findings:readonly ReviewFinding[]):WorkstreamPlan{
 const board=buildManagementDecisionBoard(findings);
 const gaps=buildEvidenceGapReport(findings);
 const closure=buildClosureReadinessPortfolio(findings);
 const categories:Record<string,Workstream>={
  verification:"evidence",investigation:"investigation",
  approval:"approval",execution:"execution",closure:"closure",
 };
 const items:WorkstreamItem[]=board.items.map(item=>{
  const workstream=categories[item.category]??"investigation";
  const definition=descriptions[workstream];
  return {
   id:item.id,findingId:item.findingId,
   findingTitle:item.findingTitle,severity:item.severity,
   actionId:item.actionId,workstream,state:item.category,
   title:item.title,instructions:item.recommendedAction,
   criteria:[...item.successCriteria,...definition.criteria],
   limitations:[...new Set([...item.warnings,...definition.limitations])],
   timestamp:item.lastFindingSeenAt,
   ownerRole:definition.role,
   urgency:streamOrder[workstream]*10+(severityRank[item.severity]??5),
  };
 });
 items.sort((a,b)=>a.urgency-b.urgency||a.findingId.localeCompare(b.findingId));
 const streams=(Object.keys(descriptions) as Workstream[]).map(stream=>{
  const rows=items.filter(item=>item.workstream===stream);
  return {
   stream,total:rows.length,
   critical:rows.filter(x=>x.severity==="CRITICAL").length,
   high:rows.filter(x=>x.severity==="HIGH").length,
   affectedFindings:new Set(rows.map(x=>x.findingId)).size,
   requiresEvidence:rows.filter(x=>x.workstream==="evidence"||x.workstream==="closure").length,
   items:rows,
  };
 });
 return {
  total:items.length,findings:findings.length,
  openFindings:findings.filter(x=>x.status==="OPEN").length,
  streams,items,
  unaddressedFindings:findings.filter(x=>x.actions.length===0).length,
  outdatedObservations:gaps.summary.observationOld,
  noMatchedEvidence:gaps.summary.unmatched,
  reviewGatesMissing:closure.blocked,
 };
}
export function workstreamPlanText(plan:WorkstreamPlan):string{
 const lines=[
  "CYBERPILOT — SECURITY OPERATIONS WORKSTREAM PLAN",
  "Read-only suggested assignments. Does not create staff assignments.",
  "Findings assessed: "+plan.findings,
  "Tasks: "+plan.total,
  "Open findings: "+plan.openFindings,
  "No matched evidence: "+plan.noMatchedEvidence,
  "Observations predating work: "+plan.outdatedObservations,
  "",
 ];
 for(const section of plan.streams){
  lines.push(section.stream.toUpperCase()+" — "+section.total+" tasks");
  for(const [i,item] of section.items.entries()){
   lines.push(
    `${i+1}. ${item.title}`,
    "Finding: "+item.findingTitle,
    "Severity: "+item.severity,
    "Suggested owner role: "+item.ownerRole,
    "Next step: "+item.instructions,
    "Success criteria:",
    ...item.criteria.map(x=>"  - "+x),
    "Important limitations:",
    ...item.limitations.map(x=>"  - "+x),
    "",
   );
  }
 }
 lines.push("Tasks are suggestions derived from existing findings and action states.");
 return lines.join("\n")+"\n";
}
export function workstreamPlanCsv(plan:WorkstreamPlan):string{
 const cell=(value:string)=>{
  const safe=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
  return '"'+safe.replaceAll('"','""')+'"';
 };
 const rows=[
  ["Finding ID","Finding title","Severity","Workstream","Suggested role",
   "Task","Next action","Linked remediation","Criteria","Limitations","Finding timestamp UTC"],
  ...plan.items.map(x=>[
   x.findingId,x.findingTitle,x.severity,x.workstream,
   x.ownerRole,x.title,x.instructions,x.actionId??"",
   x.criteria.join(" | "),x.limitations.join(" | "),x.timestamp.toISOString(),
  ]),
 ];
 return "\uFEFF"+rows.map(x=>x.map(cell).join(",")).join("\r\n")+"\r\n";
}
