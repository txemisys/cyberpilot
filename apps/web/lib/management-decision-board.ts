import type {ReviewFinding} from "./finding-evidence-review";
import {buildFindingDossier} from "./finding-dossier";
import {collectFindingReviewExceptions} from "./review-exceptions";
import {buildVerificationPlan} from "./verification-plan";

export type ManagementPriority="urgent"|"high"|"normal"|"monitor";
export type ManagementDecision={
 id:string;findingId:string;findingTitle:string;severity:string;
 priority:ManagementPriority;rank:number;
 category:"verification"|"investigation"|"approval"|"execution"|"closure";
 title:string;reason:string;recommendedAction:string;
 prerequisites:string[];successCriteria:string[];
 warnings:string[];actionId:string|null;
 lastFindingSeenAt:Date;lastObservedAt:Date|null;
 lastRemediationAt:Date|null;verificationAt:Date|null;
};
export type ManagementDecisionSummary={
 total:number;urgent:number;high:number;normal:number;monitor:number;
 verification:number;investigation:number;approval:number;execution:number;closure:number;
 affectedFindings:number;
};
const severityOrder:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const priorityOrder:Record<ManagementPriority,number>={urgent:0,high:1,normal:2,monitor:3};
function priorityFor(severity:string,category:ManagementDecision["category"]):ManagementPriority{
 if(category==="verification"&&["CRITICAL","HIGH"].includes(severity))return "urgent";
 if(severity==="CRITICAL")return "urgent";
 if(["HIGH","MEDIUM"].includes(severity))return "high";
 if(category==="closure")return "monitor";
 return "normal";
}
function categorize(status:string):ManagementDecision["category"]{
 if(status==="collect-evidence"||status==="inspect-evidence")return "verification";
 if(status==="needs-investigation")return "investigation";
 if(status==="pending-approval")return "approval";
 if(status==="perform-work")return "execution";
 return "closure";
}
export function buildManagementDecisions(finding:ReviewFinding):ManagementDecision[]{
 const dossier=buildFindingDossier(finding);
 const exceptions=collectFindingReviewExceptions(finding);
 const plan=buildVerificationPlan([finding]);
 const decisions:ManagementDecision[]=plan.items.map(task=>{
  const category=categorize(task.status);
  const priority=priorityFor(finding.severity,category);
  const relatedExceptions=exceptions.filter(item=>
   item.remediationId===null||item.remediationId===task.actionId);
  return {
   id:task.id,findingId:finding.id,findingTitle:finding.title,
   severity:finding.severity,priority,
   rank:priorityOrder[priority]*10+(severityOrder[finding.severity]??5),
   category,title:task.title,reason:task.description,
   recommendedAction:task.suggestedNextStep,
   prerequisites:[...task.prerequisites],
   successCriteria:[...task.successCriteria],
   warnings:[...new Set([
    ...task.warnings,
    ...relatedExceptions.map(item=>item.explanation),
   ])],
   actionId:task.actionId,
   lastFindingSeenAt:finding.lastSeenAt,
   lastObservedAt:dossier.latestEvidenceAt,
   lastRemediationAt:dossier.latestWorkAt,
   verificationAt:dossier.latestVerificationAt,
  };
 });
 return decisions.sort((a,b)=>a.rank-b.rank||a.id.localeCompare(b.id));
}
export function buildManagementDecisionBoard(findings:readonly ReviewFinding[]):{
 items:ManagementDecision[];summary:ManagementDecisionSummary;
}{
 const items=findings.flatMap(buildManagementDecisions);
 items.sort((a,b)=>a.rank-b.rank||
  a.findingId.localeCompare(b.findingId)||a.id.localeCompare(b.id));
 const count=(value:ManagementDecision["category"])=>items.filter(x=>x.category===value).length;
 const priority=(value:ManagementPriority)=>items.filter(x=>x.priority===value).length;
 return {items,summary:{
  total:items.length,urgent:priority("urgent"),high:priority("high"),
  normal:priority("normal"),monitor:priority("monitor"),
  verification:count("verification"),investigation:count("investigation"),
  approval:count("approval"),execution:count("execution"),
  closure:count("closure"),
  affectedFindings:new Set(items.map(x=>x.findingId)).size,
 }};
}
function csvCell(value:string):string{
 const safe=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
 return '"'+safe.replaceAll('"','""')+'"';
}
export function managementDecisionsCsv(items:readonly ManagementDecision[]):string{
 const rows=[
  ["Finding ID","Finding","Severity","Priority","Category","Decision",
   "Reason","Next action","Remediation ID","Prerequisites","Success criteria",
   "Warnings","Last finding UTC","Last observation UTC","Last work UTC","Last verification UTC"],
  ...items.map(x=>[
   x.findingId,x.findingTitle,x.severity,x.priority,x.category,x.title,
   x.reason,x.recommendedAction,x.actionId??"",
   x.prerequisites.join(" | "),x.successCriteria.join(" | "),x.warnings.join(" | "),
   x.lastFindingSeenAt.toISOString(),
   x.lastObservedAt?.toISOString()??"",x.lastRemediationAt?.toISOString()??"",
   x.verificationAt?.toISOString()??"",
  ]),
 ];
 return "\uFEFF"+rows.map(row=>row.map(csvCell).join(",")).join("\r\n")+"\r\n";
}
export function managementDecisionsText(items:readonly ManagementDecision[]):string{
 const lines=[
  "CYBERPILOT — SECURITY OPERATIONS DECISION BOARD",
  "Recorded evidence and workflow data only. Not a security certification.",
  "Proposed decisions: "+items.length,"",
 ];
 for(const [index,item] of items.entries()){
  lines.push(
   `${index+1}. ${item.title}`,
   "Finding: "+item.findingTitle,
   "Severity and priority: "+item.severity+" / "+item.priority,
   "Reason: "+item.reason,
   "Recommended next action: "+item.recommendedAction,
   "Prerequisites:",
   ...(item.prerequisites.length?item.prerequisites.map(x=>"  - "+x):["  - None recorded"]),
   "Success criteria:",
   ...item.successCriteria.map(x=>"  - "+x),
   "Review limitations:",
   ...(item.warnings.length?item.warnings.map(x=>"  - "+x):["  - None identified by the rules"]),
   "",
  );
 }
 return lines.join("\n")+"\n";
}
