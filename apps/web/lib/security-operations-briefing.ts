import type {ReviewFinding} from "./finding-evidence-review";
import {buildManagementDecisionBoard,type ManagementDecision} from "./management-decision-board";
import {buildReviewExceptionRegister} from "./review-exceptions";
import {buildClosureReadinessPortfolio} from "./closure-readiness";
import {buildEvidenceGapReport} from "./evidence-gap-report";

export type WeeklyBriefingRisk="critical"|"high"|"moderate"|"low";
export type WeeklyBriefingAction={
 id:string;findingId:string;findingTitle:string;severity:string;
 actionId:string|null;title:string;ownerPrompt:string;
 priority:WeeklyBriefingRisk;justification:string;nextStep:string;
 verificationCriteria:string[];limitations:string[];
 evidenceObservedAt:Date|null;workRecordedAt:Date|null;
};
export type WeeklyBriefingSection={
 heading:string;description:string;
 metrics:{label:string;value:number;detail:string}[];
 tasks:WeeklyBriefingAction[];
};
export type WeeklySecurityBriefing={
 organizationLabel:string;scope:string;
 generatedFor:Date|null;findings:number;
 openFindings:number;resolvedFindings:number;
 criticalFindings:number;highFindings:number;
 observedFindings:number;declarationOnlyFindings:number;
 evidenceGaps:number;verificationBacklog:number;
 unresolvedExceptions:number;actionsRequiringApproval:number;
 sections:WeeklyBriefingSection[];
 nextActions:WeeklyBriefingAction[];
 caveats:string[];
};
function riskFromDecision(item:ManagementDecision):WeeklyBriefingRisk{
 if(item.priority==="urgent")return "critical";
 if(item.priority==="high")return "high";
 if(item.priority==="normal")return "moderate";
 return "low";
}
function toBriefingAction(item:ManagementDecision):WeeklyBriefingAction{
 return {
  id:item.id,findingId:item.findingId,findingTitle:item.findingTitle,
  severity:item.severity,actionId:item.actionId,title:item.title,
  ownerPrompt:item.category==="approval"?
   "An authorized approver must review the plan.":
   item.category==="verification"?
   "Assign a competent reviewer to validate current evidence.":
   item.category==="execution"?
   "Assign an authorized operator to complete the approved change.":
   item.category==="investigation"?
   "Assign an owner to investigate the finding and evidence.": 
   "Assign a reviewer to confirm closure provenance.",
  priority:riskFromDecision(item),
  justification:item.reason,
  nextStep:item.recommendedAction,
  verificationCriteria:[...item.successCriteria],
  limitations:[...item.warnings],
  evidenceObservedAt:item.lastObservedAt,
  workRecordedAt:item.lastRemediationAt,
 };
}
const severityRanks:Record<string,number>={
 CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,
};
function sortedActions(actions:readonly WeeklyBriefingAction[]):WeeklyBriefingAction[]{
 const ranks:Record<WeeklyBriefingRisk,number>={critical:0,high:1,moderate:2,low:3};
 return [...actions].sort((a,b)=>ranks[a.priority]-ranks[b.priority]||
  (severityRanks[a.severity]??5)-(severityRanks[b.severity]??5)||
  a.findingId.localeCompare(b.findingId)||a.id.localeCompare(b.id));
}
export function buildWeeklySecurityBriefing(
 findings:readonly ReviewFinding[],
 organizationLabel:string,
 scope="Selected findings",
):WeeklySecurityBriefing{
 const decisions=buildManagementDecisionBoard(findings);
 const exceptions=buildReviewExceptionRegister(findings);
 const readiness=buildClosureReadinessPortfolio(findings);
 const gaps=buildEvidenceGapReport(findings);
 const open=findings.filter(item=>item.status==="OPEN");
 const resolved=findings.filter(item=>item.status==="RESOLVED");
 const observed=findings.filter(item=>
  item.evidence.some(evidence=>evidence.source==="OBSERVED"));
 const declarationOnly=findings.filter(item=>
  item.evidence.some(evidence=>evidence.source==="DECLARED")&&
  !item.evidence.some(evidence=>evidence.source==="OBSERVED"));
 const actions=sortedActions(decisions.items.map(toBriefingAction));
 const verificationTasks=actions.filter(item=>
  decisions.items.some(decision=>decision.id===item.id&&
   decision.category==="verification"));
 const approvalTasks=actions.filter(item=>
  decisions.items.some(decision=>decision.id===item.id&&
   decision.category==="approval"));
 const investigationTasks=actions.filter(item=>
  decisions.items.some(decision=>decision.id===item.id&&
   decision.category==="investigation"));
 const executionTasks=actions.filter(item=>
  decisions.items.some(decision=>decision.id===item.id&&
   decision.category==="execution"));
 const exceptionsByFinding=new Set(exceptions.items.map(item=>item.findingId));
 const exceptionTasks=actions.filter(item=>exceptionsByFinding.has(item.findingId));
 const sections:WeeklyBriefingSection[]=[
  {
   heading:"Security risks requiring attention",
   description:"Open high-severity findings are review priorities, not claims about newly scanned controls.",
   metrics:[
    {label:"Open findings",value:open.length,
     detail:"The current persisted state is OPEN."},
    {label:"Critical open findings",value:open.filter(x=>x.severity==="CRITICAL").length,
     detail:"The stored severity is CRITICAL."},
    {label:"High open findings",value:open.filter(x=>x.severity==="HIGH").length,
     detail:"The stored severity is HIGH."},
   ],
   tasks:sortedActions(actions.filter(x=>["CRITICAL","HIGH"].includes(x.severity))).slice(0,10),
  },
  {
   heading:"Verification and evidence follow-up",
   description:"Recorded work, declared controls and old observations are not proof of effective remediation.",
   metrics:[
    {label:"Findings with missing or outdated evidence",
     value:gaps.summary.requiresAttention,
     detail:"All non-current evidence gap classes are counted."},
    {label:"Verification decisions",value:verificationTasks.length,
     detail:"Evidence review recommended by the operational decision planner."},
    {label:"Findings without matched evidence",value:gaps.summary.unmatched,
     detail:"Exact control-identifier matches only."},
   ],
   tasks:verificationTasks.slice(0,10),
  },
  {
   heading:"Approvals and pending operational work",
   description:"This briefing never authorizes remediation or executes external changes.",
   metrics:[
    {label:"Awaiting authorization",value:approvalTasks.length,
     detail:"Suggested approvals must use the existing authenticated workflow."},
    {label:"Work actions",value:executionTasks.length,
     detail:"Work remains subject to the authorized execution process."},
    {label:"Investigations",value:investigationTasks.length,
     detail:"These records require further triage or source review."},
   ],
   tasks:sortedActions([...approvalTasks,...executionTasks,...investigationTasks]).slice(0,10),
  },
  {
   heading:"Record consistency and closure review",
   description:"Recorded state inconsistencies are prompts for human review, not new vulnerabilities.",
   metrics:[
    {label:"Review exception flags",value:exceptions.count,
     detail:"One finding may have multiple flags."},
    {label:"Findings blocked by missing readiness gates",value:readiness.blocked,
     detail:"The eight closure review gates are operational checks."},
    {label:"Recorded resolved findings",value:resolved.length,
     detail:"Resolution states require provenance review."},
   ],
   tasks:exceptionTasks.slice(0,10),
  },
 ];
 return {
  organizationLabel,scope,generatedFor:null,
  findings:findings.length,openFindings:open.length,
  resolvedFindings:resolved.length,
  criticalFindings:open.filter(x=>x.severity==="CRITICAL").length,
  highFindings:open.filter(x=>x.severity==="HIGH").length,
  observedFindings:observed.length,
  declarationOnlyFindings:declarationOnly.length,
  evidenceGaps:gaps.summary.requiresAttention,
  verificationBacklog:verificationTasks.length,
  unresolvedExceptions:exceptions.count,
  actionsRequiringApproval:approvalTasks.length,
  sections,
  nextActions:actions,
  caveats:[
   "This briefing only covers the selected stored findings and their bounded linked records.",
   "Exact control-identifier matching may miss relevant evidence under a different identifier or scope.",
   "A control observation is not proof of a passing security test without reviewing its outcome.",
   "Acknowledgement and successful execution are not evidence-based verification.",
   "Recommendations do not approve, assign, execute or change any remediation workflow.",
   "CyberScore and finding status remain unchanged by briefing generation.",
  ],
 };
}
export function formatWeeklySecurityBriefing(report:WeeklySecurityBriefing):string{
 const lines=[
  "CYBERPILOT — SECURITY OPERATIONS BRIEFING",
  "Operational review of existing records, not a new scan or certification.",
  "",
  "Organization: "+report.organizationLabel,
  "Scope: "+report.scope,
  "Findings assessed: "+report.findings,
  "Open findings: "+report.openFindings,
  "Critical open findings: "+report.criticalFindings,
  "High open findings: "+report.highFindings,
  "Verification decisions: "+report.verificationBacklog,
  "Evidence gaps: "+report.evidenceGaps,
  "Review exception flags: "+report.unresolvedExceptions,
  "Approval decisions: "+report.actionsRequiringApproval,
  "",
 ];
 for(const section of report.sections){
  lines.push(section.heading.toUpperCase(),section.description);
  for(const metric of section.metrics)
   lines.push(metric.label+": "+metric.value+" — "+metric.detail);
  lines.push("NEXT ACTIONS");
  if(!section.tasks.length)lines.push("No tasks in this section.");
  for(const [index,task] of section.tasks.entries()){
   lines.push(
    String(index+1)+". "+task.title,
    "Finding: "+task.findingTitle+" ("+task.severity+")",
    "Priority: "+task.priority,
    "Ownership: "+task.ownerPrompt,
    "Next step: "+task.nextStep,
    "Evidence criteria:",
    ...task.verificationCriteria.map(x=>"  - "+x),
    "Review limitations:",
    ...(task.limitations.length?task.limitations.map(x=>"  - "+x):
     ["  - Review source scope and provenance"]),
   );
  }
  lines.push("");
 }
 lines.push("LIMITATIONS",...report.caveats.map(x=>"- "+x),"");
 return lines.join("\n");
}
const safeCsvCell=(value:string)=>{
 const safe=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
 return '"'+safe.replaceAll('"','""')+'"';
};
export function weeklyBriefingActionsCsv(report:WeeklySecurityBriefing):string{
 const rows=[
  ["Finding ID","Finding","Severity","Priority","Suggested action",
   "Suggested owner role","Reason","Next step","Action ID",
   "Evidence criteria","Limitations","Last observation UTC","Last work UTC"],
  ...report.nextActions.map(task=>[
   task.findingId,task.findingTitle,task.severity,task.priority,task.title,
   task.ownerPrompt,task.justification,task.nextStep,task.actionId??"",
   task.verificationCriteria.join(" | "),task.limitations.join(" | "),
   task.evidenceObservedAt?.toISOString()??"",
   task.workRecordedAt?.toISOString()??"",
  ]),
 ];
 return "\uFEFF"+rows.map(row=>row.map(safeCsvCell).join(",")).join("\r\n")+"\r\n";
}
