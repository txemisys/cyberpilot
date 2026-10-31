import type {ReviewFinding} from "./finding-evidence-review";
import {buildControlChronology} from "./control-chronology";
import {assessClosureReadiness} from "./closure-readiness";
import {buildFindingDossier} from "./finding-dossier";
import {collectFindingReviewExceptions} from "./review-exceptions";

export type AuditQuestionStatus="supported"|"incomplete"|"needs-review"|"not-applicable";
export type AuditQuestion={
 id:string;category:string;question:string;status:AuditQuestionStatus;
 explanation:string;references:string[];reviewInstruction:string;
};
export type AuditPacket={
 findingId:string;title:string;severity:string;status:string;
 questions:AuditQuestion[];supported:number;incomplete:number;
 reviewRequired:number;notApplicable:number;limitations:string[];
};
export type AuditPortfolio={
 packets:AuditPacket[];findings:number;questions:number;
 supported:number;incomplete:number;reviewRequired:number;
 criticalWithGaps:number;
};
const QUESTIONS=[
 {id:"finding-exists",category:"Finding",question:"Is the finding recorded in CyberPilot?",
  instruction:"Confirm the finding identifier, affected control scope and organization."},
 {id:"severity-known",category:"Finding",question:"Is a recognized severity recorded?",
  instruction:"Review severity against the actual organization exposure."},
 {id:"finding-recent",category:"Finding",question:"Is a valid last-seen timestamp recorded?",
  instruction:"Verify the last-seen date reflects the control's applicable scope."},
 {id:"observation",category:"Evidence",question:"Is an observed signal attributed to the finding?",
  instruction:"Check whether the observed evidence tests the same control and asset scope."},
 {id:"observation-time",category:"Evidence",question:"Is the latest observation timestamp available?",
  instruction:"Confirm that the observation timestamp comes from the source and is trustworthy."},
 {id:"evidence-quality",category:"Evidence",question:"Have unknown or errored evidence records been reviewed?",
  instruction:"Investigate failures; a missing or errored signal does not establish effective control."},
 {id:"declarations",category:"Evidence",question:"Have declarations been distinguished from observations?",
  instruction:"Do not count declarations as independent verification of a control."},
 {id:"remediation",category:"Remediation",question:"Is remediation recorded or an alternative resolution documented?",
  instruction:"Review linked actions and any independent resolution process."},
 {id:"authorization",category:"Remediation",question:"Is a remediation approval recorded where required?",
  instruction:"Review the authenticated approval workflow and approval scope."},
 {id:"work-progress",category:"Remediation",question:"Is guided work progress known?",
  instruction:"Confirm acknowledged steps against actual authorized implementation."},
 {id:"after-work",category:"Verification",question:"Was evidence observed after the last remediation work?",
  instruction:"Collect a fresh observation after work and inspect its outcome."},
 {id:"criteria",category:"Verification",question:"Are verification criteria recorded?",
  instruction:"Review each checklist item against authoritative evidence."},
 {id:"verified-action",category:"Verification",question:"Is there a verified remediation record?",
  instruction:"Check both workflow status and verification timestamp."},
 {id:"finding-closure",category:"Closure",question:"Is the finding recorded resolved?",
  instruction:"Review the finding's source resolution provenance."},
 {id:"consistency",category:"Closure",question:"Have status contradictions been investigated?",
  instruction:"Inspect mismatched verification and finding states before communicating closure."},
] as const;
type QuestionId=typeof QUESTIONS[number]["id"];
function validDate(value:Date|null):boolean{
 return value instanceof Date&&Number.isFinite(value.getTime());
}
export function buildAuditPacket(finding:ReviewFinding):AuditPacket{
 const dossier=buildFindingDossier(finding);
 const timeline=buildControlChronology(finding);
 const closure=assessClosureReadiness(finding);
 const exceptions=collectFindingReviewExceptions(finding);
 const verified=finding.actions.filter(a=>a.status==="VERIFIED"&&validDate(a.verifiedAt));
 const completed=finding.actions.filter(a=>a.completedAt!==null||a.status==="SUCCEEDED");
 const approved=finding.actions.filter(a=>a.approvedAt!==null);
 const hasActions=finding.actions.length>0;
 const observed=finding.evidence.filter(x=>x.source==="OBSERVED");
 const inconclusive=finding.evidence.filter(x=>x.source==="UNKNOWN"||x.source==="ERROR");
 const declared=finding.evidence.filter(x=>x.source==="DECLARED");
 const stepCount=finding.actions.reduce((sum,action)=>sum+action.steps.length,0);
 const acknowledged=finding.actions.reduce((sum,action)=>
  sum+action.steps.filter((_,index)=>action.acknowledgedSteps.has(index)).length,0);
 const hasCriteria=finding.actions.some(a=>a.verification.length>0);
 const predicates:Record<QuestionId,{
  status:AuditQuestionStatus;explanation:string;refs:string[];
 }>={
  "finding-exists":{
   status:"supported",explanation:"A stored finding identifier and title are available.",
   refs:[finding.id],
  },
  "severity-known":{
   status:["CRITICAL","HIGH","MEDIUM","LOW","INFO"].includes(finding.severity)?
    "supported":"needs-review",
   explanation:"Stored severity: "+finding.severity,refs:[finding.id],
  },
  "finding-recent":{
   status:validDate(finding.lastSeenAt)?"needs-review":"incomplete",
   explanation:"Recorded last seen: "+(validDate(finding.lastSeenAt)?
    finding.lastSeenAt.toISOString():"Unavailable"),refs:[finding.id],
  },
  observation:{
   status:observed.length?"needs-review":"incomplete",
   explanation:observed.length+" exact-identifier matched observed evidence records.",
   refs:observed.map(x=>x.id),
  },
  "observation-time":{
   status:timeline.lastObservationAt?"needs-review":"incomplete",
   explanation:"Latest observed timestamp: "+
    (timeline.lastObservationAt?.toISOString()??"Not recorded"),
   refs:observed.map(x=>x.id),
  },
  "evidence-quality":{
   status:inconclusive.length?"incomplete":"needs-review",
   explanation:inconclusive.length+" unknown or errored records.",
   refs:inconclusive.map(x=>x.id),
  },
  declarations:{
   status:declared.length?"needs-review":"not-applicable",
   explanation:declared.length+" declared records; declarations are not direct observation.",
   refs:declared.map(x=>x.id),
  },
  remediation:{
   status:hasActions?"supported":"incomplete",
   explanation:hasActions?`${finding.actions.length} linked remediation workflows.`:
    "No linked remediation workflow; an independent resolution may exist.",
   refs:finding.actions.map(a=>a.id),
  },
  authorization:{
   status:!hasActions?"not-applicable":approved.length?"needs-review":"incomplete",
   explanation:approved.length+" workflows with recorded approval date.",
   refs:approved.map(a=>a.id),
  },
  "work-progress":{
   status:stepCount===0?"not-applicable":"needs-review",
   explanation:acknowledged+" acknowledged steps of "+stepCount+
    "; acknowledgements do not establish control effectiveness.",
   refs:finding.actions.map(a=>a.id),
  },
  "after-work":{
   status:!completed.length?"not-applicable":timeline.observationAfterWork?
    "needs-review":"incomplete",
   explanation:timeline.observationAfterWork?
    "A dated observation follows recorded work; its outcome is unreviewed.":
    "No dated observed signal is known to follow completed remediation.",
   refs:observed.map(x=>x.id),
  },
  criteria:{
   status:!hasActions?"not-applicable":hasCriteria?"supported":"incomplete",
   explanation:hasCriteria?"At least one linked verification checklist is recorded.":
    "No linked action has recorded verification criteria.",
   refs:finding.actions.filter(a=>a.verification.length>0).map(a=>a.id),
  },
  "verified-action":{
   status:!hasActions?"not-applicable":verified.length?"needs-review":"incomplete",
   explanation:verified.length+" actions have both VERIFIED state and timestamp.",
   refs:verified.map(a=>a.id),
  },
  "finding-closure":{
   status:finding.status==="RESOLVED"?"needs-review":"incomplete",
   explanation:"Stored finding status: "+finding.status,
   refs:[finding.id],
  },
  consistency:{
   status:exceptions.length?"incomplete":"needs-review",
   explanation:exceptions.length+" exception flags; flags are review prompts, not new findings.",
   refs:exceptions.map(x=>x.id),
  },
 };
 const questions:AuditQuestion[]=QUESTIONS.map(q=>({
  id:q.id,category:q.category,question:q.question,
  status:predicates[q.id].status,
  explanation:predicates[q.id].explanation,
  references:predicates[q.id].refs,
  reviewInstruction:q.instruction,
 }));
 const count=(status:AuditQuestionStatus)=>questions.filter(q=>q.status===status).length;
 return {
  findingId:finding.id,title:finding.title,severity:finding.severity,
  status:finding.status,questions,
  supported:count("supported"),incomplete:count("incomplete"),
  reviewRequired:count("needs-review"),notApplicable:count("not-applicable"),
  limitations:[...new Set([
   ...dossier.warnings,...closure.warnings,
   "This packet is a documentation inventory and does not independently verify security compliance.",
  ])],
 };
}
export function buildAuditPortfolio(findings:readonly ReviewFinding[]):AuditPortfolio{
 const packets=findings.map(buildAuditPacket);
 const ranks:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 packets.sort((a,b)=>b.incomplete-a.incomplete||
  (ranks[a.severity]??5)-(ranks[b.severity]??5)||
  a.findingId.localeCompare(b.findingId));
 return {
  packets,findings:packets.length,
  questions:packets.reduce((sum,p)=>sum+p.questions.length,0),
  supported:packets.reduce((sum,p)=>sum+p.supported,0),
  incomplete:packets.reduce((sum,p)=>sum+p.incomplete,0),
  reviewRequired:packets.reduce((sum,p)=>sum+p.reviewRequired,0),
  criticalWithGaps:packets.filter(p=>p.severity==="CRITICAL"&&p.incomplete>0).length,
 };
}
const escapeCsv=(text:string)=>{
 const safe=/^[\s]*[=+@\-]/.test(text)?"'"+text:text;
 return '"'+safe.replaceAll('"','""')+'"';
};
export function auditPortfolioCsv(portfolio:AuditPortfolio):string{
 const rows=[
  ["Finding ID","Finding","Severity","Finding state","Category","Review question",
   "Recorded status","Reason","Required reviewer action","Record references"],
  ...portfolio.packets.flatMap(packet=>packet.questions.map(question=>[
   packet.findingId,packet.title,packet.severity,packet.status,
   question.category,question.question,question.status,
   question.explanation,question.reviewInstruction,
   question.references.join(" | "),
  ])),
 ];
 return "\uFEFF"+rows.map(row=>row.map(escapeCsv).join(",")).join("\r\n")+"\r\n";
}
export function auditPacketText(packet:AuditPacket):string{
 const lines=[
  "CYBERPILOT — FINDING AUDIT PREPARATION PACKET",
  "Stored documentation only; not a compliance certificate.",
  "Finding: "+packet.title,
  "Severity: "+packet.severity,
  "Status: "+packet.status,
  "Recorded supporting checks: "+packet.supported,
  "Incomplete checks: "+packet.incomplete,
  "Checks needing review: "+packet.reviewRequired,
  "",
 ];
 for(const question of packet.questions){
  lines.push(
   question.category.toUpperCase()+" — "+question.question,
   "Recorded state: "+question.status,
   "Facts: "+question.explanation,
   "Reviewer instruction: "+question.reviewInstruction,
   "References: "+(question.references.join(", ")||"None"),
   "",
  );
 }
 lines.push("LIMITATIONS",...packet.limitations.map(x=>"- "+x),"");
 return lines.join("\n");
}

export type AuditSectionSummary={
 category:string;questions:number;supported:number;incomplete:number;
 needsReview:number;notApplicable:number;affectedFindings:number;
};
export function auditSectionSummaries(portfolio:AuditPortfolio):AuditSectionSummary[]{
 const categories=["Finding","Evidence","Remediation","Verification","Closure"];
 return categories.map(category=>{
  const entries=portfolio.packets.flatMap(packet=>
   packet.questions.filter(question=>question.category===category)
    .map(question=>({findingId:packet.findingId,question})));
  return {
   category,questions:entries.length,
   supported:entries.filter(x=>x.question.status==="supported").length,
   incomplete:entries.filter(x=>x.question.status==="incomplete").length,
   needsReview:entries.filter(x=>x.question.status==="needs-review").length,
   notApplicable:entries.filter(x=>x.question.status==="not-applicable").length,
   affectedFindings:new Set(entries.filter(x=>x.question.status==="incomplete")
    .map(x=>x.findingId)).size,
  };
 });
}
export function auditPortfolioText(portfolio:AuditPortfolio):string{
 const lines=[
  "CYBERPILOT — AUDIT DOCUMENTATION PREPARATION REPORT",
  "This is an inventory of stored documentation, not a compliance attestation.",
  "Findings assessed: "+portfolio.findings,
  "Questions assessed: "+portfolio.questions,
  "Supported recorded facts: "+portfolio.supported,
  "Incomplete documentation: "+portfolio.incomplete,
  "Requires independent human review: "+portfolio.reviewRequired,
  "",
  "REVIEW CATEGORY SUMMARY",
 ];
 for(const section of auditSectionSummaries(portfolio)){
  lines.push(
   section.category+": "+section.questions+" questions",
   "  Supported: "+section.supported,
   "  Incomplete: "+section.incomplete,
   "  Needs review: "+section.needsReview,
   "  Not applicable: "+section.notApplicable,
   "  Findings with missing documents: "+section.affectedFindings,
  );
 }
 lines.push("", "INDIVIDUAL EVIDENCE PACKETS");
 for(const packet of portfolio.packets){
  lines.push(auditPacketText(packet),"");
 }
 lines.push(
  "Incomplete records do not by themselves prove that the security control is absent.",
  "Only an authorized independent reviewer can assess whether evidence satisfies applicable requirements.",
  "",
 );
 return lines.join("\n");
}

/** Review coverage ratios refer to documentation questions, not security controls. */
export function auditDocumentationRates(portfolio:AuditPortfolio):{
 supportedPercent:number|null;incompletePercent:number|null;reviewPercent:number|null;
}{
 const total=portfolio.questions;
 return {
  supportedPercent:total?Math.round(portfolio.supported/total*100):null,
  incompletePercent:total?Math.round(portfolio.incomplete/total*100):null,
  reviewPercent:total?Math.round(portfolio.reviewRequired/total*100):null,
 };
}
