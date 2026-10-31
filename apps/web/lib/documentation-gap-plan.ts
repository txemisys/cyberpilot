import type {ReviewFinding} from "./finding-evidence-review";
import {buildAuditPacket,type AuditQuestion, type AuditQuestionStatus} from "./audit-preparation";
export type DocumentationGapCategory="finding"|"evidence"|"remediation"|"verification"|"closure";
export type DocumentationGap={
 id:string;findingId:string;findingTitle:string;severity:string;
 findingStatus:string;category:DocumentationGapCategory;
 question:string;recordedStatus:AuditQuestionStatus;explanation:string;
 requiredReviewerAction:string;references:string[];
 priority:number;nextReviewStep:string;impact:string;
};
export type DocumentationGapPlan={
 items:DocumentationGap[];total:number;affectedFindings:number;
 missing:number;requiresReview:number;
 critical:number;high:number;
 categories:{name:DocumentationGapCategory;items:number;findings:number;critical:number}[];
};
const severityRanks:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const categories:Record<string,DocumentationGapCategory>={
 Finding:"finding",Evidence:"evidence",Remediation:"remediation",
 Verification:"verification",Closure:"closure",
};
const categoryPriority:Record<DocumentationGapCategory,number>={
 evidence:0,verification:1,remediation:2,closure:3,finding:4,
};
function nextStep(question:AuditQuestion):string{
 if(question.status==="incomplete")return "Gather the missing record, then review its scope and provenance.";
 return "Arrange a competent human assessment of the stored facts and security outcome.";
}
function impactText(category:DocumentationGapCategory):string{
 switch(category){
  case "evidence":return "Security outcome cannot be independently established from this documentation.";
  case "verification":return "Implementation or a timestamp is insufficient to demonstrate effective remediation.";
  case "remediation":return "Approval, implementation or remediation history may be incomplete.";
  case "closure":return "Finding status and underlying evidence may not be reconciled.";
  case "finding":return "The finding's recorded scope, severity or observation date requires review.";
 }
}
export function deriveDocumentationGaps(finding:ReviewFinding):DocumentationGap[]{
 const packet=buildAuditPacket(finding);
 const gaps=packet.questions.filter(q=>q.status==="incomplete"||q.status==="needs-review");
 return gaps.map(q=>{
  const category=categories[q.category]??"finding";
  const priority=(q.status==="incomplete"?0:50)+
   categoryPriority[category]*10+(severityRanks[finding.severity]??5);
  return {
   id:finding.id+":"+q.id,
   findingId:finding.id,findingTitle:finding.title,severity:finding.severity,
   findingStatus:finding.status,category,question:q.question,
   recordedStatus:q.status,explanation:q.explanation,
   requiredReviewerAction:q.reviewInstruction,references:[...q.references],
   priority,nextReviewStep:nextStep(q),impact:impactText(category),
  };
 });
}
export function buildDocumentationGapPlan(findings:readonly ReviewFinding[]):DocumentationGapPlan{
 const items=findings.flatMap(deriveDocumentationGaps).sort((a,b)=>
  a.priority-b.priority||a.findingId.localeCompare(b.findingId)||a.id.localeCompare(b.id));
 const names=["evidence","verification","remediation","closure","finding"] as const;
 return {
  items,total:items.length,
  affectedFindings:new Set(items.map(x=>x.findingId)).size,
  missing:items.filter(x=>x.recordedStatus==="incomplete").length,
  requiresReview:items.filter(x=>x.recordedStatus==="needs-review").length,
  critical:items.filter(x=>x.severity==="CRITICAL").length,
  high:items.filter(x=>x.severity==="HIGH").length,
  categories:names.map(name=>{
   const subset=items.filter(x=>x.category===name);
   return {
    name,items:subset.length,
    findings:new Set(subset.map(x=>x.findingId)).size,
    critical:subset.filter(x=>x.severity==="CRITICAL").length,
   };
  }),
 };
}
export function documentationGapCsv(plan:DocumentationGapPlan):string{
 const safe=(value:string):string=>{
  const normalized=/^[\s]*[=+@\-]/.test(value)?"'"+value:value;
  return '"'+normalized.replaceAll('"','""')+'"';
 };
 const rows=[
  ["Finding ID","Finding","Severity","Finding status","Category",
   "Documentation question","Recorded state","Facts","Impact",
   "Required reviewer action","Next step","References"],
  ...plan.items.map(x=>[
   x.findingId,x.findingTitle,x.severity,x.findingStatus,x.category,
   x.question,x.recordedStatus,x.explanation,x.impact,
   x.requiredReviewerAction,x.nextReviewStep,x.references.join(" | "),
  ]),
 ];
 return "\uFEFF"+rows.map(row=>row.map(safe).join(",")).join("\r\n")+"\r\n";
}
export function documentationGapText(plan:DocumentationGapPlan):string{
 const lines=[
  "CYBERPILOT — SECURITY DOCUMENTATION GAPS",
  "Read-only preparation agenda; incomplete documentation is not proof of insecure controls.",
  "Review questions: "+plan.total,
  "Missing documentation: "+plan.missing,
  "Questions requiring review: "+plan.requiresReview,
  "Affected findings: "+plan.affectedFindings,
  "",
 ];
 for(const section of plan.categories){
  lines.push(section.name.toUpperCase(),"Review questions: "+section.items);
  for(const item of plan.items.filter(x=>x.category===section.name)){
   lines.push(
    "Finding: "+item.findingTitle+" ("+item.severity+")",
    "Question: "+item.question,
    "State: "+item.recordedStatus,
    "Recorded facts: "+item.explanation,
    "Impact: "+item.impact,
    "Reviewer instruction: "+item.requiredReviewerAction,
    "Next action: "+item.nextReviewStep,
    "References: "+(item.references.join(", ")||"None"),
    "",
   );
  }
 }
 lines.push("Verify results through an authorized reviewer; this plan does not perform scans.");
 return lines.join("\n")+"\n";
}
