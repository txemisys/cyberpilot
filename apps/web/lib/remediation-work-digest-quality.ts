import type {DigestResult,DigestItem} from "./remediation-work-digest";

/**
 * Operational hygiene diagnostics across the full snapshot.
 * This does not calculate CyberScore or use scanner data.
 */
export type DigestQualityIssue="MISSING_OWNER"|"MISSING_TARGET"|"STALE_UPDATE"|
 "NO_CHECKLIST"|"NO_EVIDENCE_REFERENCE"|"OPEN_HANDOFF";
export type DigestQualityFinding={
 workId:string;title:string;issues:DigestQualityIssue[];
 severity:"HIGH"|"MEDIUM"|"LOW";suggestion:string;
};
export type DigestQualitySummary={
 inspected:number;withIssues:number;clean:number;
 high:number;medium:number;low:number;
 categories:Record<DigestQualityIssue,number>;
 completenessPercent:number;
};
const issueNames:DigestQualityIssue[]=[
 "MISSING_OWNER","MISSING_TARGET","STALE_UPDATE",
 "NO_CHECKLIST","NO_EVIDENCE_REFERENCE","OPEN_HANDOFF",
];
export function inspectDigestQuality(item:DigestItem):DigestQualityFinding{
 const issues:DigestQualityIssue[]=[];
 if(item.owner==="Unassigned")issues.push("MISSING_OWNER");
 if(item.dueAt===null)issues.push("MISSING_TARGET");
 if(item.daysIdle>=14)issues.push("STALE_UPDATE");
 if(item.checklistTotal===0)issues.push("NO_CHECKLIST");
 if(item.activeEvidence===0)issues.push("NO_EVIDENCE_REFERENCE");
 if(item.pendingHandoffs>0)issues.push("OPEN_HANDOFF");
 const severity=issues.some(issue=>issue==="MISSING_OWNER"||issue==="OPEN_HANDOFF")
  ?"HIGH":issues.length>=3?"MEDIUM":"LOW";
 const suggestion=issues.includes("OPEN_HANDOFF")
  ?"Request an explicit recipient decision on the pending handoff."
  :issues.includes("MISSING_OWNER")
  ?"Assign an eligible member through the authenticated work management flow."
  :issues.includes("MISSING_TARGET")
  ?"Agree and record a realistic operational target date."
  :issues.includes("STALE_UPDATE")
  ?"Request and record an updated progress report."
  :issues.includes("NO_CHECKLIST")
  ?"Record the operational steps required for this task."
  :issues.includes("NO_EVIDENCE_REFERENCE")
  ?"Link available supporting evidence without treating links as verification."
  :"Maintain this task's supporting records.";
 return {workId:item.id,title:item.title,issues,severity,suggestion};
}
export function summarizeDigestQuality(items:readonly DigestItem[]):DigestQualitySummary{
 const categories=Object.fromEntries(issueNames.map(issue=>[issue,0])) as
  Record<DigestQualityIssue,number>;
 let withIssues=0,high=0,medium=0,low=0;
 for(const item of items){
  const assessment=inspectDigestQuality(item);
  if(!assessment.issues.length)continue;
  withIssues++;
  if(assessment.severity==="HIGH")high++;
  else if(assessment.severity==="MEDIUM")medium++;
  else low++;
  for(const issue of assessment.issues)categories[issue]++;
 }
 const inspected=items.length;
 return {
  inspected,withIssues,clean:inspected-withIssues,high,medium,low,categories,
  completenessPercent:inspected?Math.round((inspected-withIssues)/inspected*100):100,
 };
}
export function buildDigestQualityReview(report:DigestResult){
 const preview=report.priorities.map(inspectDigestQuality);
 const summary=summarizeDigestQuality(report.priorities);
 return {
  generatedAt:report.generatedAt,
  summary,findings:preview.filter(item=>item.issues.length>0),
  coverage:{
   totalInventory:report.coverage.inventory,
   inspectedPreview:summary.inspected,
   omitted:report.coverage.excludedFromPreview,
   completeForEntireInventory:report.coverage.complete&&
    report.coverage.excludedFromPreview===0,
  },
  disclaimer:"Completeness is operational record hygiene, not independent evidence assessment or a security score.",
 };
}
