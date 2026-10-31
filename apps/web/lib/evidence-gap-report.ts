import type {ReviewFinding} from "./finding-evidence-review";
export type EvidenceGapKind="unmatched"|"declaration-only"|"observation-old"|"observation-current"|"inconclusive"|"unresolved-after-work";
export type EvidenceGap={
 findingId:string;findingTitle:string;severity:string;kind:EvidenceGapKind;
 description:string;nextStep:string;observationAt:Date|null;
 lastFindingSeenAt:Date;lastWorkAt:Date|null;observedCount:number;
 declaredCount:number;erroredCount:number;actionCount:number;
};
export type EvidenceGapSummary={
 total:number;unmatched:number;declarationOnly:number;
 observationOld:number;observationCurrent:number;inconclusive:number;
 unresolvedAfterWork:number;requiresAttention:number;
};
function latest(dates:readonly (Date|null)[]):Date|null{
 const valid=dates.filter((x):x is Date=>x!==null&&Number.isFinite(x.getTime()));
 if(!valid.length)return null;
 return valid.reduce((a,b)=>a.getTime()>b.getTime()?a:b);
}
export function classifyFindingEvidenceGap(finding:ReviewFinding):EvidenceGap{
 const observed=finding.evidence.filter(e=>e.source==="OBSERVED");
 const declared=finding.evidence.filter(e=>e.source==="DECLARED");
 const failures=finding.evidence.filter(e=>e.source==="ERROR"||e.source==="UNKNOWN");
 const latestSeen=latest(observed.map(x=>x.lastObservedAt??x.capturedAt));
 const lastWork=latest(finding.actions.map(a=>a.completedAt??a.startedAt));
 const observationOutdated=Boolean(latestSeen&&lastWork&&latestSeen<lastWork);
 const completedWithoutVerification=finding.actions.some(a=>
  a.status==="SUCCEEDED"||(a.mode==="GUIDED"&&
  a.status==="APPROVED"&&a.steps.length>0&&
  a.steps.every((_,index)=>a.acknowledgedSteps.has(index))));
 let kind:EvidenceGapKind;
 if(!finding.evidence.length)kind="unmatched";
 else if(!observed.length&&declared.length)kind="declaration-only";
 else if(!observed.length)kind="inconclusive";
 else if(observationOutdated)kind="observation-old";
 else if(completedWithoutVerification&&finding.status==="OPEN")kind="unresolved-after-work";
 else kind="observation-current";
 const messages:Record<EvidenceGapKind,[string,string]>={
  unmatched:[
   "No evidence is linked by exact control identifier.",
   "Check the source control mapping and collect relevant observed evidence.",
  ],
  "declaration-only":[
   "Only declarations were matched; independent observation is unavailable.",
   "Connect an authorized evidence source or review the control manually.",
  ],
  inconclusive:[
   "Matched evidence is unknown or an error.",
   "Review collection errors and obtain an authoritative result.",
  ],
  "observation-old":[
   "The latest matched observation predates recorded remediation work.",
   "Refresh the observation and compare the affected control.",
  ],
  "unresolved-after-work":[
   "Work was completed or acknowledged, but the finding is still open.",
   "Check fresh evidence and use the existing verification workflow.",
  ],
  "observation-current":[
   "A matched observation is recorded; its scope and conclusion still require review.",
   "Review the observation and finding state together.",
  ],
 };
 return {
  findingId:finding.id,findingTitle:finding.title,severity:finding.severity,
  kind,description:messages[kind][0],nextStep:messages[kind][1],
  observationAt:latestSeen,lastFindingSeenAt:finding.lastSeenAt,
  lastWorkAt:lastWork,observedCount:observed.length,
  declaredCount:declared.length,erroredCount:failures.length,
  actionCount:finding.actions.length,
 };
}
export function buildEvidenceGapReport(findings:readonly ReviewFinding[]):{
 items:EvidenceGap[];summary:EvidenceGapSummary;
}{
 const items=findings.map(classifyFindingEvidenceGap);
 const count=(kind:EvidenceGapKind)=>items.filter(x=>x.kind===kind).length;
 const summary={
  total:items.length,unmatched:count("unmatched"),
  declarationOnly:count("declaration-only"),
  observationOld:count("observation-old"),
  observationCurrent:count("observation-current"),
  inconclusive:count("inconclusive"),
  unresolvedAfterWork:count("unresolved-after-work"),
  requiresAttention:items.filter(x=>x.kind!=="observation-current").length,
 };
 const rank:Record<EvidenceGapKind,number>={
  "observation-old":0,"unresolved-after-work":1,unmatched:2,
  "declaration-only":3,inconclusive:4,"observation-current":5,
 };
 const severity:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 items.sort((a,b)=>rank[a.kind]-rank[b.kind]||
  (severity[a.severity]??5)-(severity[b.severity]??5)||
  a.findingId.localeCompare(b.findingId));
 return {items,summary};
}
const safeCsv=(value:string)=>'"'+
 (/^[\s]*[=+@\-]/.test(value)?"'"+value:value).replaceAll('"','""')+'"';
export function exportEvidenceGaps(items:readonly EvidenceGap[]):string{
 const rows=[
  ["Finding ID","Finding","Severity","Evidence gap","Explanation","Next action",
   "Observed signals","Declared signals","Inconclusive signals","Remediation actions",
   "Latest observation UTC","Last work UTC","Finding last seen UTC"],
  ...items.map(x=>[x.findingId,x.findingTitle,x.severity,x.kind,
   x.description,x.nextStep,String(x.observedCount),String(x.declaredCount),
   String(x.erroredCount),String(x.actionCount),
   x.observationAt?.toISOString()??"",x.lastWorkAt?.toISOString()??"",
   x.lastFindingSeenAt.toISOString()]),
 ];
 return "\uFEFF"+rows.map(row=>row.map(safeCsv).join(",")).join("\r\n")+"\r\n";
}
