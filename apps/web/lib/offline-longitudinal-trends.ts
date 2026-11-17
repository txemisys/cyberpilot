import {createHash} from "node:crypto";
/**
 * Conservative longitudinal assessment of historical persisted snapshots.
 * Snapshot score/null and scope class remain visible. No score from a
 * synthetic fixture is represented as a customer's live security trend.
 */
export type TrendSourceClass="SYNTHETIC"|"OFFLINE"|"LAB"|"LIVE_LABEL"|
 "DECLARED"|"UNKNOWN";
export type TrendRiskInput={
 id:string;organizationId:string;snapshotId:string;
 modelId:string;modelRevision:number;
 evaluatedAt:string;score:number|null;status:string;
 coveragePercent:number;verifiedControls:number;totalControls:number;
 riskPoints:number;sourceClass:string;
 manifestDigest:string;reportDigest:string;
};
export type TrendActionInput={
 actionId:string;organizationId:string;riskKey:string;
 status:string;priority:string;revision:number;
 ownerUserId:string|null;updatedAt:string;dueAt:string|null;
};
export type TrendEventInput={
 organizationId:string;actionId:string;revision:number;
 kind:string;previousStatus:string;nextStatus:string;
 actorUserId:string;occurredAt:string;
};
export type TrendInput={
 organizationId:string;evaluatedAt:string;
 assessments:TrendRiskInput[];
 actions:TrendActionInput[];events:TrendEventInput[];
 sourceCounts:{assessments:number;actions:number;events:number};
 caps:{assessments:number;actions:number;events:number};
};
export type TrendPoint={
 snapshotId:string;modelId:string;modelRevision:number;
 evaluatedAt:string;sourceClass:string;sourceKind:TrendSourceClass;
 score:number|null;coveragePercent:number;riskPoints:number;
 totalControls:number;verifiedControls:number;status:string;
 reportDigest:string;manifestDigest:string;
 uniqueScopeAuthenticated:false;
 customerSecurityCertified:false;
};
export type TrendPair={
 earlierId:string;laterId:string;
 from:string;to:string;
 scoreDelta:number|null;coverageDelta:number|null;
 riskPointDelta:number|null;
 verifiedControlsDelta:number|null;
 comparable:boolean;
 comparisonClass:"SAME_MODEL_SAME_SOURCE_KIND"|
 "INCOMPATIBLE_MODEL"|"INCOMPATIBLE_REVISION"|
 "INCOMPATIBLE_SOURCE_CLASS"|"INVALID_SCOPE"|
 "INSUFFICIENT_COVERAGE";
 reasonCodes:string[];
 interpretedRiskReduction:false;
 externallyVerifiedImprovement:false;
};
export type TrendActionPulse={
 total:number;active:number;blocked:number;reportedDone:number;
 exceptions:number;unassigned:number;
 expiredDue:number;events:number;invalidEventChains:number;
 providerRemediationsVerified:0;
};
export type TrendFinding={
 code:string;severity:"BLOCK"|"WARNING"|"INFO";
 snapshotIds:string[];description:string;
};
export type TrendReport={
 schema:"cyberpilot.offline.longitudinal.v1";
 organizationId:string;evaluatedAt:string;
 outcome:"INCOMPLETE"|"NO_SNAPSHOTS"|"COMPARABLE_WITH_LIMITS";
 points:TrendPoint[];pairs:TrendPair[];
 actionPulse:TrendActionPulse;
 findings:TrendFinding[];
 summary:{
  snapshots:number;comparablePairs:number;
  incomparablePairs:number;syntheticSnapshots:number;
  liveLabelsNotAuthenticated:number;nullScores:number;
  v2ModelRevisions:number;latestCoverage:number|null;
  latestStoredScore:number|null;latestSnapshotId:string|null;
  scoreImprovementProven:0;providerActionsPerformed:0;
  historicalV1Touched:0;
 };
 sourceComplete:boolean;scopeValid:boolean;
 tenantAuthenticationProven:false;
 noRawPersonalDataIncluded:true;
 historicalCyberScoreChanged:false;
 customerRiskReductionCertified:false;
 limitedToStoredAssessments:true;
 reportDigest:string;
};
export type TrendFilter={
 sourceKinds?:TrendSourceClass[];
 models?:string[];status?:string[];
 onlyComparable?:boolean;from?:string;to?:string;
 offset?:number;limit?:number;
};
const iso=(s:string)=>typeof s==="string"&&
 Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const sha=(s:string)=>createHash("sha256").update(s).digest("hex");
const unique=<T>(xs:readonly T[]):T[]=>[...new Set(xs)];
function canonical(x:unknown):string{
 if(x===null||typeof x==="string"||typeof x==="boolean"||
 typeof x==="number"){
  if(typeof x==="number"&&!Number.isFinite(x))
   throw Error("INVALID_NUMERIC_TREND");
  return JSON.stringify(x);
 }
 if(Array.isArray(x))return"["+x.map(canonical).join(",")+"]";
 if(typeof x==="object")return"{"+Object.entries(x)
 .sort(([a],[b])=>a.localeCompare(b))
 .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
 throw Error("NON_JSON_TREND");
}
const digest=(x:unknown)=>sha(canonical(x));
function classifySource(source:string):TrendSourceClass{
 const upper=source.toUpperCase();
 if(upper.includes("SYNTHETIC"))return"SYNTHETIC";
 if(upper.includes("LAB"))return"LAB";
 if(upper.includes("OFFLINE"))return"OFFLINE";
 if(upper.includes("LIVE"))return"LIVE_LABEL";
 if(upper.includes("DECLARED"))return"DECLARED";
 return"UNKNOWN";
}
function finding(code:string,severity:TrendFinding["severity"],
 description:string,snapshotIds:string[]=[]):TrendFinding{
 return{code,severity,description,snapshotIds:unique(snapshotIds).sort()};
}
function validPoint(x:TrendRiskInput){
 return Boolean(x.id&&x.snapshotId&&x.modelId&&
 Number.isSafeInteger(x.modelRevision)&&x.modelRevision>0&&
 iso(x.evaluatedAt)&&
 (x.score===null||Number.isFinite(x.score)&&x.score>=0&&x.score<=100)&&
 Number.isFinite(x.coveragePercent)&&x.coveragePercent>=0&&
 x.coveragePercent<=100&&
 Number.isSafeInteger(x.verifiedControls)&&x.verifiedControls>=0&&
 Number.isSafeInteger(x.totalControls)&&
 x.totalControls>=x.verifiedControls&&
 Number.isFinite(x.riskPoints)&&x.riskPoints>=0&&
 /^[a-f0-9]{64}$/.test(x.reportDigest)&&
 /^[a-f0-9]{64}$/.test(x.manifestDigest));
}
function point(x:TrendRiskInput):TrendPoint{
 return{
  snapshotId:x.snapshotId,modelId:x.modelId,
  modelRevision:x.modelRevision,evaluatedAt:x.evaluatedAt,
  sourceClass:x.sourceClass,sourceKind:classifySource(x.sourceClass),
  score:x.score,coveragePercent:x.coveragePercent,
  riskPoints:x.riskPoints,totalControls:x.totalControls,
  verifiedControls:x.verifiedControls,status:x.status,
  reportDigest:x.reportDigest,manifestDigest:x.manifestDigest,
  uniqueScopeAuthenticated:false,customerSecurityCertified:false,
 };
}
function comparePair(a:TrendPoint,b:TrendPoint):TrendPair{
 const reasons:string[]=[];
 let comparisonClass:TrendPair["comparisonClass"]=
  "SAME_MODEL_SAME_SOURCE_KIND";
 if(a.modelId!==b.modelId){
  reasons.push("DIFFERENT_MODEL_IDS");
  comparisonClass="INCOMPATIBLE_MODEL";
 }
 if(a.modelRevision!==b.modelRevision){
  reasons.push("MODEL_REVISION_CHANGED");
  if(comparisonClass==="SAME_MODEL_SAME_SOURCE_KIND")
   comparisonClass="INCOMPATIBLE_REVISION";
 }
 if(a.sourceKind!==b.sourceKind){
  reasons.push("SOURCE_AUTHENTICITY_CLASSES_DIFFER");
  if(comparisonClass==="SAME_MODEL_SAME_SOURCE_KIND")
   comparisonClass="INCOMPATIBLE_SOURCE_CLASS";
 }
 if(a.evaluatedAt>=b.evaluatedAt){
  reasons.push("NONCHRONOLOGICAL_SNAPSHOTS");
  comparisonClass="INVALID_SCOPE";
 }
 if(a.status==="INVALID_EVIDENCE"||b.status==="INVALID_EVIDENCE"){
  reasons.push("INVALID_EVIDENCE_SNAPSHOT");
  comparisonClass="INVALID_SCOPE";
 }
 if(a.score===null||b.score===null){
  reasons.push("NULL_SCORE_IN_ONE_OR_BOTH_SNAPSHOTS");
  if(comparisonClass==="SAME_MODEL_SAME_SOURCE_KIND")
   comparisonClass="INSUFFICIENT_COVERAGE";
 }
 if(a.totalControls!==b.totalControls)
  reasons.push("CONTROL_POPULATIONS_DIFFER");
 if(a.sourceKind!=="LIVE_LABEL"||b.sourceKind!=="LIVE_LABEL")
  reasons.push("NO_AUTHENTICATED_LIVE_SCOPE");
 else reasons.push("STORED_LIVE_LABEL_NOT_INDEPENDENTLY_AUTHENTICATED");
 const comparable=comparisonClass==="SAME_MODEL_SAME_SOURCE_KIND"&&
  a.totalControls===b.totalControls;
 return{
  earlierId:a.snapshotId,laterId:b.snapshotId,
  from:a.evaluatedAt,to:b.evaluatedAt,
  scoreDelta:comparable&&a.score!==null&&b.score!==null?
    b.score-a.score:null,
  coverageDelta:comparable?
    b.coveragePercent-a.coveragePercent:null,
  riskPointDelta:comparable?
    b.riskPoints-a.riskPoints:null,
  verifiedControlsDelta:comparable?
    b.verifiedControls-a.verifiedControls:null,
  comparable,comparisonClass,
  reasonCodes:unique(reasons),
  interpretedRiskReduction:false,externallyVerifiedImprovement:false,
 };
}
function pulse(actions:TrendActionInput[],events:TrendEventInput[],
 asOf:string):TrendActionPulse{
 let broken=0;
 for(const action of actions){
  const chain=events.filter(x=>x.actionId===action.actionId).sort(
   (a,b)=>a.revision-b.revision);
  if(chain.length!==action.revision||
   chain.some((x,i)=>x.revision!==i+1||
     x.organizationId!==action.organizationId)||
   chain.at(-1)?.nextStatus!==action.status)
    broken++;
 }
 return{
  total:actions.length,
  active:actions.filter(x=>["OPEN","IN_PROGRESS","REOPENED"].includes(x.status)).length,
  blocked:actions.filter(x=>x.status==="BLOCKED").length,
  reportedDone:actions.filter(x=>x.status==="DONE_REPORTED").length,
  exceptions:actions.filter(x=>x.status==="EXCEPTION").length,
  unassigned:actions.filter(x=>x.ownerUserId===null).length,
  expiredDue:actions.filter(x=>x.dueAt!==null&&x.dueAt<asOf&&
   !["DONE_REPORTED","EXCEPTION"].includes(x.status)).length,
  events:events.length,invalidEventChains:broken,
  providerRemediationsVerified:0,
 };
}
export function buildTrendReport(input:TrendInput):TrendReport{
 if(!input.organizationId||!iso(input.evaluatedAt))
  throw Error("TREND_SCOPE_INVALID");
 const foreign=[
  ...input.assessments.filter(x=>x.organizationId!==input.organizationId)
   .map(x=>x.id),
  ...input.actions.filter(x=>x.organizationId!==input.organizationId)
   .map(x=>x.actionId),
  ...input.events.filter(x=>x.organizationId!==input.organizationId)
   .map(x=>x.actionId),
 ];
 if(foreign.length)throw Error("CROSS_TENANT_TREND_INPUT");
 if(input.assessments.length>200||input.actions.length>500||
   input.events.length>2000)
  throw Error("TREND_SOURCE_CAPACITY_EXCEEDED");
 const counts=input.sourceCounts,caps=input.caps;
 const complete=(Object.keys(counts) as Array<keyof typeof counts>)
  .every(k=>Number.isSafeInteger(counts[k])&&counts[k]>=0&&
   counts[k]<=caps[k]);
 const findings:TrendFinding[]=[];
 if(!complete)findings.push(finding("TRUNCATED_SOURCE","BLOCK",
  "One or more historical source read windows were truncated."));
 const invalid=input.assessments.filter(x=>!validPoint(x));
 if(invalid.length)findings.push(finding("INVALID_SNAPSHOT","BLOCK",
  "Stored snapshots failed numeric or provenance validation.",
  invalid.map(x=>x.snapshotId)));
 const accepted=input.assessments.filter(validPoint);
 if(new Set(accepted.map(x=>x.snapshotId)).size!==accepted.length)
  findings.push(finding("DUPLICATE_SNAPSHOT_ID","BLOCK",
   "One snapshot ID occurs more than once."));
 const points=accepted.map(point).sort((a,b)=>
  a.evaluatedAt.localeCompare(b.evaluatedAt)||
  a.snapshotId.localeCompare(b.snapshotId));
 const pairs:TrendPair[]=[];
 for(let i=1;i<points.length;i++)
  pairs.push(comparePair(points[i-1]!,points[i]!));
 for(const pair of pairs){
  if(!pair.comparable)findings.push(finding(
   "INCOMPARABLE_ASSESSMENTS","WARNING",
   pair.reasonCodes.join(";"),
   [pair.earlierId,pair.laterId]));
  if(pair.comparable&&pair.reasonCodes.includes(
    "STORED_LIVE_LABEL_NOT_INDEPENDENTLY_AUTHENTICATED"))
   findings.push(finding("LIVE_PROVENANCE_NOT_REVALIDATED","WARNING",
    "A stored LIVE class does not establish external consent or scope.",
    [pair.earlierId,pair.laterId]));
 }
 const actionPulse=pulse(input.actions,input.events,input.evaluatedAt);
 if(actionPulse.invalidEventChains)
  findings.push(finding("ACTION_AUDIT_CHAIN_INCOMPLETE","BLOCK",
   "One or more action revision histories are incomplete."));
 const latest=points.at(-1);
 const distinctModels=unique(points.map(x=>
  x.modelId+":"+x.modelRevision));
 const base={
  schema:"cyberpilot.offline.longitudinal.v1" as const,
  organizationId:input.organizationId,evaluatedAt:input.evaluatedAt,
  outcome:(findings.some(x=>x.severity==="BLOCK")?"INCOMPLETE":
   !points.length?"NO_SNAPSHOTS":"COMPARABLE_WITH_LIMITS") as
   TrendReport["outcome"],
  points,pairs,actionPulse,findings,
  summary:{
   snapshots:points.length,
   comparablePairs:pairs.filter(x=>x.comparable).length,
   incomparablePairs:pairs.filter(x=>!x.comparable).length,
   syntheticSnapshots:points.filter(x=>["SYNTHETIC","LAB","OFFLINE"]
    .includes(x.sourceKind)).length,
   liveLabelsNotAuthenticated:points.filter(x=>
    x.sourceKind==="LIVE_LABEL").length,
   nullScores:points.filter(x=>x.score===null).length,
   v2ModelRevisions:distinctModels.length,
   latestCoverage:latest?.coveragePercent??null,
   latestStoredScore:latest?.score??null,
   latestSnapshotId:latest?.snapshotId??null,
   scoreImprovementProven:0 as const,
   providerActionsPerformed:0 as const,
   historicalV1Touched:0 as const,
  },
  sourceComplete:complete,scopeValid:foreign.length===0,
  tenantAuthenticationProven:false as const,
  noRawPersonalDataIncluded:true as const,
  historicalCyberScoreChanged:false as const,
  customerRiskReductionCertified:false as const,
  limitedToStoredAssessments:true as const,
 };
 return{...base,reportDigest:digest(base)};
}
export function verifyTrendReport(report:TrendReport,tenant?:string){
 const errors:string[]=[];
 const{reportDigest,...base}=report;
 if(digest(base)!==reportDigest)errors.push("DIGEST_MISMATCH");
 if(tenant&&tenant!==report.organizationId)errors.push("TENANT_MISMATCH");
 if(report.tenantAuthenticationProven!==false||
   report.historicalCyberScoreChanged!==false||
   report.customerRiskReductionCertified!==false||
   report.summary.scoreImprovementProven!==0||
   report.summary.providerActionsPerformed!==0)
  errors.push("FALSE_SECURITY_ASSERTION");
 if(report.pairs.some(x=>x.externallyVerifiedImprovement!==false||
   x.interpretedRiskReduction!==false))
  errors.push("FALSE_TREND_CERTIFICATION");
 return{valid:errors.length===0,errors};
}
export function selectTrendPoints(report:TrendReport,filter:TrendFilter={}){
 if(!verifyTrendReport(report).valid)throw Error("INVALID_TREND_REPORT");
 const offset=filter.offset??0,limit=filter.limit??40;
 if(!Number.isSafeInteger(offset)||offset<0||
   !Number.isSafeInteger(limit)||limit<1||limit>200)
  throw Error("INVALID_TREND_PAGING");
 const rows=report.points.filter(x=>
  (!filter.sourceKinds||filter.sourceKinds.includes(x.sourceKind))&&
  (!filter.models||filter.models.includes(x.modelId))&&
  (!filter.status||filter.status.includes(x.status))&&
  (!filter.from||x.evaluatedAt>=filter.from)&&
  (!filter.to||x.evaluatedAt<=filter.to)&&
  (!filter.onlyComparable||report.pairs.some(pair=>
   pair.comparable&&
   (pair.earlierId===x.snapshotId||pair.laterId===x.snapshotId))));
 return{
  organizationId:report.organizationId,total:rows.length,
  items:rows.slice(offset,offset+limit),
  nextOffset:offset+limit<rows.length?offset+limit:null,
  fullCoverageCertified:false as const,
 };
}
export function compareTrendReports(
 before:TrendReport,after:TrendReport){
 if(!verifyTrendReport(before).valid||!verifyTrendReport(after).valid||
  before.organizationId!==after.organizationId||
  before.evaluatedAt>=after.evaluatedAt)
  throw Error("INVALID_LONGITUDINAL_COMPARISON");
 const oldIds=new Set(before.points.map(x=>x.snapshotId));
 const nextIds=new Set(after.points.map(x=>x.snapshotId));
 return{
  organizationId:before.organizationId,
  beforeDigest:before.reportDigest,afterDigest:after.reportDigest,
  newSnapshots:after.points.filter(x=>!oldIds.has(x.snapshotId))
   .map(x=>x.snapshotId),
  snapshotsOutsideWindow:before.points.filter(x=>
   !nextIds.has(x.snapshotId)).map(x=>x.snapshotId),
  comparablePairsDelta:after.summary.comparablePairs-
   before.summary.comparablePairs,
  sourceWindowMayChange:true as const,
  scoreImprovementIndependentlyEstablished:false as const,
  historicalV1ScoreComparable:false as const,
 };
}
export function exportTrendReport(
 report:TrendReport,format:"JSON"|"CSV"|"MARKDOWN"){
 if(!verifyTrendReport(report).valid)throw Error("INVALID_TREND_EXPORT");
 const stem="offline-trend-"+report.evaluatedAt.slice(0,10);
 if(format==="JSON")return{
  filename:stem+".json",mime:"application/json",
  content:JSON.stringify(report,null,2),
 };
 const q=(x:string|number|null)=>'"'+String(x??"").replaceAll('"','""')+'"';
 if(format==="CSV")return{
  filename:stem+".csv",mime:"text/csv",
  content:[
   "snapshotId,modelId,revision,sourceKind,evaluatedAt,score,coverage,verifiedControls",
   ...report.points.map(x=>[
    x.snapshotId,x.modelId,x.modelRevision,x.sourceKind,
    x.evaluatedAt,x.score,x.coveragePercent,x.verifiedControls,
   ].map(q).join(",")),
  ].join("\n"),
 };
 if(format!=="MARKDOWN")throw Error("INVALID_TREND_FORMAT");
 return{
  filename:stem+".md",mime:"text/markdown",
  content:[
   "# Stored assessment history (not a LIVE security claim)",
   "Organization: "+report.organizationId,
   "Evaluated: "+report.evaluatedAt,
   "Digest: "+report.reportDigest,
   "Outcome: "+report.outcome,"",
   "## Stored assessments",
   ...report.points.map(x=>
    "- "+x.evaluatedAt+": "+x.snapshotId+
    " ["+x.modelId+"@"+x.modelRevision+
    ", "+x.sourceKind+"] score="+(x.score??"unassessable")+
    ", coverage="+x.coveragePercent+"%"),
   "",
   "## Comparable adjacent snapshots",
   ...report.pairs.map(x=>
    "- "+x.earlierId+" → "+x.laterId+
    ": "+x.comparisonClass+
    ", Δscore="+(x.scoreDelta??"n/a")+
    ", constraints="+x.reasonCodes.join(";")),
   "",
   "No actual customer security improvement is established.",
  ].join("\n"),
 };
}
