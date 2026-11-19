import{db,type Prisma}from "@cyberpilot/database";
import type{IntegratedReviewer}from "./integrated-risk-service";
import{buildOfflineRecoveryRehearsal,verifyRecoveryRehearsal,
 createRecoveryRemediationPlan,compareRecoveryRehearsals,
 defaultRecoveryRehearsalPolicy,
 type RecoveryRehearsalPolicy,type OfflineRecoveryRehearsal}
 from "./offline-recovery-rehearsal-domain";
import{listOfflineCaptures,readOfflineCapture}from
 "./offline-report-capture-service";
import type{OfflineCapture}from "./offline-report-capture-domain";
export class RecoveryRehearsalError extends Error{
 constructor(public readonly code:string){super(code);}
}
const fail=(code:string):never=>{throw new RecoveryRehearsalError(code);};
const id=(x:string)=>typeof x==="string"&&
 /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
type DbRehearsal=NonNullable<Awaited<ReturnType<
 typeof db.offlineRecoveryRehearsal.findFirst>>>;
export type RecoveryRehearsalSelection={
 captureIds:string[];policy?:RecoveryRehearsalPolicy;
 expectedCaptureDigests?:Record<string,string>;
};
async function authorize(actor:IntegratedReviewer,write:boolean){
 if(!id(actor.organizationId)||!id(actor.userId))
 fail("RECOVERY_ACTOR_INVALID");
 const member=await db.membership.findFirst({
 where:{organizationId:actor.organizationId,userId:actor.userId},
 select:{role:true},
 });
 if(!member||member.role!==actor.role)
 fail("RECOVERY_MEMBERSHIP_REQUIRED");
 if(write&&!["OWNER","ADMIN"].includes(member.role))
 fail("RECOVERY_MANAGER_REQUIRED");
 if(!["OWNER","ADMIN","AUDITOR"].includes(member.role))
 fail("RECOVERY_REVIEWER_REQUIRED");
}
function extractManifest(row:DbRehearsal){
 const candidate=row.manifest as unknown as OfflineRecoveryRehearsal;
 if(!candidate||candidate.schema!==
 "cyberpilot.offline.recovery.rehearsal.v1"||
 candidate.organizationId!==row.organizationId||
 candidate.digest!==row.manifestDigest||
 !verifyRecoveryRehearsal(candidate,row.organizationId).valid)
 fail("STORED_REHEARSAL_TAMPERED");
 return candidate;
}
async function loadSelected(actor:IntegratedReviewer,
 captureIds:string[]){
 if(!Array.isArray(captureIds)||captureIds.length===0||
 captureIds.length>100||captureIds.some(x=>!id(x))||
 new Set(captureIds).size!==captureIds.length)
 fail("RECOVERY_CAPTURE_SELECTION_INVALID");
 const selected=await Promise.all(captureIds.map(async captureId=>{
 const value=await readOfflineCapture(actor,captureId);
 if(value.organizationId!==actor.organizationId)
 fail("RECOVERY_CAPTURE_SCOPE_INVALID");
 return value.capture;
 }));
 return selected;
}
export async function runOfflineRecoveryRehearsal(
 actor:IntegratedReviewer,selection:RecoveryRehearsalSelection){
 await authorize(actor,true);
 const captures=await loadSelected(actor,selection.captureIds);
 if(selection.expectedCaptureDigests){
 const expectations=selection.expectedCaptureDigests;
 if(Object.keys(expectations).some(x=>
 !selection.captureIds.includes(x)))
 fail("UNEXPECTED_CAPTURE_DIGEST_KEY");
 if(captures.some(x=>expectations[x.id]!==x.payloadDigest))
 fail("STALE_OR_DIFFERENT_CAPTURE_SELECTION");
 }
 const report=buildOfflineRecoveryRehearsal({
 organizationId:actor.organizationId,
 executedAt:new Date().toISOString(),captures,
 policy:selection.policy??defaultRecoveryRehearsalPolicy(),
 });
 if(!verifyRecoveryRehearsal(report,actor.organizationId).valid)
 fail("RECOVERY_REHEARSAL_DIGEST_INVALID");
 const created=await db.offlineRecoveryRehearsal.create({
 data:{
 organizationId:actor.organizationId,
 captureIds:selection.captureIds as Prisma.InputJsonValue,
 manifest:report as unknown as Prisma.InputJsonValue,
 manifestDigest:report.digest,
 status:report.status,
 failures:report.issues as Prisma.InputJsonValue,
 createdById:actor.userId,
 createdAt:new Date(report.executedAt),
 },
 });
 return{
 rehearsalId:created.id,report,
 remediationPlan:createRecoveryRemediationPlan(report),
 actuallyRestoredDatabase:false as const,
 sentExternalRequests:0 as const,
 customerLiveCertification:false as const,
 };
}
export async function readOfflineRecoveryRehearsal(
 actor:IntegratedReviewer,rehearsalId:string){
 await authorize(actor,false);
 if(!id(rehearsalId))fail("RECOVERY_ID_INVALID");
 const row=await db.offlineRecoveryRehearsal.findFirst({
 where:{id:rehearsalId,organizationId:actor.organizationId},
 });
 if(!row)fail("RECOVERY_REHEARSAL_NOT_IN_TENANT");
 const report=extractManifest(row);
 return{
 rehearsalId:row.id,organizationId:actor.organizationId,
 createdAt:row.createdAt.toISOString(),createdById:row.createdById,
 report,remediationPlan:createRecoveryRemediationPlan(report),
 providerCalls:0 as const,
 databaseRestored:false as const,
 };
}
export async function listOfflineRecoveryRehearsals(
 actor:IntegratedReviewer,limit=50){
 await authorize(actor,false);
 if(!Number.isSafeInteger(limit)||limit<1||limit>100)
 fail("RECOVERY_LIST_LIMIT_INVALID");
 const rows=await db.offlineRecoveryRehearsal.findMany({
 where:{organizationId:actor.organizationId},
 orderBy:[{createdAt:"desc"},{id:"asc"}],
 take:limit+1,
 });
 const results=rows.slice(0,limit).map(row=>{
 const report=extractManifest(row);
 return{
 id:row.id,organizationId:row.organizationId,
 createdAt:row.createdAt.toISOString(),createdById:row.createdById,
 status:report.status,digest:report.digest,
 selectedCaptures:report.overview.selectedCaptures,
 blockedGates:report.overview.blockedGates,
 unverifiableGates:report.overview.unverifiableGates,
 report,
 };
 });
 return{
 schema:"cyberpilot.offline.recovery.inventory.v1" as const,
 organizationId:actor.organizationId,
 truncated:rows.length>limit,
 entries:results,
 summary:{
 total:results.length,
 passed:results.filter(x=>x.status==="PASS").length,
 blocked:results.filter(x=>x.status==="BLOCKED").length,
 incomplete:results.filter(x=>x.status==="INCOMPLETE").length,
 issues:results.reduce((n,x)=>n+x.blockedGates,0),
 },
 databaseRestores:0 as const,
 providerCalls:0 as const,
 externalCertification:false as const,
 };
}
export async function compareStoredRehearsals(
 actor:IntegratedReviewer,earlierId:string,laterId:string){
 await authorize(actor,false);
 if(!id(earlierId)||!id(laterId)||earlierId===laterId)
 fail("RECOVERY_PAIR_INVALID");
 const items=await db.offlineRecoveryRehearsal.findMany({
 where:{organizationId:actor.organizationId,
 id:{in:[earlierId,laterId]}},
 });
 if(items.length!==2)fail("RECOVERY_PAIR_NOT_IN_TENANT");
 const a=items.find(x=>x.id===earlierId);
 const b=items.find(x=>x.id===laterId);
 if(!a||!b)fail("RECOVERY_PAIR_MISSING");
 let diff;
 try{diff=compareRecoveryRehearsals(extractManifest(a),
 extractManifest(b));}
 catch{fail("RECOVERY_PAIR_NOT_COMPARABLE");}
 return{
 organizationId:actor.organizationId,
 comparison:diff,
 realRestoreSuccessfullyPerformed:false as const,
 };
}
export async function buildRecoveryAcceptanceMatrix(
 actor:IntegratedReviewer){
 await authorize(actor,false);
 const captures=await listOfflineCaptures(actor,{
 limit:100,includePayload:true,
 });
 const items=captures.captures as OfflineCapture[];
 const kinds=["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
 "EXECUTIVE","LONGITUDINAL"] as const;
 const byKind=kinds.map(kind=>{
 const matches=items.filter(x=>x.kind===kind).sort((a,b)=>
 b.createdAt.localeCompare(a.createdAt));
 const latest=matches[0];
 return{
 kind,selectedCaptureId:latest?.id??null,
 availableCaptures:matches.length,
 latestCapturedAt:latest?.createdAt??null,
 latestSourceComplete:latest?.sourceComplete??false,
 localDigestVerified:captures.validations.some(x=>
 x.id===latest?.id&&x.valid),
 crossReportLineageVerified:false as const,
 customerTenantAuthorized:false as const,
 };
 });
 const candidates=byKind.map(x=>x.selectedCaptureId)
 .filter((x):x is string=>x!==null);
 const rehearsal=candidates.length?
 buildOfflineRecoveryRehearsal({
 organizationId:actor.organizationId,executedAt:new Date().toISOString(),
 captures:items.filter(x=>candidates.includes(x.id)),
 policy:defaultRecoveryRehearsalPolicy(),
 }):null;
 return{
 organizationId:actor.organizationId,
 matrix:byKind,
 preview:rehearsal,
 blocking:rehearsal?.status!=="PASS",
 requiredKindsMissing:byKind.filter(x=>x.selectedCaptureId===null)
 .map(x=>x.kind),
 noSqlRestoreExecuted:true as const,
 noLiveProviderCalls:true as const,
 };
}
export async function auditRecoveryRehearsalInventory(
 actor:IntegratedReviewer){
 const list=await listOfflineRecoveryRehearsals(actor,100);
 const entries=list.entries;
 const repeated=entries.filter((x,i)=>entries.findIndex(y=>
 y.digest===x.digest)!==i);
 return{
 organizationId:actor.organizationId,
 totalRuns:entries.length,
 uniqueManifests:entries.length-repeated.length,
 duplicateIds:repeated.map(x=>x.id),
 failed:entries.filter(x=>x.status!=="PASS").map(x=>x.id),
 windowsCovered:entries.map(x=>x.createdAt.slice(0,10))
 .filter((x,i,all)=>all.indexOf(x)===i).sort(),
 state:entries.every(x=>x.report.status==="PASS")&&
 !list.truncated?"REHEARSALS_ONLY_PASS":"REVIEW_REQUIRED",
 certificateGranted:false as const,
 databaseRestorePerformed:false as const,
 };
}
