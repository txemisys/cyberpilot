import{db,type Prisma}from "@cyberpilot/database";
import type{IntegratedReviewer}from "./integrated-risk-service";
import{collectIntegratedRiskDigest}from "./integrated-risk-service";
import{collectEvidenceDecisionReport}from "./evidence-decision-service";
import{collectExecutiveCockpit}from "./integrated-executive-cockpit-service";
import{collectOfflineLongitudinalTrends}from
 "./offline-longitudinal-trends-service";
import{
 buildOfflineCapturePayload,sealOfflineCapture,
 verifyOfflineCapture,compareOfflineCaptures,
 buildCaptureIntegrityManifest,verifyCaptureManifest,
 type OfflineCapture,type OfflineCaptureKind,type CapturePayload,
 type CapturableReport,
}from "./offline-report-capture-domain";
export class OfflineCaptureError extends Error{
 constructor(public readonly code:string){super(code);}
}
function fail(code:string):never{throw new OfflineCaptureError(code);}
const id=(x:string)=>typeof x==="string"&&
 /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const digest=(x:string)=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const kinds:OfflineCaptureKind[]=[
 "INTEGRATED_RISKS","EVIDENCE_DECISIONS","EXECUTIVE","LONGITUDINAL"];
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const date=(x:Date)=>x.toISOString();
type DbCapture=Awaited<ReturnType<
 typeof db.offlineReportCapture.findMany>>[number];
function mapCapture(row:DbCapture):OfflineCapture{
 return{
 id:row.id,organizationId:row.organizationId,
 kind:row.kind as OfflineCaptureKind,
 schemaVersion:row.schemaVersion,
 originalDigest:row.originalDigest,payloadDigest:row.payloadDigest,
 payload:row.payload as unknown as CapturePayload,
 sourceComplete:row.sourceComplete,createdById:row.createdById,
 createdAt:date(row.createdAt),
 externalAttestation:false,customerCertification:false,
 };
}
async function authorize(actor:IntegratedReviewer,write:boolean){
 if(!id(actor.userId)||!id(actor.organizationId))
 fail("CAPTURE_ACTOR_INVALID");
 const membership=await db.membership.findFirst({
 where:{organizationId:actor.organizationId,userId:actor.userId},
 select:{role:true},
 });
 if(!membership||membership.role!==actor.role)
 fail("CAPTURE_MEMBERSHIP_REQUIRED");
 if(write&&!["OWNER","ADMIN"].includes(membership.role))
 fail("CAPTURE_CREATOR_PERMISSION_REQUIRED");
 if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
 fail("CAPTURE_REVIEW_PERMISSION_REQUIRED");
}
export type CaptureRequest={
 kind:OfflineCaptureKind;strictComplete:boolean;
 expectedOriginalDigest?:string;
};
async function currentReport(actor:IntegratedReviewer,
 kind:OfflineCaptureKind):Promise<CapturableReport>{
 switch(kind){
 case"INTEGRATED_RISKS":return collectIntegratedRiskDigest(actor);
 case"EVIDENCE_DECISIONS":return collectEvidenceDecisionReport(actor);
 case"EXECUTIVE":return collectExecutiveCockpit(actor);
 case"LONGITUDINAL":return collectOfflineLongitudinalTrends(actor);
 }
}
export async function captureOfflineReport(
 actor:IntegratedReviewer,request:CaptureRequest){
 await authorize(actor,true);
 if(!kinds.includes(request.kind)||typeof request.strictComplete!=="boolean")
 fail("CAPTURE_REQUEST_INVALID");
 const report=await currentReport(actor,request.kind);
 const at=new Date().toISOString();
 const payload=buildOfflineCapturePayload({
 organizationId:actor.organizationId,kind:request.kind,
 capturedAt:at,report,
 });
 if(request.strictComplete&&!payload.sourceComplete)
 fail("CAPTURE_INCOMPLETE_SOURCE_REJECTED");
 if(request.expectedOriginalDigest!==undefined&&
 request.expectedOriginalDigest!==payload.reportDigest)
 fail("CAPTURE_STALE_ORIGINAL_DIGEST");
 const checksum=sealOfflineCapture({
 id:"capture-placeholder",actorUserId:actor.userId,
 createdAt:at,payload,
 });
 const existing=await db.offlineReportCapture.findUnique({
 where:{organizationId_kind_payloadDigest:{
 organizationId:actor.organizationId,kind:request.kind,
 payloadDigest:checksum.payloadDigest,
 }},
 });
 if(existing){
 const archived=mapCapture(existing);
 if(!verifyOfflineCapture(archived,actor.organizationId).valid)
 fail("CAPTURE_EXISTING_DIGEST_INVALID");
 return{
 created:false,capture:archived,providerCalls:0 as const,
 customerApprovalGranted:false as const,
 };
 }
 try{
 const inserted=await db.offlineReportCapture.create({
 data:{
 organizationId:actor.organizationId,kind:request.kind,
 schemaVersion:payload.reportSchema,
 originalDigest:payload.reportDigest,
 payloadDigest:checksum.payloadDigest,
 payload:payload as unknown as Prisma.InputJsonValue,
 sourceComplete:payload.sourceComplete,
 createdById:actor.userId,createdAt:new Date(at),
 },
 });
 const archived=mapCapture(inserted);
 if(!verifyOfflineCapture(archived,actor.organizationId).valid)
 fail("CAPTURE_WRITTEN_DIGEST_INVALID");
 return{
 created:true,capture:archived,providerCalls:0 as const,
 customerApprovalGranted:false as const,
 };
 }catch(error){
 if(error&&typeof error==="object"&&"code" in error&&
 error.code==="P2002"){
 const replay=await db.offlineReportCapture.findUnique({
 where:{organizationId_kind_payloadDigest:{
 organizationId:actor.organizationId,kind:request.kind,
 payloadDigest:checksum.payloadDigest,
 }},
 });
 if(replay&&verifyOfflineCapture(mapCapture(replay),
 actor.organizationId).valid)
 return{created:false,capture:mapCapture(replay),
 providerCalls:0 as const,customerApprovalGranted:false as const};
 }
 throw error;
 }
}
export async function listOfflineCaptures(actor:IntegratedReviewer,
 input:{kind?:OfflineCaptureKind;limit?:number;includePayload?:boolean}={}){
 await authorize(actor,false);
 if(input.kind!==undefined&&!kinds.includes(input.kind))
 fail("CAPTURE_KIND_INVALID");
 const limit=input.limit??100;
 if(!Number.isSafeInteger(limit)||limit<1||limit>500)
 fail("CAPTURE_LIMIT_INVALID");
 const where={
 organizationId:actor.organizationId,
 ...(input.kind?{kind:input.kind}:{}),
 };
 const rows=await db.offlineReportCapture.findMany({
 where,orderBy:[{createdAt:"desc"},{id:"asc"}],
 take:limit+1,
 });
 const selected=rows.slice(0,limit).map(mapCapture);
 const validations=selected.map(x=>({
 id:x.id,...verifyOfflineCapture(x,actor.organizationId),
 }));
 const broken=validations.filter(x=>!x.valid);
 const manifest=buildCaptureIntegrityManifest(actor.organizationId,
 new Date().toISOString(),selected);
 if(!verifyCaptureManifest(manifest,actor.organizationId).valid)
 fail("CAPTURE_MANIFEST_INVALID");
 return{
 schema:"cyberpilot.offline.captures.read.v1" as const,
 organizationId:actor.organizationId,
 sourceTruncated:rows.length>limit,
 captures:input.includePayload?selected:
 selected.map(x=>({
 id:x.id,organizationId:x.organizationId,
 kind:x.kind,schemaVersion:x.schemaVersion,
 originalDigest:x.originalDigest,payloadDigest:x.payloadDigest,
 sourceComplete:x.sourceComplete,createdAt:x.createdAt,
 createdById:x.createdById,externalAttestation:false as const,
 customerCertification:false as const,
 })),
 validations,manifest,
 stats:{
 total:selected.length,
 complete:selected.filter(x=>x.sourceComplete).length,
 incomplete:selected.filter(x=>!x.sourceComplete).length,
 invalid:broken.length,
 kindCounts:Object.fromEntries(kinds.map(kind=>[
 kind,selected.filter(x=>x.kind===kind).length])),
 },
 providerCalls:0 as const,customerSecurityCertified:false as const,
 };
}
export async function readOfflineCapture(
 actor:IntegratedReviewer,captureId:string){
 await authorize(actor,false);
 if(!id(captureId))fail("CAPTURE_ID_INVALID");
 const item=await db.offlineReportCapture.findFirst({
 where:{organizationId:actor.organizationId,id:captureId},
 });
 if(!item)fail("CAPTURE_NOT_IN_TENANT");
 const capture=mapCapture(item);
 const validation=verifyOfflineCapture(capture,actor.organizationId);
 if(!validation.valid)fail("CAPTURE_TAMPERED");
 return{
 organizationId:actor.organizationId,capture,validation,
 providerCalls:0 as const,restorePerformed:false as const,
 };
}
export async function comparePersistedCaptures(
 actor:IntegratedReviewer,earlierId:string,laterId:string){
 await authorize(actor,false);
 if(!id(earlierId)||!id(laterId)||earlierId===laterId)
 fail("CAPTURE_COMPARISON_IDS_INVALID");
 const rows=await db.offlineReportCapture.findMany({
 where:{organizationId:actor.organizationId,
 id:{in:[earlierId,laterId]}},
 });
 if(rows.length!==2)fail("CAPTURE_PAIR_NOT_IN_TENANT");
 const captures=rows.map(mapCapture);
 const earlier=captures.find(x=>x.id===earlierId);
 const later=captures.find(x=>x.id===laterId);
 if(!earlier||!later)fail("CAPTURE_PAIR_INVALID");
 try{
 const comparison=compareOfflineCaptures(earlier,later);
 return{
 organizationId:actor.organizationId,comparison,
 providerCalls:0 as const,actualRiskReductionConfirmed:false as const,
 };
 }catch{fail("CAPTURE_PAIR_INCOMPATIBLE");}
}
export async function buildPersistedCaptureManifest(
 actor:IntegratedReviewer,ids:string[]){
 await authorize(actor,false);
 if(ids.length===0||ids.length>100||
 ids.some(x=>!id(x))||new Set(ids).size!==ids.length)
 fail("CAPTURE_MANIFEST_IDS_INVALID");
 const rows=await db.offlineReportCapture.findMany({
 where:{organizationId:actor.organizationId,id:{in:ids}},
 });
 if(rows.length!==ids.length)fail("CAPTURE_MANIFEST_SOURCE_MISSING");
 const manifest=buildCaptureIntegrityManifest(actor.organizationId,
 new Date().toISOString(),rows.map(mapCapture));
 if(!verifyCaptureManifest(manifest,actor.organizationId).valid)
 fail("CAPTURE_MANIFEST_DIGEST_FAILED");
 return{
 organizationId:actor.organizationId,manifest,
 allSourcesPresent:true as const,
 externalSignatureVerified:false as const,
 };
}
export async function auditOfflineCaptureInventory(
 actor:IntegratedReviewer){
 const list=await listOfflineCaptures(actor,{limit:500,
 includePayload:true});
 const items=list.captures as OfflineCapture[];
 const invalid=items.filter(x=>!verifyOfflineCapture(x,
 actor.organizationId).valid);
 const groups=kinds.map(kind=>{
 const rows=items.filter(x=>x.kind===kind);
 const hashes=new Set(rows.map(x=>x.payloadDigest));
 return{
 kind,count:rows.length,
 uniquePayloadDigests:hashes.size,
 latestAt:rows[0]?.createdAt??null,
 completenessRatio:rows.length?
 rows.filter(x=>x.sourceComplete).length/rows.length:null,
 immutableIntegrityVerified:rows.every(x=>
 verifyOfflineCapture(x,actor.organizationId).valid),
 };
 });
 return{
 organizationId:actor.organizationId,
 kindGroups:groups,
 totalStored:items.length,
 invalidCaptures:invalid.map(x=>x.id),
 sourceTruncated:list.sourceTruncated,
 manifestDigest:list.manifest.digest,
 tenantExternallyCertified:false as const,
 databaseBackupRestoreExecuted:false as const,
 };
}
