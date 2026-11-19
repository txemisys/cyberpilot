import{createHash,timingSafeEqual}from "node:crypto";
import type{IntegratedRiskDigest}from "./integrated-risk-engine";
import type{EvidenceDecisionReport}from "./evidence-decision-engine";
import type{ExecutiveCockpitReport}from "./integrated-executive-cockpit";
import type{TrendReport}from "./offline-longitudinal-trends";
import{verifyIntegratedRiskDigest}from "./integrated-risk-engine";
import{verifyEvidenceDecisionReport}from "./evidence-decision-engine";
import{verifyExecutiveCockpit}from "./integrated-executive-cockpit";
import{verifyTrendReport}from "./offline-longitudinal-trends";
export type OfflineCaptureKind="INTEGRATED_RISKS"|"EVIDENCE_DECISIONS"|
 "EXECUTIVE"|"LONGITUDINAL";
export type CapturableReport=IntegratedRiskDigest|EvidenceDecisionReport|
 ExecutiveCockpitReport|TrendReport;
export type CapturePayload={
 schema:"cyberpilot.offline.capture.payload.v1";
 organizationId:string;kind:OfflineCaptureKind;capturedAt:string;
 reportSchema:string;reportDigest:string;report:CapturableReport;
 sourceComplete:boolean;
 providerCalls:0;customerConsentConfirmed:false;
 historicalScoreRewritten:false;
};
export type OfflineCapture={
 id:string;organizationId:string;kind:OfflineCaptureKind;
 schemaVersion:string;originalDigest:string;
 payloadDigest:string;payload:CapturePayload;
 sourceComplete:boolean;createdById:string;createdAt:string;
 externalAttestation:false;customerCertification:false;
};
export type CaptureValidation={
 valid:boolean;errors:string[];digest:string;
 reportVerified:boolean;scopeMatches:boolean;
 tenantExternallyAuthenticated:false;
 evidenceUnmodifiedByVerifier:true;
};
export type CaptureDiff={
 organizationId:string;kind:OfflineCaptureKind;
 earlierId:string;laterId:string;
 earlierAt:string;laterAt:string;
 sourceCompleteBoth:boolean;
 reportSchemaMatches:boolean;
 originalDigestChanged:boolean;
 sourceDigestChanged:boolean;
 recordCountDelta:number|null;
 riskCountDelta:number|null;
 declaredCompleteDelta:number|null;
 trendSnapshotDelta:number|null;
 evidenceSourceClassChanged:boolean;
 compareSnapshotsAsCertifiedSecurity:false;
 actualRiskReductionProven:false;
 customerTenantReauthenticated:false;
};
export type CaptureIntegrityManifest={
 schema:"cyberpilot.offline.capture.manifest.v1";
 organizationId:string;generatedAt:string;
 entries:Array<{
  captureId:string;kind:OfflineCaptureKind;
  originalDigest:string;payloadDigest:string;
  complete:boolean;capturedAt:string;
 }>;
 entryCount:number;incompleteSources:number;
 duplicates:number;integrityFailures:number;
 readyForDevelopmentRehearsal:boolean;
 readyForCustomerLIVEAcceptance:false;
 trustedExternalSignaturePresent:false;
 digest:string;
};
export type CaptureFilters={
 kind?:OfflineCaptureKind[];sourceComplete?:boolean;
 from?:string;to?:string;offset?:number;limit?:number;
};
const sha=(str:string)=>createHash("sha256").update(str).digest("hex");
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const id=(x:string)=>typeof x==="string"&&
 /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const hash=(x:string)=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
function canonical(x:unknown):string{
 if(x===null||typeof x==="string"||typeof x==="boolean"||
 typeof x==="number"){
  if(typeof x==="number"&&!Number.isFinite(x))
   throw Error("NONFINITE_REPORT_CAPTURE");
  return JSON.stringify(x);
 }
 if(Array.isArray(x))return"["+x.map(canonical).join(",")+"]";
 if(typeof x==="object")return"{"+Object.entries(x).sort(
 ([a],[b])=>a.localeCompare(b)).map(([k,v])=>
 JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
 throw Error("UNSUPPORTED_CAPTURE_VALUE");
}
const digest=(x:unknown)=>sha(canonical(x));
function constantTime(a:string,b:string){
 if(!hash(a)||!hash(b))return false;
 return timingSafeEqual(Buffer.from(a,"hex"),Buffer.from(b,"hex"));
}
export function reportDescriptor(report:CapturableReport):{
 kind:OfflineCaptureKind;organizationId:string;
 schema:string;digest:string;sourceComplete:boolean;
 recordCount:number;riskCount:number;
 declaredComplete:number;trendSnapshots:number;
 sourceClasses:string[];
}{
 switch(report.schema){
 case"cyberpilot.integrated.risks.v1":
  return{
   kind:"INTEGRATED_RISKS",organizationId:report.organizationId,
   schema:report.schema,digest:report.digest,
   sourceComplete:report.coverage.persistedRecordsComplete,
   recordCount:report.counts.evidence+report.counts.findings,
   riskCount:report.risks.length,
   declaredComplete:report.counts.declaredActions,
   trendSnapshots:0,
   sourceClasses:report.coverage.sourceFamilies,
  };
 case"cyberpilot.evidence.decisions.v1":
  return{
   kind:"EVIDENCE_DECISIONS",organizationId:report.organizationId,
   schema:report.schema,digest:report.reportDigest,
   sourceComplete:report.outcome!=="BLOCKED",
   recordCount:report.totals.decisions,
   riskCount:report.totals.unresolvedRisks,
   declaredComplete:0,trendSnapshots:0,
   sourceClasses:report.sources.map(x=>x.source),
  };
 case"cyberpilot.executive.cockpit.v1":
  return{
   kind:"EXECUTIVE",organizationId:report.organizationId,
   schema:report.schema,digest:report.digest,
   sourceComplete:report.audit.riskSourceComplete&&
    report.audit.actionsSourceComplete&&
    report.audit.actionAuditIssues.length===0,
   recordCount:report.summary.sourceEvidenceCount,
   riskCount:report.summary.openRisks,
   declaredComplete:report.summary.reportedCompletedActions,
   trendSnapshots:report.summary.syntheticSnapshots,
   sourceClasses:[report.provenance.latestOptionalV2SourceClass??"UNKNOWN"],
  };
 case"cyberpilot.offline.longitudinal.v1":
  return{
   kind:"LONGITUDINAL",organizationId:report.organizationId,
   schema:report.schema,digest:report.reportDigest,
   sourceComplete:report.sourceComplete&&
    report.outcome!=="INCOMPLETE",
   recordCount:report.points.length,
   riskCount:report.actionPulse.active+report.actionPulse.blocked,
   declaredComplete:report.actionPulse.reportedDone,
   trendSnapshots:report.summary.snapshots,
   sourceClasses:[...new Set(report.points.map(x=>x.sourceKind))],
  };
 }
}
export function verifyCapturableReport(report:CapturableReport,
 organizationId:string){
 const descriptor=reportDescriptor(report);
 if(descriptor.organizationId!==organizationId)return false;
 switch(report.schema){
 case"cyberpilot.integrated.risks.v1":
  return verifyIntegratedRiskDigest(report,organizationId).valid;
 case"cyberpilot.evidence.decisions.v1":
  return verifyEvidenceDecisionReport(report,organizationId).valid;
 case"cyberpilot.executive.cockpit.v1":
  return verifyExecutiveCockpit(report,organizationId).valid;
 case"cyberpilot.offline.longitudinal.v1":
  return verifyTrendReport(report,organizationId).valid;
 }
}
export function buildOfflineCapturePayload(input:{
 organizationId:string;kind:OfflineCaptureKind;
 capturedAt:string;report:CapturableReport;
}):CapturePayload{
 const descriptor=reportDescriptor(input.report);
 if(!id(input.organizationId)||!iso(input.capturedAt)||
 descriptor.kind!==input.kind||
 descriptor.organizationId!==input.organizationId||
 !verifyCapturableReport(input.report,input.organizationId))
 throw Error("INVALID_CAPTURE_INPUT_OR_FOREIGN_TENANT");
 const result:CapturePayload={
 schema:"cyberpilot.offline.capture.payload.v1",
 organizationId:input.organizationId,kind:input.kind,
 capturedAt:input.capturedAt,reportSchema:descriptor.schema,
 reportDigest:descriptor.digest,report:input.report,
 sourceComplete:descriptor.sourceComplete,
 providerCalls:0,customerConsentConfirmed:false,
 historicalScoreRewritten:false,
 };
 const bytes=Buffer.byteLength(JSON.stringify(result));
 if(bytes>256*1024)throw Error("CAPTURE_PAYLOAD_TOO_LARGE");
 return result;
}
export function digestOfflineCapturePayload(payload:CapturePayload){
 return digest(payload);
}
export function sealOfflineCapture(input:{
 id:string;actorUserId:string;createdAt:string;
 payload:CapturePayload;
}):OfflineCapture{
 if(!id(input.id)||!id(input.actorUserId)||!iso(input.createdAt))
 throw Error("CAPTURE_ACTOR_OR_TIME_INVALID");
 return{
 id:input.id,organizationId:input.payload.organizationId,
 kind:input.payload.kind,schemaVersion:input.payload.reportSchema,
 originalDigest:input.payload.reportDigest,
 payloadDigest:digestOfflineCapturePayload(input.payload),
 payload:input.payload,sourceComplete:input.payload.sourceComplete,
 createdById:input.actorUserId,createdAt:input.createdAt,
 externalAttestation:false,customerCertification:false,
 };
}
export function verifyOfflineCapture(capture:OfflineCapture,
 organizationId?:string):CaptureValidation{
 const errors:string[]=[];
 if(!id(capture.id)||!id(capture.organizationId)||
 !id(capture.createdById)||!iso(capture.createdAt))
 errors.push("CAPTURE_IDENTITY_INVALID");
 if(organizationId&&capture.organizationId!==organizationId)
 errors.push("CAPTURE_CROSS_TENANT");
 const payload=capture.payload;
 if(payload.schema!=="cyberpilot.offline.capture.payload.v1"||
 payload.organizationId!==capture.organizationId||
 payload.kind!==capture.kind||payload.reportSchema!==capture.schemaVersion||
 payload.reportDigest!==capture.originalDigest||
 payload.sourceComplete!==capture.sourceComplete)
 errors.push("CAPTURE_ENVELOPE_MISMATCH");
 if(payload.providerCalls!==0||
 payload.customerConsentConfirmed!==false||
 payload.historicalScoreRewritten!==false||
 capture.externalAttestation!==false||
 capture.customerCertification!==false)
 errors.push("FALSE_SECURITY_OR_PROVIDER_CLAIM");
 let reportValid=false;
 try{reportValid=verifyCapturableReport(payload.report,
 capture.organizationId);}catch{reportValid=false;}
 if(!reportValid)errors.push("ORIGINAL_REPORT_NOT_VERIFIED");
 const computed=digestOfflineCapturePayload(payload);
 if(!constantTime(computed,capture.payloadDigest))
 errors.push("CAPTURE_DIGEST_MISMATCH");
 if(!hash(capture.originalDigest)||!hash(capture.payloadDigest))
 errors.push("CAPTURE_HASH_FORMAT_INVALID");
 return{
 valid:errors.length===0,errors,digest:computed,
 reportVerified:reportValid,
 scopeMatches:payload.organizationId===capture.organizationId&&
 (!organizationId||organizationId===capture.organizationId),
 tenantExternallyAuthenticated:false,
 evidenceUnmodifiedByVerifier:true,
 };
}
export function compareOfflineCaptures(
 before:OfflineCapture,after:OfflineCapture):CaptureDiff{
 if(!verifyOfflineCapture(before).valid||
 !verifyOfflineCapture(after).valid||
 before.organizationId!==after.organizationId||
 before.kind!==after.kind||before.createdAt>=after.createdAt)
 throw Error("INCOMPATIBLE_OR_UNVERIFIED_CAPTURE_PAIR");
 const first=reportDescriptor(before.payload.report);
 const last=reportDescriptor(after.payload.report);
 const compatible=before.schemaVersion===after.schemaVersion;
 return{
 organizationId:after.organizationId,kind:after.kind,
 earlierId:before.id,laterId:after.id,
 earlierAt:before.createdAt,laterAt:after.createdAt,
 sourceCompleteBoth:before.sourceComplete&&after.sourceComplete,
 reportSchemaMatches:compatible,
 originalDigestChanged:before.originalDigest!==after.originalDigest,
 sourceDigestChanged:before.payloadDigest!==after.payloadDigest,
 recordCountDelta:compatible?
 last.recordCount-first.recordCount:null,
 riskCountDelta:compatible?last.riskCount-first.riskCount:null,
 declaredCompleteDelta:compatible?
 last.declaredComplete-first.declaredComplete:null,
 trendSnapshotDelta:compatible?
 last.trendSnapshots-first.trendSnapshots:null,
 evidenceSourceClassChanged:
 canonical(first.sourceClasses)!==canonical(last.sourceClasses),
 compareSnapshotsAsCertifiedSecurity:false,
 actualRiskReductionProven:false,
 customerTenantReauthenticated:false,
 };
}
export function buildCaptureIntegrityManifest(
 organizationId:string,generatedAt:string,
 captures:OfflineCapture[]):CaptureIntegrityManifest{
 if(!id(organizationId)||!iso(generatedAt)||captures.length>500)
 throw Error("INVALID_CAPTURE_MANIFEST_REQUEST");
 const validations=captures.map(x=>verifyOfflineCapture(x,organizationId));
 const entries=[...captures].map(x=>({
 captureId:x.id,kind:x.kind,originalDigest:x.originalDigest,
 payloadDigest:x.payloadDigest,complete:x.sourceComplete,
 capturedAt:x.createdAt,
 })).sort((a,b)=>a.kind.localeCompare(b.kind)||
 a.capturedAt.localeCompare(b.capturedAt)||
 a.captureId.localeCompare(b.captureId));
 const duplicates=entries.length-
 new Set(entries.map(x=>x.captureId)).size;
 const integrityFailures=validations.filter(x=>!x.valid).length;
 const incompleteSources=captures.filter(x=>!x.sourceComplete).length;
 const base={
 schema:"cyberpilot.offline.capture.manifest.v1" as const,
 organizationId,generatedAt,entries,entryCount:entries.length,
 incompleteSources,duplicates,integrityFailures,
 readyForDevelopmentRehearsal:duplicates===0&&integrityFailures===0&&
 incompleteSources===0&&entries.length>0,
 readyForCustomerLIVEAcceptance:false as const,
 trustedExternalSignaturePresent:false as const,
 };
 return{...base,digest:digest(base)};
}
export function verifyCaptureManifest(manifest:CaptureIntegrityManifest,
 tenant?:string){
 const{digest:stored,...base}=manifest;
 const errors:string[]=[];
 if(!constantTime(digest(base),stored))errors.push("MANIFEST_DIGEST_INVALID");
 if(tenant&&tenant!==manifest.organizationId)
 errors.push("MANIFEST_TENANT_INVALID");
 if(manifest.trustedExternalSignaturePresent!==false||
 manifest.readyForCustomerLIVEAcceptance!==false)
 errors.push("FALSE_EXTERNAL_ATTESTATION");
 if(manifest.readyForDevelopmentRehearsal&&(
 manifest.integrityFailures>0||manifest.incompleteSources>0||
 manifest.duplicates>0||manifest.entryCount===0))
 errors.push("UNJUSTIFIED_REHEARSAL_READINESS");
 return{valid:errors.length===0,errors};
}
export function filterOfflineCaptures(captures:OfflineCapture[],
 input:CaptureFilters={}){
 const offset=input.offset??0,limit=input.limit??30;
 if(!Number.isSafeInteger(offset)||offset<0||
 !Number.isSafeInteger(limit)||limit<1||limit>100)
 throw Error("INVALID_CAPTURE_PAGING");
 const items=captures.filter(x=>
 (!input.kind||input.kind.includes(x.kind))&&
 (input.sourceComplete===undefined||
 x.sourceComplete===input.sourceComplete)&&
 (!input.from||x.createdAt>=input.from)&&
 (!input.to||x.createdAt<=input.to))
 .sort((a,b)=>b.createdAt.localeCompare(a.createdAt)||
 a.id.localeCompare(b.id));
 return{
 total:items.length,offset,limit,
 items:items.slice(offset,offset+limit),
 nextOffset:offset+limit<items.length?offset+limit:null,
 customerSecurityCertified:false as const,
 };
}
export function replayOfflineCapturePayload(capture:OfflineCapture){
 const check=verifyOfflineCapture(capture);
 if(!check.valid)throw Error("INVALID_STORED_CAPTURE:"+check.errors.join(","));
 // Replay is a read-only validation of the stored JSON artifact.
 // It does not restore customer data, SQL tables or provider state.
 return{
 organizationId:capture.organizationId,kind:capture.kind,
 originalDigest:capture.originalDigest,
 report:structuredClone(capture.payload.report),
 replayDigest:check.digest,
 originalEvidenceVerified:check.reportVerified,
 databaseRestoreExecuted:false as const,
 providerRestoreExecuted:false as const,
 };
}
export function exportOfflineCaptures(
 captures:OfflineCapture[],tenant:string,
 format:"JSON"|"CSV"|"MARKDOWN"){
 if(captures.some(x=>!verifyOfflineCapture(x,tenant).valid))
 throw Error("CANNOT_EXPORT_TAMPERED_CAPTURE");
 const stem="cyberpilot-offline-captures";
 if(format==="JSON")return{
 filename:stem+".json",mime:"application/json",
 content:JSON.stringify(captures,null,2),
 };
 const q=(x:string|number|boolean)=>'"'+
 String(x).replaceAll('"','""')+'"';
 if(format==="CSV")return{
 filename:stem+".csv",mime:"text/csv",
 content:[
 "id,kind,createdAt,sourceComplete,originalDigest,payloadDigest",
 ...captures.map(x=>[x.id,x.kind,x.createdAt,
 x.sourceComplete,x.originalDigest,x.payloadDigest]
 .map(q).join(","))].join("\n"),
 };
 if(format!=="MARKDOWN")throw Error("INVALID_CAPTURE_EXPORT_FORMAT");
 return{
 filename:stem+".md",mime:"text/markdown",
 content:["# Immutable offline report captures",
 "Organization: "+tenant,
 ...captures.map(x=>"- "+x.kind+" @ "+x.createdAt+
 " digest="+x.payloadDigest+" source complete="+x.sourceComplete),
 "Hashes attest only local integrity, not a customer's real security."
 ].join("\n"),
 };
}
