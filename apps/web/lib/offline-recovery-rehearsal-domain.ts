import{createHash,timingSafeEqual}from "node:crypto";
import type{OfflineCapture,OfflineCaptureKind,
 CaptureIntegrityManifest}from "./offline-report-capture-domain";
import{verifyOfflineCapture,buildCaptureIntegrityManifest,
 verifyCaptureManifest,replayOfflineCapturePayload}from
 "./offline-report-capture-domain";
export type RecoveryRehearsalPolicy={
 requiredKinds:OfflineCaptureKind[];
 maxAgeDays:number;
 requireCompleteSources:boolean;
 requireCrossReportBindings:boolean;
 refuseDuplicateKinds:boolean;
 failOnSourceClassChanges:boolean;
};
export type RecoveryGateId="SOURCE_PRESENT"|"TENANT_BOUNDARY"|
 "PAYLOAD_DIGEST"|"ORIGINAL_REPORT"|"SOURCE_COMPLETE"|
 "CAPTURE_AGE"|"KIND_DUPLICATION"|"RISK_LINEAGE"|
 "DECISION_LINEAGE"|"EXECUTIVE_LINEAGE"|
 "RECOVERY_MANIFEST"|"REPLAY_INTEGRITY"|
 "LIVE_AUTHORIZATION"|"DATABASE_RESTORE";
export type RecoveryGate={
 id:RecoveryGateId;status:"PASS"|"BLOCK"|"NOT_APPLICABLE"|
 "NOT_VERIFIED";
 affectedCaptures:string[];
 reason:string;requiresHumanIntervention:boolean;
 evidenceDigests:string[];
 externalAttestation:false;
};
export type RecoveryCaptureResult={
 captureId:string;kind:OfflineCaptureKind;
 originalDigest:string;payloadDigest:string;
 createdAt:string;ageDays:number;
 sourceComplete:boolean;
 envelopeVerified:boolean;reportVerified:boolean;
 readOnlyReplayVerified:boolean;
 tenantIsolated:boolean;
 problems:string[];
 restoredDatabaseRows:0;externalProviderCalls:0;
};
export type OfflineRecoveryRehearsal={
 schema:"cyberpilot.offline.recovery.rehearsal.v1";
 organizationId:string;executedAt:string;
 policy:RecoveryRehearsalPolicy;
 manifest:CaptureIntegrityManifest;
 gates:RecoveryGate[];
 captures:RecoveryCaptureResult[];
 status:"PASS"|"BLOCKED"|"INCOMPLETE";
 issues:string[];
 overview:{
 selectedCaptures:number;
 passedGates:number;blockedGates:number;
 unverifiableGates:number;
 payloadIntegrityFailures:number;missingRequiredKinds:number;
 expiredCaptures:number;
 crossReportConflicts:number;
 reportsReplayedReadOnly:number;
 independentCustomerTenantValidations:0;
 databaseRestoreOperations:0;
 providerCalls:0;
 historicalScoreWrites:0;
 };
 operatorDevelopmentAcceptanceAllowed:boolean;
 customerLiveAcceptanceAllowed:false;
 actualDatabaseRestoreExecuted:false;
 secretsRotated:false;
 externalTenantReauthorized:false;
 legacyCyberScoreModified:false;
 digest:string;
};
export type RecoveryRemediationPlan={
 organizationId:string;rehearsalDigest:string;generatedAt:string;
 steps:Array<{
 key:string;gate:RecoveryGateId;severity:"BLOCK"|"WARNING";
 instruction:string;captureIds:string[];ownerRequired:true;
 requiresCustomerTenantAuthorization:boolean;
 executed:false;
 }>;
 remainingBlockers:number;
 technicalRemediationAutomaticallyPerformed:false;
 legalConsentGenerated:false;
};
export type RecoveryRehearsalDiff={
 organizationId:string;earlierDigest:string;laterDigest:string;
 fixedGateIds:RecoveryGateId[];newFailures:RecoveryGateId[];
 selectedCaptureChange:number;readyStateChanged:boolean;
 dataRecoveryVerifiedInProduction:false;
 actualProviderDataRestored:false;
};
const sha=(x:string)=>createHash("sha256").update(x).digest("hex");
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const unique=<T>(x:readonly T[]):T[]=>[...new Set(x)];
function canonical(value:unknown):string{
 if(value===null||typeof value==="string"||typeof value==="boolean"||
 typeof value==="number"){
  if(typeof value==="number"&&!Number.isFinite(value))
   throw Error("NONFINITE_RECOVERY_DATA");
  return JSON.stringify(value);
 }
 if(Array.isArray(value))return"["+value.map(canonical).join(",")+"]";
 if(typeof value==="object")return"{"+Object.entries(value)
 .sort(([a],[b])=>a.localeCompare(b))
 .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
 throw Error("NON_JSON_RECOVERY_DATA");
}
const digest=(x:unknown)=>sha(canonical(x));
const equal=(a:string,b:string)=>{
 if(!/^[a-f0-9]{64}$/.test(a)||!/^[a-f0-9]{64}$/.test(b))
 return false;
 return timingSafeEqual(Buffer.from(a,"hex"),Buffer.from(b,"hex"));
};
export function defaultRecoveryRehearsalPolicy():
 RecoveryRehearsalPolicy{
 return{
 requiredKinds:["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
 "EXECUTIVE","LONGITUDINAL"],
 maxAgeDays:30,requireCompleteSources:true,
 requireCrossReportBindings:true,refuseDuplicateKinds:true,
 failOnSourceClassChanges:true,
 };
}
export function validateRecoveryPolicy(
 policy:RecoveryRehearsalPolicy):string[]{
 const issues:string[]=[];
 const valid:OfflineCaptureKind[]=[
 "INTEGRATED_RISKS","EVIDENCE_DECISIONS",
 "EXECUTIVE","LONGITUDINAL"];
 if(!Array.isArray(policy.requiredKinds)||
 policy.requiredKinds.length>4||
 new Set(policy.requiredKinds).size!==policy.requiredKinds.length||
 policy.requiredKinds.some(x=>!valid.includes(x)))
 issues.push("REQUIRED_KINDS_INVALID");
 if(!Number.isSafeInteger(policy.maxAgeDays)||
 policy.maxAgeDays<1||policy.maxAgeDays>3650)
 issues.push("RETENTION_AGE_INVALID");
 if(typeof policy.requireCompleteSources!=="boolean"||
 typeof policy.requireCrossReportBindings!=="boolean"||
 typeof policy.refuseDuplicateKinds!=="boolean"||
 typeof policy.failOnSourceClassChanges!=="boolean")
 issues.push("RECOVERY_FLAGS_INVALID");
 return unique(issues);
}
function gate(id:RecoveryGateId,status:RecoveryGate["status"],
 reason:string,captures:OfflineCapture[]=[]):RecoveryGate{
 return{
 id,status,reason,
 affectedCaptures:unique(captures.map(x=>x.id)).sort(),
 requiresHumanIntervention:status!=="PASS"&&
 status!=="NOT_APPLICABLE",
 evidenceDigests:unique(captures.map(x=>x.payloadDigest)).sort(),
 externalAttestation:false,
 };
}
function latestCapture(captures:OfflineCapture[],
 kind:OfflineCaptureKind){
 return captures.filter(x=>x.kind===kind)
 .sort((a,b)=>b.createdAt.localeCompare(a.createdAt)||
 a.id.localeCompare(b.id))[0];
}
function sourceBinding(captures:OfflineCapture[],
 required:boolean):RecoveryGate[]{
 const risks=latestCapture(captures,"INTEGRATED_RISKS");
 const decisions=latestCapture(captures,"EVIDENCE_DECISIONS");
 const executive=latestCapture(captures,"EXECUTIVE");
 const checks:RecoveryGate[]=[];
 if(!required){
 checks.push(gate("RISK_LINEAGE","NOT_APPLICABLE",
 "Cross-report lineage not mandated by policy."));
 checks.push(gate("DECISION_LINEAGE","NOT_APPLICABLE",
 "Cross-report lineage not mandated by policy."));
 checks.push(gate("EXECUTIVE_LINEAGE","NOT_APPLICABLE",
 "Cross-report lineage not mandated by policy."));
 return checks;
 }
 if(!risks){
 checks.push(gate("RISK_LINEAGE","NOT_VERIFIED",
 "A stored risk source is required before cross-report linkage."));
 }else{
 checks.push(gate("RISK_LINEAGE","PASS",
 "A locally verified integrated risk capture is available.",[risks]));
 }
 if(!decisions||!risks){
 checks.push(gate("DECISION_LINEAGE","NOT_VERIFIED",
 "Both an evidence decision and a risk report must be archived."));
 }else{
 const report=decisions.payload.report;
 const riskReport=risks.payload.report;
 const expected=report.schema==="cyberpilot.evidence.decisions.v1"?
 report.riskDigest:null;
 const actual=riskReport.schema==="cyberpilot.integrated.risks.v1"?
 riskReport.digest:null;
 const verified=Boolean(expected&&actual&&equal(expected,actual));
 checks.push(gate("DECISION_LINEAGE",verified?"PASS":"BLOCK",
 verified?"Decision report references this exact risk digest.":
 "Decision source digest differs from the selected risk report.",
 [decisions,risks]));
 }
 if(!executive||!risks){
 checks.push(gate("EXECUTIVE_LINEAGE","NOT_VERIFIED",
 "Both an executive and a risk capture must be available."));
 }else{
 const report=executive.payload.report;
 const source=risks.payload.report;
 const expected=report.schema==="cyberpilot.executive.cockpit.v1"?
 report.riskDigest:null;
 const actual=source.schema==="cyberpilot.integrated.risks.v1"?
 source.digest:null;
 const verified=Boolean(expected&&actual&&equal(expected,actual));
 checks.push(gate("EXECUTIVE_LINEAGE",
 verified?"PASS":"BLOCK",
 verified?"Executive digest refers to the selected persisted risk report.":
 "Executive provenance cannot be joined with the selected risk capture.",
 [executive,risks]));
 }
 return checks;
}
export function buildOfflineRecoveryRehearsal(input:{
 organizationId:string;executedAt:string;
 captures:OfflineCapture[];policy:RecoveryRehearsalPolicy;
}):OfflineRecoveryRehearsal{
 if(!input.organizationId||!iso(input.executedAt)||
 input.captures.length>100||validateRecoveryPolicy(input.policy).length)
 throw Error("INVALID_RECOVERY_SCOPE_OR_POLICY");
 if(input.captures.some(x=>x.organizationId!==input.organizationId))
 throw Error("RECOVERY_CROSS_TENANT_SOURCE");
 const captures=input.captures;
 const validations=captures.map(x=>verifyOfflineCapture(x,
 input.organizationId));
 const manifest=buildCaptureIntegrityManifest(input.organizationId,
 input.executedAt,captures);
 const result:RecoveryCaptureResult[]=captures.map((x,i)=>{
 const validation=validations[i]!;
 const ageDays=Math.max(0,Math.floor(
 (Date.parse(input.executedAt)-Date.parse(x.createdAt))/86400000));
 let replayValid=false;
 if(validation.valid){
 try{
 const replay=replayOfflineCapturePayload(x);
 replayValid=replay.originalEvidenceVerified&&
 equal(replay.replayDigest,x.payloadDigest);
 }catch{replayValid=false;}
 }
 return{
 captureId:x.id,kind:x.kind,
 originalDigest:x.originalDigest,payloadDigest:x.payloadDigest,
 createdAt:x.createdAt,ageDays,
 sourceComplete:x.sourceComplete,
 envelopeVerified:validation.valid,
 reportVerified:validation.reportVerified,
 readOnlyReplayVerified:replayValid,
 tenantIsolated:validation.scopeMatches,
 problems:validation.errors,
 restoredDatabaseRows:0,externalProviderCalls:0,
 };
 });
 const gates:RecoveryGate[]=[];
 gates.push(gate("SOURCE_PRESENT",
 captures.length?"PASS":"BLOCK",
 captures.length?"At least one archived source exists.":
 "No offline report captures were selected."));
 gates.push(gate("TENANT_BOUNDARY",
 result.every(x=>x.tenantIsolated)?"PASS":"BLOCK",
 "All archive rows must be bound to the same organization.",
 captures.filter((_,i)=>!result[i]!.tenantIsolated)));
 gates.push(gate("PAYLOAD_DIGEST",
 result.every(x=>x.envelopeVerified)?"PASS":"BLOCK",
 "Canonical archived payload checksums must validate.",
 captures.filter((_,i)=>!result[i]!.envelopeVerified)));
 gates.push(gate("ORIGINAL_REPORT",
 result.every(x=>x.reportVerified)?"PASS":"BLOCK",
 "Original source-report digest verification is required.",
 captures.filter((_,i)=>!result[i]!.reportVerified)));
 const incomplete=captures.filter(x=>!x.sourceComplete);
 gates.push(gate("SOURCE_COMPLETE",
 input.policy.requireCompleteSources&&incomplete.length?
 "BLOCK":"PASS",
 incomplete.length?
 "Source datasets contain known truncation or incomplete coverage.":
 "All archived source completeness flags are true.",incomplete));
 const expired=captures.filter((x,i)=>
 result[i]!.ageDays>input.policy.maxAgeDays||
 x.createdAt>input.executedAt);
 gates.push(gate("CAPTURE_AGE",expired.length?"BLOCK":"PASS",
 expired.length?"Archived sources are outside the configured age window.":
 "All selected sources are in the permitted age window.",expired));
 const duplicates=captures.filter((x,i)=>
 captures.findIndex(y=>y.kind===x.kind)!==i);
 gates.push(gate("KIND_DUPLICATION",
 duplicates.length&&input.policy.refuseDuplicateKinds?
 "BLOCK":"PASS",
 duplicates.length?"More than one capture has the same report kind.":
 "Kinds are unique in the rehearsal set.",duplicates));
 const missing=input.policy.requiredKinds.filter(kind=>
 !captures.some(x=>x.kind===kind));
 if(missing.length)gates.push(gate("SOURCE_PRESENT","BLOCK",
 "Required source kinds are missing: "+missing.join(", ")));
 gates.push(...sourceBinding(captures,
 input.policy.requireCrossReportBindings));
 const manifestValid=verifyCaptureManifest(manifest,
 input.organizationId).valid;
 gates.push(gate("RECOVERY_MANIFEST",
 manifestValid?"PASS":"BLOCK",
 "The local report manifest is checked using canonical SHA-256.",
 captures));
 gates.push(gate("REPLAY_INTEGRITY",
 result.every(x=>x.readOnlyReplayVerified)?"PASS":"BLOCK",
 "Each stored JSON report is decoded and reverified without mutation.",
 captures.filter((_,i)=>!result[i]!.readOnlyReplayVerified)));
 gates.push(gate("LIVE_AUTHORIZATION","NOT_VERIFIED",
 "External tenant authorization is outside this offline integrity rehearsal."));
 gates.push(gate("DATABASE_RESTORE","NOT_VERIFIED",
 "A real PostgreSQL restore is not performed by this JSON rehearsal."));
 const blocked=gates.filter(x=>x.status==="BLOCK");
 const unverifiable=gates.filter(x=>x.status==="NOT_VERIFIED");
 const actualBlockers=gates.filter(x=>x.status==="BLOCK"&&
 x.id!=="DATABASE_RESTORE"&&x.id!=="LIVE_AUTHORIZATION");
 const status:OfflineRecoveryRehearsal["status"]=actualBlockers.length?"BLOCKED":
 captures.length===0||missing.length?"INCOMPLETE":"PASS";
 const overview={
 selectedCaptures:captures.length,
 passedGates:gates.filter(x=>x.status==="PASS").length,
 blockedGates:blocked.length,unverifiableGates:unverifiable.length,
 payloadIntegrityFailures:result.filter(x=>!x.envelopeVerified).length,
 missingRequiredKinds:missing.length,
 expiredCaptures:expired.length,
 crossReportConflicts:gates.filter(x=>
 ["DECISION_LINEAGE","EXECUTIVE_LINEAGE"].includes(x.id)&&
 x.status==="BLOCK").length,
 reportsReplayedReadOnly:result.filter(x=>x.readOnlyReplayVerified).length,
 independentCustomerTenantValidations:0 as const,
 databaseRestoreOperations:0 as const,
 providerCalls:0 as const,historicalScoreWrites:0 as const,
 };
 const issues=unique(gates.filter(x=>
 x.status==="BLOCK"||x.status==="NOT_VERIFIED")
 .map(x=>x.id+":"+x.reason));
 const base={
 schema:"cyberpilot.offline.recovery.rehearsal.v1" as const,
 organizationId:input.organizationId,executedAt:input.executedAt,
 policy:input.policy,manifest,gates,captures:result,
 status,issues,overview,
 operatorDevelopmentAcceptanceAllowed:status==="PASS"&&
 captures.length>0,
 customerLiveAcceptanceAllowed:false as const,
 actualDatabaseRestoreExecuted:false as const,
 secretsRotated:false as const,externalTenantReauthorized:false as const,
 legacyCyberScoreModified:false as const,
 };
 return{...base,digest:digest(base)};
}
export function verifyRecoveryRehearsal(
 report:OfflineRecoveryRehearsal,organizationId?:string){
 const errors:string[]=[];
 const{digest:stored,...base}=report;
 if(!equal(digest(base),stored))errors.push("RECOVERY_DIGEST_INVALID");
 if(organizationId&&report.organizationId!==organizationId)
 errors.push("RECOVERY_TENANT_MISMATCH");
 if(report.actualDatabaseRestoreExecuted!==false||
 report.externalTenantReauthorized!==false||
 report.customerLiveAcceptanceAllowed!==false||
 report.legacyCyberScoreModified!==false||
 report.overview.databaseRestoreOperations!==0||
 report.overview.providerCalls!==0||
 report.overview.historicalScoreWrites!==0)
 errors.push("FALSE_RECOVERY_OR_SECURITY_CLAIM");
 if(report.status==="PASS"&&report.gates.some(x=>
 x.status==="BLOCK"))
 errors.push("PASSED_BLOCKED_REHEARSAL");
 if(!verifyCaptureManifest(report.manifest,report.organizationId).valid)
 errors.push("RECOVERY_MANIFEST_INVALID");
 if(report.captures.some(x=>x.restoredDatabaseRows!==0||
 x.externalProviderCalls!==0))
 errors.push("UNAUTHORIZED_RESTORE_METRIC");
 return{valid:errors.length===0,errors};
}
export function createRecoveryRemediationPlan(
 report:OfflineRecoveryRehearsal):RecoveryRemediationPlan{
 if(!verifyRecoveryRehearsal(report).valid)
 throw Error("INVALID_RECOVERY_PLAN_SOURCE");
 const steps=report.gates.filter(x=>x.status==="BLOCK"||
 x.status==="NOT_VERIFIED").map(item=>({
 key:sha(report.digest+":"+item.id+":"+
 item.affectedCaptures.join(",")),
 gate:item.id,severity:(item.status==="BLOCK"?
 "BLOCK":"WARNING") as "BLOCK"|"WARNING",
 instruction:item.id==="SOURCE_PRESENT"?
 "Generate permitted source reports and re-run the rehearsal.":
 item.id==="PAYLOAD_DIGEST"||item.id==="ORIGINAL_REPORT"?
 "Quarantine the mismatched artifact and investigate integrity.":
 item.id==="TENANT_BOUNDARY"?
 "Remove foreign-organization records and investigate isolation.":
 item.id==="CAPTURE_AGE"?
 "Create a fresh signed-off local capture under the retention policy.":
 item.id==="DATABASE_RESTORE"?
 "Use the separate PostgreSQL backup/restore CI rehearsal for real SQL recovery.":
 item.id==="LIVE_AUTHORIZATION"?
 "Acquire independently verified real customer authorization before LIVE.":
 "Review source scope and lineage, then regenerate a fresh capture.",
 captureIds:[...item.affectedCaptures],
 ownerRequired:true as const,
 requiresCustomerTenantAuthorization:item.id==="LIVE_AUTHORIZATION",
 executed:false as const,
 }));
 return{
 organizationId:report.organizationId,rehearsalDigest:report.digest,
 generatedAt:report.executedAt,steps,
 remainingBlockers:steps.filter(x=>x.severity==="BLOCK").length,
 technicalRemediationAutomaticallyPerformed:false,
 legalConsentGenerated:false,
 };
}
export function compareRecoveryRehearsals(
 before:OfflineRecoveryRehearsal,after:OfflineRecoveryRehearsal):
 RecoveryRehearsalDiff{
 if(!verifyRecoveryRehearsal(before).valid||
 !verifyRecoveryRehearsal(after).valid||
 before.organizationId!==after.organizationId||
 before.executedAt>=after.executedAt)
 throw Error("INCOMPATIBLE_RECOVERY_REHEARSALS");
 const blocked=(x:OfflineRecoveryRehearsal)=>
 new Set(x.gates.filter(g=>g.status==="BLOCK").map(g=>g.id));
 const old=blocked(before),current=blocked(after);
 return{
 organizationId:after.organizationId,
 earlierDigest:before.digest,laterDigest:after.digest,
 fixedGateIds:[...old].filter(x=>!current.has(x)),
 newFailures:[...current].filter(x=>!old.has(x)),
 selectedCaptureChange:after.overview.selectedCaptures-
 before.overview.selectedCaptures,
 readyStateChanged:before.status!==after.status,
 dataRecoveryVerifiedInProduction:false,
 actualProviderDataRestored:false,
 };
}
export function exportRecoveryRehearsal(
 report:OfflineRecoveryRehearsal,
 format:"JSON"|"CSV"|"MARKDOWN"){
 if(!verifyRecoveryRehearsal(report).valid)
 throw Error("INVALID_RECOVERY_EXPORT");
 const stem="cyberpilot-offline-recovery-"+report.executedAt.slice(0,10);
 if(format==="JSON")return{
 filename:stem+".json",mime:"application/json",
 content:JSON.stringify(report,null,2),
 };
 const q=(x:string|number|null)=>'"'+String(x??"")
 .replaceAll('"','""')+'"';
 if(format==="CSV")return{
 filename:stem+".csv",mime:"text/csv",
 content:["gate,status,reason,affectedCaptures",
 ...report.gates.map(x=>[x.id,x.status,x.reason,
 x.affectedCaptures.join(";")].map(q).join(","))].join("\n"),
 };
 if(format!=="MARKDOWN")throw Error("UNSUPPORTED_RECOVERY_FORMAT");
 return{
 filename:stem+".md",mime:"text/markdown",
 content:["# Offline JSON report integrity rehearsal",
 "Organization: "+report.organizationId,
 "Date: "+report.executedAt,
 "Status: "+report.status,
 "Digest: "+report.digest,
 "Artifacts read-only replayed: "+report.overview.reportsReplayedReadOnly,
 "Real PostgreSQL restore operations: 0",
 "LIVE providers contacted: 0",
 "",
 "## Gates",
 ...report.gates.map(x=>"- "+x.status+" "+x.id+" — "+x.reason),
 "",
 "This is a local JSON artifact integrity rehearsal.",
 "It does not replace CI's actual database backup and restore exercise.",
 "No LIVE customer security certification or consent is established.",
 ].join("\n"),
 };
}
