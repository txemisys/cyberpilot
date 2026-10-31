/**
 * Explicit links between human work and stored evidence are references only.
 * A link never implies that the evidence is applicable, fresh or verifies a control.
 */
export type EvidenceState="OBSERVED"|"DECLARED"|"UNKNOWN"|"ERROR"|"OTHER";
export type LinkRole="OWNER"|"ADMIN"|"MEMBER"|"AUDITOR";
export type LinkCommand=
 |{kind:"attach";evidenceId:string;reason:string}
 |{kind:"detach";evidenceId:string}
 |{kind:"restore";evidenceId:string;reason:string};
export class EvidenceLinkError extends Error{
 constructor(public readonly code:"INVALID"|"FORBIDDEN"|"NOT_FOUND"|"CONFLICT"|"CAPACITY",message:string){
  super(message);this.name="EvidenceLinkError";
 }
}
const VALID_ID=/^[a-zA-Z0-9_-]{5,100}$/;
export function parseEvidenceId(value:unknown):string{
 if(typeof value!=="string"||!VALID_ID.test(value))
  throw new EvidenceLinkError("INVALID","Invalid stored evidence identifier.");
 return value;
}
export function parseEvidenceReason(value:unknown):string{
 if(typeof value!=="string")throw new EvidenceLinkError("INVALID","Reason must be text.");
 const reason=value.trim();
 if(reason.length<8||reason.length>1500||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(reason))
  throw new EvidenceLinkError("INVALID","Explain the link in 8–1500 printable characters.");
 return reason;
}
export function parseEvidenceCommand(value:unknown):LinkCommand{
 if(!value||typeof value!=="object"||Array.isArray(value))
  throw new EvidenceLinkError("INVALID","Expected link operation.");
 const input=value as Record<string,unknown>;
 const keys=Object.keys(input);
 const allowed=input.kind==="detach"?["kind","evidenceId"]:["kind","evidenceId","reason"];
 if(keys.some(key=>!allowed.includes(key)))
  throw new EvidenceLinkError("INVALID","Unsupported link operation field.");
 const evidenceId=parseEvidenceId(input.evidenceId);
 if(input.kind==="detach")return {kind:"detach",evidenceId};
 if(input.kind==="attach"||input.kind==="restore"){
  return {kind:input.kind,evidenceId,reason:parseEvidenceReason(input.reason)};
 }
 throw new EvidenceLinkError("INVALID","Unsupported evidence-link operation.");
}
export function canEditEvidenceLinks(role:LinkRole,assigneeId:string|null,actorId:string):boolean{
 return role==="OWNER"||role==="ADMIN"||(role==="MEMBER"&&assigneeId===actorId);
}
export function authorizeEvidenceLink(role:LinkRole,assigneeId:string|null,actorId:string):void{
 if(!canEditEvidenceLinks(role,assigneeId,actorId))
  throw new EvidenceLinkError("FORBIDDEN","Only managers or the assigned teammate can link observations.");
}
export type EvidenceRecord={
 id:string;organizationId:string;controlId:string;domain:string;scope:string;
 state:string;source:string;observedAt:Date|null;createdAt:Date;updatedAt:Date;
};
export type FindingReference={ruleId:string;key:string;status:string};
export type EvidenceAssessment={
 state:EvidenceState;age:"NOT_OBSERVED"|"FUTURE"|"RECENT"|"AGING"|"STALE";
 relationship:"CONTROL_ID_MATCH"|"NO_EXACT_MATCH";
 isObserved:boolean;isExplicitMatch:boolean;maySupportReview:boolean;
 warnings:string[];
};
export function normalizeEvidenceState(value:string):EvidenceState{
 return value==="OBSERVED"||value==="DECLARED"||value==="UNKNOWN"||value==="ERROR"?value:"OTHER";
}
export function assessLinkedEvidence(
 evidence:EvidenceRecord,finding:FindingReference,now=new Date(),freshnessDays=30
):EvidenceAssessment{
 const state=normalizeEvidenceState(evidence.state);
 const warnings:string[]=[];
 const isExplicitMatch=evidence.controlId===finding.ruleId||evidence.controlId===finding.key;
 if(!isExplicitMatch)
  warnings.push("Control identifier does not exactly match the finding rule or key.");
 if(state!=="OBSERVED")
  warnings.push("This evidence is not a successful observed security result.");
 let age:EvidenceAssessment["age"]="NOT_OBSERVED";
 if(evidence.observedAt){
  const delta=now.getTime()-evidence.observedAt.getTime();
  if(!Number.isFinite(delta))age="NOT_OBSERVED";
  else if(delta<0)age="FUTURE";
  else if(delta<=freshnessDays*86400000)age="RECENT";
  else if(delta<=freshnessDays*2*86400000)age="AGING";
  else age="STALE";
 }
 if(age==="NOT_OBSERVED")warnings.push("No observation timestamp is available.");
 if(age==="FUTURE")warnings.push("Observation timestamp lies in the future.");
 if(age==="STALE"||age==="AGING")warnings.push("Observation requires a freshness review.");
 if(finding.status==="RESOLVED")
  warnings.push("Finding is currently resolved; this link does not prove its closure.");
 if(state==="ERROR")warnings.push("Evidence source recorded an error, not an effective control.");
 if(state==="UNKNOWN")warnings.push("Evidence source did not determine the control state.");
 if(state==="DECLARED")warnings.push("Declared evidence is not an independent observation.");
 return {
  state,age,relationship:isExplicitMatch?"CONTROL_ID_MATCH":"NO_EXACT_MATCH",
  isObserved:state==="OBSERVED",isExplicitMatch,
  maySupportReview:state==="OBSERVED"&&isExplicitMatch&&age==="RECENT",
  warnings
 };
}
export type LinkItem={
 id:string;evidenceId:string;reason:string;linkedAt:Date;unlinkedAt:Date|null;
 evidence:EvidenceRecord;
};
export function summarizeLinks(rows:readonly LinkItem[],finding:FindingReference,now=new Date()){
 const active=rows.filter(x=>!x.unlinkedAt);
 const assessments=active.map(link=>({id:link.id,evidenceId:link.evidenceId,
  assessment:assessLinkedEvidence(link.evidence,finding,now)}));
 return {
  active:active.length,detached:rows.length-active.length,
  exactMatches:assessments.filter(x=>x.assessment.isExplicitMatch).length,
  recentObservedReferences:assessments.filter(x=>x.assessment.maySupportReview).length,
  mismatched:assessments.filter(x=>!x.assessment.isExplicitMatch).length,
  needsReview:assessments.filter(x=>x.assessment.warnings.length>0).length,
  assessments,
  disclaimer:"References are not proof of verification; review scope, context and observations independently."
 };
}
export function parseEvidenceSearch(value:unknown){
 if(typeof value!=="string")return "";
 return value.trim().slice(0,120);
}
export function evidenceCandidateSort<T extends {controlId:string;observedAt:Date|null;id:string}>(
 rows:readonly T[],finding:FindingReference
):T[]{
 return rows.slice().sort((a,b)=>{
  const ma=a.controlId===finding.ruleId||a.controlId===finding.key?0:1;
  const mb=b.controlId===finding.ruleId||b.controlId===finding.key?0:1;
  return ma-mb||(b.observedAt?.getTime()??0)-(a.observedAt?.getTime()??0)||a.id.localeCompare(b.id);
 });
}
export function enforceLinkCapacity(activeCount:number,limit=50):void{
 if(activeCount>=limit)
  throw new EvidenceLinkError("CAPACITY",`At most ${limit} active references per work item.`);
}
export function linkExportFields(row:LinkItem,finding:FindingReference,now=new Date()):string[]{
 const a=assessLinkedEvidence(row.evidence,finding,now);
 return [
  row.evidenceId,row.evidence.source,row.evidence.controlId,row.evidence.domain,
  row.evidence.scope,row.evidence.state,row.evidence.observedAt?.toISOString()??"",
  row.reason,row.linkedAt.toISOString(),row.unlinkedAt?.toISOString()??"",
  a.relationship,a.age,String(a.maySupportReview),a.warnings.join("; ")
 ];
}
