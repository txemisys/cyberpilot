import{createHash}from "node:crypto";
import type{EvidenceDecision,EvidenceDecisionReport,
 EvidenceDecisionPriority,EvidenceDecisionCode}from "./evidence-decision-engine";
import{verifyEvidenceDecisionReport}from "./evidence-decision-engine";

export type DecisionCaseState="OPEN"|"IN_REVIEW"|"WAITING_EVIDENCE"|
 "REVIEW_REPORTED"|"REOPENED";
export type DecisionCaseCommand="CREATE"|"START"|"REQUEST_EVIDENCE"|
 "REPORT_REVIEW"|"REOPEN"|"ASSIGN"|"EDIT_DUE"|"LINK_ACTION"|"COMMENT";
export type DecisionCaseSnapshot={
 caseId:string;organizationId:string;decisionKey:string;
 sourceReportDigest:string;code:EvidenceDecisionCode;
 priority:EvidenceDecisionPriority;domain:string;controlId:string;scope:string;
 evidenceIds:string[];findingIds:string[];relatedActionId:string|null;
 ownerUserId:string|null;status:DecisionCaseState;
 reviewNote:string|null;dueAt:string|null;
 revision:number;createdById:string;updatedById:string;updatedAt:string;
 independentlyVerified:false;providerOperations:0;
 customerConsentProven:false;historicalScoreModified:false;
};
export type DecisionCaseTransition={
 kind:Exclude<DecisionCaseCommand,"CREATE">;
 organizationId:string;caseId:string;actorUserId:string;
 expectedRevision:number;at:string;
 reason?:string;nextOwnerUserId?:string|null;
 nextDueAt?:string|null;relatedActionId?:string|null;
};
export type DecisionCaseEvent={
 organizationId:string;caseId:string;revision:number;
 kind:DecisionCaseCommand;
 actorUserId:string;previousStatus:DecisionCaseState;
 nextStatus:DecisionCaseState;occurredAt:string;snapshotDigest:string;
 externalExecution:false;independentProofEstablished:false;
};
export type DecisionCaseResult={
 accepted:boolean;reason:string;
 previous:DecisionCaseSnapshot;
 next:DecisionCaseSnapshot|null;
 event:DecisionCaseEvent|null;
 externalWriteOccurred:false;
 legalCustomerApprovalGranted:false;
};
export type DecisionCaseAudit={
 valid:boolean;codes:string[];
 latestRevision:number;eventsObserved:number;
 latestDigestMatches:boolean;chainContiguous:boolean;
 technicalClosureVerified:false;
};
export type DecisionCaseBoard={
 organizationId:string;asOf:string;
 cases:DecisionCaseSnapshot[];events:DecisionCaseEvent[];
 audit:DecisionCaseAudit[];
 counts:{
 total:number;open:number;inReview:number;waitingEvidence:number;
 reportedReviews:number;reopened:number;unowned:number;
 overdue:number;withoutEvidence:number;linkedActions:number;
 highPriority:number;invalidAudit:number;expiredWithoutOwner:number;
 };
 riskReductionProven:false;externalActionsExecuted:0;
 tenantRiskAccepted:false;
};
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const key=(x:string)=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const id=(x:string)=>typeof x==="string"&&
 /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const clean=(x:string,max:number)=>typeof x==="string"&&
 x.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(x);
function canonical(value:unknown):string{
 if(value===null||typeof value==="string"||typeof value==="boolean"||
 typeof value==="number"){
  if(typeof value==="number"&&!Number.isFinite(value))
   throw Error("NONFINITE_CASE_FIELD");
  return JSON.stringify(value);
 }
 if(Array.isArray(value))return"["+value.map(canonical).join(",")+"]";
 if(typeof value==="object")return"{"+Object.entries(value)
  .sort(([a],[b])=>a.localeCompare(b))
  .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
 throw Error("NONCANONICAL_CASE_INPUT");
}
const digest=(x:unknown)=>createHash("sha256").update(canonical(x)).digest("hex");
export function digestDecisionCase(snapshot:DecisionCaseSnapshot){
 return digest(snapshot);
}
export function validateDecisionCase(snapshot:DecisionCaseSnapshot):string[]{
 const errors:string[]=[];
 if(!id(snapshot.organizationId)||!id(snapshot.caseId)||
 !key(snapshot.decisionKey)||!key(snapshot.sourceReportDigest))
 errors.push("IDENTITY_OR_SOURCE_INVALID");
 if(!clean(snapshot.domain,120)||!clean(snapshot.controlId,160)||
 !clean(snapshot.scope,250))errors.push("SOURCE_FIELDS_INVALID");
 if(!["P0","P1","P2","P3"].includes(snapshot.priority))
 errors.push("PRIORITY_INVALID");
 if(!["OPEN","IN_REVIEW","WAITING_EVIDENCE",
 "REVIEW_REPORTED","REOPENED"].includes(snapshot.status))
 errors.push("STATUS_INVALID");
 if(!Array.isArray(snapshot.evidenceIds)||
 snapshot.evidenceIds.length>100||
 snapshot.evidenceIds.some(x=>!id(x))||
 new Set(snapshot.evidenceIds).size!==snapshot.evidenceIds.length)
 errors.push("EVIDENCE_LINKS_INVALID");
 if(!Array.isArray(snapshot.findingIds)||
 snapshot.findingIds.length>100||
 snapshot.findingIds.some(x=>!id(x))||
 new Set(snapshot.findingIds).size!==snapshot.findingIds.length)
 errors.push("FINDING_LINKS_INVALID");
 if(snapshot.ownerUserId!==null&&!id(snapshot.ownerUserId)||
 snapshot.relatedActionId!==null&&!id(snapshot.relatedActionId))
 errors.push("ASSIGNEE_OR_LINK_INVALID");
 if(snapshot.dueAt!==null&&!iso(snapshot.dueAt))
 errors.push("DUE_DATE_INVALID");
 if(snapshot.reviewNote!==null&&!clean(snapshot.reviewNote,3000))
 errors.push("REVIEW_NOTE_INVALID");
 if(!Number.isSafeInteger(snapshot.revision)||snapshot.revision<1||
 !id(snapshot.createdById)||!id(snapshot.updatedById)||
 !iso(snapshot.updatedAt))errors.push("ACTOR_OR_REVISION_INVALID");
 if(snapshot.independentlyVerified!==false||
 snapshot.providerOperations!==0||snapshot.customerConsentProven!==false||
 snapshot.historicalScoreModified!==false)
 errors.push("FALSE_SECURITY_CLAIM");
 return[...new Set(errors)];
}
export function createDecisionCaseSnapshot(input:{
 caseId:string;actorUserId:string;at:string;
 report:EvidenceDecisionReport;decisionKey:string;
 ownerUserId:string|null;dueAt:string|null;
 relatedActionId:string|null;reviewNote:string|null;
}):DecisionCaseSnapshot{
 if(!verifyEvidenceDecisionReport(input.report).valid||
 !id(input.caseId)||!id(input.actorUserId)||!iso(input.at))
 throw Error("INVALID_DECISION_SOURCE");
 const choice=input.report.decisions.find(x=>x.key===input.decisionKey);
 if(!choice||choice.organizationId!==input.report.organizationId||
 choice.code==="QUARANTINE")
 throw Error("DECISION_NOT_ELIGIBLE_FOR_CASE");
 const result:DecisionCaseSnapshot={
 caseId:input.caseId,organizationId:choice.organizationId,
 decisionKey:choice.key,sourceReportDigest:input.report.reportDigest,
 code:choice.code,priority:choice.priority,
 domain:choice.domain,controlId:choice.controlId,scope:choice.scope,
 evidenceIds:[...choice.supportingEvidenceIds].sort(),
 findingIds:[...choice.supportingFindingIds].sort(),
 relatedActionId:input.relatedActionId,
 ownerUserId:input.ownerUserId,status:"OPEN",
 reviewNote:input.reviewNote,dueAt:input.dueAt,
 revision:1,createdById:input.actorUserId,
 updatedById:input.actorUserId,updatedAt:input.at,
 independentlyVerified:false,providerOperations:0,
 customerConsentProven:false,historicalScoreModified:false,
 };
 const errors=validateDecisionCase(result);
 if(errors.length)throw Error("NEW_CASE_INVALID:"+errors.join(","));
 return result;
}
export function caseCreationEvent(snapshot:DecisionCaseSnapshot):
 DecisionCaseEvent{
 if(validateDecisionCase(snapshot).length||snapshot.revision!==1||
 snapshot.status!=="OPEN")throw Error("INVALID_INITIAL_CASE");
 return{
 organizationId:snapshot.organizationId,caseId:snapshot.caseId,
 revision:1,kind:"CREATE",actorUserId:snapshot.createdById,
 previousStatus:"OPEN",nextStatus:"OPEN",occurredAt:snapshot.updatedAt,
 snapshotDigest:digestDecisionCase(snapshot),
 externalExecution:false,independentProofEstablished:false,
 };
}
const permitted:Record<Exclude<DecisionCaseCommand,"CREATE">,
 DecisionCaseState[]>={
 START:["OPEN","REOPENED","WAITING_EVIDENCE"],
 REQUEST_EVIDENCE:["OPEN","IN_REVIEW","REOPENED"],
 REPORT_REVIEW:["IN_REVIEW","WAITING_EVIDENCE"],
 REOPEN:["REVIEW_REPORTED","WAITING_EVIDENCE"],
 ASSIGN:["OPEN","IN_REVIEW","WAITING_EVIDENCE","REOPENED","REVIEW_REPORTED"],
 EDIT_DUE:["OPEN","IN_REVIEW","WAITING_EVIDENCE","REOPENED"],
 LINK_ACTION:["OPEN","IN_REVIEW","WAITING_EVIDENCE","REOPENED","REVIEW_REPORTED"],
 COMMENT:["OPEN","IN_REVIEW","WAITING_EVIDENCE","REOPENED","REVIEW_REPORTED"],
};
const states:Partial<Record<DecisionCaseCommand,DecisionCaseState>>={
 START:"IN_REVIEW",REQUEST_EVIDENCE:"WAITING_EVIDENCE",
 REPORT_REVIEW:"REVIEW_REPORTED",REOPEN:"REOPENED",
};
function reject(previous:DecisionCaseSnapshot,reason:string):
 DecisionCaseResult{
 return{accepted:false,reason,previous,next:null,event:null,
 externalWriteOccurred:false,legalCustomerApprovalGranted:false};
}
export function applyDecisionCaseTransition(
 previous:DecisionCaseSnapshot,command:DecisionCaseTransition
):DecisionCaseResult{
 if(validateDecisionCase(previous).length)
 return reject(previous,"INVALID_PREVIOUS_SNAPSHOT");
 if(command.organizationId!==previous.organizationId||
 command.caseId!==previous.caseId||!id(command.actorUserId))
 return reject(previous,"CROSS_TENANT_OR_ACTOR_INVALID");
 if(command.expectedRevision!==previous.revision)
 return reject(previous,"REVISION_CONFLICT");
 if(!iso(command.at)||command.at<previous.updatedAt)
 return reject(previous,"NONMONOTONIC_TIMESTAMP");
 if(!permitted[command.kind]?.includes(previous.status))
 return reject(previous,"ILLEGAL_STATE_TRANSITION");
 const reason=command.reason?.trim()??"";
 if(!clean(reason,3000))
 return reject(previous,"UNSAFE_REASON");
 if(["REQUEST_EVIDENCE","REPORT_REVIEW","REOPEN"].includes(command.kind)&&
 reason.length<15)
 return reject(previous,"SUBSTANTIVE_REASON_REQUIRED");
 if(command.kind==="ASSIGN"&&command.nextOwnerUserId!==null&&
 (command.nextOwnerUserId===undefined||!id(command.nextOwnerUserId)))
 return reject(previous,"OWNER_REQUIRED_OR_NULL");
 if(command.kind==="EDIT_DUE"&&command.nextDueAt!==null&&
 (command.nextDueAt===undefined||!iso(command.nextDueAt)))
 return reject(previous,"INVALID_NEW_DUE_DATE");
 if(command.kind==="LINK_ACTION"&&command.relatedActionId!==null&&
 (command.relatedActionId===undefined||!id(command.relatedActionId)))
 return reject(previous,"INVALID_ACTION_ID");
 if(command.kind==="REPORT_REVIEW"&&
 previous.ownerUserId===null)
 return reject(previous,"REVIEWER_OWNER_REQUIRED");
 const next:DecisionCaseSnapshot={
 ...previous,revision:previous.revision+1,
 updatedAt:command.at,updatedById:command.actorUserId,
 status:states[command.kind]??previous.status,
 reviewNote:reason||previous.reviewNote,
 independentlyVerified:false,providerOperations:0,
 customerConsentProven:false,historicalScoreModified:false,
 };
 if(command.kind==="ASSIGN")next.ownerUserId=command.nextOwnerUserId??null;
 if(command.kind==="EDIT_DUE")next.dueAt=command.nextDueAt??null;
 if(command.kind==="LINK_ACTION")
 next.relatedActionId=command.relatedActionId??null;
 const failures=validateDecisionCase(next);
 if(failures.length)return reject(previous,failures[0]!);
 const event:DecisionCaseEvent={
 organizationId:next.organizationId,caseId:next.caseId,
 revision:next.revision,kind:command.kind,
 actorUserId:command.actorUserId,previousStatus:previous.status,
 nextStatus:next.status,occurredAt:command.at,
 snapshotDigest:digestDecisionCase(next),
 externalExecution:false,independentProofEstablished:false,
 };
 return{accepted:true,reason:"ACCEPTED",previous,next,event,
 externalWriteOccurred:false,legalCustomerApprovalGranted:false};
}
export function auditDecisionCase(
 snapshot:DecisionCaseSnapshot,events:DecisionCaseEvent[]
):DecisionCaseAudit{
 const errors=validateDecisionCase(snapshot);
 const ordered=[...events].sort((a,b)=>a.revision-b.revision);
 const chainContiguous=ordered.length===snapshot.revision&&
 ordered.every((x,i)=>x.revision===i+1)&&
 ordered.every((x,i)=>i===0||x.previousStatus===ordered[i-1]!.nextStatus);
 if(!chainContiguous)errors.push("REVISION_HISTORY_INCOMPLETE");
 if(ordered.some(x=>x.organizationId!==snapshot.organizationId||
 x.caseId!==snapshot.caseId||!id(x.actorUserId)||
 !iso(x.occurredAt)||!key(x.snapshotDigest)||
 x.externalExecution!==false||x.independentProofEstablished!==false))
 errors.push("EVENT_PROVENANCE_INVALID");
 const latest=ordered.at(-1);
 if(latest?.nextStatus!==snapshot.status)
 errors.push("LATEST_STATUS_MISMATCH");
 const latestDigestMatches=latest?.snapshotDigest===
 digestDecisionCase(snapshot);
 if(!latestDigestMatches)errors.push("LATEST_DIGEST_MISMATCH");
 return{
 valid:errors.length===0,codes:[...new Set(errors)],
 latestRevision:latest?.revision??0,eventsObserved:events.length,
 latestDigestMatches,chainContiguous,
 technicalClosureVerified:false,
 };
}
export function buildDecisionCaseBoard(input:{
 organizationId:string;asOf:string;cases:DecisionCaseSnapshot[];
 events:DecisionCaseEvent[];truncated:boolean;
}):DecisionCaseBoard{
 if(!id(input.organizationId)||!iso(input.asOf))
 throw Error("INVALID_CASE_BOARD_SCOPE");
 if(input.cases.length>500||input.events.length>2000)
 throw Error("CASE_BOARD_BOUNDS_EXCEEDED");
 if(input.cases.some(x=>x.organizationId!==input.organizationId)||
 input.events.some(x=>x.organizationId!==input.organizationId))
 throw Error("CROSS_TENANT_CASE_BOARD");
 const audits=input.cases.map(item=>auditDecisionCase(item,
 input.events.filter(x=>x.caseId===item.caseId)));
 const count=(status:DecisionCaseState)=>
 input.cases.filter(x=>x.status===status).length;
 const overdue=input.cases.filter(x=>x.dueAt!==null&&
 x.dueAt<input.asOf&&x.status!=="REVIEW_REPORTED");
 const sorted=[...input.cases].sort((a,b)=>
 ({P0:0,P1:1,P2:2,P3:3}[a.priority]-
 {P0:0,P1:1,P2:2,P3:3}[b.priority])||
 (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||
 a.caseId.localeCompare(b.caseId));
 return{
 organizationId:input.organizationId,asOf:input.asOf,
 cases:sorted,events:[...input.events].sort((a,b)=>
 a.occurredAt.localeCompare(b.occurredAt)),
 audit:audits,
 counts:{
 total:input.cases.length,open:count("OPEN"),
 inReview:count("IN_REVIEW"),waitingEvidence:count("WAITING_EVIDENCE"),
 reportedReviews:count("REVIEW_REPORTED"),reopened:count("REOPENED"),
 unowned:input.cases.filter(x=>x.ownerUserId===null).length,
 overdue:overdue.length,
 withoutEvidence:input.cases.filter(x=>x.evidenceIds.length===0).length,
 linkedActions:input.cases.filter(x=>x.relatedActionId!==null).length,
 highPriority:input.cases.filter(x=>["P0","P1"].includes(x.priority)).length,
 invalidAudit:audits.filter(x=>!x.valid).length+
 Number(input.truncated),
 expiredWithoutOwner:overdue.filter(x=>x.ownerUserId===null).length,
 },
 riskReductionProven:false,externalActionsExecuted:0,
 tenantRiskAccepted:false,
 };
}
export function selectDecisionCases(board:DecisionCaseBoard,filter:{
 status?:DecisionCaseState[];priority?:EvidenceDecisionPriority[];
 ownerUserId?:string|null;onlyUnlinked?:boolean;
 overdueOnly?:boolean;search?:string;offset?:number;limit?:number;
}={}){
 const offset=filter.offset??0,limit=filter.limit??50;
 if(!Number.isSafeInteger(offset)||offset<0||
 !Number.isSafeInteger(limit)||limit<1||limit>200)
 throw Error("INVALID_CASE_PAGING");
 const search=filter.search?.trim().toLowerCase()??"";
 const items=board.cases.filter(x=>
 (!filter.status||filter.status.includes(x.status))&&
 (!filter.priority||filter.priority.includes(x.priority))&&
 (filter.ownerUserId===undefined||x.ownerUserId===filter.ownerUserId)&&
 (!filter.onlyUnlinked||x.relatedActionId===null)&&
 (!filter.overdueOnly||x.dueAt!==null&&x.dueAt<board.asOf)&&
 (!search||[x.domain,x.controlId,x.scope,x.code,x.reviewNote??""]
 .join(" ").toLowerCase().includes(search)));
 return{organizationId:board.organizationId,total:items.length,
 offset,limit,items:items.slice(offset,offset+limit),
 nextOffset:offset+limit<items.length?offset+limit:null,
 unverifiedRemediation:true as const};
}
export function correlateDecisionCases(
 board:DecisionCaseBoard,report:EvidenceDecisionReport){
 if(board.organizationId!==report.organizationId||
 !verifyEvidenceDecisionReport(report).valid)
 throw Error("CASE_CORRELATION_SCOPE_INVALID");
 const indexed=new Map(report.decisions.map(x=>[x.key,x]));
 return board.cases.map(item=>{
 const current=indexed.get(item.decisionKey);
 const historical=item.sourceReportDigest!==report.reportDigest;
 return{
 caseId:item.caseId,decisionKey:item.decisionKey,
 decisionStillPresent:Boolean(current),
 sourceReportChanged:historical,
 evidenceIdsChanged:Boolean(current)&&
 canonical(current!.supportingEvidenceIds)!==canonical(item.evidenceIds),
 findingIdsChanged:Boolean(current)&&
 canonical(current!.supportingFindingIds)!==canonical(item.findingIds),
 currentPriority:current?.priority??null,
 relatedActionId:item.relatedActionId,
 reportedReviewNotVerified:item.status==="REVIEW_REPORTED",
 technicalRemediationEstablished:false as const,
 };
 });
}
export function exportDecisionCaseBoard(board:DecisionCaseBoard,
 format:"JSON"|"CSV"|"MARKDOWN"){
 if(format==="JSON")return{
 filename:"evidence-cases-"+board.asOf.slice(0,10)+".json",
 mime:"application/json",content:JSON.stringify(board,null,2),
 };
 const q=(x:string|number|null)=>'"'+String(x??"").replaceAll('"','""')+'"';
 if(format==="CSV")return{
 filename:"evidence-cases-"+board.asOf.slice(0,10)+".csv",
 mime:"text/csv",content:[
 "caseId,decisionKey,priority,code,status,owner,due,revision,linkedAction",
 ...board.cases.map(x=>[x.caseId,x.decisionKey,x.priority,x.code,
 x.status,x.ownerUserId,x.dueAt,x.revision,x.relatedActionId]
 .map(q).join(","))].join("\n"),
 };
 if(format!=="MARKDOWN")throw Error("UNSUPPORTED_CASE_EXPORT");
 return{
 filename:"evidence-cases-"+board.asOf.slice(0,10)+".md",
 mime:"text/markdown",
 content:["# Evidence decision follow-ups",
 "Tenant: "+board.organizationId,"As of: "+board.asOf,
 "Audit anomalies: "+board.counts.invalidAudit,
 ...board.cases.map(x=>"- "+x.priority+" "+x.code+" "+x.controlId+
 " / "+x.status+" / "+(x.ownerUserId??"unassigned")),
 "No technical risk remediation or customer consent was established."
 ].join("\n"),
 };
}
