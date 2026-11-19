import{db,type Prisma}from "@cyberpilot/database";
import{collectEvidenceDecisionReport}from "./evidence-decision-service";
import type{IntegratedReviewer}from "./integrated-risk-service";
import{
 createDecisionCaseSnapshot,caseCreationEvent,
 applyDecisionCaseTransition,buildDecisionCaseBoard,
 correlateDecisionCases,digestDecisionCase,
 type DecisionCaseSnapshot,type DecisionCaseEvent,
 type DecisionCaseTransition,type DecisionCaseCommand,
 type DecisionCaseState,
}from "./evidence-decision-case-domain";
export class DecisionCaseServiceError extends Error{
 constructor(public readonly code:string){super(code);}
}
const fail=(code:string):never=>{throw new DecisionCaseServiceError(code);};
const id=(x:string)=>typeof x==="string"&&
 /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const digest=(x:string)=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const iso=(x:string)=>typeof x==="string"&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const date=(x:Date|null)=>x?.toISOString()??null;
const refs=(x:Prisma.JsonValue):string[]=>Array.isArray(x)?
 x.filter((v):v is string=>typeof v==="string"):[];
type DbCase=NonNullable<Awaited<ReturnType<
 typeof db.evidenceDecisionCase.findFirst>>>;
type DbEvent=Awaited<ReturnType<
 typeof db.evidenceDecisionCaseEvent.findMany>>[number];
function mapCase(row:DbCase):DecisionCaseSnapshot{
 return{
 caseId:row.id,organizationId:row.organizationId,
 decisionKey:row.decisionKey,sourceReportDigest:row.sourceReportDigest,
 code:row.code as DecisionCaseSnapshot["code"],
 priority:row.priority as DecisionCaseSnapshot["priority"],
 domain:row.domain,controlId:row.controlId,scope:row.scope,
 evidenceIds:refs(row.evidenceIds),findingIds:refs(row.findingIds),
 relatedActionId:row.relatedActionId,ownerUserId:row.ownerUserId,
 status:row.status as DecisionCaseState,reviewNote:row.reviewNote,
 dueAt:date(row.dueAt),revision:row.revision,
 createdById:row.createdById,updatedById:row.updatedById,
 updatedAt:row.updatedAt.toISOString(),
 independentlyVerified:false,providerOperations:0,
 customerConsentProven:false,historicalScoreModified:false,
 };
}
function mapEvent(row:DbEvent):DecisionCaseEvent{
 return{
 organizationId:row.organizationId,caseId:row.caseId,
 revision:row.revision,kind:row.kind as DecisionCaseCommand,
 previousStatus:row.previousStatus as DecisionCaseState,
 nextStatus:row.nextStatus as DecisionCaseState,
 actorUserId:row.actorUserId,
 occurredAt:row.occurredAt.toISOString(),
 snapshotDigest:row.snapshotDigest,
 externalExecution:false,independentProofEstablished:false,
 };
}
async function authorize(actor:IntegratedReviewer,write:boolean){
 if(!id(actor.userId)||!id(actor.organizationId))
 fail("CASE_ACTOR_INVALID");
 const member=await db.membership.findFirst({
 where:{organizationId:actor.organizationId,userId:actor.userId},
 select:{role:true},
 });
 if(!member||member.role!==actor.role)
 fail("CASE_ACTIVE_MEMBERSHIP_REQUIRED");
 if(write&&!["OWNER","ADMIN"].includes(member.role))
 fail("CASE_MUTATOR_ROLE_REQUIRED");
 if(!["OWNER","ADMIN","AUDITOR"].includes(member.role))
 fail("CASE_REVIEW_ROLE_REQUIRED");
}
async function verifyOwner(organizationId:string,userId:string|null){
 if(userId===null)return;
 if(!id(userId))fail("CASE_OWNER_ID_INVALID");
 const member=await db.membership.findFirst({
 where:{organizationId,userId},select:{id:true},
 });
 if(!member)fail("CASE_OWNER_NOT_TENANT_MEMBER");
}
async function verifyRelatedAction(
 organizationId:string,actionId:string|null,decisionFindingIds:string[],
){
 if(actionId===null)return;
 if(!id(actionId))fail("CASE_ACTION_ID_INVALID");
 const action=await db.integratedRiskAction.findFirst({
 where:{organizationId,id:actionId},
 select:{riskKey:true,evidenceRefs:true},
 });
 if(!action)fail("CASE_ACTION_NOT_IN_TENANT");
 if(!decisionFindingIds.length)
 fail("CASE_ACTION_MUST_HAVE_ORIGINAL_FINDING");
 // An action can be bound only if its persisted source risk is present
 // in the current integrated register and shares an original finding.
 const linked=await db.securityFinding.findMany({
 where:{organizationId,id:{in:decisionFindingIds}},
 select:{id:true},
 });
 if(linked.length===0)fail("CASE_FINDING_NOT_IN_TENANT");
}
export type NewDecisionCase={
 decisionKey:string;ownerUserId:string|null;
 relatedActionId:string|null;dueAt:string|null;
 reviewNote:string|null;
};
export type UpdateDecisionCase={
 caseId:string;expectedRevision:number;
 kind:Exclude<DecisionCaseCommand,"CREATE">;
 reason?:string;
 nextOwnerUserId?:string|null;
 nextDueAt?:string|null;
 relatedActionId?:string|null;
};
export async function readEvidenceDecisionCases(
 actor:IntegratedReviewer,asOf=new Date().toISOString()){
 await authorize(actor,false);
 if(!iso(asOf))fail("CASE_READ_TIME_INVALID");
 const organizationId=actor.organizationId;
 const [rows,events]=await Promise.all([
 db.evidenceDecisionCase.findMany({
 where:{organizationId},take:501,
 orderBy:[{updatedAt:"desc"},{id:"asc"}],
 }),
 db.evidenceDecisionCaseEvent.findMany({
 where:{organizationId},take:2001,
 orderBy:[{occurredAt:"asc"},{id:"asc"}],
 }),
 ]);
 const cases=rows.slice(0,500).map(mapCase);
 const history=events.slice(0,2000).map(mapEvent);
 const board=buildDecisionCaseBoard({
 organizationId,asOf,cases,events:history,
 truncated:rows.length>500||events.length>2000,
 });
 const report=await collectEvidenceDecisionReport(actor);
 const correlation=correlateDecisionCases(board,report);
 return{
 schema:"cyberpilot.evidence.decision.case.read.v1" as const,
 organizationId,board,correlation,
 currentDecisionReportDigest:report.reportDigest,
 currentDecisionCount:report.decisions.length,
 sourceTruncated:rows.length>500||events.length>2000,
 externalProviderCalls:0 as const,
 remediationVerified:false as const,
 customerApprovalCreated:false as const,
 };
}
export async function createEvidenceDecisionCase(
 actor:IntegratedReviewer,input:NewDecisionCase){
 await authorize(actor,true);
 if(!digest(input.decisionKey)||input.reviewNote!==null&&
 (typeof input.reviewNote!=="string"||
 input.reviewNote.length>3000)||
 input.dueAt!==null&&!iso(input.dueAt))
 fail("CASE_CREATE_INPUT_INVALID");
 await verifyOwner(actor.organizationId,input.ownerUserId);
 const report=await collectEvidenceDecisionReport(actor);
 if(report.outcome==="BLOCKED")
 fail("CASE_SOURCE_TRIAGE_BLOCKED");
 const decision=report.decisions.find(x=>x.key===input.decisionKey);
 if(!decision||decision.code==="QUARANTINE")
 fail("CASE_DECISION_NOT_CURRENT");
 await verifyRelatedAction(actor.organizationId,
 input.relatedActionId,decision.supportingFindingIds);
 const existing=await db.evidenceDecisionCase.findUnique({
 where:{organizationId_decisionKey:{
 organizationId:actor.organizationId,decisionKey:input.decisionKey,
 }},
 });
 if(existing)return{created:false,case:mapCase(existing),
 externalCalls:0 as const};
 const now=new Date();
 try{
 const created=await db.$transaction(async tx=>{
 const inserted=await tx.evidenceDecisionCase.create({
 data:{
 organizationId:actor.organizationId,decisionKey:decision.key,
 sourceReportDigest:report.reportDigest,code:decision.code,
 priority:decision.priority,domain:decision.domain.slice(0,120),
 controlId:decision.controlId.slice(0,160),scope:decision.scope.slice(0,250),
 evidenceIds:decision.supportingEvidenceIds as Prisma.InputJsonValue,
 findingIds:decision.supportingFindingIds as Prisma.InputJsonValue,
 relatedActionId:input.relatedActionId,
 ownerUserId:input.ownerUserId,status:"OPEN",
 reviewNote:input.reviewNote,dueAt:input.dueAt?new Date(input.dueAt):null,
 revision:1,createdById:actor.userId,updatedById:actor.userId,
 updatedAt:now,
 },
 });
 const snapshot=createDecisionCaseSnapshot({
 caseId:inserted.id,actorUserId:actor.userId,
 at:inserted.updatedAt.toISOString(),report,decisionKey:decision.key,
 ownerUserId:input.ownerUserId,dueAt:date(inserted.dueAt),
 reviewNote:input.reviewNote,relatedActionId:input.relatedActionId,
 });
 const event=caseCreationEvent(snapshot);
 await tx.evidenceDecisionCaseEvent.create({data:{
 organizationId:actor.organizationId,caseId:inserted.id,
 revision:1,kind:"CREATE",previousStatus:"OPEN",nextStatus:"OPEN",
 actorUserId:actor.userId,occurredAt:inserted.updatedAt,
 snapshotDigest:event.snapshotDigest,
 }});
 return inserted;
 },{isolationLevel:"Serializable"});
 return{created:true,case:mapCase(created),
 externalCalls:0 as const};
 }catch(error){
 if(error&&typeof error==="object"&&"code" in error&&
 error.code==="P2002"){
 const found=await db.evidenceDecisionCase.findUnique({
 where:{organizationId_decisionKey:{
 organizationId:actor.organizationId,decisionKey:input.decisionKey,
 }},
 });
 if(found)return{created:false,case:mapCase(found),externalCalls:0 as const};
 }
 throw error;
 }
}
export async function updateEvidenceDecisionCase(
 actor:IntegratedReviewer,command:UpdateDecisionCase){
 await authorize(actor,true);
 if(!id(command.caseId)||!Number.isSafeInteger(command.expectedRevision)||
 command.expectedRevision<1)
 fail("CASE_MUTATION_INPUT_INVALID");
 if(command.nextOwnerUserId!==undefined)
 await verifyOwner(actor.organizationId,command.nextOwnerUserId);
 const current=await db.evidenceDecisionCase.findFirst({
 where:{id:command.caseId,organizationId:actor.organizationId},
 });
 if(!current)fail("CASE_NOT_IN_TENANT");
 if(command.kind==="LINK_ACTION"&&
 command.relatedActionId!==undefined)
 await verifyRelatedAction(actor.organizationId,command.relatedActionId,
 refs(current.findingIds));
 const transition:DecisionCaseTransition={
 organizationId:actor.organizationId,caseId:current.id,
 actorUserId:actor.userId,expectedRevision:command.expectedRevision,
 kind:command.kind,at:new Date().toISOString(),
 ...(command.reason!==undefined?{reason:command.reason}:{}),
 ...(command.nextOwnerUserId!==undefined?
 {nextOwnerUserId:command.nextOwnerUserId}:{}),
 ...(command.nextDueAt!==undefined?{nextDueAt:command.nextDueAt}:{}),
 ...(command.relatedActionId!==undefined?
 {relatedActionId:command.relatedActionId}:{}),
 };
 const outcome=applyDecisionCaseTransition(mapCase(current),transition);
 if(!outcome.accepted||!outcome.next||!outcome.event)
 fail(outcome.reason);
 const next=outcome.next,event=outcome.event;
 const updated=await db.$transaction(async tx=>{
 const changed=await tx.evidenceDecisionCase.updateMany({
 where:{id:current.id,organizationId:actor.organizationId,
 revision:current.revision},
 data:{
 revision:next.revision,status:next.status,
 ownerUserId:next.ownerUserId,
 dueAt:next.dueAt?new Date(next.dueAt):null,
 relatedActionId:next.relatedActionId,reviewNote:next.reviewNote,
 updatedById:actor.userId,updatedAt:new Date(next.updatedAt),
 },
 });
 if(changed.count!==1)fail("CASE_CONCURRENT_REVISION_CONFLICT");
 await tx.evidenceDecisionCaseEvent.create({data:{
 organizationId:actor.organizationId,caseId:current.id,
 revision:event.revision,kind:event.kind,
 previousStatus:event.previousStatus,nextStatus:event.nextStatus,
 actorUserId:actor.userId,occurredAt:new Date(event.occurredAt),
 snapshotDigest:digestDecisionCase(next),
 }});
 return tx.evidenceDecisionCase.findFirstOrThrow({
 where:{id:current.id,organizationId:actor.organizationId},
 });
 },{isolationLevel:"Serializable"});
 return{case:mapCase(updated),event,
 providerCalls:0 as const,remediationVerified:false as const};
}
export async function linkDecisionToExistingRiskAction(
 actor:IntegratedReviewer,caseId:string,actionId:string,
 expectedRevision:number){
 return updateEvidenceDecisionCase(actor,{
 caseId,expectedRevision,kind:"LINK_ACTION",
 relatedActionId:actionId,
 });
}
export async function readDecisionCaseEvents(
 actor:IntegratedReviewer,caseId:string){
 await authorize(actor,false);
 if(!id(caseId))fail("CASE_ID_INVALID");
 const item=await db.evidenceDecisionCase.findFirst({
 where:{organizationId:actor.organizationId,id:caseId},
 select:{id:true},
 });
 if(!item)fail("CASE_NOT_IN_TENANT");
 const events=await db.evidenceDecisionCaseEvent.findMany({
 where:{organizationId:actor.organizationId,caseId},
 orderBy:[{revision:"asc"}],take:2001,
 });
 return{
 organizationId:actor.organizationId,caseId,
 events:events.slice(0,2000).map(mapEvent),
 truncated:events.length>2000,
 providerEvents:0 as const,
 };
}
