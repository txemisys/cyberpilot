import { db,type Prisma } from "@cyberpilot/database";
import {createHash} from "node:crypto";
import {
  applyIntegratedActionCommand,auditIntegratedActionHistory,
  summarizeIntegratedActionBoard,sortIntegratedActions,
  digestIntegratedActionSnapshot,
  type ActionSnapshot,type ActionCommand,type ActionDomainEvent,
  type ActionPriority,
} from "./integrated-action-domain";
import {collectIntegratedRiskDigest,
  type IntegratedReviewer} from "./integrated-risk-service";

export type ActionActor=IntegratedReviewer;
export type CreateRiskAction={
  riskKey:string;priority:ActionPriority;
  ownerUserId:string|null;dueAt:string|null;
  rationale:string|null;
};
export type ActionMutation={
  actionId:string;expectedRevision:number;
  kind:ActionCommand["kind"];
  nextOwnerUserId?:string|null;
  nextPriority?:ActionPriority;
  nextDueAt?:string|null;
  reason?:string;
  exceptionExpiresAt?:string|null;
};
export class RiskActionError extends Error{
  constructor(public readonly code:string){super(code);}
}
function fail(code:string):never{throw new RiskActionError(code);}
const isISO=(s:string)=>typeof s==="string"&&
  Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const id=(s:string)=>typeof s==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const digest=(s:string)=>typeof s==="string"&&/^[a-f0-9]{64}$/.test(s);
const sha=(s:string)=>createHash("sha256").update(s).digest("hex");
const optionalDate=(d:Date|null)=>d?.toISOString()??null;
type DbRiskAction=Awaited<ReturnType<typeof db.integratedRiskAction.findFirst>>;
export function rowToSnapshot(row:NonNullable<DbRiskAction>):ActionSnapshot{
  return{
    organizationId:row.organizationId,actionId:row.id,
    riskKey:row.riskKey,title:row.title,
    description:row.description,
    severity:row.severity,sourceFingerprint:row.sourceFingerprint,
    evidenceRefs:Array.isArray(row.evidenceRefs)?
      row.evidenceRefs.filter((x):x is string=>typeof x==="string"):[],
    status:row.status as ActionSnapshot["status"],
    priority:row.priority as ActionPriority,
    ownerUserId:row.ownerUserId,dueAt:optionalDate(row.dueAt),
    rationale:row.rationale,exceptionReason:row.exceptionReason,
    exceptionExpiresAt:optionalDate(row.exceptionExpiresAt),
    revision:row.revision,createdById:row.createdById,
    updatedById:row.updatedById,updatedAt:row.updatedAt.toISOString(),
    independentRemediationVerified:false,
    customerLegalAcceptanceProven:false,sourceEvidenceReevaluated:false,
  };
}
type ActionEventRow=Awaited<ReturnType<
  typeof db.integratedRiskActionEvent.findMany>>[number];
function eventToDomain(row:ActionEventRow):ActionDomainEvent{
  const payload=row.snapshot as Record<string,unknown>;
  return{
    organizationId:row.organizationId,actionId:row.actionId,
    revision:row.revision,
    kind:row.kind as ActionCommand["kind"],
    previousStatus:row.previousStatus as ActionSnapshot["status"],
    nextStatus:row.nextStatus as ActionSnapshot["status"],
    actorUserId:row.actorUserId,occurredAt:row.occurredAt.toISOString(),
    snapshotDigest:String(payload.snapshotDigest??""),
    automaticallyExecutedRemediation:false,
  };
}
async function access(actor:ActionActor,mutate:boolean){
  if(!id(actor.organizationId)||!id(actor.userId))
    fail("INVALID_TENANT_OR_ACTOR");
  const membership=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!membership||membership.role!==actor.role)
    fail("ACTIVE_ORGANIZATION_MEMBERSHIP_REQUIRED");
  if(mutate&&!["OWNER","ADMIN"].includes(membership.role))
    fail("ACTION_MANAGER_PERMISSION_REQUIRED");
}
async function eligibleOwner(organizationId:string,userId:string|null){
  if(userId===null)return true;
  if(!id(userId))return false;
  const candidate=await db.membership.findFirst({
    where:{organizationId,userId},select:{id:true},
  });
  return Boolean(candidate);
}
export async function readIntegratedActions(actor:ActionActor,
  asOf=new Date().toISOString()){
  await access(actor,false);
  if(!isISO(asOf))fail("INVALID_READING_TIME");
  const [items,events]=await Promise.all([
    db.integratedRiskAction.findMany({
      where:{organizationId:actor.organizationId},
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
      take:501,
    }),
    db.integratedRiskActionEvent.findMany({
      where:{organizationId:actor.organizationId},
      orderBy:[{occurredAt:"asc"},{id:"asc"}],
      take:2001,
    }),
  ]);
  const actions=items.slice(0,500).map(rowToSnapshot);
  const history=events.slice(0,2000).map(eventToDomain);
  const audits=actions.map(action=>({
    actionId:action.actionId,
    ...auditIntegratedActionHistory(action,
      history.filter(x=>x.actionId===action.actionId)),
  }));
  const orphan=history.filter(x=>!actions.some(a=>
    a.actionId===x.actionId)).map(x=>x.actionId);
  const duplicates=actions.filter((x,i)=>
    actions.findIndex(a=>a.riskKey===x.riskKey)!==i);
  const issues=[
    ...(items.length>500?["ACTIONS_TRUNCATED"]:[]),
    ...(events.length>2000?["EVENTS_TRUNCATED"]:[]),
    ...audits.filter(x=>!x.valid).map(x=>"AUDIT:"+x.actionId),
    ...(orphan.length?["MISSING_EVENT_PARENT"]:[]),
    ...(duplicates.length?["DUPLICATE_RISK_KEY"]:[]),
  ];
  return{
    schema:"cyberpilot.integrated.actions.read.v1" as const,
    organizationId:actor.organizationId,asOf,
    actions:sortIntegratedActions(actions),
    audits,
    summary:summarizeIntegratedActionBoard(actions,asOf),
    issues:[...new Set(issues)],
    history,
    counts:{actions:items.length,events:events.length},
    truncated:items.length>500||events.length>2000,
    externalProviderOperations:0 as const,
    liveRemediationPerformed:false as const,
    riskAcceptedByClient:false as const,
    CyberScoreV1Changed:false as const,
  };
}
export async function createIntegratedAction(
  actor:ActionActor,input:CreateRiskAction){
  await access(actor,true);
  if(!digest(input.riskKey)||!["LOW","NORMAL","HIGH","URGENT"]
    .includes(input.priority)||input.rationale!==null&&
    (typeof input.rationale!=="string"||
      input.rationale.length>2000)||
    input.dueAt!==null&&(!isISO(input.dueAt)||
      input.dueAt.length>30))
    fail("NEW_ACTION_INPUT_INVALID");
  if(!await eligibleOwner(actor.organizationId,input.ownerUserId))
    fail("CROSS_TENANT_ASSIGNEE_DENIED");
  // The risk originates in persisted tenant data, not a caller-supplied
  // title or fabricated control ID. No provider is contacted here.
  const digestReport=await collectIntegratedRiskDigest(actor);
  if(digestReport.state==="INCOMPLETE")
    fail("RISK_REGISTRY_INCOMPLETE");
  const risk=digestReport.risks.find(x=>x.key===input.riskKey);
  if(!risk||risk.status!=="OPEN")
    fail("RISK_NOT_PRESENT_OR_NOT_OPEN");
  const now=new Date();
  const sourceFingerprint=sha(JSON.stringify({
    riskKey:risk.key,sourceFindingIds:risk.sourceFindingIds,
    sourceEvidenceIds:risk.sourceEvidenceIds,
  }));
  const existing=await db.integratedRiskAction.findUnique({
    where:{organizationId_riskKey:{
      organizationId:actor.organizationId,riskKey:risk.key,
    }},
  });
  if(existing)
    return{created:false,action:rowToSnapshot(existing)};
  try{
    const row=await db.$transaction(async tx=>{
      const created=await tx.integratedRiskAction.create({
        data:{
          organizationId:actor.organizationId,riskKey:risk.key,
          title:risk.title.slice(0,250),
          description:risk.description,
          severity:risk.severity,
          sourceFingerprint,
          evidenceRefs:risk.sourceEvidenceIds as Prisma.InputJsonValue,
          status:"OPEN",priority:input.priority,
          ownerUserId:input.ownerUserId,
          dueAt:input.dueAt?new Date(input.dueAt):null,
          rationale:input.rationale,
          revision:1,
          createdById:actor.userId,
          updatedById:actor.userId,
          updatedAt:now,
        },
      });
      const snap=rowToSnapshot(created);
      const snapshotDigest=digestIntegratedActionSnapshot(snap);
      await tx.integratedRiskActionEvent.create({
        data:{
          organizationId:actor.organizationId,actionId:created.id,
          revision:1,kind:"CREATE",previousStatus:"OPEN",
          nextStatus:"OPEN",actorUserId:actor.userId,occurredAt:now,
          snapshot:{snapshotDigest} as Prisma.InputJsonValue,
        },
      });
      return created;
    },{isolationLevel:"Serializable"});
    return{created:true,action:rowToSnapshot(row),
      externalProviderOperations:0 as const};
  }catch(error){
    if(error&&typeof error==="object"&&
      "code" in error&&error.code==="P2002"){
      const found=await db.integratedRiskAction.findUnique({
        where:{organizationId_riskKey:{
          organizationId:actor.organizationId,riskKey:risk.key,
        }},
      });
      if(found)return{created:false,action:rowToSnapshot(found)};
    }
    throw error;
  }
}
export async function updateIntegratedAction(
  actor:ActionActor,mutation:ActionMutation){
  await access(actor,true);
  if(!id(mutation.actionId)||
    !Number.isSafeInteger(mutation.expectedRevision)||
    mutation.expectedRevision<1||mutation.kind==="CREATE")
    fail("ACTION_MUTATION_INVALID");
  if(mutation.nextOwnerUserId!==undefined&&
    !await eligibleOwner(actor.organizationId,mutation.nextOwnerUserId))
    fail("CROSS_TENANT_ASSIGNEE_DENIED");
  const row=await db.integratedRiskAction.findFirst({
    where:{id:mutation.actionId,organizationId:actor.organizationId},
  });
  if(!row)fail("ACTION_NOT_FOUND_IN_ORGANIZATION");
  const command:ActionCommand={
    actionId:row.id,organizationId:actor.organizationId,
    actorUserId:actor.userId,
    expectedRevision:mutation.expectedRevision,kind:mutation.kind,
    at:new Date().toISOString(),
    ...(mutation.nextOwnerUserId!==undefined?
      {nextOwnerUserId:mutation.nextOwnerUserId}:{}),
    ...(mutation.nextPriority!==undefined?
      {nextPriority:mutation.nextPriority}:{}),
    ...(mutation.nextDueAt!==undefined?
      {nextDueAt:mutation.nextDueAt}:{}),
    ...(mutation.reason!==undefined?
      {reason:mutation.reason}:{}),
    ...(mutation.exceptionExpiresAt!==undefined?
      {exceptionExpiresAt:mutation.exceptionExpiresAt}:{}),
  };
  const outcome=applyIntegratedActionCommand(rowToSnapshot(row),command);
  if(!outcome.accepted||!outcome.next||!outcome.event)
    fail(outcome.code);
  const next=outcome.next;
  const event=outcome.event;
  const result=await db.$transaction(async tx=>{
    const updated=await tx.integratedRiskAction.updateMany({
      where:{id:row.id,organizationId:actor.organizationId,
        revision:row.revision},
      data:{
        revision:next.revision,status:next.status,
        priority:next.priority,ownerUserId:next.ownerUserId,
        dueAt:next.dueAt?new Date(next.dueAt):null,
        rationale:next.rationale,
        exceptionReason:next.exceptionReason,
        exceptionExpiresAt:next.exceptionExpiresAt?
          new Date(next.exceptionExpiresAt):null,
        updatedById:actor.userId,updatedAt:new Date(next.updatedAt),
      },
    });
    if(updated.count!==1)fail("ACTION_CAS_CONCURRENT_CONFLICT");
    await tx.integratedRiskActionEvent.create({
      data:{
        organizationId:actor.organizationId,
        actionId:row.id,revision:event.revision,kind:event.kind,
        previousStatus:event.previousStatus,
        nextStatus:event.nextStatus,actorUserId:actor.userId,
        occurredAt:new Date(event.occurredAt),
        snapshot: { snapshotDigest: digestIntegratedActionSnapshot(next) },
      },
    });
    return tx.integratedRiskAction.findFirstOrThrow({
      where:{id:row.id,organizationId:actor.organizationId},
    });
  },{isolationLevel:"Serializable"});
  return{
    action:rowToSnapshot(result),event,
    externalProviderOperations:0 as const,
    legalRiskAcceptanceIssued:false as const,
    securityRemediationConfirmed:false as const,
  };
}
