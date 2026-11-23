import { db, type Prisma } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { reviewIncidentAssurance,
  type AssuranceRequest } from "./incident-assurance-service";
import {
  beginAssuranceHandoffBoard, applyAssuranceHandoffCommand,
  validateAssuranceHandoffBoard, validateAssuranceHandoffAudit,
  assuranceHandoffBoardDigest, summarizeAssuranceHandoffBoard,
  planInternalAssuranceEscalations,
  type AssuranceHandoffBoard, type HandoffCommand,
  type HandoffLedgerEvent,
} from "./incident-assurance-handoff-domain";
export class AssuranceHandoffServiceError extends Error {
  constructor(public readonly code:string){super(code);}
}
const fail=(code:string):never=>{throw new AssuranceHandoffServiceError(code);};
const ident=(x:unknown):x is string=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
async function authorize(actor:IncidentActor,write=false){
  if(!ident(actor.organizationId)||!ident(actor.userId)||
      !["OWNER","ADMIN","AUDITOR"].includes(actor.role)||
      write&&!["OWNER","ADMIN"].includes(actor.role))
    fail("HANDOFF_ROLE_DENIED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)
    fail("HANDOFF_MEMBERSHIP_REVOKED");
}
type Row=NonNullable<Awaited<ReturnType<
  typeof db.incidentAssuranceHandoffBoard.findFirst>>>;
function unpack(row:Row){
  const board=row.snapshot as unknown as AssuranceHandoffBoard;
  if(!board||validateAssuranceHandoffBoard(board).length||
      board.organizationId!==row.organizationId||
      board.incidentId!==row.incidentId||board.id!==row.id||
      board.revision!==row.revision||board.status!==row.state||
      board.assuranceDigest!==row.assuranceDigest||
      assuranceHandoffBoardDigest(board)!==row.snapshotDigest)
    fail("HANDOFF_PERSISTED_SNAPSHOT_CORRUPT");
  return board;
}
function eventData(event:HandoffLedgerEvent){
  return{
    organizationId:event.organizationId,boardId:event.boardId,
    revision:event.revision,commandId:event.commandId,
    actorUserId:event.actorId,action:event.kind,
    occurredAt:new Date(event.at),eventDigest:event.eventDigest,
    previousDigest:event.beforeDigest,nextDigest:event.afterDigest,
    priorEventDigest:event.priorEventDigest,handoffId:event.handoffId,
  };
}
function unpackEvent(row:{
  organizationId:string;boardId:string;revision:number;
  commandId:string;actorUserId:string;action:string;occurredAt:Date;
  eventDigest:string;previousDigest:string|null;nextDigest:string;
  priorEventDigest:string|null;handoffId:string|null;
},incidentId:string):HandoffLedgerEvent{
  return{
    schema:"cyberpilot.incident.assurance.handoff-event.v1",
    organizationId:row.organizationId,boardId:row.boardId,
    incidentId,revision:row.revision,commandId:row.commandId,
    actorId:row.actorUserId,
    kind:row.action as HandoffLedgerEvent["kind"],
    handoffId:row.handoffId,at:row.occurredAt.toISOString(),
    beforeDigest:row.previousDigest,afterDigest:row.nextDigest,
    priorEventDigest:row.priorEventDigest,
    eventDigest:row.eventDigest,externalWrites:0,
  };
}
async function load(actor:IncidentActor,boardId:string){
  if(!ident(boardId))fail("HANDOFF_BOARD_ID_INVALID");
  const row=await db.incidentAssuranceHandoffBoard.findFirst({
    where:{organizationId:actor.organizationId,id:boardId},
  });
  if(!row)fail("HANDOFF_BOARD_NOT_FOUND");
  return unpack(row);
}
async function incident(actor:IncidentActor,incidentId:string){
  if(!ident(incidentId))fail("HANDOFF_INCIDENT_INVALID");
  const found=await db.guidedIncidentCase.findFirst({
    where:{organizationId:actor.organizationId,id:incidentId},
    select:{id:true,revision:true},
  });
  if(!found)fail("HANDOFF_INCIDENT_NOT_IN_TENANT");
  return found;
}
async function assignmentMember(actor:IncidentActor,userId:string){
  if(!ident(userId))fail("HANDOFF_ASSIGNEE_INVALID");
  const membership=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId},
    select:{role:true},
  });
  if(!membership||!["OWNER","ADMIN"].includes(membership.role))
    fail("HANDOFF_ASSIGNEE_ROLE_INVALID");
}
export async function createPersistedAssuranceHandoffBoard(
  actor:IncidentActor,boardId:string,request:AssuranceRequest,
){
  await authorize(actor,true);
  if(!ident(boardId))fail("HANDOFF_BOARD_ID_INVALID");
  if(request.situation.consistency!=="FAIL_CLOSED")
    fail("HANDOFF_PARTIAL_READ_CREATE_DENIED");
  const result=await reviewIncidentAssurance(actor,request);
  const caseRow=await incident(actor,result.incidentId);
  if(caseRow.revision!==result.incidentRevision)
    fail("HANDOFF_INCIDENT_CONCURRENT_DRIFT");
  const now=new Date().toISOString();
  const {board,event}=beginAssuranceHandoffBoard(
    boardId,result.report,actor.userId,now,
  );
  return db.$transaction(async tx=>{
    const latest=await tx.guidedIncidentCase.findFirst({
      where:{organizationId:actor.organizationId,id:board.incidentId},
      select:{revision:true},
    });
    if(!latest||latest.revision!==board.incidentRevision)
      fail("HANDOFF_INCIDENT_RACE");
    const existing=await tx.incidentAssuranceHandoffBoard.findFirst({
      where:{id:boardId,organizationId:actor.organizationId},
    });
    if(existing){
      const old=unpack(existing);
      if(old.assuranceDigest!==board.assuranceDigest||
          old.createdBy!==actor.userId)
        fail("HANDOFF_BOARD_IDEMPOTENCY_CONFLICT");
      return{board:old,created:false as const,
        providerWrites:0 as const};
    }
    await tx.incidentAssuranceHandoffBoard.create({data:{
      id:board.id,organizationId:actor.organizationId,
      incidentId:board.incidentId,revision:board.revision,
      state:board.status,assuranceDigest:board.assuranceDigest,
      snapshotDigest:assuranceHandoffBoardDigest(board),
      snapshot:board as unknown as Prisma.InputJsonValue,
      createdById:actor.userId,createdAt:new Date(now),updatedAt:new Date(now),
    }});
    await tx.incidentAssuranceHandoffEvent.create({data:eventData(event)});
    return{board,created:true as const,providerWrites:0 as const};
  },{isolationLevel:"Serializable"});
}
export async function mutatePersistedAssuranceHandoffBoard(
  actor:IncidentActor,
  input:Omit<HandoffCommand,"organizationId"|"actorId"|"at">,
){
  await authorize(actor,true);
  if(!ident(input.boardId)||!ident(input.commandId)||
      !Number.isSafeInteger(input.expectedRevision))
    fail("HANDOFF_COMMAND_INVALID");
  const current=await load(actor,input.boardId);
  await incident(actor,current.incidentId);
  if(input.action.kind==="ASSIGN")
    await assignmentMember(actor,input.action.assigneeId);
  const rows=await db.incidentAssuranceHandoffEvent.findMany({
    where:{organizationId:actor.organizationId,boardId:input.boardId},
    orderBy:{revision:"asc"},take:1500,
  });
  const events=rows.map(x=>unpackEvent(x,current.incidentId));
  if(validateAssuranceHandoffAudit(current,events).length)
    fail("HANDOFF_AUDIT_INTEGRITY_BROKEN");
  const last=events.at(-1);
  if(!last)fail("HANDOFF_EVENT_CHAIN_EMPTY");
  const {board,event}=applyAssuranceHandoffCommand(current,{
    ...input,organizationId:actor.organizationId,
    actorId:actor.userId,at:new Date().toISOString(),
  },last!.eventDigest);
  return db.$transaction(async tx=>{
    const cas=await tx.incidentAssuranceHandoffBoard.updateMany({
      where:{organizationId:actor.organizationId,id:current.id,
        revision:current.revision,
        snapshotDigest:assuranceHandoffBoardDigest(current)},
      data:{revision:board.revision,state:board.status,
        snapshot:board as unknown as Prisma.InputJsonValue,
        snapshotDigest:assuranceHandoffBoardDigest(board),
        updatedAt:new Date(board.updatedAt)},
    });
    if(cas.count!==1)fail("HANDOFF_CAS_CONFLICT");
    await tx.incidentAssuranceHandoffEvent.create({data:eventData(event)});
    return{board,event,providerWrites:0 as const,
      externalNotificationsSent:0 as const};
  },{isolationLevel:"Serializable"});
}
export async function readPersistedAssuranceHandoffBoard(
  actor:IncidentActor,boardId:string,
){
  await authorize(actor);
  const board=await load(actor,boardId);
  const rows=await db.incidentAssuranceHandoffEvent.findMany({
    where:{organizationId:actor.organizationId,boardId},
    orderBy:{revision:"asc"},take:1500,
  });
  const events=rows.map(x=>unpackEvent(x,board.incidentId));
  const errors=validateAssuranceHandoffAudit(board,events);
  if(errors.length)fail("HANDOFF_EVENT_HISTORY_CORRUPT:"+errors.join(","));
  const current=await incident(actor,board.incidentId);
  const asOf=new Date().toISOString();
  return{
    schema:"cyberpilot.incident.assurance.handoff.read.v1" as const,
    board,events,
    summary:summarizeAssuranceHandoffBoard(board,asOf),
    escalationPlan:planInternalAssuranceEscalations(board,asOf),
    caseRevisionDrift:current.revision!==board.incidentRevision,
    sourceReportNotIndependentlyRecollected:true as const,
    providerWrites:0 as const,notificationsSent:0 as const,
  };
}
export async function listPersistedAssuranceHandoffBoards(
  actor:IncidentActor,incidentId:string,offset=0,limit=30,
){
  await authorize(actor);
  await incident(actor,incidentId);
  if(!Number.isSafeInteger(offset)||offset<0||offset>10000||
      !Number.isSafeInteger(limit)||limit<1||limit>100)
    fail("HANDOFF_INDEX_PAGING_INVALID");
  const where={organizationId:actor.organizationId,incidentId};
  const [rows,total]=await Promise.all([
    db.incidentAssuranceHandoffBoard.findMany({
      where,skip:offset,take:limit,
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
    }),
    db.incidentAssuranceHandoffBoard.count({where}),
  ]);
  return{
    schema:"cyberpilot.incident.assurance.handoff.index.v1" as const,
    incidentId,organizationId:actor.organizationId,
    total,offset,limit,nextOffset:offset+limit<total?offset+limit:null,
    boards:rows.map(unpack),externalWrites:0 as const,
  };
}
export async function reviewAssuranceHandoffTenantAssignments(
  actor:IncidentActor,boardId:string,
){
  await authorize(actor);
  const board=await load(actor,boardId);
  const assigned=[...new Set(board.handoffs.flatMap(x=>
    x.assignedUserId?[x.assignedUserId]:[]))];
  const members=await db.membership.findMany({
    where:{organizationId:actor.organizationId,userId:{in:assigned}},
    select:{userId:true,role:true},
  });
  const lookup=new Map(members.map(x=>[x.userId,x.role]));
  const missing=assigned.filter(x=>!lookup.has(x));
  return{
    schema:"cyberpilot.incident.assurance.handoff.membership.v1" as const,
    boardId,organizationId:actor.organizationId,
    assignedCount:assigned.length,missingMembershipIds:missing,
    assignments:board.handoffs.map(x=>({
      id:x.id,assignedUserId:x.assignedUserId,
      memberRole:x.assignedUserId?lookup.get(x.assignedUserId)??null:null,
      activeMembership:x.assignedUserId?
        lookup.has(x.assignedUserId):false,
    })),
    providerWrites:0 as const,
  };
}
