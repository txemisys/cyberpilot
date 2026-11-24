import { db, type Prisma } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { INCIDENT_TYPES, type IncidentType } from "./incident-playbook-catalog";
import { TABLETOP_FAULTS, type TabletopFault } from "./incident-tabletop-domain";
import {
  startPersistedTabletopSession, evolvePersistedTabletopSession,
  tabletopSessionDigest, verifyPersistedTabletopSession,
  verifyTabletopSessionEventChain, deterministicTabletopSessionReplay,
  type PersistedTabletopSession, type SessionEvent,
  type SessionCommand, type SessionParticipant,
} from "./incident-tabletop-session-domain";
export class TabletopSessionServiceError extends Error {
  constructor(public readonly code:string){super(code);}
}
const fail=(code:string):never=>{throw new TabletopSessionServiceError(code);};
const id=(x:unknown):x is string=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
async function authorize(actor:IncidentActor,write=false){
  if(!id(actor.organizationId)||!id(actor.userId)||
      !["OWNER","ADMIN","AUDITOR"].includes(actor.role)||
      (write&&!["OWNER","ADMIN"].includes(actor.role)))
    fail("SESSION_ACTOR_ROLE_DENIED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)
    fail("SESSION_MEMBERSHIP_REVOKED");
}
type Row=NonNullable<Awaited<ReturnType<typeof db.incidentTabletopSession.findFirst>>>;
function unpack(row:Row){
  const value=row.snapshot as unknown as PersistedTabletopSession;
  if(!value||verifyPersistedTabletopSession(value).length||
      value.id!==row.id||value.organizationId!==row.organizationId||
      value.incidentId!==row.incidentId||value.revision!==row.revision||
      value.state!==row.state||tabletopSessionDigest(value)!==row.snapshotDigest)
    fail("SESSION_SNAPSHOT_TAMPERED");
  return value;
}
function eventData(event:SessionEvent){
  return{
    organizationId:event.organizationId,sessionId:event.sessionId,
    revision:event.revision,commandId:event.commandId,
    actorUserId:event.actorId,kind:event.kind,
    at:new Date(event.at),beforeDigest:event.beforeDigest,
    afterDigest:event.afterDigest,priorEventDigest:event.priorEventDigest,
    eventDigest:event.eventDigest,moveAccepted:event.moveAccepted,
  };
}
function unpackEvent(row:{
  organizationId:string;sessionId:string;revision:number;
  commandId:string;actorUserId:string;kind:string;at:Date;
  beforeDigest:string|null;afterDigest:string;
  priorEventDigest:string|null;eventDigest:string;moveAccepted:boolean|null;
}):SessionEvent{
  return{
    schema:"cyberpilot.incident.tabletop.session.event.v1",
    organizationId:row.organizationId,sessionId:row.sessionId,
    revision:row.revision,commandId:row.commandId,actorId:row.actorUserId,
    kind:row.kind as SessionEvent["kind"],at:row.at.toISOString(),
    beforeDigest:row.beforeDigest,afterDigest:row.afterDigest,
    priorEventDigest:row.priorEventDigest,eventDigest:row.eventDigest,
    moveAccepted:row.moveAccepted,providerWrites:0,
  };
}
async function load(actor:IncidentActor,sessionId:string){
  if(!id(sessionId))fail("SESSION_ID_INVALID");
  const row=await db.incidentTabletopSession.findFirst({
    where:{organizationId:actor.organizationId,id:sessionId},
  });
  if(!row)fail("SESSION_NOT_FOUND");
  return unpack(row!);
}
async function memberFor(
  organizationId:string,userId:string,
){
  if(!id(userId))fail("SESSION_MEMBER_ID_INVALID");
  const member=await db.membership.findFirst({
    where:{organizationId,userId},select:{role:true},
  });
  if(!member)fail("SESSION_PARTICIPANT_NOT_MEMBER");
  return member!.role;
}
export async function createOrganizationTabletopSession(
  actor:IncidentActor,input:{
    id:string;incidentId:string|null;type:IncidentType;
    title:string;seed:number;faultCount:number;
    additionalFaults?:TabletopFault[];
  },
){
  await authorize(actor,true);
  if(!id(input.id)||!INCIDENT_TYPES.includes(input.type)||
      typeof input.title!=="string"||input.title.length<5||
      input.title.length>180||!Number.isSafeInteger(input.seed)||
      input.seed<0||input.seed>0xffffffff||
      !Number.isSafeInteger(input.faultCount)||
      input.faultCount<1||input.faultCount>8||
      !Array.isArray(input.additionalFaults??[])||
      (input.additionalFaults??[]).some(x=>!TABLETOP_FAULTS.includes(x))||
      (input.additionalFaults??[]).length>8)
    fail("SESSION_REQUEST_INVALID");
  if(input.incidentId!==null){
    if(!id(input.incidentId))fail("SESSION_INCIDENT_INVALID");
    const incident=await db.guidedIncidentCase.findFirst({
      where:{organizationId:actor.organizationId,id:input.incidentId},
      select:{id:true},
    });
    if(!incident)fail("SESSION_INCIDENT_NOT_IN_TENANT");
  }
  const now=new Date().toISOString();
  const {session,event}=startPersistedTabletopSession({
    id:input.id,organizationId:actor.organizationId,
    incidentId:input.incidentId,facilitatorId:actor.userId,
    type:input.type,title:input.title,seed:input.seed,
    at:now,faultCount:input.faultCount,
    ...(input.additionalFaults?{additionalFaults:input.additionalFaults}:{}),
  });
  return db.$transaction(async tx=>{
    const exists=await tx.incidentTabletopSession.findFirst({
      where:{id:input.id,organizationId:actor.organizationId},
    });
    if(exists){
      const prior=unpack(exists);
      if(prior.createdBy!==actor.userId||
          prior.scenario.incidentType!==input.type||
          prior.scenario.scenarioSeed!==input.seed||
          prior.scenario.title!==input.title)
        fail("SESSION_IDEMPOTENCY_CONFLICT");
      return{session:prior,created:false as const,providerWrites:0 as const};
    }
    await tx.incidentTabletopSession.create({data:{
      id:input.id,organizationId:actor.organizationId,
      incidentId:input.incidentId,state:session.state,
      revision:session.revision,snapshot:session as unknown as Prisma.InputJsonValue,
      snapshotDigest:tabletopSessionDigest(session),
      createdById:actor.userId,createdAt:new Date(now),updatedAt:new Date(now),
    }});
    await tx.incidentTabletopSessionEvent.create({data:eventData(event)});
    return{session,created:true as const,providerWrites:0 as const};
  },{isolationLevel:"Serializable"});
}
export async function commandOrganizationTabletopSession(
  actor:IncidentActor,input:Omit<SessionCommand,
    "organizationId"|"at">,
){
  await authorize(actor,true);
  if(!id(input.sessionId)||!id(input.commandId)||
      !Number.isSafeInteger(input.expectedRevision)||
      !input.action||!id(input.action.userId)||
      input.action.userId!==actor.userId)
    fail("SESSION_COMMAND_INVALID");
  const previous=await load(actor,input.sessionId);
  if(input.action.kind==="ENROLL"||
      input.action.kind==="TRANSFER_FACILITATOR"){
    await memberFor(actor.organizationId,input.action.participantId);
  }
  const events=await db.incidentTabletopSessionEvent.findMany({
    where:{organizationId:actor.organizationId,sessionId:input.sessionId},
    orderBy:{revision:"asc"},take:1500,
  });
  const mapped=events.map(unpackEvent);
  if(verifyTabletopSessionEventChain(previous,mapped).length)
    fail("SESSION_EVENT_CHAIN_TAMPERED");
  const last=mapped.at(-1);
  if(!last)fail("SESSION_EVENT_CHAIN_EMPTY");
  const command:SessionCommand={
    ...input,organizationId:actor.organizationId,
    at:new Date().toISOString(),
  };
  if(input.action.kind==="PLAY"){
    command.action={...input.action,
      move:{...input.action.move,at:command.at}};
  }
  const {session,event}=evolvePersistedTabletopSession(
    previous,command,last!.eventDigest,
  );
  return db.$transaction(async tx=>{
    const cas=await tx.incidentTabletopSession.updateMany({
      where:{id:previous.id,organizationId:actor.organizationId,
        revision:previous.revision,snapshotDigest:tabletopSessionDigest(previous)},
      data:{revision:session.revision,state:session.state,
        snapshot:session as unknown as Prisma.InputJsonValue,
        snapshotDigest:tabletopSessionDigest(session),updatedAt:new Date(command.at)},
    });
    if(cas.count!==1)fail("SESSION_CAS_CONFLICT");
    await tx.incidentTabletopSessionEvent.create({data:eventData(event)});
    return{session,event,providerWrites:0 as const,
      actualRemediationVerified:false as const};
  },{isolationLevel:"Serializable"});
}
export async function readOrganizationTabletopSession(
  actor:IncidentActor,sessionId:string,
){
  await authorize(actor);
  const session=await load(actor,sessionId);
  const rows=await db.incidentTabletopSessionEvent.findMany({
    where:{organizationId:actor.organizationId,sessionId},
    orderBy:{revision:"asc"},take:1500,
  });
  const events=rows.map(unpackEvent);
  const faults=verifyTabletopSessionEventChain(session,events);
  if(faults.length)fail("SESSION_AUDIT_INVALID:"+faults.join(","));
  const replay=deterministicTabletopSessionReplay(session);
  if(!replay.identical)fail("SESSION_REPLAY_DIVERGENT");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member)fail("SESSION_ACCESS_LOST");
  return{
    schema:"cyberpilot.incident.tabletop.session.read.v1" as const,
    session,events,replay,
    participant:session.participants.find(x=>
      x.userId===actor.userId&&x.active)??null,
    externalProviderWrites:0 as const,
    providerContainmentProven:false as const,
  };
}
export async function listOrganizationTabletopSessions(
  actor:IncidentActor,offset=0,limit=30,
){
  await authorize(actor);
  if(!Number.isSafeInteger(offset)||offset<0||offset>10000||
      !Number.isSafeInteger(limit)||limit<1||limit>100)
    fail("SESSION_PAGING_INVALID");
  const where={organizationId:actor.organizationId};
  const [rows,total]=await Promise.all([
    db.incidentTabletopSession.findMany({
      where,skip:offset,take:limit,
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
    }),
    db.incidentTabletopSession.count({where}),
  ]);
  const sessions=rows.map(unpack);
  return{
    schema:"cyberpilot.incident.tabletop.session.index.v1" as const,
    total,offset,limit,
    nextOffset:offset+limit<total?offset+limit:null,
    sessions:sessions.map(x=>({
      id:x.id,incidentId:x.incidentId,type:x.scenario.incidentType,
      title:x.scenario.title,state:x.state,revision:x.revision,
      createdAt:x.createdAt,updatedAt:x.updatedAt,
      participants:x.participants.filter(y=>y.active).length,
      trainingMoves:x.moveReceipts.length,
      unsafeAttempts:x.exercise.unsafeOperationsBlocked,
      providerWrites:0 as const,
    })),
  };
}
export async function inspectTabletopSessionParticipants(
  actor:IncidentActor,sessionId:string,
){
  await authorize(actor);
  const session=await load(actor,sessionId);
  const current=await db.membership.findMany({
    where:{organizationId:actor.organizationId,
      userId:{in:session.participants.map(x=>x.userId)}},
    select:{userId:true,role:true},
  });
  const lookup=new Map(current.map(x=>[x.userId,x.role]));
  return{
    schema:"cyberpilot.incident.tabletop.membership.review.v1" as const,
    sessionId,participants:session.participants.map(x=>({
      ...x,currentlyMember:lookup.has(x.userId),
      currentTenantRole:lookup.get(x.userId)??null,
      accessRevoked:!lookup.has(x.userId),
    })),
    allActiveParticipantsStillMembers:
      session.participants.filter(x=>x.active).every(x=>lookup.has(x.userId)),
    providerWrites:0 as const,
  };
}
