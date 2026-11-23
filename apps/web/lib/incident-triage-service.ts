import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import type { IncidentSnapshot, IncidentEvent } from "./incident-case-domain";
import { validateIncidentSnapshot, incidentDigest } from "./incident-case-domain";
import { buildIncidentTriageBoard } from "./incident-triage-assurance";
import { buildTriageCaseDossier, exportTriageBoard,
  exportTriageDossier } from "./incident-triage-dossier";

export class IncidentTriageError extends Error {
  constructor(public readonly code:string){super(code);}
}
function fail(code:string):never{throw new IncidentTriageError(code);}
const ident=(v:unknown):v is string=>typeof v==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
async function authorize(actor:IncidentActor){
  if(!ident(actor.userId)||!ident(actor.organizationId)||
    !["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("TRIAGE_REVIEW_ROLE_DENIED");
  const row=await db.membership.findFirst({where:{
    organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true}});
  if(!row||row.role!==actor.role)fail("TRIAGE_MEMBERSHIP_REVOKED");
}
type IncidentRow=NonNullable<Awaited<ReturnType<
  typeof db.guidedIncidentCase.findFirst>>>;
type EventRow=Awaited<ReturnType<typeof db.guidedIncidentEvent.findMany>>[number];
function mapIncident(row:IncidentRow):IncidentSnapshot{
  const s=row.snapshot as unknown as IncidentSnapshot;
  if(!s||typeof s!=="object"||
    validateIncidentSnapshot(s).length||
    s.id!==row.id||s.organizationId!==row.organizationId||
    s.revision!==row.revision||s.status!==row.status||
    incidentDigest(s)!==row.snapshotDigest)
    fail("TRIAGE_PERSISTED_SNAPSHOT_CORRUPT");
  return s;
}
function mapEvent(event:EventRow):IncidentEvent{
  return {organizationId:event.organizationId,incidentId:event.incidentId,
    revision:event.revision,kind:event.command as IncidentEvent["kind"],
    actorUserId:event.actorUserId,
    occurredAt:event.occurredAt.toISOString(),
    previousState:event.previousState as IncidentEvent["previousState"],
    nextState:event.nextState as IncidentEvent["nextState"],
    snapshotDigest:event.snapshotDigest,providerWrite:false,
    independentlyClosed:false};
}
export async function readIncidentTriageBoard(actor:IncidentActor,
  opts:{limit?:number;offset?:number;format?:"JSON"|"CSV"|"MARKDOWN"}={}){
  await authorize(actor);
  const limit=opts.limit??50,offset=opts.offset??0;
  if(!Number.isSafeInteger(limit)||limit<1||limit>100||
    !Number.isSafeInteger(offset)||offset<0||offset>10000)
    fail("TRIAGE_PAGING_INVALID");
  const where={organizationId:actor.organizationId};
  const [rows,total]=await Promise.all([
    db.guidedIncidentCase.findMany({where,skip:offset,take:limit,
      orderBy:[{createdAt:"desc"},{id:"asc"}]}),
    db.guidedIncidentCase.count({where}),
  ]);
  const board=buildIncidentTriageBoard(actor.organizationId,
    rows.map(mapIncident),new Date().toISOString(),
    undefined,total>offset+rows.length||offset>0);
  return {schema:"cyberpilot.incident.triage.page.v1" as const,
    organizationId:actor.organizationId,board,total,offset,limit,
    nextOffset:offset+limit<total?offset+limit:null,
    artifact:opts.format?exportTriageBoard(board,opts.format):null,
    source:"PERSISTED_GUIDED_CASES" as const,
    providerCalls:0 as const,liveExecutionProven:false as const};
}
export async function readIncidentTriageDossier(actor:IncidentActor,
  incidentId:string,format?:"JSON"|"CSV"|"MARKDOWN"){
  await authorize(actor);
  if(!ident(incidentId))fail("TRIAGE_INCIDENT_ID_INVALID");
  const row=await db.guidedIncidentCase.findFirst({where:{
    organizationId:actor.organizationId,id:incidentId}});
  if(!row)fail("TRIAGE_CASE_NOT_IN_TENANT");
  const events=await db.guidedIncidentEvent.findMany({where:{
    organizationId:actor.organizationId,incidentId},
    orderBy:{revision:"asc"},take:2001});
  const dossier=buildTriageCaseDossier(mapIncident(row),
    events.slice(0,2000).map(mapEvent),new Date().toISOString(),
    events.length>2000);
  return {schema:"cyberpilot.incident.triage.dossier.read.v1" as const,
    organizationId:actor.organizationId,dossier,
    artifact:format?exportTriageDossier(dossier,format):null,
    eventRows:Math.min(events.length,2000),
    auditTruncated:events.length>2000,
    providerCalls:0 as const,
    independentlyVerifiedContainment:false as const};
}
export async function readIncidentTriageOwnerWorkload(actor:IncidentActor){
  await authorize(actor);
  const rows=await db.guidedIncidentCase.findMany({where:{
    organizationId:actor.organizationId,status:{not:"CLOSED"}},
    take:501,orderBy:{updatedAt:"desc"}});
  const board=buildIncidentTriageBoard(actor.organizationId,
    rows.slice(0,500).map(mapIncident),new Date().toISOString(),
    {triageTargetMinutes:{LOW:1440,MEDIUM:480,HIGH:120,CRITICAL:30},
      followUpMinutes:{LOW:2880,MEDIUM:1440,HIGH:240,CRITICAL:60},
      maximumOpenHours:{LOW:720,MEDIUM:336,HIGH:72,CRITICAL:24},
      evidenceStaleHours:72,earliestEscalationMinutes:5,
      requireSeparateApprover:true,maxPageItems:500},rows.length>500);
  return {schema:"cyberpilot.incident.triage.workload.v1" as const,
    organizationId:actor.organizationId,assignedOwners:board.assignedOwners,
    immediate:board.immediate,unassigned:board.unassigned,
    overdue:board.overdue,truncated:board.truncated,
    workloadFairnessGuaranteed:false as const,
    providerOperations:0 as const};
}
