import { createHash } from "node:crypto";
import {
  applyTabletopMove, createTabletopExercise, generateTabletopScenario,
  reviewTabletopExercise, validateTabletopScenario,
  type TabletopScenario, type TabletopExercise, type TabletopMove,
  type TabletopActorRole, type TabletopFault,
} from "./incident-tabletop-domain";
import { INCIDENT_TYPES, type IncidentType } from "./incident-playbook-catalog";

/** A persisted training session; no step is licensed to call a provider. */
export type SessionState = "ACTIVE" | "PAUSED" | "DEBRIEFED" | "ARCHIVED";
export type SessionParticipant = {
  userId: string; role: TabletopActorRole;
  joinedAt: string; active: boolean;
  permissions: "FACILITATOR" | "PARTICIPANT" | "OBSERVER";
  assignedBy: string;
};
export type SessionMoveReceipt = {
  sequence: number; move: TabletopMove; userId: string;
  accepted: boolean; code: string; exerciseDigest: string;
  recordedAt: string; externalWrites: 0;
};
export type PersistedTabletopSession = {
  schema: "cyberpilot.incident.tabletop.session.v1";
  id: string; organizationId: string; incidentId: string | null;
  state: SessionState; revision: number;
  createdAt: string; updatedAt: string; createdBy: string;
  facilitatorId: string;
  scenario: TabletopScenario; exercise: TabletopExercise;
  participants: SessionParticipant[];
  moveReceipts: SessionMoveReceipt[];
  notes: Array<{id:string;userId:string;at:string;text:string}>;
  debrief: {
    recordedBy: string; recordedAt: string;
    evidenceDigest: string; unreviewedSteps: string[];
    unsafeAttempts: number; acceptedMoves: number;
    failedMoves: number; independentProviderProof: false;
  } | null;
  supersededBy: string | null;
  externallyExecutedCommands: 0;
  providerContainmentProven: false;
};
export type SessionAction =
  | {kind:"ENROLL";userId:string;participantId:string;
      role:TabletopActorRole;permissions:SessionParticipant["permissions"]}
  | {kind:"REMOVE";userId:string;participantId:string}
  | {kind:"TRANSFER_FACILITATOR";userId:string;participantId:string}
  | {kind:"PAUSE";userId:string}
  | {kind:"RESUME";userId:string}
  | {kind:"PLAY";userId:string;move:TabletopMove}
  | {kind:"NOTE";userId:string;text:string}
  | {kind:"DEBRIEF";userId:string}
  | {kind:"ARCHIVE";userId:string}
  | {kind:"SUPERSEDE";userId:string;successorId:string};
export type SessionCommand = {
  organizationId:string;sessionId:string;expectedRevision:number;
  commandId:string;at:string;action:SessionAction;
};
export type SessionEvent = {
  schema:"cyberpilot.incident.tabletop.session.event.v1";
  organizationId:string;sessionId:string;revision:number;
  commandId:string;actorId:string;kind:SessionAction["kind"];at:string;
  beforeDigest:string|null;afterDigest:string;
  priorEventDigest:string|null;eventDigest:string;
  moveAccepted:boolean|null;providerWrites:0;
};
const id=(x:unknown):x is string=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso=(x:unknown):x is string=>typeof x==="string"&&
  Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const sha=(x:unknown):x is string=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const digest=(x:unknown)=>createHash("sha256").update(JSON.stringify(x)).digest("hex");
const fail=(code:string):never=>{throw Error(code);};
const roleAllowed=(r:string):r is TabletopActorRole=>
  ["INCIDENT_COMMANDER","SECURITY_REVIEWER","IT_OPERATOR","FINANCE_APPROVER",
    "LEGAL_REVIEWER","EVIDENCE_COLLECTOR"].includes(r);
export function tabletopSessionDigest(s:PersistedTabletopSession){return digest(s);}
export function tabletopSessionEventDigest(e:Omit<SessionEvent,"eventDigest">){
  return digest(e);
}
export function verifyPersistedTabletopSession(
  value:PersistedTabletopSession,
):string[]{
  const errors:string[]=[];
  if(!value||value.schema!=="cyberpilot.incident.tabletop.session.v1"||
      !id(value.id)||!id(value.organizationId)||!id(value.createdBy)||
      !id(value.facilitatorId)||!iso(value.createdAt)||!iso(value.updatedAt))
    errors.push("SESSION_HEADER_INVALID");
  if(value.incidentId!==null&&!id(value.incidentId))
    errors.push("SESSION_INCIDENT_LINK_INVALID");
  if(!Number.isSafeInteger(value.revision)||value.revision<1||
      !["ACTIVE","PAUSED","DEBRIEFED","ARCHIVED"].includes(value.state))
    errors.push("SESSION_STATE_INVALID");
  if(value.externallyExecutedCommands!==0||
      value.providerContainmentProven!==false)
    errors.push("SESSION_FALSE_PROVIDER_CLAIM");
  if(!value.scenario||validateTabletopScenario(value.scenario).length||
      value.scenario.organizationId!==value.organizationId)
    errors.push("SESSION_SCENARIO_INVALID");
  if(!value.exercise||value.exercise.organizationId!==value.organizationId||
      value.exercise.scenarioId!==value.scenario?.id||
      value.exercise.externalProviderWrites!==0||
      value.exercise.operationalContainmentProven!==false)
    errors.push("SESSION_EXERCISE_INVALID");
  if(!Array.isArray(value.participants)||value.participants.length>60||
      new Set(value.participants.map(x=>x.userId)).size!==
      value.participants.length||value.participants.some(x=>
        !id(x.userId)||!id(x.assignedBy)||!iso(x.joinedAt)||
        !roleAllowed(x.role)||typeof x.active!=="boolean"||
        !["FACILITATOR","PARTICIPANT","OBSERVER"].includes(x.permissions)))
    errors.push("SESSION_PARTICIPANTS_INVALID");
  if(!value.participants.some(x=>x.userId===value.facilitatorId&&
      x.active&&x.permissions==="FACILITATOR"))
    errors.push("SESSION_FACILITATOR_MISSING");
  if(!Array.isArray(value.moveReceipts)||
      value.moveReceipts.length!==value.exercise?.events.length||
      value.moveReceipts.some((x,i)=>x.sequence!==i+1||
        x.move.id!==value.exercise.events[i]?.moveId||
        !id(x.userId)||!iso(x.recordedAt)||!sha(x.exerciseDigest)||
        x.externalWrites!==0))
    errors.push("SESSION_MOVE_HISTORY_INVALID");
  if(!Array.isArray(value.notes)||value.notes.length>1000||
      value.notes.some(x=>!id(x.id)||!id(x.userId)||!iso(x.at)||
        typeof x.text!=="string"||!x.text.trim()||x.text.length>2000))
    errors.push("SESSION_NOTES_INVALID");
  if(value.state==="DEBRIEFED"||value.state==="ARCHIVED"){
    if(!value.debrief||!id(value.debrief.recordedBy)||
        !iso(value.debrief.recordedAt)||!sha(value.debrief.evidenceDigest)||
        value.debrief.independentProviderProof!==false)
      errors.push("SESSION_DEBRIEF_MISSING");
  } else if(value.debrief!==null)
    errors.push("SESSION_PREMATURE_DEBRIEF");
  if(value.supersededBy!==null&&!id(value.supersededBy))
    errors.push("SESSION_SUCCESSOR_INVALID");
  return [...new Set(errors)].sort();
}
export function startPersistedTabletopSession(input:{
  id:string;organizationId:string;incidentId:string|null;
  facilitatorId:string;type:IncidentType;title:string;
  seed:number;at:string;faultCount:number;additionalFaults?:TabletopFault[];
}):{session:PersistedTabletopSession;event:SessionEvent}{
  if(!id(input.id)||!id(input.organizationId)||!id(input.facilitatorId)||
      !iso(input.at)||(input.incidentId!==null&&!id(input.incidentId))||
      !INCIDENT_TYPES.includes(input.type))
    fail("TABLETOP_SESSION_CREATE_INVALID");
  const scenario=generateTabletopScenario({
    id:"scenario-"+input.id,organizationId:input.organizationId,
    type:input.type,title:input.title,seed:input.seed,at:input.at,
    faultCount:input.faultCount,
    ...(input.additionalFaults?{additionalFaults:input.additionalFaults}:{}),
  });
  const session:PersistedTabletopSession={
    schema:"cyberpilot.incident.tabletop.session.v1",
    id:input.id,organizationId:input.organizationId,
    incidentId:input.incidentId,state:"ACTIVE",revision:1,
    createdAt:input.at,updatedAt:input.at,createdBy:input.facilitatorId,
    facilitatorId:input.facilitatorId,
    scenario,exercise:createTabletopExercise(scenario),
    participants:[{userId:input.facilitatorId,role:"INCIDENT_COMMANDER",
      joinedAt:input.at,active:true,permissions:"FACILITATOR",
      assignedBy:input.facilitatorId}],
    moveReceipts:[],notes:[],debrief:null,supersededBy:null,
    externallyExecutedCommands:0,providerContainmentProven:false,
  };
  if(verifyPersistedTabletopSession(session).length)
    fail("TABLETOP_SESSION_GENESIS_INVALID");
  const bare={
    schema:"cyberpilot.incident.tabletop.session.event.v1" as const,
    organizationId:input.organizationId,sessionId:input.id,revision:1,
    commandId:"genesis-"+input.id,actorId:input.facilitatorId,
    kind:"ENROLL" as const,at:input.at,beforeDigest:null,
    afterDigest:tabletopSessionDigest(session),priorEventDigest:null,
    moveAccepted:null,providerWrites:0 as const,
  };
  return {session,event:{...bare,eventDigest:digest(bare)}};
}
export function evolvePersistedTabletopSession(
  original:PersistedTabletopSession,command:SessionCommand,
  priorEventDigest:string,
):{session:PersistedTabletopSession;event:SessionEvent}{
  if(verifyPersistedTabletopSession(original).length)
    fail("TABLETOP_SESSION_CORRUPT");
  if(command.organizationId!==original.organizationId||
      command.sessionId!==original.id)
    fail("TABLETOP_SESSION_SCOPE_DENIED");
  if(command.expectedRevision!==original.revision)
    fail("TABLETOP_SESSION_CAS_CONFLICT");
  if(!id(command.commandId)||!iso(command.at)||
      command.at<original.updatedAt||!sha(priorEventDigest))
    fail("TABLETOP_SESSION_COMMAND_INVALID");
  if(["ARCHIVED"].includes(original.state))
    fail("TABLETOP_SESSION_ARCHIVED");
  const action=command.action;
  const author=original.participants.find(x=>x.userId===action.userId&&x.active);
  if(!author||author.permissions==="OBSERVER")
    fail("TABLETOP_SESSION_PARTICIPANT_DENIED");
  const facilitator=author!.permissions==="FACILITATOR"&&
    original.facilitatorId===action.userId;
  const next:PersistedTabletopSession={
    ...original,revision:original.revision+1,updatedAt:command.at,
    participants:original.participants.map(x=>({...x})),
    moveReceipts:[...original.moveReceipts],
    notes:[...original.notes],
  };
  let accepted:boolean|null=null;
  if(action.kind==="ENROLL"){
    if(!facilitator||!id(action.participantId)||!roleAllowed(action.role)||
        !["FACILITATOR","PARTICIPANT","OBSERVER"].includes(action.permissions))
      fail("TABLETOP_SESSION_ENROLL_DENIED");
    if(next.participants.some(x=>x.userId===action.participantId))
      fail("TABLETOP_SESSION_DUPLICATE_PARTICIPANT");
    if(next.participants.length>=60)
      fail("TABLETOP_SESSION_CAPACITY");
    next.participants.push({userId:action.participantId,role:action.role,
      joinedAt:command.at,active:true,permissions:action.permissions,
      assignedBy:action.userId});
  }else if(action.kind==="REMOVE"){
    if(!facilitator||action.participantId===original.facilitatorId)
      fail("TABLETOP_SESSION_REMOVE_DENIED");
    const participant=next.participants.find(x=>x.userId===action.participantId);
    if(!participant||!participant.active)
      fail("TABLETOP_SESSION_PARTICIPANT_NOT_FOUND");
    participant!.active=false;
  }else if(action.kind==="TRANSFER_FACILITATOR"){
    if(!facilitator||action.participantId===action.userId)
      fail("TABLETOP_SESSION_TRANSFER_DENIED");
    const replacement=next.participants.find(x=>
      x.userId===action.participantId&&x.active&&
      x.permissions!=="OBSERVER");
    if(!replacement)fail("TABLETOP_SESSION_TRANSFER_TARGET_INVALID");
    next.facilitatorId=replacement!.userId;
    const old=next.participants.find(x=>x.userId===action.userId)!;
    old.permissions="PARTICIPANT";
    replacement!.permissions="FACILITATOR";
  }else if(action.kind==="PAUSE"){
    if(!facilitator||original.state!=="ACTIVE")
      fail("TABLETOP_SESSION_PAUSE_DENIED");
    next.state="PAUSED";
  }else if(action.kind==="RESUME"){
    if(!facilitator||original.state!=="PAUSED")
      fail("TABLETOP_SESSION_RESUME_DENIED");
    next.state="ACTIVE";
  }else if(action.kind==="PLAY"){
    if(original.state!=="ACTIVE"||author!.role!==action.move.actorRole)
      fail("TABLETOP_SESSION_MOVE_ROLE_OR_STATE_DENIED");
    if(action.move.at!==command.at)
      fail("TABLETOP_SESSION_CLOCK_MISMATCH");
    const result=applyTabletopMove(original.scenario,original.exercise,
      action.move,original.exercise.revision);
    next.exercise=result.exercise;
    accepted=result.accepted;
    next.moveReceipts.push({
      sequence:next.moveReceipts.length+1,move:action.move,
      userId:action.userId,accepted:result.accepted,code:result.code,
      exerciseDigest:result.exercise.exerciseDigest,recordedAt:command.at,
      externalWrites:0,
    });
  }else if(action.kind==="NOTE"){
    if(!action.text?.trim()||action.text.length>2000||
        next.notes.length>=1000)
      fail("TABLETOP_SESSION_NOTE_INVALID");
    next.notes.push({
      id:command.commandId,userId:action.userId,at:command.at,
      text:action.text.trim(),
    });
  }else if(action.kind==="DEBRIEF"){
    if(!facilitator||!["ACTIVE","PAUSED"].includes(original.state))
      fail("TABLETOP_SESSION_DEBRIEF_DENIED");
    const reviewed=reviewTabletopExercise(original.scenario,
      original.exercise,command.at);
    next.state="DEBRIEFED";
    next.debrief={
      recordedBy:action.userId,recordedAt:command.at,
      evidenceDigest:digest(reviewed),
      unreviewedSteps:original.scenario.activeStepIds.filter(step=>
        !original.exercise.events.some(e=>e.stepId===step&&e.accepted)),
      unsafeAttempts:original.exercise.unsafeOperationsBlocked,
      acceptedMoves:original.exercise.acceptedMoves,
      failedMoves:original.exercise.rejectedMoves,
      independentProviderProof:false,
    };
  }else if(action.kind==="ARCHIVE"){
    if(!facilitator||original.state!=="DEBRIEFED")
      fail("TABLETOP_SESSION_ARCHIVE_DENIED");
    next.state="ARCHIVED";
  }else if(action.kind==="SUPERSEDE"){
    if(!facilitator||!id(action.successorId)||
        action.successorId===original.id)
      fail("TABLETOP_SESSION_SUCCESSOR_DENIED");
    next.supersededBy=action.successorId;
    next.state="ARCHIVED";
    if(!next.debrief)
      fail("TABLETOP_SESSION_UNREVIEWED_SUCCESSOR");
  }else fail("TABLETOP_SESSION_ACTION_UNKNOWN");
  if(verifyPersistedTabletopSession(next).length)
    fail("TABLETOP_SESSION_TRANSITION_INVALID");
  const bare={
    schema:"cyberpilot.incident.tabletop.session.event.v1" as const,
    organizationId:original.organizationId,sessionId:original.id,
    revision:next.revision,commandId:command.commandId,
    actorId:action.userId,kind:action.kind,at:command.at,
    beforeDigest:tabletopSessionDigest(original),
    afterDigest:tabletopSessionDigest(next),
    priorEventDigest,moveAccepted:accepted,providerWrites:0 as const,
  };
  return {session:next,event:{...bare,eventDigest:digest(bare)}};
}
export function verifyTabletopSessionEventChain(
  session:PersistedTabletopSession,events:SessionEvent[],
):string[]{
  const errors:string[]=[];
  if(verifyPersistedTabletopSession(session).length)
    errors.push("SESSION_CHAIN_SNAPSHOT_CORRUPT");
  if(events.length!==session.revision)
    errors.push("SESSION_CHAIN_LENGTH_INVALID");
  let previous:SessionEvent|null=null;
  const commands=new Set<string>();
  for(const [index,event] of events.entries()){
    const {eventDigest,...unsigned}=event;
    if(event.eventDigest!==digest(unsigned))
      errors.push("SESSION_CHAIN_EVENT_TAMPERED");
    if(event.sessionId!==session.id||
        event.organizationId!==session.organizationId||
        event.revision!==index+1||commands.has(event.commandId))
      errors.push("SESSION_CHAIN_SCOPE_OR_SEQUENCE_INVALID");
    if(previous&&(event.beforeDigest!==previous.afterDigest||
        event.priorEventDigest!==previous.eventDigest||
        event.at<previous.at))
      errors.push("SESSION_CHAIN_LINK_BROKEN");
    if(!previous&&(event.beforeDigest!==null||
        event.priorEventDigest!==null))
      errors.push("SESSION_CHAIN_GENESIS_INVALID");
    commands.add(event.commandId);
    previous=event;
  }
  if(!previous||previous.afterDigest!==tabletopSessionDigest(session))
    errors.push("SESSION_CHAIN_CURRENT_DIGEST_INVALID");
  return [...new Set(errors)].sort();
}
export function deterministicTabletopSessionReplay(
  session:PersistedTabletopSession,
){
  if(verifyPersistedTabletopSession(session).length)
    fail("TABLETOP_SESSION_REPLAY_INVALID");
  let state=createTabletopExercise(session.scenario);
  const divergent:string[]=[];
  for(const receipt of session.moveReceipts){
    try{
      const outcome=applyTabletopMove(session.scenario,state,receipt.move,
        state.revision);
      state=outcome.exercise;
      if(receipt.accepted!==outcome.accepted||
          receipt.code!==outcome.code||
          receipt.exerciseDigest!==state.exerciseDigest)
        divergent.push(receipt.move.id);
    }catch{divergent.push(receipt.move.id);}
  }
  return {
    schema:"cyberpilot.incident.tabletop.session.replay.v1" as const,
    sessionId:session.id,organizationId:session.organizationId,
    recordedExerciseDigest:session.exercise.exerciseDigest,
    replayExerciseDigest:state.exerciseDigest,
    divergentMoveIds:divergent,
    identical:divergent.length===0&&
      state.exerciseDigest===session.exercise.exerciseDigest,
    externalProviderWrites:0 as const,
    liveContainmentProven:false as const,
  };
}
