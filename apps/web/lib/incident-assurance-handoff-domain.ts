import {createHash} from "node:crypto";
import type {AssuranceReport,AssuranceControl} from "./incident-assurance-domain";
import {prepareAssuranceWorkPacket} from "./incident-assurance-operations";

export type HandoffStatus =
  "UNASSIGNED"|"ASSIGNED"|"ACCEPTED"|"NEEDS_EVIDENCE"|
  "ESCALATED_INTERNAL"|"REVIEWED_INTERNAL"|"REOPENED";
export type HandoffPriority="P0"|"P1"|"P2";
export type AssuranceHandoff={
  id:string;controlId:string;category:string;controlState:string;
  importance:AssuranceControl["importance"];priority:HandoffPriority;
  suggestedOwnerRole:string;guidance:string;dueAt:string;
  assignedUserId:string|null;assignedBy:string|null;assignedAt:string|null;
  acceptedBy:string|null;acceptedAt:string|null;
  status:HandoffStatus;revision:number;updatedAt:string;
  escalationCount:number;lastEscalatedAt:string|null;
  needsEvidence:string[];evidenceReferences:string[];
  notes:Array<{id:string;authorId:string;at:string;text:string}>;
  independentlyVerifiedProviderOutcome:false;
  externallyNotified:false;externalWrites:0;
};
export type AssuranceHandoffBoard={
  schema:"cyberpilot.incident.assurance.handoff-board.v1";
  id:string;organizationId:string;incidentId:string;incidentRevision:number;
  situationDigest:string;assuranceDigest:string;policyId:string;
  createdAt:string;updatedAt:string;createdBy:string;
  revision:number;status:"ACTIVE"|"CLOSED_INTERNAL"|"SUPERSEDED";
  handoffs:AssuranceHandoff[];sourceCoverage:string;
  unknownCount:number;criticalFailures:number;
  nextReviewBy:string;supersededBy:string|null;
  providerContainmentVerified:false;providerWrites:0;
  notificationsDispatched:0;
};
export type HandoffCommandAction=
  |{kind:"ASSIGN";handoffId:string;assigneeId:string;reason:string}
  |{kind:"ACCEPT";handoffId:string;reason:string}
  |{kind:"NEEDS_EVIDENCE";handoffId:string;reason:string}
  |{kind:"ADD_NOTE";handoffId:string;reason:string}
  |{kind:"ADD_REFERENCE";handoffId:string;referenceId:string;reason:string}
  |{kind:"ESCALATE_INTERNAL";handoffId:string;reason:string}
  |{kind:"ACK_DEADLINE";handoffId:string;reason:string}
  |{kind:"COMPLETE_INTERNAL_REVIEW";handoffId:string;reason:string}
  |{kind:"REOPEN";handoffId:string;reason:string}
  |{kind:"CLOSE_BOARD";reason:string}
  |{kind:"SUPERSEDE_BOARD";successorId:string;reason:string};
export type HandoffCommand={
  organizationId:string;boardId:string;expectedRevision:number;
  commandId:string;actorId:string;at:string;
  action:HandoffCommandAction;
};
export type HandoffLedgerEvent={
  schema:"cyberpilot.incident.assurance.handoff-event.v1";
  organizationId:string;boardId:string;incidentId:string;
  revision:number;commandId:string;actorId:string;
  kind:"CREATE"|HandoffCommandAction["kind"];
  handoffId:string|null;at:string;beforeDigest:string|null;
  afterDigest:string;priorEventDigest:string|null;
  eventDigest:string;externalWrites:0;
};
const ident=(x:unknown):x is string=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso=(x:unknown):x is string=>typeof x==="string"&&
  Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const sha=(x:unknown):x is string=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const hash=(x:unknown)=>createHash("sha256").update(JSON.stringify(x)).digest("hex");
const reject=(code:string):never=>{throw Error(code);};
const sortedUnique=(x:string[])=>[...new Set(x)].sort();
const statuses:HandoffStatus[]=["UNASSIGNED","ASSIGNED","ACCEPTED",
  "NEEDS_EVIDENCE","ESCALATED_INTERNAL","REVIEWED_INTERNAL","REOPENED"];
export function assuranceHandoffBoardDigest(board:AssuranceHandoffBoard){
  return hash(board);
}
export function assuranceHandoffEventDigest(
  event:Omit<HandoffLedgerEvent,"eventDigest">,
){return hash(event);}
export function validateAssuranceHandoffBoard(
  board:AssuranceHandoffBoard,
):string[]{
  const problems:string[]=[];
  if(!board||board.schema!=="cyberpilot.incident.assurance.handoff-board.v1"||
      !ident(board.id)||!ident(board.organizationId)||
      !ident(board.incidentId)||!ident(board.createdBy)||
      !iso(board.createdAt)||!iso(board.updatedAt)||!iso(board.nextReviewBy))
    problems.push("HANDOFF_BOARD_HEADER_INVALID");
  if(!sha(board?.situationDigest)||!sha(board?.assuranceDigest)||
      !ident(board?.policyId)||!Number.isSafeInteger(board?.incidentRevision)||
      board.incidentRevision<1||!Number.isSafeInteger(board?.revision)||
      board.revision<1)
    problems.push("HANDOFF_BOARD_SOURCE_INVALID");
  if(!["ACTIVE","CLOSED_INTERNAL","SUPERSEDED"].includes(board?.status)||
      !Number.isSafeInteger(board?.unknownCount)||board.unknownCount<0||
      !Number.isSafeInteger(board?.criticalFailures)||board.criticalFailures<0)
    problems.push("HANDOFF_BOARD_STATUS_INVALID");
  if(board?.providerContainmentVerified!==false||board?.providerWrites!==0||
      board?.notificationsDispatched!==0)
    problems.push("HANDOFF_EXTERNAL_OUTCOME_FORGED");
  if(!Array.isArray(board?.handoffs)||board.handoffs.length>300||
      new Set(board.handoffs.map(x=>x.id)).size!==board.handoffs.length||
      new Set(board.handoffs.map(x=>x.controlId)).size!==board.handoffs.length)
    problems.push("HANDOFF_ITEMS_INVALID");
  else for(const item of board.handoffs){
    if(!ident(item.id)||!ident(item.controlId)||
        !["P0","P1","P2"].includes(item.priority)||
        !["CRITICAL","HIGH","NORMAL"].includes(item.importance)||
        !statuses.includes(item.status)||!iso(item.dueAt)||
        !iso(item.updatedAt)||!Number.isSafeInteger(item.revision)||
        item.revision<1||!Number.isSafeInteger(item.escalationCount)||
        item.escalationCount<0)
      problems.push("HANDOFF_ITEM_HEADER_INVALID");
    if(item.independentlyVerifiedProviderOutcome!==false||
        item.externallyNotified!==false||item.externalWrites!==0)
      problems.push("HANDOFF_ITEM_PROVIDER_CLAIM_FORGED");
    if(item.assignedUserId!==null&&!ident(item.assignedUserId)||
        item.assignedBy!==null&&!ident(item.assignedBy)||
        item.assignedAt!==null&&!iso(item.assignedAt)||
        item.acceptedBy!==null&&!ident(item.acceptedBy)||
        item.acceptedAt!==null&&!iso(item.acceptedAt))
      problems.push("HANDOFF_ASSIGNMENT_INVALID");
    if(item.status==="UNASSIGNED"&&item.assignedUserId!==null)
      problems.push("HANDOFF_UNASSIGNED_WITH_OWNER");
    if(item.status!=="UNASSIGNED"&&item.assignedUserId===null)
      problems.push("HANDOFF_OWNER_REQUIRED");
    if(item.acceptedBy!==null&&item.acceptedBy!==item.assignedUserId)
      problems.push("HANDOFF_ACCEPTOR_MISMATCH");
    if(item.acceptedBy===item.assignedBy&&item.acceptedBy!==null)
      problems.push("HANDOFF_SELF_ACCEPTANCE");
    if(item.lastEscalatedAt!==null&&!iso(item.lastEscalatedAt))
      problems.push("HANDOFF_ESCALATION_TIME_INVALID");
    if(!Array.isArray(item.needsEvidence)||item.needsEvidence.length>50||
        item.needsEvidence.some(x=>typeof x!=="string"||x.length>300)||
        !Array.isArray(item.evidenceReferences)||
        item.evidenceReferences.length>50||
        item.evidenceReferences.some(x=>!ident(x)))
      problems.push("HANDOFF_EVIDENCE_INVALID");
    if(!Array.isArray(item.notes)||item.notes.length>100||
        item.notes.some(x=>!ident(x.id)||!ident(x.authorId)||!iso(x.at)||
          typeof x.text!=="string"||x.text.length>2000||!x.text.trim()))
      problems.push("HANDOFF_NOTES_INVALID");
  }
  if(board?.status==="SUPERSEDED"&&!ident(board.supersededBy))
    problems.push("HANDOFF_SUCCESSOR_REQUIRED");
  if(board?.status!=="SUPERSEDED"&&board?.supersededBy!==null)
    problems.push("HANDOFF_UNEXPECTED_SUCCESSOR");
  return sortedUnique(problems);
}
export function beginAssuranceHandoffBoard(
  boardId:string,report:AssuranceReport,actorId:string,at:string,
):{board:AssuranceHandoffBoard;event:HandoffLedgerEvent}{
  if(!ident(boardId)||!ident(actorId)||!iso(at)||
      !ident(report.organizationId)||!ident(report.incidentId)||
      !sha(report.integrityDigest)||!sha(report.situationDigest)||
      !Number.isSafeInteger(report.incidentRevision)||
      report.externallyExecutableActions!==0||
      report.independentProviderContainmentVerified||
      report.actuallyApprovedForProviderExecution||
      report.controls.length>300)
    reject("HANDOFF_BOARD_REPORT_REJECTED");
  const packet=prepareAssuranceWorkPacket(report);
  const pending=report.controls.filter(x=>x.state!=="PASS_OFFLINE"&&
    x.state!=="NOT_APPLICABLE");
  const handoffs:AssuranceHandoff[]=pending.map(x=>{
    const planned=packet.prioritization.find(p=>p.id===x.id);
    const dueAt=planned?.deadline??report.nextReviewBy;
    return{
      id:"handoff-"+boardId+"-"+x.id,controlId:x.id,
      category:x.category,controlState:x.state,importance:x.importance,
      priority:x.importance==="CRITICAL"?"P0":
        x.importance==="HIGH"?"P1":"P2",
      suggestedOwnerRole:x.ownerRole,guidance:x.remediationGuidance,
      dueAt,assignedUserId:null,assignedBy:null,assignedAt:null,
      acceptedBy:null,acceptedAt:null,status:"UNASSIGNED" as const,
      revision:1,updatedAt:at,escalationCount:0,
      lastEscalatedAt:null,
      needsEvidence:x.missingEvidence.slice(0,50),
      evidenceReferences:x.evidenceRefs.filter(ident).slice(0,50),
      notes:[],independentlyVerifiedProviderOutcome:false as const,
      externallyNotified:false as const,externalWrites:0 as const,
    };
  });
  if(handoffs.some(x=>!ident(x.id)||!iso(x.dueAt)))
    reject("HANDOFF_BOARD_CONTROL_MAPPING_INVALID");
  const board:AssuranceHandoffBoard={
    schema:"cyberpilot.incident.assurance.handoff-board.v1",
    id:boardId,organizationId:report.organizationId,
    incidentId:report.incidentId,incidentRevision:report.incidentRevision,
    situationDigest:report.situationDigest,assuranceDigest:report.integrityDigest,
    policyId:report.policyId,createdAt:at,updatedAt:at,createdBy:actorId,
    revision:1,status:"ACTIVE",handoffs,sourceCoverage:report.sourceCoverage,
    unknownCount:report.unknownControls,criticalFailures:report.criticalFailures,
    nextReviewBy:report.nextReviewBy,supersededBy:null,
    providerContainmentVerified:false,providerWrites:0,
    notificationsDispatched:0,
  };
  if(validateAssuranceHandoffBoard(board).length)
    reject("HANDOFF_BOARD_GENESIS_INVALID");
  const bare={
    schema:"cyberpilot.incident.assurance.handoff-event.v1" as const,
    organizationId:report.organizationId,boardId,
    incidentId:report.incidentId,revision:1,
    commandId:"genesis-"+boardId,actorId,
    kind:"CREATE" as const,handoffId:null,at,
    beforeDigest:null,afterDigest:assuranceHandoffBoardDigest(board),
    priorEventDigest:null,externalWrites:0 as const,
  };
  return{board,event:{...bare,eventDigest:hash(bare)}};
}
export function applyAssuranceHandoffCommand(
  current:AssuranceHandoffBoard,command:HandoffCommand,
  priorEventDigest:string,
):{board:AssuranceHandoffBoard;event:HandoffLedgerEvent}{
  if(validateAssuranceHandoffBoard(current).length)
    reject("HANDOFF_BOARD_CORRUPT");
  if(command.organizationId!==current.organizationId||
      command.boardId!==current.id)
    reject("HANDOFF_TENANT_SCOPE_INVALID");
  if(!ident(command.actorId)||!ident(command.commandId)||
      !iso(command.at)||command.at<current.updatedAt||
      !sha(priorEventDigest))
    reject("HANDOFF_COMMAND_INVALID");
  if(command.expectedRevision!==current.revision)
    reject("HANDOFF_CAS_STALE");
  if(current.status!=="ACTIVE")reject("HANDOFF_BOARD_INACTIVE");
  const action=command.action;
  if(!action||typeof action.reason!=="string"||
      !action.reason.trim()||action.reason.length>2000)
    reject("HANDOFF_REASON_REQUIRED");
  const next:AssuranceHandoffBoard={
    ...current,revision:current.revision+1,updatedAt:command.at,
    handoffs:current.handoffs.map(x=>({
      ...x,evidenceReferences:[...x.evidenceReferences],
      notes:[...x.notes],
    })),
  };
  const item="handoffId" in action?
    next.handoffs.find(x=>x.id===action.handoffId):null;
  if("handoffId" in action&&!item)
    reject("HANDOFF_UNKNOWN_CONTROL");
  if(item){item.revision++;item.updatedAt=command.at;}
  if(action.kind==="ASSIGN"){
    if(!item||!ident(action.assigneeId)||
        item.status==="REVIEWED_INTERNAL")
      reject("HANDOFF_ASSIGN_INVALID");
    item.assignedUserId=action.assigneeId;
    item.assignedBy=command.actorId;item.assignedAt=command.at;
    item.acceptedBy=null;item.acceptedAt=null;item.status="ASSIGNED";
  }else if(action.kind==="ACCEPT"){
    if(!item||item.status!=="ASSIGNED"||
        item.assignedUserId!==command.actorId||
        item.assignedBy===command.actorId)
      reject("HANDOFF_ACCEPT_SEPARATION_REQUIRED");
    item.status="ACCEPTED";
    item.acceptedBy=command.actorId;item.acceptedAt=command.at;
  }else if(action.kind==="NEEDS_EVIDENCE"){
    if(!item||item.assignedUserId!==command.actorId||
        !["ACCEPTED","ESCALATED_INTERNAL"].includes(item.status))
      reject("HANDOFF_EVIDENCE_ROLE_DENIED");
    item.status="NEEDS_EVIDENCE";
  }else if(action.kind==="ADD_NOTE"){
    if(!item||item.assignedUserId!==command.actorId&&
        command.actorId!==current.createdBy)
      reject("HANDOFF_NOTE_ROLE_DENIED");
    if(item.notes.length>=100)reject("HANDOFF_NOTE_LIMIT");
    item.notes.push({id:command.commandId,authorId:command.actorId,
      at:command.at,text:action.reason.trim()});
  }else if(action.kind==="ADD_REFERENCE"){
    if(!item||!ident(action.referenceId)||
        item.assignedUserId!==command.actorId)
      reject("HANDOFF_REFERENCE_ROLE_DENIED");
    if(item.evidenceReferences.length>=50)
      reject("HANDOFF_REFERENCE_LIMIT");
    item.evidenceReferences=sortedUnique([...item.evidenceReferences,
      action.referenceId]);
  }else if(action.kind==="ESCALATE_INTERNAL"){
    if(!item||!item.assignedUserId||
        item.status==="REVIEWED_INTERNAL")
      reject("HANDOFF_ESCALATION_INVALID");
    item.status="ESCALATED_INTERNAL";
    item.escalationCount++;item.lastEscalatedAt=command.at;
  }else if(action.kind==="ACK_DEADLINE"){
    if(!item||!item.assignedUserId||
        item.assignedUserId!==command.actorId)
      reject("HANDOFF_DEADLINE_ACK_DENIED");
    if(item.notes.length>=100)reject("HANDOFF_NOTE_LIMIT");
    item.notes.push({id:command.commandId,authorId:command.actorId,
      at:command.at,text:"DEADLINE_ACK: "+action.reason.trim()});
  }else if(action.kind==="COMPLETE_INTERNAL_REVIEW"){
    if(!item||!["ACCEPTED","NEEDS_EVIDENCE","ESCALATED_INTERNAL"]
        .includes(item.status)||item.assignedUserId!==command.actorId)
      reject("HANDOFF_COMPLETION_NOT_AUTHORIZED");
    if(item.needsEvidence.length>0&&item.evidenceReferences.length===0)
      reject("HANDOFF_UNRESOLVED_EVIDENCE");
    item.status="REVIEWED_INTERNAL";
  }else if(action.kind==="REOPEN"){
    if(!item||item.status!=="REVIEWED_INTERNAL")
      reject("HANDOFF_REOPEN_STATE_DENIED");
    item.status="REOPENED";
    item.acceptedBy=null;item.acceptedAt=null;
  }else if(action.kind==="CLOSE_BOARD"){
    if(command.actorId!==current.createdBy||
        next.handoffs.some(x=>x.status!=="REVIEWED_INTERNAL"))
      reject("HANDOFF_BOARD_CLOSE_CONDITIONS_UNMET");
    next.status="CLOSED_INTERNAL";
  }else if(action.kind==="SUPERSEDE_BOARD"){
    if(command.actorId!==current.createdBy||
        !ident(action.successorId)||action.successorId===current.id)
      reject("HANDOFF_BOARD_SUPERSEDE_DENIED");
    next.status="SUPERSEDED";next.supersededBy=action.successorId;
  }else reject("HANDOFF_UNKNOWN_ACTION");
  if(validateAssuranceHandoffBoard(next).length)
    reject("HANDOFF_TRANSITION_INVALID");
  const bare={
    schema:"cyberpilot.incident.assurance.handoff-event.v1" as const,
    organizationId:current.organizationId,
    boardId:current.id,incidentId:current.incidentId,
    revision:next.revision,commandId:command.commandId,
    actorId:command.actorId,kind:action.kind,
    handoffId:item?.id??null,at:command.at,
    beforeDigest:assuranceHandoffBoardDigest(current),
    afterDigest:assuranceHandoffBoardDigest(next),
    priorEventDigest,externalWrites:0 as const,
  };
  return{board:next,event:{...bare,eventDigest:hash(bare)}};
}
export function validateAssuranceHandoffAudit(
  board:AssuranceHandoffBoard,events:HandoffLedgerEvent[],
):string[]{
  const errors:string[]=[];
  if(validateAssuranceHandoffBoard(board).length)
    errors.push("HANDOFF_AUDIT_BOARD_INVALID");
  if(events.length!==board.revision)errors.push("HANDOFF_AUDIT_REVISION_GAP");
  let last:HandoffLedgerEvent|null=null;
  const commandIds=new Set<string>();
  for(const [i,event] of events.entries()){
    const {eventDigest,...unsigned}=event;
    if(eventDigest!==hash(unsigned))
      errors.push("HANDOFF_AUDIT_EVENT_TAMPERED");
    if(event.organizationId!==board.organizationId||
        event.boardId!==board.id||event.incidentId!==board.incidentId||
        event.revision!==i+1||commandIds.has(event.commandId))
      errors.push("HANDOFF_AUDIT_SCOPE_INVALID");
    if(last&&(event.beforeDigest!==last.afterDigest||
        event.priorEventDigest!==last.eventDigest||event.at<last.at))
      errors.push("HANDOFF_AUDIT_CHAIN_BROKEN");
    if(!last&&(event.kind!=="CREATE"||event.beforeDigest!==null||
        event.priorEventDigest!==null))
      errors.push("HANDOFF_AUDIT_GENESIS_INVALID");
    commandIds.add(event.commandId);
    last=event;
  }
  if(!last||last.afterDigest!==assuranceHandoffBoardDigest(board))
    errors.push("HANDOFF_AUDIT_FINAL_DIGEST_MISMATCH");
  return sortedUnique(errors);
}
export function summarizeAssuranceHandoffBoard(
  board:AssuranceHandoffBoard,asOf:string,
){
  if(validateAssuranceHandoffBoard(board).length||!iso(asOf))
    reject("HANDOFF_SUMMARY_INVALID");
  const overdue=board.handoffs.filter(x=>
    x.dueAt<asOf&&x.status!=="REVIEWED_INTERNAL");
  const unassigned=board.handoffs.filter(x=>
    x.status==="UNASSIGNED");
  const escalated=board.handoffs.filter(x=>
    x.status==="ESCALATED_INTERNAL");
  const reviewed=board.handoffs.filter(x=>
    x.status==="REVIEWED_INTERNAL");
  const top=board.handoffs.filter(x=>
    x.priority==="P0"&&x.status!=="REVIEWED_INTERNAL");
  const highest=overdue.some(x=>x.priority==="P0")?"P0":
    overdue.some(x=>x.priority==="P1")?"P1":"P2";
  return{
    schema:"cyberpilot.incident.assurance.handoff-summary.v1" as const,
    organizationId:board.organizationId,incidentId:board.incidentId,
    boardId:board.id,boardStatus:board.status,
    evaluatedAt:asOf,total:board.handoffs.length,
    overdue:overdue.length,unassigned:unassigned.length,
    escalated:escalated.length,reviewedInternal:reviewed.length,
    unresolvedCritical:top.length,highestOverduePriority:highest,
    overdueIds:overdue.map(x=>x.id),
    unassignedIds:unassigned.map(x=>x.id),
    escalationIds:escalated.map(x=>x.id),
    externalNotificationsSent:0 as const,
    providerWorkExecuted:0 as const,
    independentSecurityOutcomeVerified:false as const,
  };
}
export function planInternalAssuranceEscalations(
  board:AssuranceHandoffBoard,asOf:string,
){
  const summary=summarizeAssuranceHandoffBoard(board,asOf);
  const candidates=board.handoffs.filter(x=>x.status!=="REVIEWED_INTERNAL"&&
    (x.dueAt<asOf||x.status==="UNASSIGNED"&&x.priority==="P0"));
  const rank:{[key:string]:number}={P0:3,P1:2,P2:1};
  return{
    schema:"cyberpilot.incident.assurance.escalation-proposals.v1" as const,
    boardId:board.id,asOf,summary,
    proposals:candidates.map(x=>({
      handoffId:x.id,controlId:x.controlId,
      priority:x.priority,dueAt:x.dueAt,
      assignedUserId:x.assignedUserId,
      reason:x.status==="UNASSIGNED"?"Critical unassigned control":
        "Past internal review deadline",
      state:"PROPOSED_NOT_DISPATCHED" as const,
      externalNotificationSent:false as const,
    })).sort((a,b)=>rank[b.priority]!-rank[a.priority]!||
      a.dueAt.localeCompare(b.dueAt)||a.handoffId.localeCompare(b.handoffId)),
    actualDispatches:0 as const,
    providerWrites:0 as const,
  };
}
