import {describe,expect,it} from "vitest";
import {createIncident} from "./incident-case-domain";
import {buildIncidentSituation} from "./incident-situation-domain";
import {assessIncidentAssurance,DEFAULT_ASSURANCE_POLICY}
  from "./incident-assurance-domain";
import {
  beginAssuranceHandoffBoard,applyAssuranceHandoffCommand,
  validateAssuranceHandoffBoard,validateAssuranceHandoffAudit,
  summarizeAssuranceHandoffBoard,planInternalAssuranceEscalations,
  assuranceHandoffBoardDigest,
} from "./incident-assurance-handoff-domain";
const at="2026-11-23T10:00:00.000Z";
const next="2026-11-23T10:01:00.000Z";
const late="2026-11-24T10:00:00.000Z";
function genesis(){
  const caseValue=createIncident({
    id:"incident-1234",organizationId:"tenant-1234",
    type:"COMPROMISED_ACCOUNT",title:"Identity compromise",
    subjectReference:"principal-1234",actorUserId:"admin-1234",
    ownerUserId:null,at,
  });
  const situation=buildIncidentSituation({
    incident:caseValue,evidence:null,assets:null,remediation:null,
    sourceStates:{evidence:"ABSENT",assets:"ABSENT",remediation:"ABSENT"},
    capturedAt:at,sourceMode:"PERSISTED_READ_ONLY",
  });
  const report=assessIncidentAssurance({
    situation,tabletop:null,policy:DEFAULT_ASSURANCE_POLICY,evaluatedAt:at,
  });
  return beginAssuranceHandoffBoard("board-1234",report,"admin-1234",at);
}
function reorderJsonb(value:unknown):unknown {
  if(Array.isArray(value))return value.map(reorderJsonb);
  if(value!==null&&typeof value==="object"){
    const entries=Object.entries(value as Record<string,unknown>)
      .reverse().map(([key,entry])=>[key,reorderJsonb(entry)]);
    return Object.fromEntries(entries);
  }
  return value;
}
describe("assurance handoff board",()=>{
  it("keeps persisted JSONB digests stable when object keys reorder",()=>{
    const {board:snapshot}=genesis();
    const reordered=reorderJsonb(snapshot) as typeof snapshot;
    expect(assuranceHandoffBoardDigest(reordered)).toBe(assuranceHandoffBoardDigest(snapshot));
    expect(assuranceHandoffBoardDigest({...reordered,revision:reordered.revision+1}))
      .not.toBe(assuranceHandoffBoardDigest(snapshot));
  });

  it("captures bounded unknown controls without external security claims",()=>{
    const {board,event}=genesis();
    expect(validateAssuranceHandoffBoard(board)).toEqual([]);
    expect(validateAssuranceHandoffAudit(board,[event])).toEqual([]);
    expect(board.providerWrites).toBe(0);
    expect(board.notificationsDispatched).toBe(0);
    expect(board.handoffs.length).toBeGreaterThan(1);
    expect(board.handoffs.every(x=>x.independentlyVerifiedProviderOutcome===false))
      .toBe(true);
  });
  it("supports CAS assignment and independent acceptance",()=>{
    const {board,event}=genesis();
    const item=board.handoffs[0]!;
    const assigned=applyAssuranceHandoffCommand(board,{
      organizationId:board.organizationId,boardId:board.id,
      actorId:"admin-1234",commandId:"command-1234",at:next,
      expectedRevision:1,action:{kind:"ASSIGN",handoffId:item.id,
        assigneeId:"analyst-1234",reason:"Explicit tenant member assignment"},
    },event.eventDigest);
    expect(assigned.board.handoffs[0]?.assignedUserId).toBe("analyst-1234");
    expect(validateAssuranceHandoffAudit(assigned.board,
      [event,assigned.event])).toEqual([]);
    expect(()=>applyAssuranceHandoffCommand(assigned.board,{
      organizationId:board.organizationId,boardId:board.id,
      actorId:"admin-1234",commandId:"command-5678",at:late,
      expectedRevision:1,action:{kind:"ACCEPT",handoffId:item.id,
        reason:"Trying stale CAS"},
    },assigned.event.eventDigest)).toThrow("HANDOFF_CAS_STALE");
    const accepted=applyAssuranceHandoffCommand(assigned.board,{
      organizationId:board.organizationId,boardId:board.id,
      actorId:"analyst-1234",commandId:"command-5678",at:late,
      expectedRevision:2,action:{kind:"ACCEPT",handoffId:item.id,
        reason:"Accept internal follow-up"},
    },assigned.event.eventDigest);
    expect(accepted.board.handoffs[0]?.status).toBe("ACCEPTED");
    expect(accepted.board.handoffs[0]?.acceptedBy).toBe("analyst-1234");
  });
  it("rejects mismatched tenants, self-approval and fabricated evidence",()=>{
    const {board,event}=genesis();
    const item=board.handoffs[0]!;
    expect(()=>applyAssuranceHandoffCommand(board,{
      organizationId:"tenant-foreign",boardId:board.id,
      actorId:"admin-1234",commandId:"command-1234",at:next,
      expectedRevision:1,action:{kind:"ASSIGN",handoffId:item.id,
        assigneeId:"analyst-1234",reason:"Cross tenant"},
    },event.eventDigest)).toThrow("HANDOFF_TENANT_SCOPE_INVALID");
    const assigned=applyAssuranceHandoffCommand(board,{
      organizationId:board.organizationId,boardId:board.id,
      actorId:"admin-1234",commandId:"command-1234",at:next,
      expectedRevision:1,action:{kind:"ASSIGN",handoffId:item.id,
        assigneeId:"admin-1234",reason:"Self assignment"},
    },event.eventDigest);
    expect(()=>applyAssuranceHandoffCommand(assigned.board,{
      organizationId:board.organizationId,boardId:board.id,
      actorId:"admin-1234",commandId:"command-5678",at:late,
      expectedRevision:2,action:{kind:"ACCEPT",handoffId:item.id,
        reason:"Unlawful self acceptance"},
    },assigned.event.eventDigest)).toThrow("HANDOFF_ACCEPT_SEPARATION_REQUIRED");
    expect(validateAssuranceHandoffBoard({
      ...board,providerContainmentVerified:true as false,
    })).toContain("HANDOFF_EXTERNAL_OUTCOME_FORGED");
  });
  it("exposes only proposed internal escalations and detects tampering",()=>{
    const {board,event}=genesis();
    const state=summarizeAssuranceHandoffBoard(board,late);
    expect(state.overdue).toBeGreaterThan(0);
    const plan=planInternalAssuranceEscalations(board,late);
    expect(plan.actualDispatches).toBe(0);
    expect(plan.proposals.every(x=>!x.externalNotificationSent)).toBe(true);
    expect(validateAssuranceHandoffAudit(board,[{
      ...event,eventDigest:"0".repeat(64),
    }])).toContain("HANDOFF_AUDIT_EVENT_TAMPERED");
  });
});
