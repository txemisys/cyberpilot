import { describe, expect, it } from "vitest";
import {
  startPersistedTabletopSession, evolvePersistedTabletopSession,
  deterministicTabletopSessionReplay, tabletopSessionDigest,
  verifyPersistedTabletopSession, verifyTabletopSessionEventChain,
} from "./incident-tabletop-session-domain";
const t0="2026-11-23T10:00:00.000Z";
const t1="2026-11-23T10:01:00.000Z";
const t2="2026-11-23T10:02:00.000Z";
const t3="2026-11-23T10:03:00.000Z";
const genesis=()=>startPersistedTabletopSession({
  id:"session-1234",organizationId:"tenant-1234",
  incidentId:null,facilitatorId:"admin-1234",
  type:"COMPROMISED_ACCOUNT",title:"Reproducible credential compromise exercise",
  seed:42,at:t0,faultCount:3,
});
const change=(base:ReturnType<typeof genesis>["session"],
  kind:"ENROLL"|"PLAY"|"PAUSE"|"DEBRIEF",
  actorId:string,at:string,extra:Record<string,unknown>={},
  lastEvent=genesis().event.eventDigest,
)=>evolvePersistedTabletopSession(base,{
  organizationId:base.organizationId,sessionId:base.id,
  expectedRevision:base.revision,commandId:"command-"+base.revision,
  at,action:{kind,userId:actorId,...extra} as
    Parameters<typeof evolvePersistedTabletopSession>[1]["action"],
},lastEvent);
function reorderJsonb(value:unknown):unknown {
  if(Array.isArray(value))return value.map(reorderJsonb);
  if(value!==null&&typeof value==="object"){
    const entries=Object.entries(value as Record<string,unknown>)
      .reverse().map(([key,entry])=>[key,reorderJsonb(entry)]);
    return Object.fromEntries(entries);
  }
  return value;
}
describe("durable tabletop training session",()=>{
  it("keeps persisted JSONB digests stable when object keys reorder",()=>{
    const {session:snapshot}=genesis();
    const reordered=reorderJsonb(snapshot) as typeof snapshot;
    expect(tabletopSessionDigest(reordered)).toBe(tabletopSessionDigest(snapshot));
    expect(tabletopSessionDigest({...reordered,revision:reordered.revision+1}))
      .not.toBe(tabletopSessionDigest(snapshot));
  });

  it("creates deterministic unknown-only scenario and verifies genesis",()=>{
    const {session,event}=genesis();
    expect(verifyPersistedTabletopSession(session)).toEqual([]);
    expect(verifyTabletopSessionEventChain(session,[event])).toEqual([]);
    expect(session.externallyExecutedCommands).toBe(0);
    expect(session.providerContainmentProven).toBe(false);
    expect(deterministicTabletopSessionReplay(session).identical).toBe(true);
  });
  it("requires facilitator to enroll tenant-bound participants",()=>{
    const {session,event}=genesis();
    const enrolled=change(session,"ENROLL","admin-1234",t1,{
      participantId:"reviewer-1234",role:"SECURITY_REVIEWER",
      permissions:"PARTICIPANT",
    },event.eventDigest);
    expect(enrolled.session.participants).toHaveLength(2);
    expect(verifyTabletopSessionEventChain(enrolled.session,
      [event,enrolled.event])).toEqual([]);
    expect(()=>change(enrolled.session,"ENROLL","reviewer-1234",t2,{
      participantId:"another-1234",role:"IT_OPERATOR",permissions:"OBSERVER",
    },enrolled.event.eventDigest)).toThrow("TABLETOP_SESSION_ENROLL_DENIED");
  });
  it("rejects unsafe real provider commands while preserving negative replay",()=>{
    const {session,event}=genesis();
    const step=session.scenario.activeStepIds[0];
    const changed=change(session,"PLAY","admin-1234",t1,{move:{
      id:"move-1234",stepId:step,actorRole:"INCIDENT_COMMANDER",
      command:"SEND_PROVIDER_COMMAND",reason:"Exercise forbidden operation",
      at:t1,assertedIndependentEvidence:false,
      assertedExternalCompletion:false,
    }},event.eventDigest);
    expect(changed.session.moveReceipts[0]!.accepted).toBe(false);
    expect(changed.session.exercise.unsafeOperationsBlocked).toBe(1);
    expect(changed.session.exercise.externalProviderWrites).toBe(0);
    expect(deterministicTabletopSessionReplay(changed.session).identical)
      .toBe(true);
    expect(verifyTabletopSessionEventChain(changed.session,
      [event,changed.event])).toEqual([]);
  });
  it("enforces CAS, tenant and digest chains",()=>{
    const {session,event}=genesis();
    expect(()=>evolvePersistedTabletopSession(session,{
      organizationId:"tenant-foreign",sessionId:session.id,
      expectedRevision:1,commandId:"different-1234",at:t1,
      action:{kind:"PAUSE",userId:"admin-1234"},
    },event.eventDigest)).toThrow("TABLETOP_SESSION_SCOPE_DENIED");
    expect(()=>evolvePersistedTabletopSession(session,{
      organizationId:session.organizationId,sessionId:session.id,
      expectedRevision:0,commandId:"different-1234",at:t1,
      action:{kind:"PAUSE",userId:"admin-1234"},
    },event.eventDigest)).toThrow("TABLETOP_SESSION_CAS_CONFLICT");
    const paused=change(session,"PAUSE","admin-1234",t1,{},event.eventDigest);
    expect(verifyTabletopSessionEventChain(paused.session,[
      event,{...paused.event,eventDigest:"0".repeat(64)},
    ])).toContain("SESSION_CHAIN_EVENT_TAMPERED");
    expect(verifyPersistedTabletopSession({...session,
      providerContainmentProven:true as false}))
      .toContain("SESSION_FALSE_PROVIDER_CLAIM");
    expect(tabletopSessionDigest(paused.session)).toMatch(/^[0-9a-f]{64}$/);
  });
  it("records debrief but no independent proof, rejects post-debrief moves",()=>{
    const {session,event}=genesis();
    const reviewed=change(session,"DEBRIEF","admin-1234",t1,{},event.eventDigest);
    expect(reviewed.session.state).toBe("DEBRIEFED");
    expect(reviewed.session.debrief?.independentProviderProof).toBe(false);
    expect(()=>change(reviewed.session,"PLAY","admin-1234",t2,{move:{
      id:"move-5678",stepId:session.scenario.activeStepIds[0],
      actorRole:"INCIDENT_COMMANDER",command:"DECLARE_UNKNOWN",
      reason:"Test after review",at:t2,
      assertedIndependentEvidence:false,assertedExternalCompletion:false,
    }},reviewed.event.eventDigest)).toThrow();
  });
});
