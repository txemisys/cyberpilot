import {describe,expect,it} from "vitest";
import {INCIDENT_TYPES} from "./incident-playbook-catalog";
import {generateTabletopScenario,createTabletopExercise,
  applyTabletopMove,reviewTabletopExercise} from "./incident-tabletop-domain";
import {planTabletopExercise,executeDeterministicTabletop,
  debriefTabletopExercise,exportTabletopReplay}
  from "./incident-tabletop-operations";
const at="2026-11-23T10:00:00.000Z";
const later="2026-11-23T11:00:00.000Z";
const scenario=(type=INCIDENT_TYPES[0])=>generateTabletopScenario({
  id:"scenario-1234",organizationId:"tenant-1234",
  type,title:"LAB readiness scenario",seed:2026,at,faultCount:4,
});
describe("tabletop deterministic offline incident response",()=>{
  it("covers all five playbooks with safe fault injection",()=>{
    for(const type of INCIDENT_TYPES){
      const s=scenario(type);
      expect(s.injectedFaults).toHaveLength(4);
      expect(s.liveProviderCredential).toBe(false);
      expect(s.tenantConsentForWrites).toBe(false);
      expect(planTabletopExercise(s).walkthrough.length).toBeGreaterThan(0);
      expect(generateTabletopScenario({
        id:s.id,organizationId:s.organizationId,type,title:s.title,
        seed:s.scenarioSeed,at:s.createdAt,faultCount:4,
      }).injectedFaults).toEqual(s.injectedFaults);
    }
  });
  it("refuses provider commands and fake provider proof",()=>{
    const s=scenario();
    const exercise=createTabletopExercise(s);
    const stepId=s.activeStepIds[0]!;
    const rejected=applyTabletopMove(s,exercise,{
      id:"move-1234",stepId,actorRole:"INCIDENT_COMMANDER",
      command:"SEND_PROVIDER_COMMAND",reason:"Attempt remote command",
      at,assertedIndependentEvidence:false,
      assertedExternalCompletion:false,
    },exercise.revision);
    expect(rejected.accepted).toBe(false);
    expect(rejected.exercise.unsafeOperationsBlocked).toBe(1);
    expect(rejected.exercise.externalProviderWrites).toBe(0);
    expect(()=>applyTabletopMove(s,rejected.exercise,{
      id:"move-1235",stepId,actorRole:"SECURITY_REVIEWER",
      command:"MARK_PROVEN",reason:"Fake confidence report",at,
      assertedIndependentEvidence:true,assertedExternalCompletion:true,
    },rejected.exercise.revision)).not.toThrow();
  });
  it("preserves uncertain signals and audit revisions",()=>{
    const s=scenario(),first=createTabletopExercise(s);
    const outcome=applyTabletopMove(s,first,{
      id:"move-1234",stepId:s.activeStepIds[0]!,
      actorRole:"INCIDENT_COMMANDER",command:"DECLARE_UNKNOWN",
      reason:"No independent observation",at,
      assertedIndependentEvidence:false,assertedExternalCompletion:false,
    },0);
    expect(outcome.accepted).toBe(true);
    expect(outcome.exercise.unknownsPreserved).toBe(1);
    expect(outcome.event?.revision).toBe(1);
    expect(()=>applyTabletopMove(s,outcome.exercise,{
      id:"move-1235",stepId:s.activeStepIds[0]!,
      actorRole:"SECURITY_REVIEWER",command:"COLLECT_EVIDENCE",
      reason:"Need fresh telemetry",at,
      assertedIndependentEvidence:false,assertedExternalCompletion:false,
    },0)).toThrow("TABLETOP_CONCURRENT_REVISION_CONFLICT");
    expect(reviewTabletopExercise(s,outcome.exercise,later)
      .technicalContainmentVerified).toBe(false);
  });
  it("requires exact scenario checksum and tenant identity",()=>{
    const s=scenario(),e=createTabletopExercise(s);
    expect(()=>applyTabletopMove({...s,organizationId:"foreign-tenant"},
      e,{id:"move-1234",stepId:s.activeStepIds[0]!,
      actorRole:"INCIDENT_COMMANDER",command:"ESCALATE",
      reason:"Need response",at,
      assertedIndependentEvidence:false,assertedExternalCompletion:false,
    },0)).toThrow();
  });
  it("produces debrief and safely escaped exports",()=>{
    const s=scenario(),result=executeDeterministicTabletop(s,[],later);
    expect(result.debrief.readiness).toBe("NEEDS_PRACTICE");
    expect(result.debrief.externalContainmentProven).toBe(false);
    expect(debriefTabletopExercise(s,result.exercise,later)
      .missingStages.length).toBeGreaterThan(0);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const a=exportTabletopReplay(result,format);
      expect(a.digest).toMatch(/^[a-f0-9]{64}$/);
      expect(a.content.length).toBeGreaterThan(30);
    }
  });
});
