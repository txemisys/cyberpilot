import { describe,expect,it } from "vitest";
import { createIncident,incidentCreationEvent,type IncidentSnapshot }
  from "./incident-case-domain";
import { evaluateIncidentTriage,buildIncidentTriageBoard }
  from "./incident-triage-assurance";
import { auditIncidentTimeline,reviewIncidentApprovals,
  planIncidentFollowUps } from "./incident-triage-timeline";
import { buildTriageCaseDossier,exportTriageBoard,
  exportTriageDossier,compareIncidentTriageBoards }
  from "./incident-triage-dossier";
const at="2026-11-23T09:00:00.000Z";
const later="2026-11-23T11:00:00.000Z";
function sample(id="incident-1234"):IncidentSnapshot{
  return createIncident({id,organizationId:"tenant-1234",
    type:"COMPROMISED_ACCOUNT",title:"Suspicious access",
    subjectReference:"user-object-1234",actorUserId:"admin-1234",
    ownerUserId:null,at});
}
describe("evidence-first incident SLA triage",()=>{
  it("prioritizes critical unassigned incidents without claiming containment",()=>{
    const s=sample(),item=evaluateIncidentTriage(s,later);
    expect(item.urgency).toBe("IMMEDIATE");
    expect(item.unassigned).toBe(true);
    expect(item.overdueByMinutes).toBeGreaterThan(0);
    expect(item.containmentProven).toBe(false);
    expect(item.nextSteps).toContain("Assign an accountable incident owner");
  });
  it("sorts by urgency and refuses cross-tenant boards",()=>{
    const s=sample(),other=sample("incident-2345");
    const board=buildIncidentTriageBoard(s.organizationId,[s,other],later);
    expect(board.total).toBe(2);
    expect(board.providerWrites).toBe(0);
    expect(board.nextReviewQueue).toHaveLength(2);
    expect(()=>buildIncidentTriageBoard("foreign-tenant",[s],later)).toThrow();
  });
  it("distinguishes missing source proof from human declarations",()=>{
    const s=sample();
    const step=s.steps[0]!;
    s.evidence.push({id:"evidence-1234",stepId:step.stepId,
      source:"identity",sourceReference:"human-note",
      observedAt:at,recordedAt:at,verdict:"DECLARED",
      independent:false,providerOperation:false,summary:"Reported identity"});
    step.evidenceIds.push("evidence-1234");
    const reviewed=evaluateIncidentTriage(s,later);
    expect(reviewed.stageReviews[0]!.missingSources).toContain("identity");
    expect(reviewed.stageReviews[0]!.declaredSources).toContain("identity");
    expect(reviewed.containmentProven).toBe(false);
  });
  it("rejects incomplete event chronology and false latest digests",()=>{
    const s=sample(),event=incidentCreationEvent(s);
    expect(auditIncidentTimeline(s,[event]).complete).toBe(true);
    expect(auditIncidentTimeline(s,[]).complete).toBe(false);
    expect(auditIncidentTimeline(s,[{...event,
      snapshotDigest:"bad"}]).complete).toBe(false);
    expect(()=>auditIncidentTimeline(s,Array.from({length:2001},
      ()=>event))).toThrow();
  });
  it("produces approval diagnostics without execution claims",()=>{
    const s=sample();
    const a=reviewIncidentApprovals(s,later);
    expect(a.expectedApprovalSteps).toBeGreaterThan(0);
    expect(a.legalAuthorizationInferred).toBe(false);
    expect(a.remediationActionsExecuted).toBe(0);
  });
  it("builds followups, case dossier, exports and trend safely",()=>{
    const s=sample(),events=[incidentCreationEvent(s)];
    const dossier=buildTriageCaseDossier(s,events,later);
    expect(dossier.audit.complete).toBe(true);
    expect(dossier.manualActionCount).toBeGreaterThan(0);
    expect(dossier.customerSecurityImprovementVerified).toBe(false);
    expect(planIncidentFollowUps(s,later).some(x=>x.code==="ASSIGN_OWNER")).toBe(true);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      expect(exportTriageDossier(dossier,format).content.length).toBeGreaterThan(0);
      const board=buildIncidentTriageBoard(s.organizationId,[s],later);
      expect(exportTriageBoard(board,format).content.length).toBeGreaterThan(0);
    }
    const before=buildIncidentTriageBoard(s.organizationId,[s],at);
    const after=buildIncidentTriageBoard(s.organizationId,[s],later);
    expect(compareIncidentTriageBoards(before,after).cybersecurityImprovementProven)
      .toBe(false);
  });
});
