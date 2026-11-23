import { describe, expect, it } from "vitest";
import { createIncident } from "./incident-case-domain";
import { buildIncidentSituation, compareIncidentSituations }
  from "./incident-situation-domain";
import { prepareIncidentBriefing, reconcileIncidentSituation,
  planIncidentShiftHandoff, exportIncidentSituation }
  from "./incident-situation-operations";
const at = "2026-11-23T10:00:00.000Z";
const input = () => ({
  incident: createIncident({
    id:"incident-1234",organizationId:"tenant-1234",
    title:"Credential risk",type:"COMPROMISED_ACCOUNT" as const,
    subjectReference:"principal-1234",ownerUserId:null,
    actorUserId:"admin-1234",at,
  }),
  evidence:null,assets:null,remediation:null,
  sourceStates:{ evidence:"ABSENT" as const,
    assets:"ABSENT" as const,remediation:"ABSENT" as const },
  capturedAt:at,sourceMode:"PERSISTED_READ_ONLY" as const,
});
describe("incident situation room and conservative product convergence",()=>{
  it("never mistakes unknown coverage for containment",()=>{
    const r=buildIncidentSituation(input());
    expect(r.completeness).toBe("UNKNOWN");
    expect(r.sourceSummaries.every(x => x.records === 0)).toBe(true);
    expect(r.actualContainmentVerified).toBe(false);
    expect(r.externalWrites).toBe(0);
    expect(r.concerns.some(x=>x.code==="EVIDENCE_ABSENT")).toBe(true);
    expect(r.concerns.some(x=>x.code==="OWNER_UNASSIGNED")).toBe(true);
  });
  it("rejects contradictory source state and invalid clocks",()=>{
    expect(()=>buildIncidentSituation({...input(),
      sourceStates:{evidence:"PRESENT",assets:"ABSENT",
        remediation:"ABSENT"}})).toThrow();
    expect(()=>buildIncidentSituation({...input(),
      capturedAt:"2026-11-23"})).toThrow();
  });
  it("provides shift priorities without external operations",()=>{
    const report=buildIncidentSituation(input());
    const plan=planIncidentShiftHandoff(report);
    expect(plan.noAutomaticDispatch).toBe(true);
    expect(plan.critical.length+plan.review.length).toBeGreaterThan(1);
    expect(prepareIncidentBriefing(report).providerContainmentVerified).toBe(false);
    expect(reconcileIncidentSituation(report).decision).toBe("REVIEW_SCOPE");
  });
  it("exports repeatable JSON/CSV/Markdown and refuses cross-tenant diffs",()=>{
    const first=buildIncidentSituation(input());
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const exportData=exportIncidentSituation(first,format);
      expect(exportData.digest).toMatch(/^[0-9a-f]{64}$/);
      expect(exportData.content.length).toBeGreaterThan(20);
    }
    const second=buildIncidentSituation({...input(),
      capturedAt:"2026-11-23T11:00:00.000Z"});
    expect(compareIncidentSituations(first,second)
      .providerContainmentChangeVerified).toBe(false);
    expect(()=>compareIncidentSituations(first,{
      ...second,organizationId:"tenant-foreign",
    })).toThrow();
  });
});
