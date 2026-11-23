import {describe,expect,it} from "vitest";
import {createIncident} from "./incident-case-domain";
import {buildIncidentSituation} from "./incident-situation-domain";
import {DEFAULT_ASSURANCE_POLICY,assessIncidentAssurance,
  compareAssuranceReports,validateAssurancePolicy}
  from "./incident-assurance-domain";
import {prepareAssuranceWorkPacket,buildAssuranceEscalationPlan,
  buildAssuranceTrend,exportAssuranceDossier}
  from "./incident-assurance-operations";
const at="2026-11-23T10:00:00.000Z";
const later="2026-11-23T11:00:00.000Z";
function situation(){
  const incident=createIncident({id:"incident-1234",
    organizationId:"tenant-1234",type:"COMPROMISED_ACCOUNT",
    title:"Identity compromise",subjectReference:"principal-1234",
    actorUserId:"admin-1234",ownerUserId:null,at});
  return buildIncidentSituation({
    incident,evidence:null,assets:null,remediation:null,
    sourceStates:{evidence:"ABSENT",assets:"ABSENT",remediation:"ABSENT"},
    capturedAt:at,sourceMode:"PERSISTED_READ_ONLY",
  });
}
function review(evaluatedAt=at){
  return assessIncidentAssurance({situation:situation(),
    tabletop:null,policy:DEFAULT_ASSURANCE_POLICY,evaluatedAt});
}
describe("offline incident assurance controls and escalation packets",()=>{
  it("never certifies a real security outcome",()=>{
    const r=review();
    expect(r.status).not.toBe("OFFLINE_REVIEW_ELIGIBLE");
    expect(r.independentProviderContainmentVerified).toBe(false);
    expect(r.externallyExecutableActions).toBe(0);
    expect(r.controls.some(x=>x.id==="REMEDIATION_PROVIDER_PROOF"&&
      x.state==="UNKNOWN")).toBe(true);
  });
  it("requires independent authorization and owner review",()=>{
    const r=review();
    expect(r.controls.find(x=>x.id==="GOVERNANCE_OWNER")?.state).toBe("FAIL");
    expect(r.controls.find(x=>x.id==="REMEDIATION_DUTIES")?.state).toBe("FAIL");
    expect(r.criticalFailures).toBeGreaterThan(0);
  });
  it("rejects policy shortcuts which convert VERIFIED into provider proof",()=>{
    expect(validateAssurancePolicy({
      ...DEFAULT_ASSURANCE_POLICY,
      allowHistoricalVerifiedAsProviderProof:true as false,
    })).toContain("PROVIDER_OUTCOME_SHORTCUT_FORBIDDEN");
    expect(()=>assessIncidentAssurance({
      situation:situation(),tabletop:null,evaluatedAt:at,
      policy:{...DEFAULT_ASSURANCE_POLICY,maxUnknownSourceCount:-1},
    })).toThrow();
  });
  it("exports review controls, escalation register and operator packet",()=>{
    const r=review();
    expect(prepareAssuranceWorkPacket(r).externalExecutionEnabled).toBe(false);
    expect(buildAssuranceEscalationPlan(r).notificationsSent).toBe(0);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const artifact=exportAssuranceDossier(r,format);
      expect(artifact.digest).toMatch(/^[a-f0-9]{64}$/);
      expect(artifact.content.length).toBeGreaterThan(30);
    }
  });
  it("compares reports without claiming real customer risk reduction",()=>{
    const first=review(),next=review(later);
    expect(compareAssuranceReports(first,next)
      .actualCustomerRiskReductionProven).toBe(false);
    const trend=buildAssuranceTrend([first,next]);
    expect(trend.complianceCertificationIssued).toBe(false);
    expect(()=>buildAssuranceTrend([first,{
      ...next,organizationId:"other-tenant",
    }])).toThrow();
  });
});
