import { describe, expect, it } from "vitest";
import { createIncident } from "./incident-case-domain";
import { correlateIncidentEvidence } from "./incident-integrated-evidence-domain";
import { buildIncidentEvidenceReviewQueue, summarizeIncidentEvidenceMatrix,
  exportIntegratedIncidentEvidence } from "./incident-integrated-evidence-operations";
const time = "2026-11-23T09:00:00.000Z";
const incident = () => createIncident({id:"incident-1234",
  organizationId:"tenant-1234",type:"COMPROMISED_ACCOUNT",
  title:"Access investigation",subjectReference:"principal-1234",
  actorUserId:"admin-1234",ownerUserId:null,at:time});
const evidence = {id:"evidence-1234",organizationId:"tenant-1234",
  source:"identity",domain:"m365",controlId:"directory-access",
  scope:"principal-1234",state:"OBSERVED",observedAt:time,
  createdAt:time,updatedAt:time};
const finding = {id:"finding-1234",organizationId:"tenant-1234",
  key:"finding-key-1234",ruleId:"IAM-ACCESS",severity:"HIGH",
  status:"OPEN",title:"Risky access",lastSeenAt:time,resolvedAt:null};
const decision = {id:"decision-1234",organizationId:"tenant-1234",
  domain:"identity",controlId:"directory-access",scope:"principal-1234",
  status:"OPEN",revision:1,evidenceIds:[evidence.id],
  findingIds:[finding.id]};
function run(partial: Record<string,unknown>={}) {
  return correlateIncidentEvidence({
    incident:incident(),selection:{evidenceIds:[evidence.id],
      findingIds:[finding.id],decisionIds:[decision.id]},
    evidence:[evidence],findings:[finding],decisions:[decision],
    asOf:time,maxAgeHours:72,truncated:false,...partial,
  });
}
describe("incident evidence cross-product integration",()=>{
  it("correlates exact persisted IDs and preserves source provenance",()=>{
    const report=run();
    expect(report.matchedEvidenceCount).toBe(1);
    expect(report.matchedFindingCount).toBe(1);
    expect(report.matchedDecisionCount).toBe(1);
    expect(report.coverage).toBe("EXPLICIT_COMPLETE");
    expect(report.providerWrites).toBe(0);
    expect(report.actualIncidentContainmentConfirmed).toBe(false);
  });
  it("rejects cross tenant evidence and never treats fuzzy name as a match",()=>{
    const r=run({evidence:[{...evidence,organizationId:"foreign-tenant"}]});
    expect(r.acceptance).toBe("BLOCKED");
    expect(r.foreignTenantIds).toContain(evidence.id);
    expect(r.matchedEvidenceCount).toBe(0);
    const noSelection=run({selection:{evidenceIds:[],
      findingIds:[],decisionIds:[]}});
    expect(noSelection.matchedEvidenceCount).toBe(0);
    expect(noSelection.coverage).toBe("NO_EXPLICIT_INPUT");
  });
  it("preserves stale and error evidence as incomplete",()=>{
    const stale=run({asOf:"2026-12-01T09:00:00.000Z"});
    expect(stale.sourceRecords.find(x=>x.kind==="EVIDENCE")?.verdict)
      .toBe("STALE_RECORD");
    const errored=run({evidence:[{...evidence,state:"ERROR"}]});
    expect(errored.sourceRecords.find(x=>x.kind==="EVIDENCE")?.verdict)
      .toBe("ERROR_RECORD");
    expect(errored.acceptance).toBe("INCOMPLETE");
  });
  it("derives only direct evidence-decision membership, no implicit telemetry",()=>{
    const r=run({selection:{evidenceIds:[],findingIds:[],
      decisionIds:[decision.id]}});
    expect(r.matchedEvidenceCount).toBe(1);
    expect(r.sourceRecords.find(x=>x.kind==="EVIDENCE")?.basis)
      .toBe("DECISION_MEMBERSHIP");
    expect(r.actualIncidentContainmentConfirmed).toBe(false);
  });
  it("refuses malformed identifiers, oversized source populations",()=>{
    expect(()=>run({selection:{evidenceIds:["../x"],
      findingIds:[],decisionIds:[]}})).toThrow();
    expect(()=>run({evidence:Array.from({length:501},()=>evidence)})).toThrow();
  });
  it("creates bounded review queue and safe exports",()=>{
    const r=run();
    const matrix=summarizeIncidentEvidenceMatrix(r);
    expect(matrix.actualSecurityPostureImproved).toBe(false);
    expect(buildIncidentEvidenceReviewQueue(r).humanOnly).toBe(true);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const artifact=exportIntegratedIncidentEvidence(r,format);
      expect(artifact.digest).toMatch(/^[a-f0-9]{64}$/);
      expect(artifact.content.length).toBeGreaterThan(50);
    }
  });
});
