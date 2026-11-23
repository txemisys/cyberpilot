import { describe, expect, it } from "vitest";
import { createIncident } from "./incident-case-domain";
import { assessIncidentAssetImpact, compareAssetImpactAssessments }
  from "./incident-integrated-assets-domain";
import { planIncidentAssetActions, crossCheckIncidentAssetSources,
  exportIncidentAssetImpact } from "./incident-integrated-assets-operations";
const at = "2026-11-23T09:00:00.000Z";
const incident = () => createIncident({
  id: "incident-1234", organizationId: "tenant-1234",
  type: "LOST_DEVICE", title: "Lost laptop",
  subjectReference: "inventory-external-1234",
  actorUserId: "admin-1234", ownerUserId: null, at,
});
const importRow = { id:"import-1234",organizationId:"tenant-1234",
  sourceLabel:"offline-csv",payloadDigest:"a".repeat(64),
  state:"COMMITTED",declaredCount:1,importedCount:1,unknownVersionCount:0,
  createdAt:at,retiredAt:null };
const device = { id:"device-1234", organizationId:"tenant-1234",
  importId:importRow.id,externalId:"external-1234",
  hostname:null,ownerHash:null,platform:"WINDOWS",
  osName:"Windows",osVersion:"11",softwareName:"Defender",
  softwareVersion:"1.0",normalizedProductKey:"windows-11",
  observedAt:at,versionStatus:"KNOWN",freshnessStatus:"FRESH",
  advisoryStatus:"NONE",advisoryIds:[],confidence:"OBSERVED" };
function review(options: Record<string,unknown> = {}) {
  return assessIncidentAssetImpact({
    incident:incident(),selection:{deviceIds:[device.id],
      imports:[],externalIds:[],requireActiveImport:true},
    devices:[device],imports:[importRow],inspections:[],
    at,freshnessHours:72,truncated:false,...options,
  });
}
describe("incident-to-inventory explicit impact",()=>{
  it("never infers a physical identity or device isolation",()=>{
    const value=review();
    expect(value.coverage).toBe("EXPLICIT_SCOPE_MATCHED");
    expect(value.affectedDevices[0]?.matchBasis).toBe("EXPLICIT_DEVICE_ID");
    expect(value.affectedDevices[0]?.needsHumanAttribution).toBe(true);
    expect(value.remoteDeviceIsolationVerified).toBe(false);
  });
  it("detects stale assets, unknown software version, retired imports",()=>{
    expect(review({at:"2026-12-01T09:00:00.000Z"})
      .staleDeviceIds).toContain(device.id);
    expect(review({devices:[{...device,osVersion:null}]})
      .unknownVersionIds).toContain(device.id);
    expect(review({imports:[{...importRow,retiredAt:at}]})
      .affectedDevices[0]?.outcome).toBe("RETIRED_IMPORT");
  });
  it("rejects cross tenant rows and wrong identifiers",()=>{
    const value=review({devices:[{...device,organizationId:"other-tenant"}]});
    expect(value.reviewGate).toBe("BLOCKED");
    expect(value.affectedDevices).toHaveLength(0);
    expect(value.foreignTenantIds).toContain(device.id);
    expect(review({selection:{deviceIds:["missing-1234"],imports:[],
      externalIds:[],requireActiveImport:true}}).missingDeviceIds)
      .toContain("missing-1234");
  });
  it("creates operator-only isolation handoff for lost devices",()=>{
    const value=review();
    const actions=planIncidentAssetActions(value);
    expect(actions.actions.some(x=>x.kind==="ISOLATION_HANDOFF")).toBe(true);
    expect(actions.actions.every(x=>x.providerWrites===0)).toBe(true);
    expect(actions.actualIsolationEstablished).toBe(false);
    expect(crossCheckIncidentAssetSources(value).verifiedIsolationCount).toBe(0);
  });
  it("displays advisory candidates without calling OSV",()=>{
    const value=review({devices:[{...device,advisoryStatus:"POSSIBLE",
      advisoryIds:["GHSA-2026-1234"]}]});
    expect(value.highPriorityDeviceIds).toContain(device.id);
    expect(value.vulnerabilityScanPerformed).toBe(false);
    expect(planIncidentAssetActions(value).advisoryCandidates).toBe(1);
  });
  it("makes exports replayable and comparisons non-causal",()=>{
    const first=review(),next=review({at:"2026-11-23T10:00:00.000Z"});
    expect(compareAssetImpactAssessments(first,next).containmentConfirmed).toBe(false);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const result=exportIncidentAssetImpact(first,format);
      expect(result.content.length).toBeGreaterThan(20);
      expect(result.digest).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});
