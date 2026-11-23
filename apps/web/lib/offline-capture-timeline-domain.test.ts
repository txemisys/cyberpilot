import{describe,it,expect}from"vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}from"./integrated-risk-engine";
import{buildOfflineCapturePayload,sealOfflineCapture}from"./offline-report-capture-domain";
import{buildCaptureTimeline,compareTimelinePoints,exportCaptureTimeline,validateTimelineQuery}from"./offline-capture-timeline-domain";
const at="2026-11-23T08:00:00.000Z";
function capture(date="2026-11-23T09:00:00.000Z",id="capture-one"){
 const input:IntegratedRiskInput={organizationId:"org-test",evaluatedAt:at,evidence:[],findings:[],assessments:[],declaredActions:[],sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},countOfRecords:{evidence:0,findings:0,assessments:0,declaredActions:0}};
 const report=buildIntegratedRiskDigest(input);
 const payload=buildOfflineCapturePayload({organizationId:"org-test",kind:"INTEGRATED_RISKS",capturedAt:date,report});
 return sealOfflineCapture({id,actorUserId:"member-one",createdAt:date,payload});
}
const query={organizationId:"org-test",limit:50,offset:0};
describe("immutable source capture chronology",()=>{
 it("verifies persisted copies without certifying security",()=>{
  const timeline=buildCaptureTimeline(query,[capture()],at,false);
  expect(timeline.points).toHaveLength(1);
  expect(timeline.points[0]?.integrityValid).toBe(true);
  expect(timeline.independentRemediationVerified).toBe(false);
  expect(timeline.providerCalls).toBe(0);
 });
 it("compares equal source digests without asserting improvements",()=>{
  const first=capture(),second=capture("2026-11-23T10:00:00.000Z","capture-two");
  const timeline=buildCaptureTimeline(query,[first,second],"2026-11-23T11:00:00.000Z",false);
  expect(timeline.changes).toHaveLength(1);
  expect(timeline.changes[0]?.independentlyVerifiedImprovement).toBe(false);
 });
 it("blocks comparisons involving corrupted source integrity",()=>{
  const older=capture(),later=capture("2026-11-23T10:00:00.000Z","capture-two");
  later.payloadDigest="0".repeat(64);
  const timeline=buildCaptureTimeline(query,[older,later],"2026-11-23T11:00:00.000Z",false);
  expect(timeline.changes[0]?.comparable).toBe(false);
  expect(timeline.changes[0]?.riskCountDelta).toBeNull();
 });
 it("prevents tenant mixing and refuses unsafe paging",()=>{
  const foreign=capture();foreign.organizationId="foreign-org";
  expect(()=>buildCaptureTimeline(query,[foreign],at,false)).toThrow("CROSS_TENANT");
  expect(validateTimelineQuery({...query,limit:201})).toContain("TIMELINE_LIMIT_INVALID");
 });
 it("marks incomplete pages, supports neutral exports",()=>{
  const timeline=buildCaptureTimeline(query,[capture()],"2026-11-23T11:00:00.000Z",true);
  expect(timeline.truncated).toBe(true);
  expect(exportCaptureTimeline(timeline,"CSV").completenessWarning).toBe(true);
  expect(exportCaptureTimeline(timeline,"MARKDOWN").content).toContain("LIVE");
 });
});
