import{describe,it,expect}from "vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}
 from "./integrated-risk-engine";
import{
 buildOfflineCapturePayload,sealOfflineCapture,
 verifyOfflineCapture,compareOfflineCaptures,
 buildCaptureIntegrityManifest,verifyCaptureManifest,
 replayOfflineCapturePayload,filterOfflineCaptures,
 exportOfflineCaptures,type OfflineCapture,
}from "./offline-report-capture-domain";
const at="2026-11-19T12:00:00.000Z";
function source():IntegratedRiskInput{
 return{
 organizationId:"org-test",evaluatedAt:at,
 evidence:[{id:"evidence-one",organizationId:"org-test",
 source:"BASELINE",domain:"BACKUP",controlId:"BACKUP_TEST",
 scope:"org",state:"DECLARED",observedAt:null,
 createdAt:at,details:{}}],
 findings:[{id:"finding-one",organizationId:"org-test",
 ruleId:"BACKUP_TEST",key:"backup-risk",
 severity:"HIGH",status:"OPEN",title:"Backup unverified",
 description:"Needs review",lastSeenAt:at,evidence:{}}],
 assessments:[],declaredActions:[],
 sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},
 countOfRecords:{evidence:1,findings:1,assessments:0,declaredActions:0},
 };
}
function capture(time="2026-11-19T13:00:00.000Z",
 id="capture-one"):OfflineCapture{
 const report=buildIntegratedRiskDigest(source());
 const payload=buildOfflineCapturePayload({
 organizationId:"org-test",kind:"INTEGRATED_RISKS",
 capturedAt:time,report,
 });
 return sealOfflineCapture({
 id,actorUserId:"member-one",createdAt:time,payload,
 });
}
describe("immutable report captures and local integrity",()=>{
 it("seals a persisted source report with a verified checksum",()=>{
 const value=capture();
 const check=verifyOfflineCapture(value,"org-test");
 expect(check.valid).toBe(true);
 expect(check.reportVerified).toBe(true);
 expect(value.sourceComplete).toBe(true);
 expect(value.externalAttestation).toBe(false);
 expect(value.customerCertification).toBe(false);
 });
 it("rejects a payload claiming a foreign organization",()=>{
 const report=buildIntegratedRiskDigest(source());
 expect(()=>buildOfflineCapturePayload({
 organizationId:"foreign-org",kind:"INTEGRATED_RISKS",
 capturedAt:at,report,
 })).toThrow();
 });
 it("detects changes to original JSON evidence and digest",()=>{
 const value=capture();
 const forged=structuredClone(value);
 forged.payload.reportDigest="a".repeat(64);
 expect(verifyOfflineCapture(forged).valid).toBe(false);
 const changed=structuredClone(value);
 changed.payload.report=structuredClone(changed.payload.report);
 if(changed.payload.report.schema==="cyberpilot.integrated.risks.v1")
 changed.payload.report.evidenceSecurityCertified=true as false;
 expect(verifyOfflineCapture(changed).valid).toBe(false);
 });
 it("fails verification of forged security certification",()=>{
 const value=capture();
 value.externalAttestation=true as false;
 const check=verifyOfflineCapture(value);
 expect(check.errors).toContain("FALSE_SECURITY_OR_PROVIDER_CLAIM");
 });
 it("replays JSON without claiming a real database restore",()=>{
 const result=replayOfflineCapturePayload(capture());
 expect(result.originalEvidenceVerified).toBe(true);
 expect(result.databaseRestoreExecuted).toBe(false);
 expect(result.providerRestoreExecuted).toBe(false);
 });
 it("builds a bounded integrity manifest with required scope",()=>{
 const list=[capture()];
 const manifest=buildCaptureIntegrityManifest("org-test",
 "2026-11-19T14:00:00.000Z",list);
 expect(manifest.entryCount).toBe(1);
 expect(manifest.integrityFailures).toBe(0);
 expect(manifest.readyForDevelopmentRehearsal).toBe(true);
 expect(manifest.readyForCustomerLIVEAcceptance).toBe(false);
 expect(verifyCaptureManifest(manifest,"org-test").valid).toBe(true);
 expect(verifyCaptureManifest(manifest,"foreign-org").valid).toBe(false);
 });
 it("rejects duplicate capture IDs and unknown tenants in manifests",()=>{
 const first=capture();
 const duplicate={...capture(),payloadDigest:first.payloadDigest};
 const manifest=buildCaptureIntegrityManifest("org-test",
 "2026-11-19T14:00:00.000Z",[first,duplicate]);
 expect(manifest.duplicates).toBe(1);
 expect(manifest.readyForDevelopmentRehearsal).toBe(false);
 expect(()=>buildCaptureIntegrityManifest("foreign-org",
 "2026-11-19T14:00:00.000Z",[first])).not.toThrow();
 expect(verifyCaptureManifest(manifest).valid).toBe(true);
 });
 it("supports conservatively scoped comparisons",()=>{
 const earlier=capture();
 const later=capture("2026-11-19T14:00:00.000Z","capture-two");
 const comparison=compareOfflineCaptures(earlier,later);
 expect(comparison.kind).toBe("INTEGRATED_RISKS");
 expect(comparison.originalDigestChanged).toBe(false);
 expect(comparison.actualRiskReductionProven).toBe(false);
 expect(comparison.customerTenantReauthenticated).toBe(false);
 });
 it("refuses incompatible tenant and kind comparison",()=>{
 const before=capture();
 const after=capture("2026-11-19T14:00:00.000Z","capture-two");
 after.organizationId="other-org";
 expect(()=>compareOfflineCaptures(before,after)).toThrow();
 });
 it("filters captures and exports cautious artifacts",()=>{
 const captures=[capture()];
 const page=filterOfflineCaptures(captures,{limit:1,offset:0});
 expect(page.items).toHaveLength(1);
 expect(page.customerSecurityCertified).toBe(false);
 expect(()=>filterOfflineCaptures(captures,{limit:101})).toThrow();
 const csv=exportOfflineCaptures(captures,"org-test","CSV");
 expect(csv.content).toContain("payloadDigest");
 expect(JSON.parse(exportOfflineCaptures(captures,"org-test","JSON")
 .content)[0].customerCertification).toBe(false);
 });
});
