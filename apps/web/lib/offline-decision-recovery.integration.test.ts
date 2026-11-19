import{randomUUID}from "node:crypto";
import{beforeAll,afterAll,describe,it,expect}from "vitest";
import{db}from "@cyberpilot/database";
import{collectEvidenceDecisionReport}from "./evidence-decision-service";
import{createEvidenceDecisionCase,readEvidenceDecisionCases,
 updateEvidenceDecisionCase}from "./evidence-decision-case-service";
import{captureOfflineReport,listOfflineCaptures,
 readOfflineCapture,comparePersistedCaptures}from
 "./offline-report-capture-service";
import{runOfflineRecoveryRehearsal,
 readOfflineRecoveryRehearsal,listOfflineRecoveryRehearsals,
 buildRecoveryAcceptanceMatrix}from "./offline-recovery-rehearsal-service";
describe.skipIf(!process.env.DATABASE_URL)(
 "offline evidence-to-case, capture and rehearsal PostgreSQL integration",()=>{
 const suffix=randomUUID().slice(0,8);
 const organizationId="decrec-org-"+suffix;
 const foreignOrganization="decrec-foreign-"+suffix;
 const ownerId="decrec-owner-"+suffix;
 const foreignId="decrec-foreign-user-"+suffix;
 const auditorId="decrec-auditor-"+suffix;
 const actor={organizationId,userId:ownerId,role:"OWNER" as const};
 const foreign={
 organizationId:foreignOrganization,userId:foreignId,
 role:"OWNER" as const,
 };
 const auditor={organizationId,userId:auditorId,role:"AUDITOR" as const};
 beforeAll(async()=>{
 await db.user.createMany({data:[
 {id:ownerId,name:"Offline owner",email:ownerId+"@example.invalid"},
 {id:foreignId,name:"Foreign owner",email:foreignId+"@example.invalid"},
 {id:auditorId,name:"Offline auditor",email:auditorId+"@example.invalid"},
 ]});
 await db.organization.createMany({data:[
 {id:organizationId,slug:organizationId,name:"Decision review organization"},
 {id:foreignOrganization,slug:foreignOrganization,
 name:"Foreign review organization"},
 ]});
 await db.membership.createMany({data:[
 {organizationId,userId:ownerId,role:"OWNER"},
 {organizationId:foreignOrganization,userId:foreignId,role:"OWNER"},
 {organizationId,userId:auditorId,role:"AUDITOR"},
 ]});
 await db.securityFinding.create({data:{
 organizationId,key:"backup-"+suffix,ruleId:"BACKUP_RECOVERY_DRILL",
 title:"Backup recovery is unverified",
 description:"Offline declaration and no external tenant",
 severity:"HIGH",status:"OPEN",
 }});
 await db.securityEvidence.create({data:{
 organizationId,source:"LAB",domain:"BACKUP",
 controlId:"BACKUP_RECOVERY_DRILL",state:"DECLARED",
 scope:"ORGANIZATION",observedAt:null,
 details:{lab:true,externalTenantAuthenticated:false},
 }});
 });
 afterAll(async()=>{
 await db.organization.deleteMany({
 where:{id:{in:[organizationId,foreignOrganization]}},
 });
 await db.user.deleteMany({
 where:{id:{in:[ownerId,foreignId,auditorId]}},
 });
 });
 it("loads actual tenant decisions while excluding foreign data",async()=>{
 const report=await collectEvidenceDecisionReport(actor);
 expect(report.decisions.length).toBeGreaterThan(0);
 expect(report.externalTenantAuthenticated).toBe(false);
 const other=await collectEvidenceDecisionReport(foreign);
 expect(other.decisions).toHaveLength(0);
 });
 it("creates a source-verified persistent case and rejects foreign assignment",async()=>{
 const source=await collectEvidenceDecisionReport(actor);
 const decision=source.decisions.find(x=>x.code==="REVIEW_OPEN_RISK")!;
 await expect(createEvidenceDecisionCase(actor,{
 decisionKey:decision.key,ownerUserId:foreignId,
 relatedActionId:null,dueAt:null,reviewNote:null,
 })).rejects.toMatchObject({code:"CASE_OWNER_NOT_TENANT_MEMBER"});
 const result=await createEvidenceDecisionCase(actor,{
 decisionKey:decision.key,ownerUserId:ownerId,
 relatedActionId:null,dueAt:null,reviewNote:"Review the operator claim",
 });
 expect(result.created).toBe(true);
 expect(result.case.status).toBe("OPEN");
 expect(result.case.sourceReportDigest).toMatch(/^[a-f0-9]{64}$/);
 const duplicate=await createEvidenceDecisionCase(actor,{
 decisionKey:decision.key,ownerUserId:ownerId,
 relatedActionId:null,dueAt:null,reviewNote:null,
 });
 expect(duplicate.created).toBe(false);
 expect(duplicate.case.caseId).toBe(result.case.caseId);
 });
 it("verifies tenant-bound CAS events and prevents auditor mutation",async()=>{
 const before=await readEvidenceDecisionCases(actor);
 expect(before.board.cases).toHaveLength(1);
 expect(before.board.audit[0]?.valid).toBe(true);
 const item=before.board.cases[0]!;
 await expect(updateEvidenceDecisionCase(auditor,{
 caseId:item.caseId,expectedRevision:1,kind:"START",
 })).rejects.toMatchObject({code:"CASE_MUTATOR_ROLE_REQUIRED"});
 const result=await updateEvidenceDecisionCase(actor,{
 caseId:item.caseId,expectedRevision:1,kind:"START",
 });
 expect(result.case.status).toBe("IN_REVIEW");
 expect(result.case.revision).toBe(2);
 const after=await readEvidenceDecisionCases(actor);
 expect(after.board.audit[0]?.valid).toBe(true);
 expect(after.board.events).toHaveLength(2);
 await expect(updateEvidenceDecisionCase(actor,{
 caseId:item.caseId,expectedRevision:1,kind:"REOPEN",
 reason:"Reopened after a second independent review",
 })).rejects.toMatchObject({code:"REVISION_CONFLICT"});
 expect((await readEvidenceDecisionCases(foreign)).board.cases)
 .toHaveLength(0);
 });
 it("persists actual server-computed capture and verifies isolation",async()=>{
 const result=await captureOfflineReport(actor,{
 kind:"INTEGRATED_RISKS",strictComplete:true,
 });
 expect(result.created).toBe(true);
 expect(result.capture.sourceComplete).toBe(true);
 const read=await readOfflineCapture(actor,result.capture.id);
 expect(read.validation.valid).toBe(true);
 const listing=await listOfflineCaptures(auditor);
 expect(listing.stats.total).toBe(1);
 expect(listing.stats.invalid).toBe(0);
 await expect(readOfflineCapture(foreign,result.capture.id))
 .rejects.toMatchObject({code:"CAPTURE_NOT_IN_TENANT"});
 await expect(captureOfflineReport(auditor,{
 kind:"INTEGRATED_RISKS",strictComplete:false,
 })).rejects.toMatchObject({code:"CAPTURE_CREATOR_PERMISSION_REQUIRED"});
 });
 it("creates local artifact rehearsal and explicitly does not restore SQL",async()=>{
 const listing=await listOfflineCaptures(actor);
 const captureId=listing.captures[0]!.id;
 const result=await runOfflineRecoveryRehearsal(actor,{
 captureIds:[captureId],
 });
 expect(result.report.status).toBe("BLOCKED");
 expect(result.report.overview.missingRequiredKinds).toBe(3);
 expect(result.report.actualDatabaseRestoreExecuted).toBe(false);
 expect(result.sentExternalRequests).toBe(0);
 const restored=await readOfflineRecoveryRehearsal(actor,
 result.rehearsalId);
 expect(restored.report.digest).toBe(result.report.digest);
 expect(restored.providerCalls).toBe(0);
 const history=await listOfflineRecoveryRehearsals(auditor);
 expect(history.entries).toHaveLength(1);
 const matrix=await buildRecoveryAcceptanceMatrix(actor);
 expect(matrix.requiredKindsMissing).toContain("EXECUTIVE");
 await expect(readOfflineRecoveryRehearsal(foreign,result.rehearsalId))
 .rejects.toMatchObject({
 code:"RECOVERY_REHEARSAL_NOT_IN_TENANT",
 });
 });
 it("rejects comparison with missing archived capture",async()=>{
 const list=await listOfflineCaptures(actor);
 await expect(comparePersistedCaptures(actor,
 list.captures[0]!.id,"missing-capture"))
 .rejects.toMatchObject({code:"CAPTURE_PAIR_NOT_IN_TENANT"});
 });
});
