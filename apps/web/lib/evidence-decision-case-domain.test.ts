import{describe,it,expect}from "vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}
 from "./integrated-risk-engine";
import{buildEvidenceDecisionReport}from "./evidence-decision-engine";
import{
 createDecisionCaseSnapshot,caseCreationEvent,
 applyDecisionCaseTransition,auditDecisionCase,
 buildDecisionCaseBoard,selectDecisionCases,
 correlateDecisionCases,exportDecisionCaseBoard,
 type DecisionCaseSnapshot,type DecisionCaseTransition
}from "./evidence-decision-case-domain";
const at="2026-11-19T15:00:00.000Z";
function fixture():IntegratedRiskInput{
 return{
 organizationId:"org-test",evaluatedAt:at,
 evidence:[{id:"evidence-one",organizationId:"org-test",
 source:"BASELINE",domain:"BACKUP",controlId:"BACKUP_TEST",
 scope:"org",state:"DECLARED",observedAt:null,
 createdAt:at,details:{}}],
 findings:[{id:"finding-one",organizationId:"org-test",
 ruleId:"BACKUP_TEST",key:"backup-rule",
 severity:"HIGH",status:"OPEN",title:"Backups unverified",
 description:"No independent evidence",lastSeenAt:at,evidence:{}}],
 assessments:[],declaredActions:[],
 sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},
 countOfRecords:{evidence:1,findings:1,assessments:0,declaredActions:0},
 };
}
function create(){
 const report=buildEvidenceDecisionReport(buildIntegratedRiskDigest(fixture()));
 const candidate=report.decisions.find(x=>x.code==="REVIEW_OPEN_RISK")!;
 const result=createDecisionCaseSnapshot({
 caseId:"case-test",actorUserId:"member-one",at,report,
 decisionKey:candidate.key,ownerUserId:"member-one",
 dueAt:"2026-11-20T12:00:00.000Z",
 relatedActionId:null,reviewNote:"Original evidence requires review",
 });
 return{report,snapshot:result};
}
function command(kind:DecisionCaseTransition["kind"],
 input:Partial<DecisionCaseTransition>={}):DecisionCaseTransition{
 return{
 kind,organizationId:"org-test",caseId:"case-test",
 actorUserId:"member-one",expectedRevision:1,
 at:"2026-11-19T16:00:00.000Z",...input,
 };
}
describe("evidence decision case CAS and source provenance",()=>{
 it("creates case strictly from original tenant report",()=>{
 const {snapshot,report}=create();
 expect(snapshot.decisionKey).toBe(report.decisions.find(x=>
 x.code==="REVIEW_OPEN_RISK")!.key);
 expect(snapshot.independentlyVerified).toBe(false);
 expect(snapshot.providerOperations).toBe(0);
 expect(snapshot.status).toBe("OPEN");
 const forged={...report,organizationId:"org-foreign"};
 expect(()=>createDecisionCaseSnapshot({
 caseId:"case-test",actorUserId:"member-one",at,
 report:forged,decisionKey:snapshot.decisionKey,
 ownerUserId:null,dueAt:null,relatedActionId:null,reviewNote:null,
 })).toThrow();
 });
 it("blocks case transitions from another organization",()=>{
 const{snapshot}=create();
 expect(applyDecisionCaseTransition(snapshot,command("START",{
 organizationId:"other-org"})).reason).toBe(
 "CROSS_TENANT_OR_ACTOR_INVALID");
 });
 it("requires expected revision before changing local case",()=>{
 const{snapshot}=create();
 const attempted=applyDecisionCaseTransition(snapshot,command("START",{
 expectedRevision:7}));
 expect(attempted.accepted).toBe(false);
 expect(attempted.reason).toBe("REVISION_CONFLICT");
 });
 it("permits transition with immutable digest but never remediates",()=>{
 const{snapshot}=create();
 const first=applyDecisionCaseTransition(snapshot,command("START"));
 expect(first.accepted).toBe(true);
 expect(first.next?.revision).toBe(2);
 expect(first.next?.status).toBe("IN_REVIEW");
 expect(first.next?.independentlyVerified).toBe(false);
 expect(first.event?.externalExecution).toBe(false);
 expect(first.legalCustomerApprovalGranted).toBe(false);
 });
 it("forbids reporting complete without review or owner",()=>{
 const{snapshot}=create();
 expect(applyDecisionCaseTransition(snapshot,
 command("REPORT_REVIEW",{reason:"All records reviewed by operator"}))
 .reason).toBe("ILLEGAL_STATE_TRANSITION");
 const started={...snapshot,status:"IN_REVIEW" as const,ownerUserId:null};
 expect(applyDecisionCaseTransition(started,
 command("REPORT_REVIEW",{reason:"Review was completed by operator"}))
 .reason).toBe("REVIEWER_OWNER_REQUIRED");
 });
 it("requires substantive reason before requesting evidence",()=>{
 const{snapshot}=create();
 expect(applyDecisionCaseTransition(snapshot,
 command("REQUEST_EVIDENCE",{reason:"no"}))
 .reason).toBe("SUBSTANTIVE_REASON_REQUIRED");
 });
 it("detects audit history truncation and digest tampering",()=>{
 const{snapshot}=create();
 const event=caseCreationEvent(snapshot);
 expect(auditDecisionCase(snapshot,[event]).valid).toBe(true);
 expect(auditDecisionCase(snapshot,[]).valid).toBe(false);
 const modified={...event,snapshotDigest:"f".repeat(64)};
 expect(auditDecisionCase(snapshot,[modified]).codes)
 .toContain("LATEST_DIGEST_MISMATCH");
 });
 it("builds decision board with overdue, source links and no risk certification",()=>{
 const{snapshot,report}=create();
 const board=buildDecisionCaseBoard({
 organizationId:"org-test",asOf:"2026-11-21T00:00:00.000Z",
 cases:[snapshot],events:[caseCreationEvent(snapshot)],
 truncated:false,
 });
 expect(board.counts.overdue).toBe(1);
 expect(board.counts.invalidAudit).toBe(0);
 expect(board.riskReductionProven).toBe(false);
 expect(correlateDecisionCases(board,report)[0]?.decisionStillPresent)
 .toBe(true);
 expect(selectDecisionCases(board,{priority:["P0"]}).total)
 .toBeLessThanOrEqual(1);
 expect(exportDecisionCaseBoard(board,"CSV").content)
 .toContain("decisionKey");
 });
 it("does not accept mixed-organization board data",()=>{
 const{snapshot}=create();
 expect(()=>buildDecisionCaseBoard({
 organizationId:"foreign-org",asOf:at,cases:[snapshot],
 events:[],truncated:false,
 })).toThrow("CROSS_TENANT");
 });
});
