import{describe,it,expect}from"vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}from"./integrated-risk-engine";
import{buildEvidenceDecisionReport}from"./evidence-decision-engine";
import{createDecisionCaseSnapshot}from"./evidence-decision-case-domain";
import{buildCaseActionHandoffBoard,verifyCaseActionHandoffBoard,selectCaseActionHandoffRows,exportCaseActionHandoffBoard}from"./case-action-handoff-domain";
const at="2026-11-23T08:00:00.000Z";
function fixture(){
 const input:IntegratedRiskInput={organizationId:"org-test",evaluatedAt:at,evidence:[{id:"evidence-one",organizationId:"org-test",source:"BASELINE",domain:"BACKUP",controlId:"BACKUP_CHECK",scope:"org",state:"DECLARED",observedAt:null,createdAt:at,details:{}}],findings:[{id:"finding-one",organizationId:"org-test",ruleId:"BACKUP_CHECK",key:"backup-original",severity:"HIGH",status:"OPEN",title:"Backup lacks verification",description:"Persisted original finding",lastSeenAt:at,evidence:{}}],assessments:[],declaredActions:[],sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},countOfRecords:{evidence:1,findings:1,assessments:0,declaredActions:0}};
 const report=buildIntegratedRiskDigest(input);
 const choices=buildEvidenceDecisionReport(report);
 const decision=choices.decisions.find(x=>x.code==="REVIEW_OPEN_RISK")!;
 const item=createDecisionCaseSnapshot({caseId:"case-one",actorUserId:"member-one",at,report:choices,decisionKey:decision.key,ownerUserId:"member-one",dueAt:null,relatedActionId:null,reviewNote:null});
 return{report,item};
}
function board(options:{noFinding?:boolean;truncated?:boolean;foreign?:boolean}={}){
 const{report,item}=fixture();
 if(options.noFinding)item.findingIds=[];
 if(options.foreign)item.organizationId="foreign-org";
 return buildCaseActionHandoffBoard({organizationId:"org-test",evaluatedAt:"2026-11-23T09:00:00.000Z",cases:[item],actions:[],report,sourceTruncated:options.truncated??false});
}
describe("source-bound handoff read model",()=>{
 it("matches persisted original findings without LIVE calls",()=>{
  const x=board();expect(x.totals.readyForHandoff).toBe(1);
  expect(x.rows[0]?.candidates[0]?.sharedFindingIds).toContain("finding-one");
  expect(x.independentRemediationVerified).toBe(false);
  expect(verifyCaseActionHandoffBoard(x,"org-test").valid).toBe(true);
 });
 it("blocks incomplete source and missing original finding",()=>{
  expect(board({truncated:true}).rows[0]?.safeForHandoff).toBe(false);
  expect(board({noFinding:true}).totals.withoutOriginalFindings).toBe(1);
 });
 it("rejects foreign tenant and false audit digest",()=>{
  expect(()=>board({foreign:true})).toThrow();
  const x=board();x.totals.readyForHandoff=5;
  expect(verifyCaseActionHandoffBoard(x,"org-test").valid).toBe(false);
  expect(()=>exportCaseActionHandoffBoard(x,"CSV")).toThrow();
 });
 it("paginates and refuses oversized pages",()=>{
  const x=board();
  expect(selectCaseActionHandoffRows(x,{limit:1}).total).toBe(1);
  expect(()=>selectCaseActionHandoffRows(x,{limit:201})).toThrow();
  expect(JSON.parse(exportCaseActionHandoffBoard(x,"JSON").content).LIVEProviderCalls).toBe(0);
 });
});
