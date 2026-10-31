import {describe,expect,it} from "vitest";
import {
 EvidenceLinkError,assessLinkedEvidence,authorizeEvidenceLink,
 canEditEvidenceLinks,enforceLinkCapacity,evidenceCandidateSort,
 linkExportFields,normalizeEvidenceState,parseEvidenceCommand,
 parseEvidenceId,parseEvidenceReason,parseEvidenceSearch,summarizeLinks,
 type EvidenceRecord,type FindingReference,type LinkItem
} from "./work-evidence-policy";
const date=new Date("2026-10-31T12:00:00Z");
const finding:FindingReference={ruleId:"MFA_ENABLED",key:"mfa-user",status:"OPEN"};
function evidence(overrides:Partial<EvidenceRecord>={}):EvidenceRecord{
 return {
  id:"clevidence123",organizationId:"cltenant123",
  controlId:"MFA_ENABLED",domain:"identity",scope:"tenant",
  state:"OBSERVED",source:"local-scanner",observedAt:new Date("2026-10-30T12:00:00Z"),
  createdAt:new Date("2026-10-29T12:00:00Z"),updatedAt:new Date("2026-10-30T12:00:00Z"),
  ...overrides
 };
}
function link(overrides:Partial<LinkItem>={}):LinkItem{
 return {
  id:"cllink123",evidenceId:"clevidence123",reason:"Supports a human review of MFA",
  linkedAt:new Date("2026-10-30T14:00:00Z"),unlinkedAt:null,
  evidence:evidence(),...overrides
 };
}
describe("work evidence link boundary",()=>{
 it("requires structured identifiers",()=>{
  expect(parseEvidenceId("clevidence123")).toBe("clevidence123");
  for(const bad of ["",null,0,{},[],true,"../other","x","a".repeat(101),"MFA/123"])
   expect(()=>parseEvidenceId(bad)).toThrow(EvidenceLinkError);
 });
 it("requires meaningful reason without control characters",()=>{
  expect(parseEvidenceReason("  Review MFA observation  ")).toBe("Review MFA observation");
  for(const bad of ["", "hi","a".repeat(1501),"invalid\u0000",null,10])
   expect(()=>parseEvidenceReason(bad)).toThrow(EvidenceLinkError);
 });
 it("parses attach and restore explicitly",()=>{
  expect(parseEvidenceCommand({
   kind:"attach",evidenceId:"clevidence123",reason:"Review for security team"
  })).toEqual({kind:"attach",evidenceId:"clevidence123",reason:"Review for security team"});
  expect(parseEvidenceCommand({
   kind:"restore",evidenceId:"clevidence123",reason:"Restoring after new review"
  }).kind).toBe("restore");
 });
 it("parses detach without permitting state changes",()=>{
  expect(parseEvidenceCommand({kind:"detach",evidenceId:"clevidence123"}))
   .toEqual({kind:"detach",evidenceId:"clevidence123"});
  expect(()=>parseEvidenceCommand({
   kind:"detach",evidenceId:"clevidence123",verified:true
  })).toThrow();
 });
 it("blocks unknown commands and tenant override fields",()=>{
  for(const kind of ["verify","resolve","scan","update","delete",null])
   expect(()=>parseEvidenceCommand({kind,evidenceId:"clevidence123"})).toThrow();
  expect(()=>parseEvidenceCommand({
   kind:"attach",evidenceId:"clevidence123",reason:"Review this evidence",
   organizationId:"another"
  })).toThrow();
 });
 it("normalizes empty and long search terms",()=>{
  expect(parseEvidenceSearch(undefined)).toBe("");
  expect(parseEvidenceSearch("   mfa ")).toBe("mfa");
  expect(parseEvidenceSearch("x".repeat(200))).toHaveLength(120);
 });
});
describe("organization role and assignee permissions",()=>{
 it("allows managers to link observations",()=>{
  expect(canEditEvidenceLinks("OWNER",null,"manager")).toBe(true);
  expect(canEditEvidenceLinks("ADMIN",null,"manager")).toBe(true);
 });
 it("allows only the assigned regular teammate",()=>{
  expect(canEditEvidenceLinks("MEMBER","user-1","user-1")).toBe(true);
  expect(canEditEvidenceLinks("MEMBER","user-2","user-1")).toBe(false);
  expect(canEditEvidenceLinks("MEMBER",null,"user-1")).toBe(false);
 });
 it("keeps auditors read-only even when assigned",()=>{
  expect(canEditEvidenceLinks("AUDITOR","user-1","user-1")).toBe(false);
 });
 it("uses the same decision in policy authorization",()=>{
  expect(()=>authorizeEvidenceLink("OWNER",null,"manager")).not.toThrow();
  expect(()=>authorizeEvidenceLink("MEMBER","other","actor")).toThrow(EvidenceLinkError);
  expect(()=>authorizeEvidenceLink("AUDITOR","actor","actor")).toThrow(EvidenceLinkError);
 });
});
describe("evidence uncertainty and relationship semantics",()=>{
 it("does not equate a link with verification",()=>{
  const a=assessLinkedEvidence(evidence(),finding,date);
  expect(a.state).toBe("OBSERVED");
  expect(a.isExplicitMatch).toBe(true);
  expect(a.maySupportReview).toBe(true);
  expect(a.relationship).toBe("CONTROL_ID_MATCH");
 });
 it("flags observation mismatch even if recent",()=>{
  const a=assessLinkedEvidence(evidence({controlId:"UNRELATED"}),finding,date);
  expect(a.maySupportReview).toBe(false);
  expect(a.relationship).toBe("NO_EXACT_MATCH");
  expect(a.warnings.join(" ")).toContain("does not exactly match");
 });
 it("supports exact finding-key matches",()=>{
  const a=assessLinkedEvidence(evidence({controlId:"mfa-user"}),finding,date);
  expect(a.isExplicitMatch).toBe(true);
 });
 it("distinguishes observed, declared, unknown, error and other",()=>{
  for(const state of ["OBSERVED","DECLARED","UNKNOWN","ERROR","OTHER"]){
   const a=assessLinkedEvidence(evidence({state}),finding,date);
   expect(a.state).toBe(state);
   if(state!=="OBSERVED")expect(a.maySupportReview).toBe(false);
  }
  expect(normalizeEvidenceState("NOT_A_STATE")).toBe("OTHER");
 });
 it("requires timestamps for freshness",()=>{
  const a=assessLinkedEvidence(evidence({observedAt:null}),finding,date);
  expect(a.age).toBe("NOT_OBSERVED");
  expect(a.maySupportReview).toBe(false);
 });
 it("flags future observations instead of accepting them",()=>{
  const a=assessLinkedEvidence(evidence({observedAt:new Date("2027-01-01")}),finding,date);
  expect(a.age).toBe("FUTURE");
  expect(a.maySupportReview).toBe(false);
 });
 it("distinguishes recent, aging and stale timestamps",()=>{
  expect(assessLinkedEvidence(evidence({observedAt:new Date("2026-10-20")}),finding,date).age).toBe("RECENT");
  expect(assessLinkedEvidence(evidence({observedAt:new Date("2026-09-20")}),finding,date).age).toBe("AGING");
  expect(assessLinkedEvidence(evidence({observedAt:new Date("2026-01-20")}),finding,date).age).toBe("STALE");
 });
 it("warns when the finding is already resolved",()=>{
  const a=assessLinkedEvidence(evidence(),{...finding,status:"RESOLVED"},date);
  expect(a.warnings.join(" ")).toContain("resolved");
 });
 it("does not infer effectiveness from declared evidence",()=>{
  const a=assessLinkedEvidence(evidence({state:"DECLARED"}),finding,date);
  expect(a.warnings.join(" ")).toContain("not an independent observation");
 });
 it("identifies observations with error as inconclusive",()=>{
  const a=assessLinkedEvidence(evidence({state:"ERROR"}),finding,date);
  expect(a.maySupportReview).toBe(false);
  expect(a.warnings.join(" ")).toContain("error");
 });
 it("does not infer a control state from unknown observations",()=>{
  const a=assessLinkedEvidence(evidence({state:"UNKNOWN"}),finding,date);
  expect(a.maySupportReview).toBe(false);
  expect(a.warnings.join(" ")).toContain("did not determine");
 });
});
describe("candidate ordering and bounded selection",()=>{
 it("ranks exact matches before unrelated controls",()=>{
  const rows=[
   evidence({id:"unrelated123",controlId:"UNRELATED",observedAt:new Date("2026-10-31")}),
   evidence({id:"matched123",controlId:"MFA_ENABLED",observedAt:new Date("2026-10-01")})
  ];
  const sorted=evidenceCandidateSort(rows,finding);
  expect(sorted.map(x=>x.id)).toEqual(["matched123","unrelated123"]);
  expect(rows[0]?.id).toBe("unrelated123");
 });
 it("ranks newer observations within match groups",()=>{
  const sorted=evidenceCandidateSort([
   evidence({id:"old12345",observedAt:new Date("2026-01-01")}),
   evidence({id:"new12345",observedAt:new Date("2026-10-20")})
  ],finding);
  expect(sorted.map(x=>x.id)).toEqual(["new12345","old12345"]);
 });
 it("enforces a bound on active references",()=>{
  expect(()=>enforceLinkCapacity(49)).not.toThrow();
  expect(()=>enforceLinkCapacity(50)).toThrow(EvidenceLinkError);
  expect(()=>enforceLinkCapacity(100)).toThrow(EvidenceLinkError);
 });
});
describe("link summaries and exports",()=>{
 it("ignores detached references in active totals",()=>{
  const rows=[link(),link({
   id:"cllink456",evidenceId:"other123",unlinkedAt:new Date("2026-10-31"),
   evidence:evidence({id:"other123",state:"DECLARED"})
  })];
  expect(summarizeLinks(rows,finding,date)).toMatchObject({
   active:1,detached:1,exactMatches:1,recentObservedReferences:1,
   mismatched:0
  });
 });
 it("reports mismatched active observations",()=>{
  expect(summarizeLinks([link({evidence:evidence({controlId:"OTHER"})})],finding,date))
   .toMatchObject({active:1,mismatched:1,recentObservedReferences:0});
 });
 it("provides no false positive from an empty list",()=>{
  expect(summarizeLinks([],finding,date)).toMatchObject({
   active:0,detached:0,exactMatches:0,recentObservedReferences:0
  });
 });
 it("serializes date, scope, state, rationale and assessment separately",()=>{
  const fields=linkExportFields(link(),finding,date);
  expect(fields).toHaveLength(14);
  expect(fields[0]).toBe("clevidence123");
  expect(fields[3]).toBe("identity");
  expect(fields[5]).toBe("OBSERVED");
  expect(fields[10]).toBe("CONTROL_ID_MATCH");
  expect(fields[11]).toBe("RECENT");
 });
});
