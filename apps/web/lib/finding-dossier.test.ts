import {describe,expect,it} from "vitest";
import {
 buildFindingDossier,buildPortfolioDossier,serializeFindingDossier,
 serializePortfolioDossier,
} from "./finding-dossier";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";

const d=(day:string)=>new Date(day+"T12:00:00Z");
const action=(status:string):ReviewAction=>({
 id:"a1",title:"Require MFA",status,mode:"GUIDED",
 createdAt:d("2026-01-01"),approvedAt:d("2026-01-02"),
 startedAt:d("2026-01-03"),completedAt:d("2026-01-04"),
 verifiedAt:status==="VERIFIED"?d("2026-01-06"):null,
 steps:["Configure MFA","Test account"],
 verification:["Confirm fresh identity signal"],
 acknowledgedSteps:new Set([0,1]),
});
const observed=(source:ReviewEvidence["source"]):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",
 summary:"Identity control",capturedAt:d("2026-01-02"),
 lastObservedAt:source==="OBSERVED"?d("2026-01-02"):null,
});
const finding=(options:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"f1",title:"Administrator MFA disabled",
 description:"Privileged account is not protected.",
 severity:"CRITICAL",status:"OPEN",
 firstSeenAt:d("2026-01-01"),lastSeenAt:d("2026-01-03"),resolvedAt:null,
 evidence:[],actions:[],...options,
});
describe("Comprehensive evidence dossier",()=>{
 it("provides a consolidated view of an unaddressed finding",()=>{
  const result=buildFindingDossier(finding());
  expect(result.findingId).toBe("f1");
  expect(result.observed).toBe(0);
  expect(result.remediations).toBe(0);
  expect(result.verifiedRemediations).toBe(0);
  expect(result.sections.map(s=>s.heading)).toEqual([
   "Evidence and provenance","Remediation activity",
   "Remaining verification tasks","Chronology",
  ]);
 });
 it("never treats declared evidence as observed",()=>{
  const dossier=buildFindingDossier(finding({
   evidence:[observed("DECLARED")],
  }));
  expect(dossier.observed).toBe(0);
  expect(dossier.declared).toBe(1);
  expect(dossier.assurance).toBe("declaration-only");
 });
 it("does not treat acknowledged work as verified remediation",()=>{
  const dossier=buildFindingDossier(finding({
   actions:[action("APPROVED")],
  }));
  expect(dossier.remediations).toBe(1);
  expect(dossier.verifiedRemediations).toBe(0);
  expect(dossier.assessment).toBe("ready-for-check");
  expect(dossier.sections.find(s=>s.heading==="Remediation activity")
   ?.statements.join(" ")).toContain("2 / 2");
 });
 it("distinguishes action verification from open finding status",()=>{
  const dossier=buildFindingDossier(finding({
   actions:[action("VERIFIED")],
  }));
  expect(dossier.verifiedRemediations).toBe(1);
  expect(dossier.findingStatus).toBe("OPEN");
  expect(dossier.warnings.join(" ")).toContain("remains open");
 });
 it("recognizes observations predating completed work",()=>{
  const dossier=buildFindingDossier(finding({
   evidence:[observed("OBSERVED")],actions:[action("SUCCEEDED")],
  }));
  expect(dossier.latestEvidenceAt).toEqual(d("2026-01-02"));
  expect(dossier.latestWorkAt).toEqual(d("2026-01-04"));
  expect(dossier.warnings.join(" ")).toContain("predates");
 });
 it("deduplicates repeated provenance limitations",()=>{
  const dossier=buildFindingDossier(finding({
   evidence:[observed("DECLARED")],
   actions:[action("SUCCEEDED")],
  }));
  expect(new Set(dossier.warnings).size).toBe(dossier.warnings.length);
 });
 it("reports portfolio counts separately for verification and resolution",()=>{
  const portfolio=buildPortfolioDossier([
   finding({id:"a",actions:[action("VERIFIED")]}),
   finding({id:"b",status:"RESOLVED",resolvedAt:d("2026-01-09")}),
   finding({id:"c",evidence:[observed("OBSERVED")]}),
  ]);
  expect(portfolio.total).toBe(3);
  expect(portfolio.open).toBe(2);
  expect(portfolio.resolved).toBe(1);
  expect(portfolio.withVerifiedRemediation).toBe(1);
  expect(portfolio.withObserved).toBe(1);
  expect(portfolio.withoutMatchedEvidence).toBe(2);
 });
 it("sorts by finding severity without changing original records",()=>{
  const input=[
   finding({id:"low",severity:"LOW"}),
   finding({id:"critical",severity:"CRITICAL"}),
  ];
  const before=input.map(item=>item.id);
  const portfolio=buildPortfolioDossier(input);
  expect(portfolio.findings.map(item=>item.findingId))
   .toEqual(["critical","low"]);
  expect(input.map(item=>item.id)).toEqual(before);
 });
 it("generates a complete text dossier with verification requirements",()=>{
  const dossier=buildFindingDossier(finding({
   actions:[action("SUCCEEDED")],
  }));
  const text=serializeFindingDossier(dossier);
  expect(text).toContain("SECURITY FINDING EVIDENCE DOSSIER");
  expect(text).toContain("Remaining verification tasks".toUpperCase());
  expect(text).toContain("Confirm fresh identity signal");
  expect(text).toContain("does not change the underlying finding");
 });
 it("generates a portfolio report without exposing raw evidence JSON",()=>{
  const portfolio=buildPortfolioDossier([finding({
   evidence:[{...observed("DECLARED"),summary:"opaque-source"}],
  })]);
  const text=serializePortfolioDossier(portfolio);
  expect(text).toContain("ORGANIZATION SECURITY EVIDENCE DOSSIER");
  expect(text).not.toContain("opaque-source");
  expect(text).toContain("not proof of compliance");
 });
 it("creates a usable empty portfolio summary",()=>{
  const portfolio=buildPortfolioDossier([]);
  expect(portfolio.total).toBe(0);
  expect(serializePortfolioDossier(portfolio)).toContain("Findings: 0");
 });
});
