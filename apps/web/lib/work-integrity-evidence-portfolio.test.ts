import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import {
  parseIntegrityEvidencePortfolioInput, parseIntegrityEvidencePortfolioQuery,
  buildIntegrityEvidencePortfolio, queryIntegrityEvidencePortfolio,
  compareIntegrityEvidencePortfolios, buildIntegrityPortfolioAtCheckpoints,
} from "./work-integrity-evidence-portfolio";
import {
  analyzeIntegrityPortfolioRisk, parseIntegrityPortfolioRiskWeights,
  parseIntegrityPortfolioRiskQuery, queryIntegrityPortfolioRisk,
  compareIntegrityPortfolioRisk,
} from "./work-integrity-portfolio-risk";
const captureId = "capture-one";
const t1 = "2026-11-01T00:00:00.000Z";
const t2 = "2026-11-02T00:00:00.000Z";
const t3 = "2026-11-03T00:00:00.000Z";
function link(auditId: string, caseKey: string, workItemId: string,
  occurredAt = t1): IntegrityLinkHistoryEvent {
  return {
    auditId, originalAuditId: null, action: "LINK", captureId,
    caseKey, workItemId, actorUserId: "actor-one", occurredAt,
  };
}
const first = link("audit-one", "case-one", "work-one");
const second = link("audit-two", "case-two", "work-two", t2);
const withdrawal: IntegrityLinkHistoryEvent = {
  ...first, auditId: "audit-three", originalAuditId: first.auditId,
  action: "UNLINK", occurredAt: t3,
};
const policy = parseIntegrityEvidenceCoveragePolicy({
  captureId, rules: [{
    id: "rule-one", caseKey: "case-one", minimumActiveWorkItems: 1,
    requiredWorkItemIds: ["work-one"],
  }],
});
const input = { captureId, policies: [policy] };
describe("integrity evidence portfolio", () => {
  it("validates capture scope", () => {
    expect(() => parseIntegrityEvidencePortfolioInput({
      captureId, policies: [{ ...policy, captureId: "capture-two" }],
    })).toThrow();
  });
  it("rejects unknown query fields", () => {
    expect(() => parseIntegrityEvidencePortfolioQuery({ mystery: true })).toThrow();
  });
  it("summarizes policy coverage and active dependencies", () => {
    const result = buildIntegrityEvidencePortfolio(input, [first, second]);
    expect(result.totals.cases).toBe(2);
    expect(result.totals.policyPasses).toBe(1);
    expect(result.totals.uncoveredCases).toBe(1);
    expect(result.cases.find(x => x.caseKey === "case-one")?.passing).toBe(true);
    expect(result.workItems.find(x => x.workItemId === "work-one")?.singlePointOfFailure)
      .toBe(true);
  });
  it("filters uncovered cases", () => {
    const portfolio = buildIntegrityEvidencePortfolio(input, [first, second]);
    const result = queryIntegrityEvidencePortfolio(portfolio, {
      states: ["UNCOVERED"], offset: 0, limit: 10,
    });
    expect(result.total).toBe(1);
    expect(result.cases[0]?.caseKey).toBe("case-two");
  });
  it("reports regressions after evidence withdrawal", () => {
    const before = buildIntegrityEvidencePortfolio(input, [first, second]);
    const after = buildIntegrityEvidencePortfolio(input, [first, second, withdrawal]);
    const delta = compareIntegrityEvidencePortfolios(before, after);
    expect(delta.regressedCases).toContain("case-one");
    expect(delta.noLongerActiveCases).toContain("case-one");
  });
  it("builds chronological portfolio snapshots", () => {
    const result = buildIntegrityPortfolioAtCheckpoints(
      input, [first, second, withdrawal], [t3, t1, t2]);
    expect(result.checkpoints).toEqual([t1, t2, t3]);
    expect(result.regressions).toBe(1);
    expect(result.lastPassing).toBe(false);
  });
  it("rejects duplicate checkpoints", () => {
    expect(() => buildIntegrityPortfolioAtCheckpoints(
      input, [first], [t1, t1])).toThrow();
  });
  it("scores missing coverage and critical dependencies", () => {
    const portfolio = buildIntegrityEvidencePortfolio(input, [first, second]);
    const risk = analyzeIntegrityPortfolioRisk(portfolio);
    expect(risk.cases).toHaveLength(2);
    expect(risk.workItems.find(x => x.workItemId === "work-one")?.singlePointOfFailure)
      .toBe(true);
  });
  it("detects risk regressions after withdrawal", () => {
    const before = analyzeIntegrityPortfolioRisk(
      buildIntegrityEvidencePortfolio(input, [first]));
    const after = analyzeIntegrityPortfolioRisk(
      buildIntegrityEvidencePortfolio(input, [first, withdrawal]));
    const delta = compareIntegrityPortfolioRisk(before, after);
    expect(delta.regressedCases).toContain("case-one");
  });
  it("supports bounded risk pagination", () => {
    const risk = analyzeIntegrityPortfolioRisk(
      buildIntegrityEvidencePortfolio(input, [first, second]));
    const query = parseIntegrityPortfolioRiskQuery({ limit: 1, offset: 0 });
    const page = queryIntegrityPortfolioRisk(risk, query);
    expect(page.cases).toHaveLength(1);
    expect(page.totalCases).toBe(2);
  });
  it("rejects invalid weights", () => {
    expect(() => parseIntegrityPortfolioRiskWeights({
      missingRequiredWork: -1,
    })).toThrow();
  });
});
