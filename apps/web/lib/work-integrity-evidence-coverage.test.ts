import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  parseIntegrityEvidenceCoveragePolicy,
  evaluateIntegrityEvidenceCoverageEvents,
  compareIntegrityEvidenceCoverage,
} from "./work-integrity-evidence-coverage";
const captureId = "capture-one";
function link(auditId: string, caseKey: string, workItemId: string): IntegrityLinkHistoryEvent {
  return {
    auditId, originalAuditId: null, action: "LINK", captureId, caseKey,
    workItemId, actorUserId: "actor-one",
    occurredAt: "2026-11-01T00:00:00.000Z",
  };
}
const policy = {
  captureId,
  rules: [{
    id: "rule-one", caseKey: "case-one",
    minimumActiveWorkItems: 2,
    requiredWorkItemIds: ["work-one", "work-two"],
    requireDistinctActors: 1,
    forbidWithdrawnOnly: true,
  }],
};
describe("integrity evidence coverage", () => {
  it("rejects unknown policy keys", () => {
    expect(() => parseIntegrityEvidenceCoveragePolicy({
      ...policy, invented: true,
    })).toThrow();
  });
  it("rejects duplicate rules and contradictory bounds", () => {
    expect(() => parseIntegrityEvidenceCoveragePolicy({
      ...policy, rules: [policy.rules[0], policy.rules[0]],
    })).toThrow();
    expect(() => parseIntegrityEvidenceCoveragePolicy({
      ...policy, rules: [{ ...policy.rules[0], maximumActiveWorkItems: 1 }],
    })).toThrow();
  });
  it("reports missing required associations", () => {
    const result = evaluateIntegrityEvidenceCoverageEvents(
      captureId, [link("audit-one", "case-one", "work-one")],
      parseIntegrityEvidenceCoveragePolicy(policy),
    );
    expect(result.passed).toBe(false);
    expect(result.cases[0]?.missingWorkItemIds).toEqual(["work-two"]);
    expect(result.findings.map(x => x.code)).toContain("MISSING_REQUIRED_WORK");
  });
  it("passes after all required work is linked", () => {
    const result = evaluateIntegrityEvidenceCoverageEvents(
      captureId, [
        link("audit-one", "case-one", "work-one"),
        link("audit-two", "case-one", "work-two"),
      ], parseIntegrityEvidenceCoveragePolicy(policy),
    );
    expect(result.passed).toBe(true);
    expect(result.passingRules).toBe(1);
  });
  it("detects coverage regression after withdrawal", () => {
    const before = [
      link("audit-one", "case-one", "work-one"),
      link("audit-two", "case-one", "work-two"),
    ];
    const withdrawal: IntegrityLinkHistoryEvent = {
      ...before[1]!, auditId: "audit-three", originalAuditId: "audit-two",
      action: "UNLINK", occurredAt: "2026-11-02T00:00:00.000Z",
    };
    const parsed = parseIntegrityEvidenceCoveragePolicy(policy);
    const a = evaluateIntegrityEvidenceCoverageEvents(captureId, before, parsed);
    const b = evaluateIntegrityEvidenceCoverageEvents(
      captureId, [...before, withdrawal], parsed);
    const delta = compareIntegrityEvidenceCoverage(a, b);
    expect(delta.regressedCases).toEqual(["case-one"]);
    expect(delta.introducedFindings.length).toBeGreaterThan(0);
  });
  it("rejects cross-capture policy evaluations", () => {
    expect(() => evaluateIntegrityEvidenceCoverageEvents(
      captureId, [], parseIntegrityEvidenceCoveragePolicy({
        ...policy, captureId: "capture-two",
      }),
    )).toThrow();
  });
});
