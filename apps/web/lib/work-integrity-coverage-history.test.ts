import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import {
  parseIntegrityCoverageCheckpoints, buildIntegrityCoverageHistory,
  summarizeIntegrityCoverageHistory, latestIntegrityCoverageSnapshot,
  coverageHistoryFromEvents,
} from "./work-integrity-coverage-history";
const captureId = "capture-one";
const t0 = "2026-11-01T00:00:00.000Z";
const t1 = "2026-11-02T00:00:00.000Z";
const t2 = "2026-11-03T00:00:00.000Z";
const t3 = "2026-11-04T00:00:00.000Z";
const policy = parseIntegrityEvidenceCoveragePolicy({
  captureId, rules: [{
    id: "coverage-one", caseKey: "case-one", minimumActiveWorkItems: 1,
    requiredWorkItemIds: ["work-one"],
  }],
});
const linked: IntegrityLinkHistoryEvent = {
  auditId: "audit-one", originalAuditId: null, action: "LINK",
  captureId, caseKey: "case-one", workItemId: "work-one",
  actorUserId: "actor-one", occurredAt: t1,
};
const withdrawn: IntegrityLinkHistoryEvent = {
  ...linked, auditId: "audit-two", originalAuditId: "audit-one",
  action: "UNLINK", occurredAt: t2,
};
describe("integrity coverage history", () => {
  it("rejects empty checkpoints", () => {
    expect(() => parseIntegrityCoverageCheckpoints([])).toThrow();
  });
  it("rejects duplicate checkpoints", () => {
    expect(() => parseIntegrityCoverageCheckpoints([t1, t1])).toThrow();
  });
  it("rejects invalid timestamps", () => {
    expect(() => parseIntegrityCoverageCheckpoints(["2026-02-30T00:00:00.000Z"]))
      .toThrow();
  });
  it("orders checkpoints chronologically", () => {
    expect(parseIntegrityCoverageCheckpoints([t3, t1, t0, t2]))
      .toEqual([t0, t1, t2, t3]);
  });
  it("tracks improvements and regressions after withdrawal", () => {
    const history = buildIntegrityCoverageHistory(
      captureId, [linked, withdrawn], policy, [t0, t1, t2, t3]);
    expect(history.checkpoints.map(x => x.report.passed))
      .toEqual([false, true, false, false]);
    expect(history.casesEverImproved).toEqual(["case-one"]);
    expect(history.casesEverRegressed).toEqual(["case-one"]);
    expect(history.firstPassingAt).toBe(t1);
    expect(history.currentlyPassing).toBe(false);
  });
  it("computes transitions without counting a withdrawal as a new link", () => {
    const history = buildIntegrityCoverageHistory(
      captureId, [linked, withdrawn], policy, [t0, t1, t2]);
    expect(history.transitions[0]?.addedAssociations).toBe(1);
    expect(history.transitions[1]?.addedAssociations).toBe(0);
    expect(history.transitions[1]?.withdrawnAssociations).toBe(1);
  });
  it("computes per-case passing and failing streaks", () => {
    const history = buildIntegrityCoverageHistory(
      captureId, [linked, withdrawn], policy, [t0, t1, t2, t3]);
    const metrics = summarizeIntegrityCoverageHistory(history);
    expect(metrics.passingCheckpoints).toBe(1);
    expect(metrics.failingCheckpoints).toBe(3);
    expect(metrics.cases[0]?.longestFailingStreak).toBe(2);
    expect(metrics.cases[0]?.longestPassingStreak).toBe(1);
    expect(metrics.regressionCount).toBe(1);
    expect(metrics.improvementCount).toBe(1);
  });
  it("provides a single snapshot with audit findings", () => {
    const snapshot = latestIntegrityCoverageSnapshot(
      captureId, [linked], policy, t1);
    expect(snapshot.report.passed).toBe(true);
    expect(snapshot.activeAssociations).toBe(1);
    expect(snapshot.auditErrors).toBe(0);
  });
  it("exposes audit totals alongside history", () => {
    const result = coverageHistoryFromEvents(
      captureId, [linked, withdrawn], policy, [t0, t1, t2]);
    expect(result.totalAuditEvents).toBe(2);
    expect(result.auditSummary.withdrawn).toBe(1);
    expect(result.metrics.checkpointCount).toBe(3);
  });
  it("rejects mismatched policy capture", () => {
    expect(() => buildIntegrityCoverageHistory(
      "capture-other", [], policy, [t1])).toThrow();
  });
});
