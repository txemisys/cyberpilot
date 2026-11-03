import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import {
  planIntegrityRemediationFromEvents,
  parseIntegrityRemediationPlanQuery,
  queryIntegrityRemediationPlan,
  compareIntegrityRemediationPlans,
} from "./work-integrity-remediation-plan";
import {
  buildIntegrityRemediationHistory,
  summarizeIntegrityRemediationHistory,
  queryIntegrityRemediationHistory,
} from "./work-integrity-remediation-history";
import {
  summarizeIntegrityRemediationWorkload,
  parseIntegrityRemediationCapacity,
  allocateIntegrityRemediationCapacity,
} from "./work-integrity-remediation-capacity";

const captureId = "capture-one";
const t1 = "2026-11-01T00:00:00.000Z";
const t2 = "2026-11-02T00:00:00.000Z";
const t3 = "2026-11-03T00:00:00.000Z";
const link: IntegrityLinkHistoryEvent = {
  auditId: "audit-one", originalAuditId: null,
  action: "LINK", captureId, caseKey: "case-one",
  workItemId: "work-one", actorUserId: "actor-one", occurredAt: t2,
};
const withdrawn: IntegrityLinkHistoryEvent = {
  ...link, auditId: "audit-two", originalAuditId: "audit-one",
  action: "UNLINK", occurredAt: t3,
};
const input = {
  captureId, policies: [parseIntegrityEvidenceCoveragePolicy({
    captureId, rules: [{
      id: "rule-one", caseKey: "case-one",
      minimumActiveWorkItems: 1, requiredWorkItemIds: ["work-one"],
    }],
  })],
};
describe("integrity remediation planning", () => {
  it("prioritizes missing required work", () => {
    const { plan } = planIntegrityRemediationFromEvents(input, []);
    expect(plan.candidates.some(x => x.action === "LINK_REQUIRED_WORK")).toBe(true);
  });
  it("flags withdrawn work for review instead of automatic execution", () => {
    const { plan } = planIntegrityRemediationFromEvents(input, [link, withdrawn]);
    const row = plan.candidates.find(x => x.action === "RELINK_WITHDRAWN_WORK");
    expect(row?.executable).toBe(false);
    expect(row?.blockedBy).toContain("REVIEW_WITHDRAWAL_HISTORY");
  });
  it("resolves missing work after linking", () => {
    const before = planIntegrityRemediationFromEvents(input, []).plan;
    const after = planIntegrityRemediationFromEvents(input, [link]).plan;
    const delta = compareIntegrityRemediationPlans(before, after);
    expect(delta.removed.some(x => x.action === "LINK_REQUIRED_WORK")).toBe(true);
  });
  it("paginates remediation candidates", () => {
    const { plan } = planIntegrityRemediationFromEvents(input, []);
    const query = parseIntegrityRemediationPlanQuery({ limit: 1 });
    expect(queryIntegrityRemediationPlan(plan, query).candidates).toHaveLength(1);
  });
  it("tracks candidate introduction and resolution", () => {
    const history = buildIntegrityRemediationHistory(
      input, [link, withdrawn], [t1, t2, t3]);
    expect(history.checkpoints).toHaveLength(3);
    expect(history.transitions).toHaveLength(2);
    expect(history.totals.candidateResolutions).toBeGreaterThan(0);
  });
  it("filters historical remediation trends", () => {
    const history = buildIntegrityRemediationHistory(
      input, [link, withdrawn], [t1, t2, t3]);
    const page = queryIntegrityRemediationHistory(history, {
      currentOnly: true, offset: 0, limit: 100,
    });
    expect(page.trends.every(x => x.current)).toBe(true);
  });
  it("summarizes remediation trends", () => {
    const history = buildIntegrityRemediationHistory(
      input, [link, withdrawn], [t1, t2, t3]);
    const summary = summarizeIntegrityRemediationHistory(history);
    expect(summary.totals.checkpointCount).toBe(3);
    expect(summary.actions.length).toBeGreaterThan(0);
  });
  it("reports workload grouped by case and action", () => {
    const { plan } = planIntegrityRemediationFromEvents(input, []);
    const workload = summarizeIntegrityRemediationWorkload(plan);
    expect(workload.byCase[0]?.group).toBe("case-one");
    expect(workload.totals.candidates).toBe(plan.candidates.length);
  });
  it("allocates review capacity without exceeding constraints", () => {
    const { plan } = planIntegrityRemediationFromEvents(input, []);
    const capacity = parseIntegrityRemediationCapacity({
      maximumCandidates: 1, maximumUrgent: 1, maximumRiskPoints: 100,
    });
    const result = allocateIntegrityRemediationCapacity(plan, capacity);
    expect(result.selected.length).toBeLessThanOrEqual(1);
    expect(result.selectedRiskPoints).toBeLessThanOrEqual(100);
  });
  it("rejects invalid capacity", () => {
    expect(() => parseIntegrityRemediationCapacity({
      maximumCandidates: -1, maximumUrgent: 1, maximumRiskPoints: 100,
    })).toThrow();
  });
});
