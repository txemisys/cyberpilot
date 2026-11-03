import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, filterIntegrityAssociations, paginateIntegrityAssociations,
  buildIntegrityReviewMatrix, diffIntegrityReviews,
} from "./work-integrity-link-review";
import {
  parseIntegrityPlanRequest, planIntegrityLinkOperations, previewIntegrityPlan,
  partitionIntegrityPlan, summarizeIntegrityExecution,
  buildIntegrityPlanFromPairs, buildIntegrityWithdrawalPlan,
} from "./work-integrity-link-plan";

const created = "2026-11-01T10:00:00.000Z";
const withdrawn = "2026-11-02T10:00:00.000Z";
function link(
  auditId: string, caseKey = "case-one", workItemId = "work-one",
): IntegrityLinkHistoryEvent {
  return {
    auditId, action: "LINK", originalAuditId: null,
    captureId: "capture-one", caseKey, workItemId,
    actorUserId: "user-one", occurredAt: created,
  };
}
function unlink(auditId: string, originalAuditId: string): IntegrityLinkHistoryEvent {
  return {
    ...link(auditId), action: "UNLINK", originalAuditId,
    occurredAt: withdrawn, actorUserId: "user-two",
  };
}
describe("integrity review and bulk planning", () => {
  it("reconstructs active and withdrawn associations from unsorted events", () => {
    const report = reviewIntegrityLinks("capture-one", [
      unlink("withdrawal-one", "audit-one"),
      link("audit-two", "case-two"), link("audit-one"),
    ]);
    expect(report.counts).toMatchObject({
      active: 1, withdrawn: 1, errors: 0,
    });
    expect(report.associations.find(x => x.auditId === "audit-one"))
      .toMatchObject({
        state: "WITHDRAWN", withdrawalAuditId: "withdrawal-one",
        withdrawnBy: "user-two",
      });
  });
  it("flags orphan withdrawals without dropping history", () => {
    const report = reviewIntegrityLinks("capture-one", [
      unlink("withdrawal-one", "missing-original"),
    ]);
    expect(report.counts.orphanWithdrawals).toBe(1);
    expect(report.findings[0]?.code).toBe("ORPHAN_WITHDRAWAL");
    expect(report.totalEvents).toBe(1);
  });
  it("flags repeated withdrawals for one original", () => {
    const report = reviewIntegrityLinks("capture-one", [
      link("audit-one"), unlink("withdrawal-one", "audit-one"),
      unlink("withdrawal-two", "audit-one"),
    ]);
    expect(report.counts.duplicateWithdrawals).toBe(1);
    expect(report.counts.withdrawn).toBe(1);
  });
  it("detects cross-case withdrawal identity mismatch", () => {
    const wrong = { ...unlink("withdrawal-one", "audit-one"), caseKey: "wrong-case" };
    const report = reviewIntegrityLinks("capture-one", [link("audit-one"), wrong]);
    expect(report.findings.map(x => x.code)).toContain("MISMATCHED_WITHDRAWAL");
  });
  it("rejects cross-capture events rather than mixing tenants", () => {
    expect(() => reviewIntegrityLinks("capture-one", [{
      ...link("audit-one"), captureId: "capture-other",
    }])).toThrow("Cross-capture");
  });
  it("detects duplicate audit identifiers", () => {
    const report = reviewIntegrityLinks("capture-one", [
      link("audit-one"), link("audit-one"),
    ]);
    expect(report.findings.map(x => x.code)).toContain("DUPLICATE_AUDIT_ID");
  });
  it("flags repeated active associations without merging audit records", () => {
    const report = reviewIntegrityLinks("capture-one", [
      link("audit-one"), link("audit-two"),
    ]);
    expect(report.counts.active).toBe(2);
    expect(report.counts.warnings).toBe(1);
  });
  it("filters associations and paginates deterministically", () => {
    const report = reviewIntegrityLinks("capture-one", [
      link("audit-one"), link("audit-two", "case-two"),
    ]);
    const filtered = filterIntegrityAssociations(report.associations, {
      caseKey: "case-two", state: "ACTIVE",
    });
    expect(paginateIntegrityAssociations(filtered, 0, 1))
      .toMatchObject({ total: 1, hasMore: false });
    expect(() => paginateIntegrityAssociations(filtered, -1)).toThrow();
  });
  it("builds a chronological trend and case/work matrix", () => {
    const report = reviewIntegrityLinks("capture-one", [
      link("audit-one"), unlink("withdrawal-one", "audit-one"),
    ]);
    const matrix = buildIntegrityReviewMatrix(report);
    expect(matrix.trends.map(x => x.activeAtEnd)).toEqual([1, 0]);
    expect(matrix.cases[0]?.withdrawn).toBe(1);
    expect(matrix.workItems[0]?.active).toBe(0);
    expect(matrix.actors.map(x => x.actorUserId))
      .toEqual(["user-one", "user-two"]);
  });
  it("diffs append-only histories and detects withdrawn links", () => {
    const before = reviewIntegrityLinks("capture-one", [link("audit-one")]);
    const after = reviewIntegrityLinks("capture-one", [
      link("audit-one"), unlink("withdrawal-one", "audit-one"),
    ]);
    expect(diffIntegrityReviews(before, after))
      .toMatchObject({ added: 0, withdrawn: 1, unchanged: 0 });
    expect(() => diffIntegrityReviews(after, before)).toThrow();
  });
  it("parses valid mixed bulk plans", () => {
    const request = parseIntegrityPlanRequest({
      captureId: "capture-one",
      operations: [
        { operationId: "operation-one", action: "LINK",
          caseKey: "case-two", workItemId: "work-two" },
        { operationId: "operation-two", action: "UNLINK", auditId: "audit-one" },
      ],
    });
    expect(request.operations).toHaveLength(2);
  });
  it.each([
    {}, { captureId: "capture-one", operations: [] },
    { captureId: "capture-one", operations: [{ operationId: "op-one", action: "BAD" }] },
    { captureId: "capture-one", operations: [{
      operationId: "operation-one", action: "UNLINK",
      auditId: "audit-one", caseKey: "case-one",
    }] },
    { captureId: "capture-one", operations: [{
      operationId: "operation-one", action: "LINK",
      caseKey: "case-one", workItemId: "work-one", auditId: "audit-one",
    }] },
  ])("rejects malformed planning input %j", input => {
    expect(() => parseIntegrityPlanRequest(input)).toThrow();
  });
  it("skips existing associations and plans new ones", () => {
    const request = buildIntegrityPlanFromPairs("capture-one", [
      { caseKey: "case-one", workItemId: "work-one" },
      { caseKey: "case-two", workItemId: "work-two" },
    ]);
    const plan = planIntegrityLinkOperations(request, [link("audit-one")]);
    expect(plan.totals).toMatchObject({
      requested: 2, ready: 1, skipped: 1, rejected: 0,
    });
    expect(partitionIntegrityPlan(plan).readyLinks).toHaveLength(1);
  });
  it("prevents withdrawal of an already withdrawn association", () => {
    const events = [link("audit-one"), unlink("withdrawal-one", "audit-one")];
    const request = buildIntegrityWithdrawalPlan("capture-one", ["audit-one"]);
    const plan = planIntegrityLinkOperations(request, events);
    expect(plan.decisions[0]?.code).toBe("ALREADY_WITHDRAWN");
  });
  it("rejects stale history before considering operations", () => {
    const request = buildIntegrityWithdrawalPlan("capture-one", ["audit-one"], 0);
    const plan = planIntegrityLinkOperations(request, [link("audit-one")]);
    expect(plan.decisions[0]?.code).toBe("STALE_HISTORY");
    expect(plan.executable).toBe(false);
  });
  it("previews expected active and withdrawn totals", () => {
    const events = [link("audit-one")];
    const request = buildIntegrityWithdrawalPlan("capture-one", ["audit-one"]);
    const plan = planIntegrityLinkOperations(request, events);
    const preview = previewIntegrityPlan(reviewIntegrityLinks("capture-one", events), plan);
    expect(preview.after).toEqual({ active: 0, withdrawn: 1 });
    expect(preview.cases[0]?.delta).toBe(-1);
  });
  it("validates execution reports against the planned operations", () => {
    const plan = planIntegrityLinkOperations(
      buildIntegrityWithdrawalPlan("capture-one", ["audit-one"]),
      [link("audit-one")],
    );
    const outcome = {
      operationId: "operation-1", status: "APPLIED" as const,
      auditId: "withdrawal-one", errorCode: null, message: null,
    };
    expect(summarizeIntegrityExecution(plan, [outcome]).applied).toBe(1);
    expect(() => summarizeIntegrityExecution(plan, [])).toThrow();
  });
});
