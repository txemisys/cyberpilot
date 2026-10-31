import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import {
  reconcileReviewReadiness, compareReconciliationReports,
  reconciliationActions, reconciliationCsv, reconciliationJson,
  snapshotReconciliationDiff,
} from "./work-integrity-reconciliation";
const makeRow = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const policy = {
  recipients: [{ id: "analyst", capacity: 5, codes: [] as string[], workItemIds: [] as string[] }],
  includeReviewed: true, includeHistorical: true,
  requireCompleteCoverage: false, allowUnassigned: true,
};
const requirements = [{
  id: "review", diagnosticCodes: [] as string[],
  mandatoryFields: ["reviewEventId", "reviewRationale"] as Array<"reviewEventId" | "reviewRationale">,
  requireCurrentRevision: true, requireCompleteCoverage: true,
  requireHumanReview: true,
}];
const capture = (rows: CaseRow[], complete = true, at = "2026-10-31T10:00:00.000Z") =>
  parseCaseSnapshot({ organizationId: "org-a", source: "offline", capturedAt: at,
    complete, cases: rows });
const reviewed = makeRow("reviewed", {
  state: "ACKNOWLEDGED", reviewEventId: "audit-1", reviewRationale: "Inspected",
  reviewedRevision: 1,
});
const missing = makeRow("missing");
const partial = makeRow("partial", { completeCoverage: false });
const historical = makeRow("historical", { historicalOnly: true });
describe("review and evidence reconciliation", () => {
  const source = capture([reviewed, missing, partial, historical]);
  const report = reconcileReviewReadiness(source, policy, requirements);
  it("preserves tenant scope", () => expect(report.organizationId).toBe("org-a"));
  it("includes all cases", () => expect(report.total).toBe(4));
  it("counts capacity-limited assignments", () => {
    expect(report.unassigned).toBe(0);
  });
  it("identifies ready and assigned cases", () => {
    expect(report.rows.find(row => row.caseKey === reviewed.key)?.status).toBe("READY_ASSIGNED");
  });
  it("identifies blocked assigned cases", () => {
    expect(report.byStatus.BLOCKED_ASSIGNED).toBeGreaterThan(0);
  });
  it("identifies incomplete linked data", () => {
    expect(report.rows.find(row => row.caseKey === partial.key)?.status).toBe("INDETERMINATE");
  });
  it("includes evidence field gaps", () => {
    expect(report.rows.find(row => row.caseKey === missing.key)?.missingFields).toContain("humanReview");
  });
  it("does not claim control verification", () => {
    expect(report.warnings.some(warning => warning.includes("not resolved"))).toBe(true);
  });
  it("includes recollection action", () => {
    expect(reconciliationActions(report).some(action => action.action === "RECOLLECT")).toBe(true);
  });
  it("includes evidence completion action", () => {
    expect(reconciliationActions(report).some(action => action.action === "COMPLETE_EVIDENCE")).toBe(true);
  });
  it("includes assignment action", () => {
    expect(reconciliationActions(reconcileReviewReadiness(source, { ...policy, recipients: [{ ...policy.recipients[0]!, capacity: 1 }] }, requirements)).some(action => action.action === "ASSIGN_REVIEWER")).toBe(true);
  });
  it("includes review action", () => {
    expect(reconciliationActions(report).some(action => action.action === "REVIEW")).toBe(true);
  });
  it("serializes JSON", () => {
    expect(JSON.parse(reconciliationJson(report)).version).toBe(1);
  });
  it("serializes CSV", () => {
    expect(reconciliationCsv(report)).toContain("\r\n");
  });
  it("neutralizes spreadsheet formulas", () => {
    const injection = makeRow("=HYPERLINK");
    const csv = reconciliationCsv(reconcileReviewReadiness(capture([injection]), policy, requirements));
    expect(csv).toContain("'=HYPERLINK");
  });
  it("marks incomplete capture indeterminate", () => {
    const partialSource = capture([reviewed], false);
    expect(reconcileReviewReadiness(partialSource, policy, requirements).byStatus.INDETERMINATE).toBe(1);
  });
});
describe("reconciliation drift", () => {
  const old = reconcileReviewReadiness(capture([missing]), policy, requirements);
  const later = reconcileReviewReadiness(capture([reviewed], true, "2026-10-31T11:00:00.000Z"), policy, requirements);
  it("rejects cross-tenant reports", () => {
    expect(() => compareReconciliationReports(old, { ...later, organizationId: "other" })).toThrow();
  });
  it("does not invent readiness changes for different cases", () => {
    expect(compareReconciliationReports(old, later).newlyReady).toEqual([]);
  });
  it("recognizes improved evidence for same case", () => {
    const updated = makeRow("missing", {
      reviewEventId: "audit-2", reviewedRevision: 1,
      reviewRationale: "Verified metadata",
    });
    const next = reconcileReviewReadiness(capture([updated], true,
      "2026-10-31T11:00:00.000Z"), policy, requirements);
    expect(compareReconciliationReports(old, next).newlyReady).toContain(missing.key);
  });
  it("recognizes lost evidence readiness", () => {
    const before = reconcileReviewReadiness(capture([reviewed]), policy, requirements);
    const after = reconcileReviewReadiness(capture([makeRow("reviewed")], true,
      "2026-10-31T11:00:00.000Z"), policy, requirements);
    expect(compareReconciliationReports(before, after).newlyBlocked).toContain(reviewed.key);
  });
  it("marks incomplete disappearance uncertain", () => {
    const before = reconcileReviewReadiness(capture([missing]), policy, requirements);
    const after = reconcileReviewReadiness(capture([], false,
      "2026-10-31T11:00:00.000Z"), policy, requirements);
    expect(compareReconciliationReports(before, after).uncertain).toContain(missing.key);
  });
  it("compares diagnostics and reconciliation together", () => {
    const before = capture([missing]);
    const after = capture([reviewed], true, "2026-10-31T11:00:00.000Z");
    const result = snapshotReconciliationDiff(before, after, policy, requirements);
    expect(result.diagnosticChanges.counts.NEW).toBe(1);
    expect(result.currentActions.length).toBeGreaterThan(0);
  });
});
