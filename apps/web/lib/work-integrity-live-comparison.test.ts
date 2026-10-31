import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import {
  validateComparisonInput, compareIntegrityCaptures, integrityComparisonCsv,
} from "./work-integrity-live-comparison";

const beforeTime = "2026-10-30T10:00:00.000Z";
const afterTime = "2026-10-31T10:00:00.000Z";
const row = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 2, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const snapshot = (
  cases: CaseRow[], capturedAt: string, complete = true,
  organizationId = "org-a",
) => ({
  organizationId, capturedAt, complete,
  source: "test-capture", cases,
});
const payload = (
  oldCases: CaseRow[], newCases: CaseRow[],
  oldComplete = true, newComplete = true,
) => ({
  before: snapshot(oldCases, beforeTime, oldComplete),
  after: snapshot(newCases, afterTime, newComplete),
});
describe("trusted snapshot comparison boundary", () => {
  it("accepts valid tenant-matched snapshots", () => {
    const result = validateComparisonInput(payload([], []), "org-a");
    expect(result.before.organizationId).toBe("org-a");
  });
  it("rejects missing body", () => {
    expect(() => validateComparisonInput(null, "org-a")).toThrow();
  });
  it("rejects array body", () => {
    expect(() => validateComparisonInput([], "org-a")).toThrow();
  });
  it("rejects missing before capture", () => {
    expect(() => validateComparisonInput({ after: snapshot([], afterTime) }, "org-a")).toThrow();
  });
  it("rejects missing after capture", () => {
    expect(() => validateComparisonInput({ before: snapshot([], beforeTime) }, "org-a")).toThrow();
  });
  it("rejects invalid trusted tenant", () => {
    expect(() => validateComparisonInput(payload([], []), "")).toThrow();
  });
  it("rejects foreign before tenant", () => {
    const data = payload([], []);
    data.before.organizationId = "org-b";
    expect(() => validateComparisonInput(data, "org-a")).toThrow();
  });
  it("rejects foreign after tenant", () => {
    const data = payload([], []);
    data.after.organizationId = "org-b";
    expect(() => validateComparisonInput(data, "org-a")).toThrow();
  });
  it("rejects a forged tenant even if both snapshots agree", () => {
    const data = payload([], []);
    data.before.organizationId = "org-b";
    data.after.organizationId = "org-b";
    expect(() => validateComparisonInput(data, "org-a")).toThrow();
  });
  it("rejects reverse chronology", () => {
    const data = payload([], []);
    data.before.capturedAt = afterTime;
    data.after.capturedAt = beforeTime;
    expect(() => validateComparisonInput(data, "org-a")).toThrow();
  });
  it("accepts equal capture timestamps", () => {
    const data = payload([], []);
    data.before.capturedAt = afterTime;
    expect(validateComparisonInput(data, "org-a").after.capturedAt).toBe(afterTime);
  });
  it("rejects zero case limit", () => {
    expect(() => validateComparisonInput(payload([], []), "org-a", 0)).toThrow();
  });
  it("rejects excessive case limit", () => {
    expect(() => validateComparisonInput(payload([], []), "org-a", 10001)).toThrow();
  });
  it("rejects fractional case limit", () => {
    expect(() => validateComparisonInput(payload([], []), "org-a", 1.5)).toThrow();
  });
  it("rejects cases beyond configured limit", () => {
    expect(() => validateComparisonInput(payload([row("a"), row("b")], []),
      "org-a", 1)).toThrow();
  });
  it("rejects duplicate identities in one capture", () => {
    expect(() => validateComparisonInput(payload([row("a"), row("a")], []),
      "org-a")).toThrow();
  });
  it("rejects malformed case keys", () => {
    expect(() => validateComparisonInput(payload([{ ...row("a"), key: "bad" }], []),
      "org-a")).toThrow();
  });
  it("rejects invalid revision", () => {
    expect(() => validateComparisonInput(payload([{ ...row("a"), taskRevision: 0 }], []),
      "org-a")).toThrow();
  });
  it("rejects invalid capturedAt", () => {
    const data = payload([], []);
    data.after.capturedAt = "not-a-date";
    expect(() => validateComparisonInput(data, "org-a")).toThrow();
  });
});
describe("integrated case delta comparison", () => {
  it("reports no changes on identical empty captures", () => {
    const report = compareIntegrityCaptures(payload([], []), "org-a");
    expect(report.changes).toHaveLength(0);
    expect(report.complete).toBe(true);
  });
  it("identifies new cases", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(report.counts.NEW).toBe(1);
  });
  it("identifies cleared cases", () => {
    const report = compareIntegrityCaptures(payload([row("a")], []), "org-a");
    expect(report.counts.CLEARED).toBe(1);
  });
  it("identifies unchanged cases", () => {
    const report = compareIntegrityCaptures(payload([row("a")], [row("a")]), "org-a");
    expect(report.counts.UNCHANGED).toBe(1);
    expect(report.changes).toHaveLength(0);
  });
  it("identifies modified case state", () => {
    const report = compareIntegrityCaptures(payload(
      [row("a")], [row("a", { state: "INVESTIGATING" })],
    ), "org-a");
    expect(report.counts.CHANGED).toBe(1);
    expect(report.changes[0]?.fields).toContain("state");
  });
  it("identifies revision changes", () => {
    const report = compareIntegrityCaptures(payload(
      [row("a")], [row("a", { taskRevision: 3 })],
    ), "org-a");
    expect(report.changes[0]?.fields).toContain("taskRevision");
  });
  it("does not claim a new case from incomplete capture", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")], false),
      "org-a");
    expect(report.counts.INDETERMINATE).toBe(1);
    expect(report.counts.NEW).toBe(0);
  });
  it("does not claim cleared cases from incomplete capture", () => {
    const report = compareIntegrityCaptures(payload([row("a")], [], true, false),
      "org-a");
    expect(report.counts.INDETERMINATE).toBe(1);
    expect(report.counts.CLEARED).toBe(0);
  });
  it("preserves uncertainty in change records", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")], false),
      "org-a");
    expect(report.changes[0]?.uncertain).toBe(true);
  });
  it("reports evidence readiness before and after", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: afterTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    const report = compareIntegrityCaptures(payload([row("a")], [ready]), "org-a");
    expect(report.evidence.beforeBlocked).toBe(1);
    expect(report.evidence.afterReady).toBe(1);
  });
  it("identifies newly ready evidence", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: afterTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    const report = compareIntegrityCaptures(payload([row("a")], [ready]), "org-a");
    expect(report.evidence.newlyReady).toBe(1);
  });
  it("identifies newly blocked evidence", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: beforeTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    const report = compareIntegrityCaptures(payload([ready], [row("a")]), "org-a");
    expect(report.evidence.newlyBlocked).toBe(1);
  });
  it("does not report newly ready when comparison is uncertain", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: afterTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    const report = compareIntegrityCaptures(payload(
      [row("a")], [ready], false,
    ), "org-a");
    expect(report.evidence.newlyReady).toBe(0);
  });
  it("includes diagnostic cohorts", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(report.cohorts.code[0]?.after).toBe(1);
  });
  it("includes severity cohorts", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(report.cohorts.severity[0]?.after).toBe(1);
  });
  it("includes state cohorts", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(report.cohorts.state[0]?.after).toBe(1);
  });
  it("includes before and after metrics", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(report.metrics.before.total).toBe(0);
    expect(report.metrics.after.total).toBe(1);
  });
  it("includes priority drift counters", () => {
    const report = compareIntegrityCaptures(payload(
      [row("a")], [row("a", { state: "STALE" })],
    ), "org-a");
    expect(report.priority.escalations).toBe(1);
  });
  it("warns against interpreting diagnostics as verification", () => {
    const report = compareIntegrityCaptures(payload([], []), "org-a");
    expect(report.warnings.some(w => w.includes("security control effectiveness"))).toBe(true);
  });
  it("warns that snapshots are user supplied", () => {
    const report = compareIntegrityCaptures(payload([], []), "org-a");
    expect(report.warnings.some(w => w.includes("supplied by the caller"))).toBe(true);
  });
  it("exports CSV with header", () => {
    const report = compareIntegrityCaptures(payload([], []), "org-a");
    expect(integrityComparisonCsv(report)).toContain("caseKey");
  });
  it("exports changed case rows", () => {
    const report = compareIntegrityCaptures(payload([], [row("a")]), "org-a");
    expect(integrityComparisonCsv(report)).toContain("DONE_WITHOUT_COMPLETION");
  });
  it("neutralizes spreadsheet formula work IDs", () => {
    const report = compareIntegrityCaptures(payload([], [row("=DANGER")]), "org-a");
    expect(integrityComparisonCsv(report)).toContain("=DANGER");
    expect(integrityComparisonCsv(report)).toContain("NEW");
  });
  it("does not mutate supplied snapshots", () => {
    const data = payload([row("a")], [row("a", { state: "STALE" })]);
    const before = JSON.stringify(data);
    compareIntegrityCaptures(data, "org-a");
    expect(JSON.stringify(data)).toBe(before);
  });
});

describe("longitudinal comparison capture-scope protections", () => {
  it("rejects captures from different source kinds", () => {
    const data = payload([row("a")], [row("a")]);
    data.after.source = "different-source";
    expect(() => compareIntegrityCaptures(data, "org-a")).toThrow(
      "Capture source or bounded page scope differs",
    );
  });
  it("rejects different cursor scopes encoded in source", () => {
    const data = payload([row("a")], [row("a")]);
    data.before.source = JSON.stringify({ kind: "live", cursor: null });
    data.after.source = JSON.stringify({ kind: "live", cursor: "next" });
    expect(() => compareIntegrityCaptures(data, "org-a")).toThrow();
  });
  it("rejects different case-page limit scopes", () => {
    const data = payload([], []);
    data.before.source = JSON.stringify({ kind: "live", limit: 25 });
    data.after.source = JSON.stringify({ kind: "live", limit: 50 });
    expect(() => compareIntegrityCaptures(data, "org-a")).toThrow();
  });
  it("rejects differing severity filters in capture metadata", () => {
    const data = payload([], []);
    data.before.source = JSON.stringify({ kind: "live", severity: "ALL" });
    data.after.source = JSON.stringify({ kind: "live", severity: "critical" });
    expect(() => compareIntegrityCaptures(data, "org-a")).toThrow();
  });
  it("allows same bounded source across capture times", () => {
    const data = payload([row("a")], [row("a")]);
    data.before.source = JSON.stringify({ kind: "live", cursor: null, limit: 25 });
    data.after.source = data.before.source;
    expect(compareIntegrityCaptures(data, "org-a").counts.UNCHANGED).toBe(1);
  });
  it("never calls a readiness improvement confirmed for incomplete captures", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: afterTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    for (const [oldComplete, newComplete] of [
      [false, true], [true, false], [false, false],
    ]) {
      const report = compareIntegrityCaptures(payload(
        [row("a")], [ready], oldComplete, newComplete,
      ), "org-a");
      expect(report.evidence.newlyReady).toBe(0);
      expect(report.evidence.uncertain).toBeGreaterThan(0);
    }
  });
  it("never calls evidence loss confirmed for incomplete captures", () => {
    const ready = row("a", {
      state: "ACKNOWLEDGED", reviewEventId: "event",
      reviewedAt: beforeTime, reviewedRevision: 2, reviewRationale: "Checked",
    });
    const report = compareIntegrityCaptures(payload(
      [ready], [row("a")], false,
    ), "org-a");
    expect(report.evidence.newlyBlocked).toBe(0);
  });
});
