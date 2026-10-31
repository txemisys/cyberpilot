import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import {
  buildIntegrityTimeline, integrityTimelineCsv, parseTimelineInput,
} from "./work-integrity-case-timeline";

const work: CaseRow = {
  key: JSON.stringify(["work-001", "DONE_WITHOUT_COMPLETION", "work-001"]),
  workItemId: "work-001",
  taskStatus: "DONE",
  taskRevision: 1,
  resourceId: "work-001",
  code: "DONE_WITHOUT_COMPLETION",
  severity: "attention",
  diagnostic: "Incomplete record",
  recommendation: "Review event history",
  state: "UNREVIEWED",
  reviewEventId: null,
  reviewedAt: null,
  reviewedRevision: null,
  reviewerUserId: null,
  reviewRationale: null,
  reviewReference: null,
  completeCoverage: true,
  historicalOnly: false,
};
const alternate: CaseRow = {
  ...work,
  key: JSON.stringify(["work-002", "DONE_WITHOUT_COMPLETION", "work-002"]),
  workItemId: "work-002",
  resourceId: "work-002",
};
const date = (day: number) => `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`;
const capture = (
  day: number, cases: CaseRow[] = [], complete = true,
  organizationId = "org-001", source = "bounded-page-scope",
) => ({
  organizationId, source, capturedAt: date(day), complete, cases,
});
const timeline = (...captures: ReturnType<typeof capture>[]) =>
  buildIntegrityTimeline(parseTimelineInput({ captures }, "org-001"));
const soleTrend = (...captures: ReturnType<typeof capture>[]) =>
  timeline(...captures).cases[0]?.trend;

describe("integrity longitudinal input boundary", () => {
  it("accepts an ordered set of authenticated captures", () => {
    expect(parseTimelineInput({
      captures: [capture(1), capture(2), capture(3)],
    }, "org-001")).toHaveLength(3);
  });
  it("requires at least two real snapshots", () => {
    expect(() => parseTimelineInput({ captures: [capture(1)] }, "org-001"))
      .toThrow();
  });
  it("rejects unknown payload options instead of silently ignoring them", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2)], hidden: "unsafe",
    }, "org-001")).toThrow(/Unsupported/);
  });
  it("rejects missing and untrusted organization IDs", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2)],
    }, "")).toThrow();
  });
  it("rejects foreign organizations regardless of where they appear", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2, [], true, "foreign")],
    }, "org-001")).toThrow(/Cross-organization/);
  });
  it("requires identical page and source scope", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2, [], true, "org-001", "other-scope")],
    }, "org-001")).toThrow(/identical source/);
  });
  it("requires strictly increasing source timestamps", () => {
    expect(() => parseTimelineInput({
      captures: [capture(2), capture(1)],
    }, "org-001")).toThrow(/chronologically/);
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(1)],
    }, "org-001")).toThrow(/chronologically/);
  });
  it("limits distinct case identities, not merely each capture size", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1, [work]), capture(2, [alternate])],
    }, "org-001", { maxTimelineCases: 1 })).toThrow(/distinct-case/);
  });
  it("limits individual captures", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1, [work, alternate]), capture(2, [])],
    }, "org-001", { maxCasesPerCapture: 1 })).toThrow();
  });
  it.each([
    { maxCaptures: 0 },
    { maxCasesPerCapture: 0 },
    { maxTimelineCases: 0 },
    { maxCaptures: 25 },
    { maxCasesPerCapture: 10001 },
  ])("rejects invalid resource policy %j", policy => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2)],
    }, "org-001", policy)).toThrow(/limit/);
  });
  it("enforces configured capture limits", () => {
    expect(() => parseTimelineInput({
      captures: [capture(1), capture(2), capture(3)],
    }, "org-001", { maxCaptures: 2 })).toThrow();
  });
});
describe("longitudinal case state and coverage", () => {
  it("identifies new cases only when all captures are complete", () => {
    expect(soleTrend(capture(1), capture(2, [work])))
      .toBe("NEW_IN_LAST_CAPTURE");
  });
  it("identifies persistent diagnostics", () => {
    expect(soleTrend(capture(1, [work]), capture(2, [work]), capture(3, [work])))
      .toBe("PERSISTENT");
  });
  it("detects flapping across real snapshots", () => {
    expect(soleTrend(
      capture(1, [work]), capture(2), capture(3, [work]),
    )).toBe("FLAPPING");
    const result = timeline(capture(1, [work]), capture(2), capture(3, [work]));
    expect(result.cases[0]?.transitions).toBe(2);
  });
  it("labels disappearance without claiming that remediation succeeded", () => {
    const result = timeline(capture(1, [work]), capture(2));
    expect(result.cases[0]?.trend).toBe("DISAPPEARED");
    expect(result.cases[0]?.gaps.join(" ")).toMatch(/not validated remediation/);
  });
  it("refuses to call disappearance confirmed when scope is incomplete", () => {
    expect(soleTrend(capture(1, [work]), capture(2, [], false)))
      .toBe("UNCERTAIN");
  });
  it("refuses positive conclusions when linked record coverage is incomplete", () => {
    expect(soleTrend(capture(1, [{ ...work, completeCoverage: false }]),
      capture(2, [work]))).toBe("UNCERTAIN");
  });
  it("measures task revisions without treating work as verified security", () => {
    const reviewed: CaseRow = {
      ...work, taskRevision: 1, state: "INVESTIGATING",
      reviewedRevision: 1, reviewEventId: "event-001",
      reviewedAt: date(1), reviewerUserId: "user-001",
      reviewRationale: "Review underway",
    };
    const updated: CaseRow = { ...reviewed, taskRevision: 2, state: "STALE" };
    const result = timeline(capture(1, [reviewed]), capture(2, [updated]));
    expect(result.cases[0]?.reviewRevisions).toBe(1);
    expect(result.cases[0]?.reviewIsCurrent).toBe(false);
    expect(result.cases[0]?.gaps.join(" ")).toMatch(/review revision/);
    expect(result.cases[0]?.lastKnownState).toBe("STALE");
  });
  it("identifies current reviews without certifying completion", () => {
    const reviewed: CaseRow = {
      ...work, state: "ACKNOWLEDGED", reviewedRevision: 1,
      reviewEventId: "event-001", reviewedAt: date(1),
      reviewerUserId: "user-001", reviewRationale: "Accepted risk",
    };
    const result = timeline(capture(1, [work]), capture(2, [reviewed]));
    expect(result.cases[0]?.reviewIsCurrent).toBe(true);
    expect(result.warnings.join(" ")).toMatch(/does not establish/);
  });
  it("produces stable chronological points with explicit absence", () => {
    const result = timeline(capture(1), capture(2, [work]), capture(3, [work]));
    expect(result.cases[0]?.points.map(point => point.present))
      .toEqual([false, true, true]);
    expect(result.cases[0]?.firstSeenAt).toBe(date(2));
    expect(result.cases[0]?.lastSeenAt).toBe(date(3));
  });
  it("counts multiple independent case trends", () => {
    const result = timeline(
      capture(1, [work]),
      capture(2, [work, alternate]),
    );
    expect(result.captures).toBe(2);
    expect(result.counts.PERSISTENT).toBe(1);
    expect(result.counts.NEW_IN_LAST_CAPTURE).toBe(1);
    expect(result.cases.map(row => row.key)).toEqual([work.key, alternate.key]);
  });
  it("reports incomplete capture quality separately from case totals", () => {
    const result = timeline(capture(1, [work]), capture(2, [], false));
    expect(result.completeCaptures).toBe(1);
    expect(result.incompleteCaptures).toBe(1);
    expect(result.comparable).toBe(false);
  });
  it("reports structural review contradictions as timeline warnings", () => {
    const result = timeline(capture(1, [work]),
      capture(2, [{ ...work, state: "STALE", reviewedRevision: 1 }]));
    expect(result.warnings.join(" ")).toMatch(/contradictory/);
  });
  it("produces a safe CSV against spreadsheet formula injection", () => {
    const malicious = {
      ...work,
      resourceId: "=HYPERLINK(1)",
      key: JSON.stringify([work.workItemId, work.code, "=HYPERLINK(1)"]),
    };
    const result = timeline(capture(1, [malicious]), capture(2, [malicious]));
    const csv = integrityTimelineCsv(result);
    expect(csv).toContain("'=HYPERLINK(1)");
    expect(csv).toContain("caseKey");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
  it("handles empty snapshots without inventing hidden cases", () => {
    const result = timeline(capture(1), capture(2));
    expect(result.cases).toEqual([]);
    expect(result.counts.NEW_IN_LAST_CAPTURE).toBe(0);
    expect(result.counts.DISAPPEARED).toBe(0);
  });
  it("revalidates direct calls rather than trusting typed input", () => {
    expect(() => buildIntegrityTimeline([
      capture(2), capture(1),
    ])).toThrow();
  });
});
