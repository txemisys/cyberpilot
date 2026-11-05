import { describe, expect, it } from "vitest";
import {
  parsePlanningQuery, planTask, buildPlanningReport,
  planningUrgency, dueForPlanning, planningHash,
} from "./work-integrity-operational-planning";
import {
  parseCohortQuery, buildCohortRow, buildCohortReport, cohortSort,
  cohortTotals, cohortDigest,
} from "./work-integrity-capture-cohorts";

const now = new Date("2026-11-05T12:00:00.000Z");
const task = {
  id: "task-12345", captureId: "capture-12345", title: "Verify 2SV",
  severity: "ERROR", disposition: "OPEN",
  ownerUserId: null, revision: 1, required: true,
  createdAt: new Date("2026-11-03T10:00:00.000Z"),
  updatedAt: new Date("2026-11-03T10:00:00.000Z"), completedAt: null,
};
const emptySources = {
  escalations: [], notifications: [], links: [], checks: [], assessments: [],
};
const capture = {
  id: "capture-12345",
  createdAt: new Date("2026-11-03T09:00:00.000Z"),
};
const cohortTask = {
  id: task.id, captureId: capture.id, severity: task.severity,
  disposition: "OPEN", createdAt: task.createdAt,
  completedAt: null, ownerUserId: null, required: true,
};
describe("phase 3C operational planning", () => {
  it("requires well bounded query fields", () => {
    expect(parsePlanningQuery({})).toMatchObject({
      limit: 40, offset: 0, horizonHours: 72, includeClosed: false,
    });
    expect(() => parsePlanningQuery({ horizonHours: 100 })).toThrow();
    expect(() => parsePlanningQuery({ limit: 101 })).toThrow();
    expect(() => parsePlanningQuery({ includeClosed: "true" })).toThrow();
    expect(() => parsePlanningQuery({ extra: "unsafe" })).toThrow();
  });
  it("calculates deadlines independently by severity", () => {
    const query = parsePlanningQuery({});
    expect(dueForPlanning(task, query).toISOString())
      .toBe("2026-11-03T22:00:00.000Z");
    expect(dueForPlanning({ ...task, severity: "WARNING" }, query)
      .toISOString()).toBe("2026-11-05T10:00:00.000Z");
  });
  it("classifies overdue and unassigned tasks conservatively", () => {
    const row = planTask(task, emptySources, parsePlanningQuery({}), now);
    expect(row.signals).toContain("OVERDUE");
    expect(row.signals).toContain("UNASSIGNED");
    expect(row.signals).toContain("NO_PROVIDER_OBSERVATION");
    expect(row.actions).toContain("ASSIGN_OWNER");
    expect(row.actions).toContain("VERIFY_PROVIDER");
    expect(row.urgency).toBe("CRITICAL");
    expect(row.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
  it("does not claim human closure means provider verification", () => {
    const row = planTask({
      ...task, disposition: "RESOLVED", completedAt: now,
    }, emptySources, parsePlanningQuery({ includeClosed: true }), now);
    expect(row.signals).toContain("REVIEW_COMPLETED");
    expect(row.signals).toContain("NO_PROVIDER_OBSERVATION");
    expect(row.actions).toContain("VERIFY_PROVIDER");
    expect(row.signals).not.toContain("OVERDUE");
  });
  it("detects historical provider failure and staleness", () => {
    const row = planTask(task, {
      ...emptySources,
      checks: [{
        id: "check-12345", taskId: task.id, outcome: "FAIL",
        checkedAt: new Date("2026-10-20T00:00:00.000Z"),
        providerObservedAt: null,
      }],
    }, parsePlanningQuery({}), now);
    expect(row.signals).toContain("PROVIDER_NOT_PASSING");
    expect(row.signals).toContain("PROVIDER_OBSERVATION_STALE");
    expect(row.actions).toContain("INSPECT_PROVIDER_FAILURE");
  });
  it("counts only unread non-dismissed in-app notifications", () => {
    const row = planTask(task, {
      ...emptySources,
      notifications: [{
        taskId: task.id, recipientUserId: "member-12345",
        createdAt: now, readAt: null, dismissedAt: null,
      }, {
        taskId: task.id, recipientUserId: "member-12345",
        createdAt: now, readAt: now, dismissedAt: null,
      }],
    }, parsePlanningQuery({}), now);
    expect(row.inbox).toMatchObject({ total: 2, unread: 1, recipients: 1 });
  });
  it("produces deterministic page digests", () => {
    const query = parsePlanningQuery({});
    const first = buildPlanningReport("org-12345", query, [task], emptySources, 2, now);
    const second = buildPlanningReport("org-12345", query, [task], emptySources, 2, now);
    expect(first.digest).toBe(second.digest);
    expect(first.complete).toBe(false);
    expect(first.summary.overdue).toBe(1);
    expect(planningUrgency(701)).toBe("CRITICAL");
    expect(planningHash({ a: 1 })).toMatch(/^[a-f0-9]{64}$/);
  });
});
describe("phase 3C capture cohort reporting", () => {
  it("validates reporting period and pagination", () => {
    const query = parseCohortQuery({}, now);
    expect(query.limit).toBe(25);
    expect(query.order).toBe("RECENT");
    expect(() => parseCohortQuery({ limit: 101 }, now)).toThrow();
    expect(() => parseCohortQuery({ overdueHours: 0 }, now)).toThrow();
    expect(() => parseCohortQuery({ order: "INVALID" }, now)).toThrow();
    expect(() => parseCohortQuery({ includeEmpty: "yes" }, now)).toThrow();
    expect(() => parseCohortQuery({ unknown: true }, now)).toThrow();
  });
  it("reports open, overdue and no-provider cases", () => {
    const row = buildCohortRow(
      capture, [cohortTask], [], [], [], parseCohortQuery({}, now), now);
    expect(row).toMatchObject({
      totalTasks: 1, open: 1, overdue: 1,
      unassigned: 1, providerUnknownTasks: 1,
    });
    expect(row.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("uses latest historical provider outcome per task", () => {
    const row = buildCohortRow(capture, [cohortTask], [], [], [{
      id: "check-old", taskId: task.id, outcome: "PASS",
      checkedAt: new Date("2026-11-04T00:00:00.000Z"),
    }, {
      id: "check-new", taskId: task.id, outcome: "FAIL",
      checkedAt: new Date("2026-11-05T00:00:00.000Z"),
    }], parseCohortQuery({}, now), now);
    expect(row.providerFailingTasks).toBe(1);
    expect(row.providerPassedTasks).toBe(0);
    expect(row.providerCheckedTasks).toBe(1);
  });
  it("detects temporal anomalies from stored operational events", () => {
    const row = buildCohortRow(capture, [{
      ...cohortTask, completedAt: new Date("2020-01-01T00:00:00.000Z"),
    }], [], [], [], parseCohortQuery({}, now), now);
    expect(row.anomalies).toContain("TASK_COMPLETED_BEFORE_CREATION");
  });
  it("sorts only supplied capture pages and aggregates their totals", () => {
    const query = parseCohortQuery({ order: "MOST_OPEN" }, now);
    const first = buildCohortRow(capture, [cohortTask],
      [], [], [], query, now);
    const second = buildCohortRow({
      id: "capture-67890", createdAt: now,
    }, [], [], [], [], query, now);
    const sorted = cohortSort([second, first], "MOST_OPEN");
    expect(sorted[0]?.captureId).toBe(capture.id);
    expect(cohortTotals(sorted)).toMatchObject({
      captures: 2, tasks: 1, open: 1, overdue: 1,
    });
  });
  it("produces reproducible and bounded cohort reports", () => {
    const query = parseCohortQuery({}, now);
    const first = buildCohortReport("org-12345", query, [capture],
      [cohortTask], [], [], [], 2, now);
    expect(first.complete).toBe(false);
    expect(first.hasMore).toBe(true);
    expect(first.totalsOnPage.open).toBe(1);
    expect(first.digest).toBe(buildCohortReport("org-12345", query,
      [capture], [cohortTask], [], [], [], 2, now).digest);
    expect(cohortDigest(first.rows)).toMatch(/^[a-f0-9]{64}$/);
  });
});
