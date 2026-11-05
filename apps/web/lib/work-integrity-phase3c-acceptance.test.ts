import { describe, expect, it } from "vitest";
import {
  analyzeAcceptanceTask, buildAcceptanceReport, acceptanceDigest,
  parseAcceptanceQuery, summarizeAcceptance,
} from "./work-integrity-phase3c-acceptance";
import {
  acceptanceWorkstream, acceptanceNextStep, acceptanceActionPriority,
  acceptanceTaskActions, buildAcceptanceExecutionPlan,
} from "./work-integrity-phase3c-acceptance-plan";

const now = new Date("2026-11-05T12:00:00.000Z");
const task = {
  id: "review-12345", captureId: "capture-12345",
  severity: "ERROR", disposition: "OPEN",
  revision: 1, ownerUserId: null,
  createdAt: new Date("2026-11-03T00:00:00.000Z"),
  completedAt: null,
};
const query = parseAcceptanceQuery({ captureId: "capture-12345" });
const empty = {
  events: [], notifications: [], escalations: [], providers: [],
  workLinks: [], audits: [], memberIds: new Set<string>(),
};
describe("phase 3C acceptance query", () => {
  it("defaults to bounded read-only capture inspection", () => {
    expect(query).toMatchObject({
      offset: 0, limit: 50, includeClosed: true,
      minimumProviderAgeHours: 168, maxNotificationAgeHours: 72,
    });
  });
  it.each([
    {}, { captureId: "bad" },
    { captureId: "capture-12345", offset: -1 },
    { captureId: "capture-12345", limit: 101 },
    { captureId: "capture-12345", includeClosed: "true" },
    { captureId: "capture-12345", minimumProviderAgeHours: 0 },
    { captureId: "capture-12345", maxNotificationAgeHours: 10000 },
    { captureId: "capture-12345", unexpected: true },
  ])("rejects invalid requests %j", value => {
    expect(() => parseAcceptanceQuery(value)).toThrow();
  });
});
describe("phase 3C persistent-state diagnostics", () => {
  it("does not flag initial revision without events as missing", () => {
    const result = analyzeAcceptanceTask(task, empty, query, now);
    expect(result.findings.map(x => x.code)).not.toContain("NO_REVIEW_EVENTS");
    expect(result.findings.map(x => x.code)).toContain("PROVIDER_CHECK_NOT_PRESENT");
    expect(result.blockers).toBe(0);
  });
  it("requires events for evolved review revisions", () => {
    const result = analyzeAcceptanceTask({
      ...task, revision: 3,
    }, empty, query, now);
    expect(result.findings.map(x => x.code)).toContain("NO_REVIEW_EVENTS");
    expect(result.blockers).toBeGreaterThan(0);
  });
  it("accepts a contiguous review transition starting at revision one", () => {
    const result = analyzeAcceptanceTask({
      ...task, revision: 2, disposition: "ACKNOWLEDGED",
    }, {
      ...empty,
      events: [{
        id: "event-12345", taskId: task.id, action: "ACKNOWLEDGE",
        revisionBefore: 1, revisionAfter: 2,
        before: "OPEN", after: "ACKNOWLEDGED",
        occurredAt: now,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).not.toContain(
      "REVIEW_EVENT_REVISION_GAP");
    expect(result.findings.map(x => x.code)).not.toContain(
      "REVIEW_EVENT_STATE_MISMATCH");
  });
  it("rejects review revision gaps and incompatible state lineage", () => {
    const result = analyzeAcceptanceTask({
      ...task, revision: 5, disposition: "IN_REVIEW",
    }, {
      ...empty,
      events: [{
        id: "event-12345", taskId: task.id, action: "START_REVIEW",
        revisionBefore: 2, revisionAfter: 4,
        before: "ACKNOWLEDGED", after: "RESOLVED",
        occurredAt: now,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "REVIEW_EVENT_REVISION_GAP");
    expect(result.findings.map(x => x.code)).toContain(
      "REVIEW_EVENT_STATE_MISMATCH");
  });
  it("identifies invalid inbox timestamps and former members", () => {
    const result = analyzeAcceptanceTask(task, {
      ...empty,
      notifications: [{
        id: "notification-12345", taskId: task.id,
        recipientUserId: "nonmember-12345", revision: 1,
        kind: "REVIEW_ASSIGNED",
        createdAt: new Date("2026-11-03T01:00:00.000Z"),
        readAt: new Date("2026-11-02T00:00:00.000Z"),
        dismissedAt: null,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "NOTIFICATION_READ_BEFORE_CREATION");
    expect(result.findings.map(x => x.code)).toContain(
      "NOTIFICATION_RECIPIENT_NOT_MEMBER");
  });
  it("detects contradictory escalation lifecycle timestamps", () => {
    const result = analyzeAcceptanceTask(task, {
      ...empty,
      escalations: [{
        id: "escalation-12345", taskId: task.id,
        state: "RESOLVED", revision: 1, level: 1,
        openedAt: now, dueAt: now,
        acknowledgedAt: null, resolvedAt: null,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "ESCALATION_STATE_INCONSISTENT");
  });
  it("never equates a human closed case with provider PASS", () => {
    const result = analyzeAcceptanceTask({
      ...task, disposition: "RESOLVED", completedAt: now,
    }, {
      ...empty,
      providers: [{
        id: "provider-12345", taskId: task.id,
        outcome: "FAIL", checkedAt: now, providerObservedAt: now,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "PROVIDER_FAILURE_WITH_HUMAN_CLOSURE");
  });
  it("detects provider observations beyond the diagnostic age", () => {
    const result = analyzeAcceptanceTask(task, {
      ...empty,
      providers: [{
        id: "provider-12345", taskId: task.id,
        outcome: "PASS",
        checkedAt: new Date("2026-10-10T00:00:00.000Z"),
        providerObservedAt: null,
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "PROVIDER_OBSERVATION_OLD");
  });
  it("detects logically impossible work link withdrawal", () => {
    const result = analyzeAcceptanceTask(task, {
      ...empty,
      workLinks: [{
        taskId: task.id, workItemId: "work-12345",
        linkedAt: now, unlinkedAt: new Date("2026-11-04T00:00:00.000Z"),
      }],
    }, query, now);
    expect(result.findings.map(x => x.code)).toContain(
      "WORK_LINK_AFTER_UNLINK");
  });
  it("returns a stable per-task digest", () => {
    const first = analyzeAcceptanceTask(task, empty, query, now);
    const second = analyzeAcceptanceTask(task, empty, query, now);
    expect(first.digest).toBe(second.digest);
    expect(first.digest).toMatch(/^[0-9a-f]{64}$/);
  });
});
describe("phase 3C conservative acceptance decision", () => {
  it("requires manual review when the scope is empty", () => {
    const report = buildAcceptanceReport("org-12345", query, [], empty, 0, now);
    expect(report.outcome).toBe("REQUIRES_REVIEW");
    expect(report.complete).toBe(true);
  });
  it("does not mark a page as globally accepted", () => {
    const report = buildAcceptanceReport("org-12345", query,
      [task], empty, 20, now);
    expect(report.complete).toBe(false);
    expect(report.outcome).toBe("REQUIRES_REVIEW");
    expect(report.hasMore).toBe(true);
  });
  it("marks invalid task state as BLOCKED", () => {
    const report = buildAcceptanceReport("org-12345", query,
      [{ ...task, revision: 8 }], empty, 1, now);
    expect(report.outcome).toBe("BLOCKED");
    expect(report.summary.blockers).toBeGreaterThan(0);
    expect(report.summary.byCode.NO_REVIEW_EVENTS).toBe(1);
  });
  it("aggregates counters and stable report digests", () => {
    const report = buildAcceptanceReport("org-12345", query,
      [task], empty, 1, now);
    expect(report.summary).toMatchObject({
      tasks: 1, providerChecks: 0,
      blockers: 0, information: 1,
    });
    expect(summarizeAcceptance(report.tasks).tasks).toBe(1);
    expect(acceptanceDigest(report.tasks)).toMatch(/^[a-f0-9]{64}$/);
  });
});
describe("acceptance investigation planning", () => {
  it("maps ledger and provider findings into separate workstreams", () => {
    expect(acceptanceWorkstream("REVIEW_EVENT_REVISION_GAP"))
      .toBe("REVIEW_LEDGER");
    expect(acceptanceWorkstream("PROVIDER_OBSERVATION_OLD"))
      .toBe("PROVIDER_OBSERVATION");
    expect(acceptanceNextStep("PROVIDER_FAILURE_WITH_HUMAN_CLOSURE"))
      .toBe("RECONCILE_REVIEW_PROVIDER");
  });
  it("assigns blockers higher priority than observational warnings", () => {
    expect(acceptanceActionPriority([{
      code: "REVIEW_EVENT_REVISION_GAP", level: "BLOCKER",
      taskId: task.id, entity: "EVENT", entityId: "event-12345",
      message: "Revision gap",
    }])).toBe("P0");
  });
  it("derives explicit non-executing plans", () => {
    const report = buildAcceptanceReport("org-12345", query,
      [{ ...task, revision: 3 }], empty, 1, now);
    const plan = buildAcceptanceExecutionPlan(report);
    expect(plan.requiresManualSignoff).toBe(true);
    expect(plan.byPriority.P0).toBeGreaterThan(0);
    expect(plan.actions.length).toBeGreaterThan(0);
    expect(plan.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(acceptanceTaskActions(report.tasks[0]!).length)
      .toBe(plan.actions.length);
  });
});
