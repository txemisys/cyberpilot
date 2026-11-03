import { describe, expect, it } from "vitest";
import {
  computeSlaReport, parseSlaQuery,
} from "./work-integrity-sla-report";
import {
  inspectConsistencyTask, parseConsistencyQuery,
  buildConsistencyReport,
} from "./work-integrity-workflow-consistency";

const now = new Date("2026-11-03T12:00:00.000Z");
const created = new Date("2026-11-01T12:00:00.000Z");
const task = {
  id: "review-task-12345",
  captureId: "capture-12345",
  severity: "ERROR",
  disposition: "OPEN",
  revision: 1,
  ownerUserId: "user-12345",
  createdAt: created,
  updatedAt: now,
  completedAt: null,
};
describe("phase 3C SLA investigation", () => {
  const query = parseSlaQuery({
    from: "2026-11-01T00:00:00.000Z",
    to: "2026-11-04T00:00:00.000Z",
    responseMinutes: 60,
    resolutionMinutes: 120,
    notificationReadMinutes: 30,
    escalationAckMinutes: 15,
  }, now);
  it("flags active breaches across all operational categories", () => {
    const report = computeSlaReport(query, {
      tasks: [task],
      notifications: [{
        id: "notification-1", taskId: task.id,
        createdAt: created, readAt: null,
        dismissedAt: null, kind: "REVIEW_ASSIGNED",
      }],
      escalations: [{
        id: "escalation-1", taskId: task.id,
        state: "OPEN", openedAt: created,
        acknowledgedAt: null, resolvedAt: null,
        dueAt: new Date("2026-11-02T12:00:00.000Z"),
        level: 1,
      }],
      events: [],
      totalTasks: 1, truncated: false,
    }, now);
    expect(report.counts).toMatchObject({
      FIRST_RESPONSE: 1,
      RESOLUTION: 1,
      READ: 1,
      ACKNOWLEDGEMENT: 1,
      DUE: 1,
    });
    expect(report.affectedTasks).toBe(1);
    expect(report.active).toBe(5);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("uses the first response event rather than task modification", () => {
    const report = computeSlaReport(query, {
      tasks: [task],
      notifications: [], escalations: [],
      events: [{
        id: "event-1", taskId: task.id,
        action: "ACKNOWLEDGE",
        occurredAt: new Date("2026-11-01T12:30:00.000Z"),
        revisionAfter: 2,
      }],
      totalTasks: 1, truncated: false,
    }, now);
    expect(report.counts.FIRST_RESPONSE).toBe(0);
    expect(report.counts.RESOLUTION).toBe(1);
  });
  it("rejects unsafe or ambiguous query inputs", () => {
    for (const patch of [
      { limit: 0 }, { limit: 2001 },
      { includeClosed: "yes" },
      { responseMinutes: -1 },
      { resolutionMinutes: 1.5 },
      { arbitrary: "field" },
    ]) {
      expect(() => parseSlaQuery(patch, now)).toThrow();
    }
  });
});
describe("phase 3C workflow consistency", () => {
  it("accepts an open review without events", () => {
    const report = inspectConsistencyTask(task, [], [], []);
    expect(report.consistent).toBe(true);
    expect(report.issues).toEqual([]);
  });
  it("detects invalid review revision and inconsistent completion", () => {
    const report = inspectConsistencyTask({
      ...task, revision: 0,
      disposition: "RESOLVED",
      completedAt: null,
    }, [], [], []);
    expect(report.issues.map(issue => issue.code)).toContain(
      "TASK_REVISION_INVALID",
    );
    expect(report.issues.map(issue => issue.code)).toContain(
      "TASK_CLOSED_WITHOUT_COMPLETION",
    );
  });
  it("detects contradictory event and notification chronology", () => {
    const report = inspectConsistencyTask(task, [{
      id: "event-1", taskId: task.id,
      revisionBefore: 3, revisionAfter: 4,
      before: "OPEN", after: "RESOLVED",
      action: "RESOLVE",
      occurredAt: new Date("2026-10-31T12:00:00.000Z"),
    }], [{
      id: "notification-1", taskId: task.id,
      recipientUserId: "user-12345",
      kind: "REVIEW_ASSIGNED", revision: 1,
      createdAt: created,
      readAt: new Date("2026-10-31T12:00:00.000Z"),
      dismissedAt: null,
    }], []);
    const codes = report.issues.map(issue => issue.code);
    expect(codes).toContain("EVENT_REVISION_GAP");
    expect(codes).toContain("EVENT_FUTURE_REVISION");
    expect(codes).toContain("EVENT_CREATED_BEFORE_TASK");
    expect(codes).toContain("NOTIFICATION_READ_BEFORE_CREATION");
  });
  it("detects invalid escalation closure and due-date ordering", () => {
    const report = inspectConsistencyTask(task, [], [], [{
      id: "escalation-1", taskId: task.id,
      state: "RESOLVED", level: 1, revision: 1,
      openedAt: created,
      dueAt: new Date("2026-10-31T12:00:00.000Z"),
      acknowledgedAt: null,
      resolvedAt: null,
    }]);
    expect(report.issues.map(issue => issue.code)).toContain(
      "ESCALATION_CLOSED_WITHOUT_RESOLUTION",
    );
    expect(report.issues.map(issue => issue.code)).toContain(
      "ESCALATION_DUE_BEFORE_OPEN",
    );
  });
  it("reports pagination and deterministic digests", () => {
    const query = parseConsistencyQuery({
      captureId: "capture-12345",
      limit: 1,
    });
    const report = buildConsistencyReport(
      "org-12345", query, 2, [task],
      [], [], [], now, false,
    );
    expect(report.hasMore).toBe(true);
    expect(report.complete).toBe(true);
    expect(report.consistent).toBe(1);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(buildConsistencyReport(
      "org-12345", query, 2, [task],
      [], [], [], now, false,
    ).digest).toBe(report.digest);
  });
  it("rejects invalid pagination and flags", () => {
    for (const patch of [
      { limit: 101 }, { offset: -1 },
      { includeResolved: "true" },
      { unknown: true },
    ]) {
      expect(() => parseConsistencyQuery(patch)).toThrow();
    }
  });
});
