import { describe, expect, it } from "vitest";
import {
  parseQueueQuery, queueDeadline, classifyQueueTask,
  sortQueueRows, queueSnapshot, queueBucketPredicate, queueDatabaseOrder,
} from "./work-integrity-operations-queue";
import {
  parseTriageCommand, parseTriageBatch,
} from "./work-integrity-review-triage";
import {
  parseOperationsMetricsQuery, metricsPeriod, rollupMetrics,
} from "./work-integrity-operations-metrics";

const now = new Date("2026-11-03T12:00:00.000Z");
const task = {
  id: "review-task-12345",
  captureId: "capture-12345",
  externalTaskId: "external-review",
  title: "Check MFA",
  severity: "ERROR",
  disposition: "OPEN",
  required: true,
  ownerUserId: "owner-user-12345",
  createdAt: new Date("2026-11-02T00:00:00.000Z"),
  updatedAt: new Date("2026-11-02T01:00:00.000Z"),
};
describe("integrity operations queue", () => {
  const query = parseQueueQuery({});
  it("defaults to bounded pagination and deadlines", () => {
    expect(query).toMatchObject({
      offset: 0, limit: 50, sort: "DEADLINE",
      errorHours: 12, warningHours: 48,
    });
  });
  it("calculates a severity-specific deadline", () => {
    expect(queueDeadline(task, query).toISOString())
      .toBe("2026-11-02T12:00:00.000Z");
  });
  it("classifies overdue work with nonzero urgency", () => {
    const result = classifyQueueTask(task, query, now);
    expect(result.bucket).toBe("OVERDUE");
    expect(result.overdueMinutes).toBe(1440);
    expect(result.urgency).toBeGreaterThan(300);
  });
  it("never labels a resolved review as overdue", () => {
    expect(classifyQueueTask({
      ...task, disposition: "RESOLVED",
    }, query, now).bucket).toBe("COMPLETED");
  });
  it("recognizes a future due-soon task", () => {
    expect(classifyQueueTask({
      ...task, createdAt: new Date("2026-11-03T03:00:00.000Z"),
    }, query, now).bucket).toBe("DUE_SOON");
  });
  it("recognizes unassigned review", () => {
    expect(classifyQueueTask({
      ...task, ownerUserId: null,
      createdAt: now,
    }, query, now).bucket).toBe("UNASSIGNED");
  });
  it.each([
    { offset: -1 }, { limit: 101 }, { sort: "RANDOM" },
    { bucket: "CLOSED" }, { severity: "CRITICAL" },
    { soonHours: 0 }, { errorHours: 9000 },
    { unexpected: "value" },
  ])("rejects invalid queue filters %j", input => {
    expect(() => parseQueueQuery(input)).toThrow();
  });
  it("sorts by deadline and stable ID", () => {
    const rows = [
      { taskId: "b", dueAt: "2026-11-03T00:00:00Z" },
      { taskId: "a", dueAt: "2026-11-02T00:00:00Z" },
    ] as Parameters<typeof sortQueueRows>[0];
    expect(sortQueueRows(rows, "DEADLINE").map(x => x.taskId))
      .toEqual(["a", "b"]);
  });
  it("produces a deterministic queue digest", () => {
    const row = {
      taskId: task.id, bucket: "OVERDUE", urgency: 1000,
      severity: "ERROR", dueAt: now.toISOString(),
      flags: ["NO_PROVIDER_CHECK"],
    } as Parameters<typeof queueSnapshot>[1][number];
    const first = queueSnapshot(task.captureId, [row], now);
    expect(first.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(queueSnapshot(task.captureId, [row], now).digest)
      .toBe(first.digest);
  });
});
describe("integrity bulk triage validation", () => {
  const command = {
    taskId: task.id, action: "ASSIGN",
    expectedRevision: 1,
    recipientUserId: "owner-user-12345",
    note: "Assign the review to the available organization member.",
    idempotencyKey: "triage-assignment-12345",
  };
  it("parses assignment with recipient", () => {
    expect(parseTriageCommand(command)).toMatchObject(command);
  });
  it("defaults batch to safe preview", () => {
    expect(parseTriageBatch({ commands: [command] }))
      .toMatchObject({ dryRun: true, stopOnError: true });
  });
  it("accepts explicit committed batch", () => {
    expect(parseTriageBatch({
      commands: [command], dryRun: false, stopOnError: false,
    })).toMatchObject({ dryRun: false, stopOnError: false });
  });
  it.each([
    { action: "DELETE" }, { expectedRevision: 0 },
    { note: "short" }, { idempotencyKey: "short" },
    { recipientUserId: "bad" }, { unexpected: true },
  ])("rejects malformed triage command %j", patch => {
    expect(() => parseTriageCommand({ ...command, ...patch })).toThrow();
  });
  it("rejects assigning without a recipient", () => {
    const { recipientUserId: _recipient, ...missing } = command;
    expect(() => parseTriageCommand(missing)).toThrow();
  });
  it("rejects duplicate command idempotency keys", () => {
    expect(() => parseTriageBatch({
      commands: [command, command],
    })).toThrow();
  });
  it("rejects oversized batches", () => {
    expect(() => parseTriageBatch({
      commands: Array.from({ length: 51 }, (_, index) => ({
        ...command, idempotencyKey: "triage-" + index + "-123456789",
      })),
    })).toThrow();
  });
});
describe("integrity operations time series", () => {
  it("defaults to a 30-day window", () => {
    const query = parseOperationsMetricsQuery({}, now);
    expect(query.to).toEqual(now);
    expect(query.from.getTime()).toBe(now.getTime() - 30 * 86400000);
  });
  it("groups weeks by UTC Monday", () => {
    expect(metricsPeriod(new Date("2026-11-03T12:00:00Z"), "WEEK"))
      .toBe("2026-11-02");
  });
  it("groups days in UTC", () => {
    expect(metricsPeriod(now, "DAY")).toBe("2026-11-03");
  });
  it("rolls up independent event categories", () => {
    const query = parseOperationsMetricsQuery({
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-04T00:00:00.000Z",
    }, now);
    const result = rollupMetrics(query, {
      tasks: [{
        createdAt: now, disposition: "RESOLVED", completedAt: now,
      }],
      escalations: [{
        openedAt: now, acknowledgedAt: now,
        resolvedAt: now, state: "RESOLVED",
      }],
      notifications: [{
        createdAt: now, readAt: now, dismissedAt: null,
      }],
      checks: [
        { checkedAt: now, outcome: "PASS" },
        { checkedAt: now, outcome: "FAIL" },
      ],
    });
    expect(result.summary).toMatchObject({
      tasksCreated: 1, reviewsResolved: 1,
      escalationsOpened: 1, notificationsCreated: 1,
      providerChecks: 2, providerPassed: 1, providerFailed: 1,
    });
    expect(result.periods).toHaveLength(1);
  });
  it.each([
    { interval: "MONTH" }, { limit: 0 },
    { from: "invalid" },
    { from: "2026-11-03T12:00:00.000Z", to: "2026-11-03T12:00:00.000Z" },
    { from: "2024-01-01T00:00:00.000Z" },
    { unknown: true },
  ])("rejects invalid metrics query %j", input => {
    expect(() => parseOperationsMetricsQuery(input, now)).toThrow();
  });
});


describe("database-scoped integrity queue filters", () => {
  const instant = new Date("2026-11-03T12:00:00.000Z");
  const policy = parseQueueQuery({});
  it("does not add a predicate without a bucket", () => {
    expect(queueBucketPredicate(policy, instant)).toEqual({});
  });
  it("filters terminal states directly before pagination", () => {
    expect(queueBucketPredicate(parseQueueQuery({ bucket: "COMPLETED" }), instant))
      .toEqual({ disposition: "RESOLVED" });
    expect(queueBucketPredicate(parseQueueQuery({ bucket: "WAIVED" }), instant))
      .toEqual({ disposition: "WAIVED" });
  });
  it("derives severity-dependent overdue boundaries", () => {
    const result = queueBucketPredicate(
      parseQueueQuery({ bucket: "OVERDUE" }), instant);
    expect(result).toMatchObject({ OR: [
      { severity: "ERROR", createdAt: { lte: new Date("2026-11-03T00:00:00.000Z") } },
      { severity: "WARNING", createdAt: { lte: new Date("2026-11-01T12:00:00.000Z") } },
      { severity: "INFO", createdAt: { lte: new Date("2026-10-29T12:00:00.000Z") } },
    ] });
  });
  it("restricts unassigned tasks to reviews not due soon", () => {
    const result = queueBucketPredicate(
      parseQueueQuery({ bucket: "UNASSIGNED" }), instant);
    expect(result).toMatchObject({ ownerUserId: null });
    expect(result.OR).toHaveLength(3);
  });
  it("requires an assignee for in-progress and awaiting states", () => {
    for (const bucket of ["IN_PROGRESS", "AWAITING_REVIEW"]) {
      const result = queueBucketPredicate(
        parseQueueQuery({ bucket }), instant);
      expect(result.ownerUserId).toEqual({ not: null });
      expect(result.OR).toHaveLength(3);
    }
  });
  it("uses stable SQL ordering for chronological pagination", () => {
    expect(queueDatabaseOrder(parseQueueQuery({ sort: "NEWEST" }))).toEqual([
      { createdAt: "desc" }, { id: "desc" },
    ]);
    expect(queueDatabaseOrder(parseQueueQuery({ sort: "OLDEST" }))).toEqual([
      { createdAt: "asc" }, { id: "asc" },
    ]);
  });
});
