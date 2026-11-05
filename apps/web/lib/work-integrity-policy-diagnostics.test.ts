import { describe, expect, it } from "vitest";
import {
  parseSimulationQuery, simulateEscalationTask,
  buildSimulationReport,
} from "./work-integrity-escalation-simulation";
import {
  parseAgingQuery, mapAgingNotification,
  buildAgingReport, agingBucket,
} from "./work-integrity-notification-aging";

const now = new Date("2026-11-03T12:00:00.000Z");
const task = {
  id: "review-task-12345",
  captureId: "capture-12345",
  title: "Review operational evidence",
  severity: "ERROR",
  disposition: "OPEN",
  ownerUserId: "user-12345",
  createdAt: new Date("2026-11-01T12:00:00.000Z"),
  completedAt: null,
  revision: 1,
};
describe("escalation policy simulation", () => {
  const query = parseSimulationQuery({
    captureId: "capture-12345",
    horizonHours: 0,
  });
  it("proposes overdue escalation without persisting anything", () => {
    const proposal = simulateEscalationTask(
      task, [], query.policy, now,
    );
    expect(proposal.status).toBe("ELIGIBLE");
    expect(proposal.proposedLevel).toBe(1);
    expect(proposal.overdueHours).toBeGreaterThan(0);
    expect(proposal.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
  it("does not propose escalation for unassigned tasks", () => {
    const proposal = simulateEscalationTask(
      { ...task, ownerUserId: null }, [],
      query.policy, now,
    );
    expect(proposal.status).toBe("MISSING_OWNER");
    expect(proposal.proposedLevel).toBeNull();
  });
  it("does not propose escalation when another escalation is active", () => {
    const proposal = simulateEscalationTask(task, [{
      id: "escalation-12345", taskId: task.id,
      level: 1, state: "OPEN",
      openedAt: now, dueAt: now,
      resolvedAt: null, acknowledgedAt: null,
    }], query.policy, now);
    expect(proposal.status).toBe("ACTIVE_ESCALATION");
  });
  it("does not propose escalation for completed review", () => {
    const proposal = simulateEscalationTask({
      ...task, disposition: "RESOLVED", completedAt: now,
    }, [], query.policy, now);
    expect(proposal.status).toBe("CLOSED");
  });
  it("returns deterministic simulation page digests", () => {
    const a = buildSimulationReport(
      "org-12345", query, [task], [], 2, now, false,
    );
    const b = buildSimulationReport(
      "org-12345", query, [task], [], 2, now, false,
    );
    expect(a.digest).toBe(b.digest);
    expect(a.eligible).toBe(1);
    expect(a.hasMore).toBe(true);
    expect(a.complete).toBe(true);
  });
  it.each([
    { limit: 101 }, { offset: -1 },
    { horizonHours: 721 }, { includeClosed: "yes" },
    { policy: { maxLevel: 0 } }, { unexpected: true },
  ])("rejects unsafe policy query %j", patch => {
    expect(() => parseSimulationQuery(patch)).toThrow();
  });
});
describe("notification aging", () => {
  const record = {
    id: "notification-12345",
    taskId: task.id,
    recipientUserId: "user-12345",
    kind: "REVIEW_ASSIGNED",
    createdAt: new Date("2026-11-01T12:00:00.000Z"),
    readAt: null,
    dismissedAt: null,
    revision: 1,
  };
  const query = parseAgingQuery({
    captureId: "capture-12345", minAgeHours: 24,
    groupBy: "AGE_BUCKET",
  });
  it("classifies age boundaries", () => {
    expect(agingBucket(23)).toBe("UNDER_1_DAY");
    expect(agingBucket(24)).toBe("ONE_TO_THREE_DAYS");
    expect(agingBucket(72)).toBe("THREE_TO_SEVEN_DAYS");
    expect(agingBucket(168)).toBe("OVER_SEVEN_DAYS");
  });
  it("pseudonymizes recipients and detects invalid chronology", () => {
    const mapped = mapAgingNotification({
      ...record,
      readAt: new Date("2026-10-31T12:00:00.000Z"),
    }, now);
    expect(mapped.recipientHash).toMatch(/^[0-9a-f]{64}$/);
    expect(mapped.recipientHash).not.toBe(record.recipientUserId);
    expect(mapped.anomalies).toContain("READ_BEFORE_CREATION");
  });
  it("aggregates page buckets with explicit scope", () => {
    const report = buildAgingReport(
      "org-12345", query, [record], 2, now,
    );
    expect(report.hasMore).toBe(true);
    expect(report.buckets[0]?.count).toBe(1);
    expect(report.buckets[0]?.unread).toBe(1);
    expect(report.buckets[0]?.olderThan24Hours).toBe(1);
    expect(report.digest).toMatch(/^[0-9a-f]{64}$/);
  });
  it.each([
    { limit: 501 }, { offset: -1 },
    { minAgeHours: 100, maxAgeDays: 1 },
    { includeRead: "true" },
    { groupBy: "UNKNOWN" }, { other: "field" },
  ])("rejects invalid aging query %j", patch => {
    expect(() => parseAgingQuery(patch)).toThrow();
  });
});
