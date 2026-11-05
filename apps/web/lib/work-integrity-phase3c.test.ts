import { describe, expect, it } from "vitest";
import {
  parseInboxFilter, parseNotificationCommand, parseNotificationPublish,
  notificationFingerprint,
} from "./work-integrity-notifications";
import {
  calculateEscalationCandidate, escalationNextState,
  parseEscalationPolicy, parseEscalationCommand,
} from "./work-integrity-escalations";
import {
  parseDispatchInput, selectEscalationRecipients,
  dispatchNotificationContent,
} from "./work-integrity-escalation-dispatch";

const taskId = "review-task-12345";
const recipientUserId = "recipient-user-12345";
const publish = {
  taskId, recipientUserId, kind: "REVIEW_OVERDUE",
  dedupeKey: "review-overdue-task-12345",
  title: "Overdue integrity review",
  message: "The integrity review needs attention.",
  context: { severity: "ERROR", level: 1 },
};
describe("integrity in-app notification validation", () => {
  it("parses a bounded inbox query", () => {
    expect(parseInboxFilter({})).toEqual({
      unreadOnly: false, includeDismissed: false,
      offset: 0, limit: 50,
    });
  });
  it("parses an explicit inbox filter", () => {
    expect(parseInboxFilter({
      taskId, unreadOnly: true, kind: "REVIEW_ESCALATED",
      includeDismissed: true, offset: 2, limit: 10,
    })).toMatchObject({
      taskId, unreadOnly: true, kind: "REVIEW_ESCALATED",
      includeDismissed: true, offset: 2, limit: 10,
    });
  });
  it.each([
    { unreadOnly: "true" }, { includeDismissed: "false" },
    { offset: -1 }, { offset: "0" }, { limit: 0 },
    { limit: 101 }, { kind: "UNKNOWN" }, { unexpected: true },
  ])("rejects invalid inbox query %j", patch => {
    expect(() => parseInboxFilter(patch)).toThrow();
  });
  it("accepts a notification publish request", () => {
    expect(parseNotificationPublish(publish).context).toEqual(publish.context);
  });
  it.each([
    { taskId: "bad" }, { recipientUserId: "bad" },
    { kind: "INVALID" }, { dedupeKey: "short" },
    { title: "" }, { message: "\n" },
    { context: { invalid: [] } },
    { context: { "invalid-key": true } },
    { extra: true },
  ])("rejects invalid publish request %j", patch => {
    expect(() => parseNotificationPublish({
      ...publish, ...patch,
    })).toThrow();
  });
  it("fingerprints notification payload deterministically", () => {
    const parsed = parseNotificationPublish(publish);
    expect(notificationFingerprint(parsed)).toMatch(/^[a-f0-9]{64}$/);
    expect(notificationFingerprint(parsed)).toBe(notificationFingerprint(parsed));
    expect(notificationFingerprint({
      ...parsed, message: "Different content",
    })).not.toBe(notificationFingerprint(parsed));
  });
  it("parses optimistic concurrency command", () => {
    expect(parseNotificationCommand({
      notificationId: "notification-12345",
      action: "DISMISS", expectedRevision: 3,
    })).toEqual({
      notificationId: "notification-12345",
      action: "DISMISS", expectedRevision: 3,
    });
  });
  it.each([
    { action: "DELETE" }, { expectedRevision: 0 },
    { expectedRevision: "1" }, { notificationId: "bad" },
  ])("rejects invalid inbox command %j", patch => {
    expect(() => parseNotificationCommand({
      notificationId: "notification-12345",
      action: "READ", expectedRevision: 1, ...patch,
    })).toThrow();
  });
});
const now = new Date("2026-11-03T12:00:00Z");
const task = {
  id: taskId, severity: "ERROR",
  disposition: "OPEN", ownerUserId: recipientUserId,
  createdAt: new Date("2026-11-02T00:00:00Z"),
};
describe("review escalation thresholds", () => {
  const policy = parseEscalationPolicy(undefined);
  it("uses documented defaults", () => {
    expect(policy).toEqual({
      warningHours: 48, errorHours: 12,
      infoHours: 120, repeatHours: 24, maxLevel: 3,
    });
  });
  it("detects overdue ERROR review at level 2", () => {
    const candidate = calculateEscalationCandidate(task, now, policy);
    expect(candidate?.level).toBe(2);
    expect(candidate?.dedupeKey).toContain("level:2");
    expect(candidate?.overdueMinutes).toBeGreaterThan(0);
  });
  it("does not escalate a resolved or waived review", () => {
    for (const disposition of ["RESOLVED", "WAIVED"])
      expect(calculateEscalationCandidate({
        ...task, disposition,
      }, now, policy)).toBeNull();
  });
  it("does not escalate a task before its deadline", () => {
    expect(calculateEscalationCandidate({
      ...task, createdAt: now,
    }, now, policy)).toBeNull();
  });
  it("caps escalation levels", () => {
    const candidate = calculateEscalationCandidate({
      ...task, createdAt: new Date("2025-01-01T00:00:00Z"),
    }, now, policy);
    expect(candidate?.level).toBe(3);
  });
  it.each([
    { warningHours: 0 }, { errorHours: 9000 },
    { infoHours: "120" }, { repeatHours: -1 },
    { maxLevel: 6 }, { extra: true },
  ])("rejects invalid escalation policy %j", patch => {
    expect(() => parseEscalationPolicy(patch)).toThrow();
  });
  it("enforces the escalation state machine", () => {
    expect(escalationNextState("OPEN", "ACKNOWLEDGE"))
      .toBe("ACKNOWLEDGED");
    expect(escalationNextState("ACKNOWLEDGED", "RESOLVE"))
      .toBe("RESOLVED");
    expect(escalationNextState("RESOLVED", "REOPEN"))
      .toBe("OPEN");
    expect(() => escalationNextState("RESOLVED", "ACKNOWLEDGE")).toThrow();
    expect(() => escalationNextState("CANCELLED", "CANCEL")).toThrow();
  });
  it("requires a reason for an escalation transition", () => {
    expect(() => parseEscalationCommand({
      escalationId: "escalation-12345", action: "RESOLVE",
      expectedRevision: 1, reason: "short",
    })).toThrow();
  });
});
describe("explicit escalation dispatch", () => {
  it("defaults to a dry run", () => {
    expect(parseDispatchInput({ captureId: "capture-12345" }).dryRun)
      .toBe(true);
  });
  it("supports a bounded administrator-triggered batch", () => {
    expect(parseDispatchInput({
      captureId: "capture-12345", dryRun: false,
      offset: 20, limit: 30,
    })).toMatchObject({ dryRun: false, offset: 20, limit: 30 });
  });
  it("routes to owner and admins without duplicates", () => {
    const recipients = selectEscalationRecipients([
      { userId: recipientUserId, role: "MEMBER" },
      { userId: "admin-user-12345", role: "ADMIN" },
      { userId: "owner-user-12345", role: "OWNER" },
      { userId: "audit-user-12345", role: "AUDITOR" },
    ], recipientUserId);
    expect(recipients).toEqual([
      "admin-user-12345", "owner-user-12345", recipientUserId,
    ]);
  });
  it("never routes to a user outside the organization", () => {
    expect(selectEscalationRecipients([
      { userId: "admin-user-12345", role: "ADMIN" },
    ], "external-user-12345")).toEqual(["admin-user-12345"]);
  });
  it("renders actionable in-app content", () => {
    const content = dispatchNotificationContent({
      title: "Review 2SV", severity: "ERROR",
    }, 2, now);
    expect(content.title).toContain("L2");
    expect(content.message).toContain("Review 2SV");
  });
  it.each([
    { dryRun: "false" }, { limit: 101 },
    { offset: -1 }, { captureId: "bad" },
    { unknown: true },
  ])("rejects invalid dispatch %j", patch => {
    expect(() => parseDispatchInput({
      captureId: "capture-12345", ...patch,
    })).toThrow();
  });
});
