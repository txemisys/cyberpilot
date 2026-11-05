import { describe, expect, it } from "vitest";
import {
  parseEventReconcileInput, eventRecipients,
  reviewEventNotice, providerEventNotice,
  planEventNotifications, groupEventReconcileRows,
} from "./work-integrity-event-notifications";
import {
  parseNotificationInspectionInput,
  classifyNotificationSource, inspectNotificationRecord,
  summarizeNotificationInspection,
} from "./work-integrity-notification-inspection";

const now = new Date("2026-11-03T12:00:00.000Z");
const task = {
  id: "review-task-12345",
  title: "Enforce MFA",
  severity: "ERROR",
  ownerUserId: "user-member-12345",
  disposition: "IN_REVIEW",
};
const members = [
  { userId: "user-admin-12345", role: "ADMIN" },
  { userId: "user-member-12345", role: "MEMBER" },
  { userId: "user-auditor-12345", role: "AUDITOR" },
];
const review = {
  id: "review-event-12345",
  taskId: task.id,
  action: "RESOLVE",
  after: "RESOLVED",
  revisionAfter: 4,
  occurredAt: now,
};
const provider = {
  id: "provider-check-12345",
  taskId: task.id,
  outcome: "FAIL",
  provider: "GOOGLE_WORKSPACE",
  controlId: "google_workspace.user_2sv",
  checkedAt: now,
};
describe("phase 3C event reconciliation planning", () => {
  it("defaults to preview and bounded task page", () => {
    expect(parseEventReconcileInput({ captureId: "capture-12345" }))
      .toMatchObject({
        dryRun: true, limit: 25, offset: 0,
        includeReviewEvents: true, includeProviderChecks: true,
      });
  });
  it.each([
    { dryRun: "false" }, { limit: 101 }, { maxNotifications: 1001 },
    { offset: -1 }, { includeReviewEvents: false, includeProviderChecks: false },
    { unknown: "field" },
  ])("rejects invalid reconciliation input %j", patch => {
    expect(() => parseEventReconcileInput({
      captureId: "capture-12345", ...patch,
    })).toThrow();
  });
  it("selects only assignee and organization administrators", () => {
    expect(eventRecipients(members, task)).toEqual([
      "user-admin-12345", "user-member-12345",
    ]);
    expect(eventRecipients(members, {
      ...task, ownerUserId: "not-a-member-12345",
    })).toEqual(["user-admin-12345"]);
  });
  it("creates human-resolution notices without implying verification", () => {
    const notice = reviewEventNotice(review, task, members[0]!.userId);
    expect(notice?.kind).toBe("REVIEW_RESOLVED");
    expect(notice?.message).toContain("does not certify");
    expect(notice?.dedupeKey).toMatch(/^event:review:/);
    expect(reviewEventNotice({
      ...review, action: "ACKNOWLEDGE",
    }, task, members[0]!.userId)).toBeNull();
  });
  it("creates provider failure notices with provenance", () => {
    const notice = providerEventNotice(provider, task, members[0]!.userId);
    expect(notice).toMatchObject({
      source: "PROVIDER", kind: "PROVIDER_FAILURE",
      context: {
        source: "PROVIDER_CHECK", sourceId: provider.id,
        outcome: "FAIL",
      },
    });
  });
  it("does not report inconclusive provider checks as passed", () => {
    expect(providerEventNotice({
      ...provider, outcome: "ERROR",
    }, task, members[0]!.userId)).toBeNull();
  });
  it("creates deterministic per-recipient dedupe keys", () => {
    const first = planEventNotifications(
      [task], members, [review], [provider],
    );
    const second = planEventNotifications(
      [task], members, [review], [provider],
    );
    expect(first.notices).toEqual(second.notices);
    expect(first.notices).toHaveLength(4);
    const keys = new Set(first.notices.map(
      row => row.dedupeKey + ":" + row.recipientUserId,
    ));
    expect(keys.size).toBe(4);
    const outcomes = new Map(first.notices.map((row, index) => [
      row.dedupeKey + ":" + row.recipientUserId,
      { id: "notification-" + index, replayed: index % 2 === 0 },
    ]));
    const rows = groupEventReconcileRows(first.notices, outcomes);
    expect(rows).toHaveLength(2);
    expect(rows.reduce((n, row) => n + row.recipients, 0)).toBe(4);
    expect(rows.reduce((n, row) => n + row.created, 0)).toBe(2);
  });
});
describe("phase 3C notification provenance inspection", () => {
  const notification = {
    id: "notification-12345",
    taskId: task.id,
    recipientUserId: members[0]!.userId,
    kind: "PROVIDER_FAILURE",
    dedupeKey: "event:provider:abcdef123456",
    createdAt: now,
    readAt: null,
    dismissedAt: null,
    revision: 1,
    context: {
      source: "PROVIDER_CHECK",
      sourceId: provider.id,
    },
  };
  const audit = {
    id: "audit-12345",
    resourceId: notification.id,
    action: "integrity.notification.event_reconciled",
    occurredAt: now,
    metadata: {
      taskId: task.id,
      recipientUserId: notification.recipientUserId,
      kind: notification.kind,
      dedupeKey: notification.dedupeKey,
      delivery: "IN_APP",
    },
  };
  it("classifies provider provenance", () => {
    expect(classifyNotificationSource(notification)).toEqual({
      source: "PROVIDER", sourceId: provider.id,
    });
  });
  it("accepts a complete audit and source linkage", () => {
    const row = inspectNotificationRecord(
      notification, [audit], true, true,
      { id: provider.id, taskId: task.id, outcome: "FAIL" },
    );
    expect(row.consistent).toBe(true);
    expect(row.issues).toEqual([]);
  });
  it("reports a missing provider observation", () => {
    const row = inspectNotificationRecord(
      notification, [audit], true, true, null,
    );
    expect(row.issues).toContain("SOURCE_NOT_FOUND");
  });
  it("reports cross-task source mismatch", () => {
    const row = inspectNotificationRecord(
      notification, [audit], true, true,
      { id: provider.id, taskId: "other-task-12345", outcome: "FAIL" },
    );
    expect(row.issues).toContain("SOURCE_TASK_MISMATCH");
  });
  it("reports missing audit and revoked recipient membership", () => {
    const row = inspectNotificationRecord(
      notification, [], true, false,
      { id: provider.id, taskId: task.id, outcome: "FAIL" },
    );
    expect(row.issues).toContain("CREATION_AUDIT_MISSING");
    expect(row.issues).toContain("RECIPIENT_NOT_MEMBER");
  });
  it("rejects malformed inspection filters", () => {
    expect(() => parseNotificationInspectionInput({
      offset: -1,
    })).toThrow();
    expect(() => parseNotificationInspectionInput({
      includeDismissed: "yes",
    })).toThrow();
  });
  it("builds a stable report digest and issue counts", () => {
    const query = parseNotificationInspectionInput({});
    const row = inspectNotificationRecord(
      notification, [], true, true, null,
    );
    const report = summarizeNotificationInspection([row], query, 2);
    expect(report.inconsistent).toBe(1);
    expect(report.issueCounts.SOURCE_NOT_FOUND).toBe(1);
    expect(report.hasMore).toBe(true);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(summarizeNotificationInspection([row], query, 2).digest)
      .toBe(report.digest);
  });
});
