import { describe, expect, it } from "vitest";
import {
  parseManifestQuery, manifestDigest,
  canonicalManifestEntries, mapManifestRecords,
  buildManifestPage,
} from "./work-integrity-operations-manifest";
import {
  parseDeliveryDiagnosticsQuery, rollupDeliveryDiagnostics,
} from "./work-integrity-delivery-diagnostics";

const now = new Date("2026-11-03T12:00:00.000Z");
const task = {
  id: "review-task-12345",
  title: "Review MFA evidence",
  severity: "ERROR",
  disposition: "IN_REVIEW",
  revision: 3,
  ownerUserId: "user-12345",
  createdAt: new Date("2026-11-02T10:00:00.000Z"),
  updatedAt: now,
  completedAt: null,
};
describe("phase 3C operational manifest", () => {
  it("parses a bounded default page", () => {
    expect(parseManifestQuery({
      captureId: "capture-12345",
    })).toMatchObject({
      limit: 20, offset: 0,
      includeProviderObservations: true,
      includeNotificationMetadata: true,
    });
  });
  it.each([
    { limit: 0 }, { limit: 51 },
    { offset: -1 }, { includeReviewEvents: "true" },
    { unexpected: "data" },
  ])("rejects invalid manifest request %j", patch => {
    expect(() => parseManifestQuery({
      captureId: "capture-12345", ...patch,
    })).toThrow();
  });
  it("maps all five record categories without raw payloads", () => {
    const entries = mapManifestRecords({
      tasks: [task],
      reviewEvents: [{
        id: "review-event-12345", taskId: task.id,
        action: "ACKNOWLEDGE", before: "OPEN", after: "IN_REVIEW",
        actorUserId: "user-12345", revisionAfter: 2, occurredAt: now,
      }],
      notifications: [{
        id: "notification-12345", taskId: task.id,
        kind: "REVIEW_ASSIGNED", recipientUserId: "user-12345",
        revision: 1, createdAt: now, readAt: null,
        dismissedAt: null, dedupeKey: "notification-dedupe-12345",
      }],
      escalations: [{
        id: "escalation-12345", taskId: task.id,
        level: 1, state: "OPEN", revision: 1,
        openedAt: now, dueAt: now,
        actorUserId: "user-12345",
        acknowledgedAt: null, resolvedAt: null,
      }],
      checks: [{
        id: "provider-check-12345", taskId: task.id,
        provider: "GOOGLE_WORKSPACE", outcome: "FAIL",
        controlId: "google_workspace.user_2sv",
        subject: "person@example.invalid", checkedAt: now,
        providerObservedAt: now, requestDigest: "a".repeat(64),
        observationDigest: "b".repeat(64),
        responseDigest: "c".repeat(64), failureCode: null,
      }],
    });
    expect(entries).toHaveLength(5);
    expect(new Set(entries.map(entry => entry.category)).size).toBe(5);
    const serialized = JSON.stringify(entries);
    expect(serialized).not.toContain("person@example.invalid");
    expect(serialized).not.toContain("notification-dedupe-12345");
    expect(serialized).not.toContain("Review MFA evidence");
  });
  it("creates deterministic page digests irrespective of entry order", () => {
    const query = parseManifestQuery({ captureId: "capture-12345" });
    const entries = mapManifestRecords({
      tasks: [task],
      reviewEvents: [], notifications: [],
      escalations: [], checks: [],
    });
    const first = buildManifestPage(
      "org-12345", query, 2, [task.id], entries, now, [],
    );
    const second = buildManifestPage(
      "org-12345", query, 2, [task.id],
      [...entries].reverse(), now, [],
    );
    expect(first.pageDigest).toBe(second.pageDigest);
    expect(first.hasMore).toBe(true);
    expect(first.complete).toBe(true);
    expect(first.counts.REVIEW).toBe(1);
    expect(first.pageDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(canonicalManifestEntries(entries)).toEqual(entries);
    expect(manifestDigest({ x: 1 })).toBe(manifestDigest({ x: 1 }));
  });
  it("marks source truncation as incomplete", () => {
    const query = parseManifestQuery({ captureId: "capture-12345" });
    const page = buildManifestPage(
      "org-12345", query, 1, [task.id], [], now,
      ["Provider check query reached its cap."],
    );
    expect(page.complete).toBe(false);
    expect(page.warnings.join(" ")).toContain("cap");
  });
});
describe("phase 3C in-app delivery diagnostics", () => {
  const query = parseDeliveryDiagnosticsQuery({
    from: "2026-11-01T00:00:00.000Z",
    to: "2026-11-04T00:00:00.000Z",
    groupBy: "KIND",
  }, now);
  const records = [
    {
      id: "notification-1", taskId: task.id,
      recipientUserId: "user-12345",
      kind: "REVIEW_ASSIGNED",
      createdAt: new Date("2026-11-02T12:00:00.000Z"),
      readAt: new Date("2026-11-02T13:00:00.000Z"),
      dismissedAt: null, revision: 2,
    },
    {
      id: "notification-2", taskId: task.id,
      recipientUserId: "user-23456",
      kind: "REVIEW_ASSIGNED",
      createdAt: new Date("2026-11-02T14:00:00.000Z"),
      readAt: null, dismissedAt: null, revision: 1,
    },
    {
      id: "notification-3", taskId: task.id,
      recipientUserId: "user-12345",
      kind: "REVIEW_ESCALATED",
      createdAt: new Date("2026-11-03T10:00:00.000Z"),
      readAt: new Date("2026-11-03T11:00:00.000Z"),
      dismissedAt: now, revision: 3,
    },
  ];
  it("aggregates read, unread and dismissed without external delivery claims", () => {
    const report = rollupDeliveryDiagnostics(query, records, 3);
    expect(report.total).toBe(3);
    expect(report.summary).toMatchObject({
      total: 3, unread: 1, read: 2,
      dismissed: 1, readWithin24Hours: 2,
      uniqueRecipients: 2, uniqueTasks: 1,
    });
    expect(report.buckets).toHaveLength(2);
    expect(report.truncated).toBe(false);
    expect(report.digest).toMatch(/^[0-9a-f]{64}$/);
  });
  it("reports query truncation and stable digests", () => {
    const report = rollupDeliveryDiagnostics(query, records, 200);
    expect(report.truncated).toBe(true);
    expect(rollupDeliveryDiagnostics(query, records, 200).digest)
      .toBe(report.digest);
  });
  it("hashes recipient grouping rather than returning email or user ID", () => {
    const byRecipient = { ...query, groupBy: "RECIPIENT" as const };
    const report = rollupDeliveryDiagnostics(byRecipient, records, 3);
    expect(report.buckets).toHaveLength(2);
    expect(report.buckets.every(bucket =>
      /^[0-9a-f]{64}$/.test(bucket.key),
    )).toBe(true);
  });
  it.each([
    { groupBy: "UNKNOWN" },
    { limit: 20001 },
    { includeDismissed: "false" },
    { from: "2026-11-04T00:00:00.000Z",
      to: "2026-11-01T00:00:00.000Z" },
  ])("rejects invalid diagnostics query %j", patch => {
    expect(() => parseDeliveryDiagnosticsQuery({
      ...patch,
    }, now)).toThrow();
  });
});
