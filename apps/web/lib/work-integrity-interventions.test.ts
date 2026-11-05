import { describe, expect, it } from "vitest";
import {
  parseInterventionCommand, parseInterventionInput, evaluateIntervention,
  interventionResponse, interventionHash, triageAction, interventionResult,
} from "./work-integrity-interventions";
import {
  parseInterventionHistoryQuery, mapInterventionAuditEvent,
  buildInterventionHistoryReport, groupInterventionHistory,
  interventionHistoryDigest,
} from "./work-integrity-intervention-history";

const now = new Date("2026-11-05T12:00:00.000Z");
const command = {
  taskId: "task-12345", kind: "REMIND_OWNER" as const,
  expectedRevision: 2, expectedOwnerUserId: "owner-12345",
  note: "Follow up on this overdue integrity review.",
  idempotencyKey: "review-reminder-12345",
};
const task = {
  id: "task-12345", captureId: "capture-12345", severity: "ERROR",
  disposition: "IN_REVIEW", ownerUserId: "owner-12345",
  revision: 2, createdAt: new Date("2026-11-01T12:00:00.000Z"),
};
const context = {
  task, members: [
    { userId: "owner-12345", role: "MEMBER" },
    { userId: "admin-12345", role: "ADMIN" },
  ], openReminders: 1, now,
};
describe("operator interventions", () => {
  it("parses an explicit admin batch with dry-run default", () => {
    expect(parseInterventionInput({
      captureId: "capture-12345", commands: [command],
    })).toMatchObject({ dryRun: true, stopOnError: true });
  });
  it("requires prior owner even when unassigned", () => {
    expect(() => parseInterventionCommand({
      ...command, expectedOwnerUserId: undefined,
    })).toThrow();
    expect(parseInterventionCommand({
      ...command, expectedOwnerUserId: null,
    }).expectedOwnerUserId).toBeNull();
  });
  it("rejects malformed and unbounded commands", () => {
    for (const patch of [
      { expectedRevision: 0 }, { note: "short" },
      { kind: "DELETE" }, { idempotencyKey: "x" },
      { unexpected: true }, { taskId: "../bad" },
      { expectedOwnerUserId: "?" },
    ]) expect(() => parseInterventionCommand({
      ...command, ...patch,
    })).toThrow();
  });
  it("requires a valid recipient only for assignments", () => {
    expect(() => parseInterventionCommand({
      ...command, kind: "ASSIGN_OWNER",
    })).toThrow();
    expect(() => parseInterventionCommand({
      ...command, assigneeUserId: "other-12345",
    })).toThrow();
    expect(parseInterventionCommand({
      ...command, kind: "ASSIGN_OWNER", assigneeUserId: "other-12345",
    }).assigneeUserId).toBe("other-12345");
  });
  it("rejects duplicate keys and overlapping operations", () => {
    expect(() => parseInterventionInput({
      captureId: "capture-12345",
      commands: [command, command],
    })).toThrow();
    expect(() => parseInterventionInput({
      captureId: "capture-12345",
      commands: [{ ...command }, {
        ...command, idempotencyKey: "another-reminder-key-12345",
      }],
    })).toThrow();
  });
  it("rejects more than 25 commands", () => {
    expect(() => parseInterventionInput({
      captureId: "capture-12345",
      commands: Array.from({ length: 26 }, (_, i) => ({
        ...command, taskId: "task-" + String(i).padStart(5, "0"),
        idempotencyKey: "reminder-key-" + i + "-1234567890",
      })),
    })).toThrow();
  });
  it("recognizes eligibility and stable canonical fingerprint", () => {
    const first = evaluateIntervention(command, context);
    const second = evaluateIntervention(command, context);
    expect(first.eligible).toBe(true);
    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.dueAt).toBe("2026-11-02T00:00:00.000Z");
  });
  it("blocks terminal reviews, stale revision and owner changes", () => {
    expect(evaluateIntervention(command, {
      ...context, task: { ...task, disposition: "RESOLVED" },
    }).eligible).toBe(false);
    expect(evaluateIntervention(command, {
      ...context, task: { ...task, revision: 3 },
    }).reason).toMatch(/revision/i);
    expect(evaluateIntervention(command, {
      ...context, task: { ...task, ownerUserId: null },
    }).reason).toMatch(/owner/i);
  });
  it("rejects assignment to an unrecognized organization member", () => {
    expect(evaluateIntervention({
      ...command, kind: "ASSIGN_OWNER", assigneeUserId: "external-12345",
    }, context).eligible).toBe(false);
  });
  it("prevents notifications to absent recipients", () => {
    expect(evaluateIntervention(command, {
      ...context, members: [],
    }).eligible).toBe(false);
    expect(evaluateIntervention({
      ...command, kind: "NOTIFY_ADMINS",
    }, { ...context, members: [] }).eligible).toBe(false);
  });
  it("does not clear nonexisting reminders", () => {
    const result = evaluateIntervention({
      ...command, kind: "CLEAR_REMINDERS",
    }, { ...context, openReminders: 0 });
    expect(result.eligible).toBe(false);
  });
  it("maps actions to existing audited triage contracts", () => {
    expect(triageAction("REMIND_OWNER")).toBe("SET_DUE_REMINDER");
    expect(triageAction("ASSIGN_OWNER")).toBe("ASSIGN");
    expect(triageAction("UNASSIGN_OWNER")).toBe("UNASSIGN");
    expect(triageAction("NOTIFY_ADMINS")).toBe("NOTIFY_ADMINS");
  });
  it("aggregates command results without claiming external delivery", () => {
    const input = parseInterventionInput({
      captureId: "capture-12345", commands: [command],
    });
    const report = interventionResponse("org-12345", input, [
      interventionResult(command, "PREVIEW", "No writes.", null, 2),
    ]);
    expect(report.previewed).toBe(1);
    expect(report.applied).toBe(0);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(interventionHash(report.results)).toMatch(/^[a-f0-9]{64}$/);
  });
});
const audit = {
  id: "audit-12345", action: "integrity.triage.assign",
  resourceId: "task-12345", actorUserId: "admin-12345",
  occurredAt: now,
  metadata: {
    idempotencyKey: "triage:reminder-key-12345",
    revisionBefore: 2, revisionAfter: 2,
    previousOwner: null, nextOwner: "owner-12345",
    recipientCount: 1, notificationCount: 1,
    note: "Reviewed the case for a new assignee.",
  },
};
describe("intervention audit history", () => {
  it("requires bounded valid dates and filters", () => {
    expect(parseInterventionHistoryQuery({
      captureId: "capture-12345",
    })).toMatchObject({ limit: 50, offset: 0 });
    for (const patch of [
      { limit: 201 }, { offset: -1 }, { action: "DELETE" },
      { includeReplays: "yes" }, { invalid: 1 },
      { from: "yesterday" }, { taskId: "?" },
    ]) expect(() => parseInterventionHistoryQuery({
      captureId: "capture-12345", ...patch,
    })).toThrow();
  });
  it("pseudonymizes actor and owner identifiers", () => {
    const entry = mapInterventionAuditEvent(audit, new Set());
    expect(entry.actorHash).toMatch(/^[a-f0-9]{64}$/);
    expect(entry.nextOwnerHash).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(entry)).not.toContain("owner-12345");
    expect(entry.anomalies).toEqual([]);
  });
  it("detects duplicate idempotency keys within the page", () => {
    const seen = new Set<string>();
    mapInterventionAuditEvent(audit, seen);
    const second = mapInterventionAuditEvent({
      ...audit, id: "audit-54321",
    }, seen);
    expect(second.anomalies).toContain("DUPLICATE_AUDIT_KEY_ON_PAGE");
  });
  it("flags invalid revision changes or missing reasons", () => {
    const event = mapInterventionAuditEvent({
      ...audit, metadata: {
        ...(audit.metadata), revisionAfter: 3, note: null,
      },
    }, new Set());
    expect(event.anomalies).toContain("TRIAGE_CHANGED_REVIEW_REVISION");
    expect(event.anomalies).toContain("MISSING_AUDIT_REASON");
  });
  it("groups audit actions and counts historical notifications", () => {
    const events = [
      mapInterventionAuditEvent(audit, new Set()),
      mapInterventionAuditEvent({
        ...audit, id: "audit-54321",
        action: "integrity.triage.notify_owner",
      }, new Set()),
    ];
    expect(groupInterventionHistory(events)).toMatchObject([{
      taskId: "task-12345", actions: 2, notifications: 2,
      assignments: 1, notices: 1,
    }]);
  });
  it("makes deterministic, explicitly page-scoped reports", () => {
    const query = parseInterventionHistoryQuery({
      captureId: "capture-12345",
    });
    const report = buildInterventionHistoryReport(
      "org-12345", query, [audit], 2, now);
    expect(report.hasMore).toBe(true);
    expect(report.complete).toBe(false);
    expect(report.groups).toHaveLength(1);
    expect(report.digest).toBe(buildInterventionHistoryReport(
      "org-12345", query, [audit], 2, now).digest);
    expect(interventionHistoryDigest(report.entries))
      .toMatch(/^[a-f0-9]{64}$/);
  });
});
