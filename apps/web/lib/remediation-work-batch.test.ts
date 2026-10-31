import { describe, expect, it } from "vitest";
import {
  MAX_WORK_BATCH, decideBatch, parseBatchRequest,
  type BatchChange, type BatchItem,
} from "./remediation-work-batch";
import { WorkInputError } from "./remediation-work-input";

const member = "user_alpha";
const other = "user_beta";
const itemId = "work_alpha";
const anotherId = "work_beta";
function work(overrides: Partial<BatchItem> = {}): BatchItem {
  return {
    id: itemId,
    organizationId: "organization_alpha",
    title: "Review tenant settings",
    revision: 2,
    status: "TODO",
    priority: "NORMAL",
    assigneeUserId: member,
    dueAt: null,
    completedAt: null,
    ...overrides,
  };
}
function change(overrides: Partial<BatchChange> = {}): BatchChange {
  return {
    id: itemId,
    revision: 2,
    field: "priority",
    value: "HIGH",
    ...overrides,
  };
}
function request(overrides: Record<string, unknown> = {}) {
  return {
    mode: "preview",
    changes: [{ id: itemId, revision: 2, field: "priority", value: "HIGH" }],
    reason: "Scheduling the next quarterly remediation review.",
    ...overrides,
  };
}
const members = new Set([member, other]);
function decisions(changes: BatchChange[], items = [work()]) {
  return decideBatch(changes, items, members);
}
function invalid(value: unknown) {
  expect(() => parseBatchRequest(value)).toThrow(WorkInputError);
}
describe("parseBatchRequest: input contract", () => {
  it("parses preview requests", () => {
    const result = parseBatchRequest(request());
    expect(result.mode).toBe("preview");
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]).toMatchObject({
      id: itemId, revision: 2, field: "priority", value: "HIGH",
    });
  });
  it("parses apply requests", () => {
    expect(parseBatchRequest(request({ mode: "apply" })).mode).toBe("apply");
  });
  it("trims a meaningful audit reason", () => {
    const parsed = parseBatchRequest(request({ reason: "   Operational handoff review   " }));
    expect(parsed.reason).toBe("Operational handoff review");
  });
  it.each([null, undefined, [], "bad", 42, true])(
    "rejects invalid top-level payload %s", value => invalid(value),
  );
  it.each(["", "previewed", "commit", null, 0, false])(
    "rejects an unsupported mode %s", mode => invalid(request({ mode })),
  );
  it("rejects unexpected top-level keys", () => {
    invalid(request({ overridePermissions: true }));
  });
  it("rejects missing changes", () => {
    invalid(request({ changes: undefined }));
  });
  it("rejects an empty change array", () => {
    invalid(request({ changes: [] }));
  });
  it("rejects more than the allowed batch size", () => {
    invalid(request({ changes: Array.from({ length: MAX_WORK_BATCH + 1 }, (_, index) => ({
      id: `work_${index.toString().padStart(4, "0")}`,
      revision: 1, field: "status", value: "TODO",
    })) }));
  });
  it("accepts exactly the allowed batch size", () => {
    const parsed = parseBatchRequest(request({
      changes: Array.from({ length: MAX_WORK_BATCH }, (_, index) => ({
        id: `work_${index.toString().padStart(4, "0")}`,
        revision: 1, field: "priority", value: "URGENT",
      })),
    }));
    expect(parsed.changes).toHaveLength(MAX_WORK_BATCH);
  });
  it.each(["", "short", " ".repeat(20), "x".repeat(1001), "a\u0001long enough"])(
    "rejects invalid audit reason", reason => invalid(request({ reason })),
  );
  it("rejects a non-text reason", () => {
    invalid(request({ reason: 123 }));
  });
  it("rejects missing revision", () => {
    invalid(request({ changes: [{ id: itemId, field: "status", value: "DONE" }] }));
  });
  it.each([0, -1, 0.5, 1.2, "2", null, 2147483648])(
    "rejects invalid revision %s", revision => {
      invalid(request({ changes: [{ id: itemId, revision, field: "status", value: "DONE" }] }));
    },
  );
  it("rejects a malformed ID", () => {
    invalid(request({ changes: [{ id: "../../secret", revision: 2, field: "status", value: "DONE" }] }));
  });
  it("rejects unexpected change properties", () => {
    invalid(request({ changes: [{
      id: itemId, revision: 2, field: "priority", value: "HIGH", organizationId: "other",
    }] }));
  });
  it.each(["title", "description", "verifiedAt", "findingStatus", "", null])(
    "rejects unsupported field %s", field => {
      invalid(request({ changes: [{ id: itemId, revision: 2, field, value: "HIGH" }] }));
    },
  );
  it.each(["OPEN", "RESOLVED", "VERIFIED", "SUCCEEDED", null, "done", ""])(
    "rejects an invalid work status %s", value => {
      invalid(request({ changes: [{ id: itemId, revision: 2, field: "status", value }] }));
    },
  );
  it.each(["CRITICAL", "NONE", "urgent", "", null, 2])(
    "rejects invalid work priority %s", value => {
      invalid(request({ changes: [{ id: itemId, revision: 2, field: "priority", value }] }));
    },
  );
  it.each(["2026-02-30", "2026-13-01", "yesterday", 123, {}, "1999-01-01"])(
    "rejects invalid due date %s", value => {
      invalid(request({ changes: [{ id: itemId, revision: 2, field: "dueAt", value }] }));
    },
  );
  it("accepts null due date", () => {
    const parsed = parseBatchRequest(request({ changes: [{
      id: itemId, revision: 2, field: "dueAt", value: null,
    }] }));
    expect(parsed.changes[0]?.value).toBeNull();
  });
  it("accepts valid leap-day due date", () => {
    const parsed = parseBatchRequest(request({ changes: [{
      id: itemId, revision: 2, field: "dueAt", value: "2028-02-29",
    }] }));
    expect(parsed.changes[0]?.value).toEqual(new Date("2028-02-29T12:00:00.000Z"));
  });
  it("accepts unassignment", () => {
    const parsed = parseBatchRequest(request({ changes: [{
      id: itemId, revision: 2, field: "assigneeUserId", value: null,
    }] }));
    expect(parsed.changes[0]?.value).toBeNull();
  });
  it("rejects duplicate fields for a work item", () => {
    invalid(request({ changes: [
      { id: itemId, revision: 2, field: "status", value: "TODO" },
      { id: itemId, revision: 2, field: "status", value: "DONE" },
    ] }));
  });
  it("rejects conflicting revisions for one work item", () => {
    invalid(request({ changes: [
      { id: itemId, revision: 2, field: "status", value: "TODO" },
      { id: itemId, revision: 3, field: "priority", value: "URGENT" },
    ] }));
  });
  it("accepts multiple distinct changes to one item at a common revision", () => {
    const parsed = parseBatchRequest(request({ changes: [
      { id: itemId, revision: 2, field: "status", value: "IN_PROGRESS" },
      { id: itemId, revision: 2, field: "priority", value: "HIGH" },
      { id: itemId, revision: 2, field: "assigneeUserId", value: member },
    ] }));
    expect(parsed.changes).toHaveLength(3);
  });
});
describe("decideBatch: optimistic revisions and tenant membership", () => {
  it("accepts a valid priority change", () => {
    expect(decisions([change()])[0]).toMatchObject({
      outcome: "READY", current: "NORMAL", proposed: "HIGH",
    });
  });
  it("detects an unchanged priority", () => {
    expect(decisions([change({ value: "NORMAL" })])[0]?.outcome).toBe("UNCHANGED");
  });
  it("rejects a stale revision", () => {
    expect(decisions([change({ revision: 1 })])[0]).toMatchObject({
      outcome: "STALE", revision: 1,
    });
  });
  it("rejects a missing work item without revealing another tenant", () => {
    const [result] = decisions([change({ id: "work_secret" })]);
    expect(result).toMatchObject({ outcome: "MISSING", current: null });
  });
  it("never returns another tenant's record in a scoped result", () => {
    const [result] = decisions([change({ id: anotherId })], [work()]);
    expect(result?.outcome).toBe("MISSING");
  });
  it("checks membership for assignment", () => {
    const [result] = decisions([change({
      field: "assigneeUserId", value: "user_outside",
    })]);
    expect(result?.outcome).toBe("INVALID");
  });
  it("accepts an organization member as an assignee", () => {
    const [result] = decisions([change({ field: "assigneeUserId", value: other })]);
    expect(result?.outcome).toBe("READY");
  });
  it("supports removing an assignee", () => {
    const [result] = decisions([change({ field: "assigneeUserId", value: null })]);
    expect(result).toMatchObject({ current: member, proposed: null, outcome: "READY" });
  });
  it("recognizes unchanged unassigned records", () => {
    const [result] = decisions([change({ field: "assigneeUserId", value: null })],
      [work({ assigneeUserId: null })]);
    expect(result?.outcome).toBe("UNCHANGED");
  });
  it("recognizes an empty due date as unchanged", () => {
    const [result] = decisions([change({ field: "dueAt", value: null })]);
    expect(result?.outcome).toBe("UNCHANGED");
  });
  it("detects a changed due date", () => {
    const date = new Date("2027-01-10T12:00:00.000Z");
    const [result] = decisions([change({ field: "dueAt", value: date })]);
    expect(result).toMatchObject({
      outcome: "READY", current: null, proposed: date.toISOString(),
    });
  });
  it("detects an identical due date", () => {
    const date = new Date("2027-01-10T12:00:00.000Z");
    const [result] = decisions([change({ field: "dueAt", value: date })],
      [work({ dueAt: date })]);
    expect(result?.outcome).toBe("UNCHANGED");
  });
  it("accepts normal TODO to IN_PROGRESS transition", () => {
    expect(decisions([change({ field: "status", value: "IN_PROGRESS" })])[0]?.outcome)
      .toBe("READY");
  });
  it("accepts blocked work", () => {
    expect(decisions([change({ field: "status", value: "BLOCKED" })])[0]?.outcome)
      .toBe("READY");
  });
  it("allows completed human work without implying verification", () => {
    expect(decisions([change({ field: "status", value: "DONE" })])[0]?.outcome)
      .toBe("READY");
  });
  it("does not immediately complete cancelled work", () => {
    expect(decisions([change({ field: "status", value: "DONE" })],
      [work({ status: "CANCELLED" })])[0]?.outcome).toBe("INVALID");
  });
  it("requires cancelled work to reopen to TODO", () => {
    expect(decisions([change({ field: "status", value: "IN_PROGRESS" })],
      [work({ status: "CANCELLED" })])[0]?.outcome).toBe("INVALID");
  });
  it("permits explicitly reopening cancelled work", () => {
    expect(decisions([change({ field: "status", value: "TODO" })],
      [work({ status: "CANCELLED" })])[0]?.outcome).toBe("READY");
  });
  it("permits reopening completed work", () => {
    expect(decisions([change({ field: "status", value: "TODO" })],
      [work({ status: "DONE" })])[0]?.outcome).toBe("READY");
  });
  it("compares every change in original order", () => {
    const changed = decisions([
      change({ field: "priority", value: "URGENT" }),
      change({ field: "status", value: "BLOCKED" }),
      change({ field: "assigneeUserId", value: other }),
    ]);
    expect(changed.map(entry => entry.field)).toEqual([
      "priority", "status", "assigneeUserId",
    ]);
    expect(changed.every(entry => entry.outcome === "READY")).toBe(true);
  });
  it("does not let a valid change hide a stale change", () => {
    const changed = decisions([
      change({ field: "status", value: "BLOCKED" }),
      change({ id: anotherId, field: "priority", revision: 999 }),
    ], [work(), work({ id: anotherId, revision: 2 })]);
    expect(changed.map(entry => entry.outcome)).toEqual(["READY", "STALE"]);
  });
  it("distinguishes multiple item revisions", () => {
    const changed = decisions([
      change({ id: itemId, revision: 2 }),
      change({ id: anotherId, revision: 5 }),
    ], [work(), work({ id: anotherId, revision: 5 })]);
    expect(changed.every(entry => entry.outcome === "READY")).toBe(true);
  });
  it("keeps current and proposed values visible for the review", () => {
    const [result] = decisions([change({ field: "status", value: "BLOCKED" })]);
    expect(result).toMatchObject({
      current: "TODO", proposed: "BLOCKED", message: "Change can be applied.",
    });
  });
});
