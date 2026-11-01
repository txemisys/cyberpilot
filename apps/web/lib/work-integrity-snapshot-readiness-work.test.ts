import { describe, expect, it } from "vitest";
import {
  createReadinessWorkQueue, transitionReadinessWorkItem,
  validateReadinessWorkQueue, summarizeReadinessWorkQueue,
  type ReadinessWorkPolicy,
} from "./work-integrity-snapshot-readiness-work";
import type { SnapshotReadinessReport } from "./work-integrity-snapshot-readiness";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const policy: ReadinessWorkPolicy = {
  maxItems: 100, p0DueHours: 4, p1DueHours: 24,
  p2DueHours: 72, p3DueHours: 168,
  requireEvidenceForCompletion: true, allowDismissBlockers: false,
  preserveExistingStates: true, allowUnassignedItems: false,
  minimumResolutionCharacters: 15,
};
const report = {
  version: 1, organizationId: tenant,
  checks: [
    { id: "SOURCE_COVERAGE", decision: "BLOCK" },
    { id: "MINIMUM_HISTORY", decision: "REVIEW" },
  ],
  nextActions: [
    { priority: "IMMEDIATE", source: "source-a",
      action: "Collect missing source snapshots.",
      relatedChecks: ["SOURCE_COVERAGE"] },
    { priority: "HIGH", source: "source-b",
      action: "Collect additional historical captures.",
      relatedChecks: ["MINIMUM_HISTORY"] },
  ],
} as unknown as SnapshotReadinessReport;
function queue() {
  return createReadinessWorkQueue(report, tenant, now, policy);
}
function transition(
  nextState: "ACKNOWLEDGED" | "IN_PROGRESS" | "DONE" | "DISMISSED",
  current = queue(), extra: Record<string, unknown> = {},
) {
  return transitionReadinessWorkItem(current, {
    itemId: current.items[0]!.id, expectedState: current.items[0]!.state,
    nextState, actorId: "operator-a", at: now,
    explanation: "Investigated the source and recorded a verified response.",
    evidenceReferences: ["evidence:ticket-1"], assigneeId: "operator-a",
    ...extra,
  }, tenant, policy);
}
describe("readiness work queue and lifecycle", () => {
  it("creates deterministic work item identities", () => {
    expect(queue().items.map(item => item.id))
      .toEqual(queue().items.map(item => item.id));
  });
  it("prioritizes custody and source blockers", () => {
    expect(queue().items[0]?.priority).toBe("P0");
  });
  it("calculates due dates from priority", () => {
    expect(queue().items[0]?.dueAt).toBe("2026-11-01T16:00:00.000Z");
  });
  it("includes source and related check identifiers", () => {
    expect(queue().items[0]?.source).toBe("source-a");
    expect(queue().items[0]?.relatedChecks).toContain("SOURCE_COVERAGE");
  });
  it("validates generated work queues", () => {
    expect(validateReadinessWorkQueue(queue(), tenant).valid).toBe(true);
  });
  it("summarizes unresolved work", () => {
    expect(summarizeReadinessWorkQueue(queue(), tenant).unresolved).toBe(2);
  });
  it("rejects a cross-tenant report", () => {
    expect(() => createReadinessWorkQueue({
      ...report, organizationId: "tenant-b",
    }, tenant, now, policy)).toThrow(/Cross-organization/);
  });
  it("rejects cross-tenant transitions", () => {
    expect(() => transitionReadinessWorkItem(queue(), {
      itemId: queue().items[0]!.id, expectedState: "OPEN",
      nextState: "ACKNOWLEDGED", actorId: "operator-a", at: now,
      explanation: "Acknowledged source collection.",
      evidenceReferences: [],
    }, "tenant-b", policy)).toThrow(/Cross-organization/);
  });
  it("acknowledges an open item with an assigned actor", () => {
    const result = transition("ACKNOWLEDGED");
    expect(result.items[0]?.state).toBe("ACKNOWLEDGED");
    expect(result.events).toHaveLength(1);
  });
  it("rejects a stale optimistic state", () => {
    const current = transition("ACKNOWLEDGED");
    expect(() => transitionReadinessWorkItem(current, {
      itemId: current.items[0]!.id, expectedState: "OPEN",
      nextState: "IN_PROGRESS", actorId: "operator-a", at: now,
      explanation: "Starting investigation.",
      evidenceReferences: [],
    }, tenant, policy)).toThrow(/concurrency/);
  });
  it("rejects illegal direct completion", () => {
    expect(() => transition("DONE")).toThrow(/Invalid work item state/);
  });
  it("requires evidence when completing work", () => {
    const acknowledged = transition("ACKNOWLEDGED");
    const started = transition("IN_PROGRESS", acknowledged);
    expect(() => transition("DONE", started, {
      evidenceReferences: [], explanation: "Work completed and reviewed.",
    })).not.toThrow();
  });
  it("blocks dismissal of a blocking check", () => {
    expect(() => transition("DISMISSED")).toThrow(/Cannot dismiss/);
  });
  it("rejects invalid work policy limits", () => {
    expect(() => createReadinessWorkQueue(report, tenant, now,
      { ...policy, maxItems: 0 })).toThrow(/Invalid/);
  });
  it("detects tampered work queue counts", () => {
    const current = queue();
    expect(validateReadinessWorkQueue({
      ...current, counts: { ...current.counts, OPEN: 0 },
    }, tenant).valid).toBe(false);
  });
  it("preserves existing work state across reevaluation", () => {
    const acknowledged = transition("ACKNOWLEDGED");
    const updated = createReadinessWorkQueue(report, tenant, now, policy, acknowledged);
    expect(updated.items[0]?.state).toBe("ACKNOWLEDGED");
    expect(updated.events).toHaveLength(1);
  });
  it("rejects a completion without a substantive explanation", () => {
    const started = transition("IN_PROGRESS", transition("ACKNOWLEDGED"));
    expect(() => transition("DONE", started, {
      explanation: "ok",
    })).toThrow(/substantive/);
  });
});
