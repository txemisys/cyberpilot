import { describe, expect, it } from "vitest";
import {
  parseIntegrityReviewEvents,
  replayIntegrityReviewEvents,
  parseIntegrityReviewReplayPolicy,
  parseIntegrityReviewReplayQuery,
  queryIntegrityReviewReplay,
} from "./work-integrity-remediation-review-event-replay";
import {
  evaluateIntegrityReviewGate,
  parseIntegrityReviewGatePolicy,
  parseIntegrityReviewGateQuery,
  queryIntegrityReviewGate,
} from "./work-integrity-remediation-review-gate";
import {
  buildIntegrityReviewCheckpointHistory,
  parseIntegrityReviewCheckpoints,
  parseIntegrityReviewCheckpointQuery,
  queryIntegrityReviewCheckpointHistory,
} from "./work-integrity-remediation-review-checkpoints";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityCapacityDecisionReport } from "./work-integrity-remediation-capacity-decision";
import type { IntegrityCapacityGovernanceReport } from "./work-integrity-remediation-capacity-governance";
const at = "2026-11-03T00:00:00.000Z";
const queue: IntegrityCapacityReviewQueue = {
  schemaVersion: 1, captureId: "capture", evaluatedAt: at,
  tasks: [{
    taskId: "task-1", action: "VERIFY_ASSIGNMENT_IMPACT",
    severity: "ERROR", bundleId: "bundle", interventionIds: ["slots"],
    findingCodes: ["SELECTION_LOSES_ASSIGNED_WORK"],
    reasons: ["Review assignments"], priority: 400, position: 1,
    reviewRequired: true, checklist: ["Verify owners"],
    affectedCandidateIds: ["candidate"], blockedBy: [],
    canBeAutoResolved: false,
  }],
  totals: {
    tasks: 1, errors: 1, warnings: 0, info: 0,
    required: 1, affectedCandidates: 1,
    byAction: { VERIFY_ASSIGNMENT_IMPACT: 1 },
    byBundle: { bundle: 1 },
  },
  limitation: "Analytical",
};
const events = parseIntegrityReviewEvents([
  {
    eventId: "one", taskId: "task-1", kind: "ACKNOWLEDGE",
    occurredAt: at, actorId: "reviewer",
    expectedVersion: 0,
  },
  {
    eventId: "two", taskId: "task-1", kind: "START_REVIEW",
    occurredAt: "2026-11-03T00:01:00.000Z",
    actorId: "reviewer", expectedVersion: 1,
  },
  {
    eventId: "three", taskId: "task-1", kind: "RESOLVE",
    occurredAt: "2026-11-03T00:02:00.000Z",
    actorId: "reviewer", expectedVersion: 2,
    reason: "Verified in scenario review",
    evidenceRefs: ["ref-1"],
  },
]);
const decision = {
  captureId: "capture", selectedBundleId: "bundle",
} as IntegrityCapacityDecisionReport;
const governance = {
  captureId: "capture", selectedBundleId: "bundle",
  status: "REVIEW_REQUIRED",
  totals: { comparedPolicySelectionChanged: false },
} as IntegrityCapacityGovernanceReport;
describe("integrity review event replay", () => {
  it("accepts valid optimistic review transitions", () => {
    const replay = replayIntegrityReviewEvents(queue, events);
    expect(replay.totals.acceptedEvents).toBe(3);
    expect(replay.totals.requiredOutstanding).toBe(0);
    expect(replay.tasks[0]?.disposition).toBe("RESOLVED");
    expect(replay.tasks[0]?.resolutionEvidenceRefs).toEqual(["ref-1"]);
  });
  it("rejects optimistic version conflicts", () => {
    const replay = replayIntegrityReviewEvents(queue, [
      events[0]!, { ...events[1]!, expectedVersion: 0 },
    ]);
    expect(replay.results[1]?.rejection).toBe("VERSION_CONFLICT");
    expect(replay.totals.requiredOutstanding).toBe(1);
  });
  it("rejects resolution without evidence", () => {
    const replay = replayIntegrityReviewEvents(queue, [
      events[0]!, events[1]!,
      { ...events[2]!, evidenceRefs: [] },
    ]);
    expect(replay.results[2]?.rejection).toBe(
      "MISSING_RESOLUTION_EVIDENCE");
  });
  it("does not waive error tasks under conservative policy", () => {
    const replay = replayIntegrityReviewEvents(queue, [
      events[0]!,
      { ...events[1]!, eventId: "waive", kind: "WAIVE",
        reason: "Risk accepted" },
    ]);
    expect(replay.results[1]?.rejection).toBe(
      "ERROR_WAIVER_FORBIDDEN");
  });
  it("filters outstanding tasks", () => {
    const replay = replayIntegrityReviewEvents(queue, events.slice(0, 1));
    const page = queryIntegrityReviewReplay(replay,
      parseIntegrityReviewReplayQuery({ onlyOutstanding: true }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown replay policy flags", () => {
    expect(() => parseIntegrityReviewReplayPolicy({
      trustCallerIdentity: true,
    })).toThrow();
  });
});
describe("integrity review gate", () => {
  it("accepts analytically completed reviews with explicit limitations", () => {
    const replay = replayIntegrityReviewEvents(queue, events);
    const gate = evaluateIntegrityReviewGate(
      governance, decision, queue, replay);
    expect(gate.status).toBe("ANALYTICALLY_REVIEWED");
    expect(gate.totals.completed).toBe(1);
    expect(gate.limitation).toContain("not authenticated");
  });
  it("blocks outstanding error review", () => {
    const replay = replayIntegrityReviewEvents(queue, events.slice(0, 1));
    const gate = evaluateIntegrityReviewGate(
      governance, decision, queue, replay);
    expect(gate.status).toBe("BLOCKED");
    expect(gate.blockers.some(x =>
      x.code === "REVIEW_NOT_COMPLETED")).toBe(true);
  });
  it("filters blocked gate tasks", () => {
    const replay = replayIntegrityReviewEvents(queue, []);
    const gate = evaluateIntegrityReviewGate(
      governance, decision, queue, replay);
    const page = queryIntegrityReviewGate(gate,
      parseIntegrityReviewGateQuery({ onlyBlocked: true }));
    expect(page.total).toBe(1);
  });
  it("rejects unrecognized gate policy fields", () => {
    expect(() => parseIntegrityReviewGatePolicy({
      bypassVerification: true,
    })).toThrow();
  });
});
describe("review checkpoint history", () => {
  const checkpoints = parseIntegrityReviewCheckpoints([
    { checkpointId: "before", eventCount: 0, evaluatedAt: at },
    { checkpointId: "after", eventCount: 3,
      evaluatedAt: "2026-11-03T00:03:00.000Z" },
  ]);
  it("reconstructs completion changes", () => {
    const history = buildIntegrityReviewCheckpointHistory(
      queue, events, checkpoints,
      parseIntegrityReviewReplayPolicy(undefined));
    expect(history.totals.finalRequiredOutstanding).toBe(0);
    expect(history.changes[0]?.newlyCompletedTaskIds).toEqual(["task-1"]);
  });
  it("filters history changes", () => {
    const history = buildIntegrityReviewCheckpointHistory(
      queue, events, checkpoints,
      parseIntegrityReviewReplayPolicy(undefined));
    const page = queryIntegrityReviewCheckpointHistory(
      history, parseIntegrityReviewCheckpointQuery({
        checkpointIds: ["after"],
      }));
    expect(page.total).toBe(1);
  });
  it("rejects nonmonotonic checkpoints", () => {
    expect(() => parseIntegrityReviewCheckpoints([
      { checkpointId: "late", eventCount: 3, evaluatedAt: at },
      { checkpointId: "early", eventCount: 1, evaluatedAt: at },
    ])).toThrow();
  });
});
