import { describe, expect, it } from "vitest";
import type { ReviewAction, ReviewDisposition } from "./work-integrity-persistent-review";
import {
  verifyPersistedReviewLedger,
} from "./work-integrity-persistent-review-ledger";

const actor = "review-actor-12345";
const task = {
  id: "review-task-12345",
  organizationId: "review-org-12345",
  captureId: "review-capture-12345",
  disposition: "ACKNOWLEDGED" as ReviewDisposition,
  revision: 2,
  ownerUserId: actor as string | null,
  completedAt: null as Date | null,
  resolutionRefs: [],
};
const event = {
  id: "review-event-12345",
  action: "ACKNOWLEDGE" as ReviewAction,
  actorUserId: actor as string | null,
  revisionBefore: 1,
  revisionAfter: 2,
  before: "OPEN" as ReviewDisposition,
  after: "ACKNOWLEDGED" as ReviewDisposition,
  evidenceRefs: [],
};
const command = {
  taskId: task.id, actorUserId: actor,
  response: {
    eventId: event.id, action: event.action,
    revision: 2, disposition: event.after,
  },
};
const audit = {
  action: "integrity.review.acknowledge",
  actorUserId: actor,
  metadata: {
    eventId: event.id,
    revisionBefore: 1, revisionAfter: 2,
    dispositionBefore: "OPEN", dispositionAfter: "ACKNOWLEDGED",
  },
};
const check = (
  taskOverride: Partial<typeof task> = {},
  events = [event],
  commands = [command],
  audits = [audit],
) => verifyPersistedReviewLedger(
  { ...task, ...taskOverride }, events, commands, audits,
  new Date("2026-11-03T10:00:00.000Z"),
);
describe("persisted review ledger verification", () => {
  it("accepts consistent persisted state and audit", () => {
    const report = check();
    expect(report.consistent).toBe(true);
    expect(report.findings).toHaveLength(0);
    expect(report.expectedRevision).toBe(2);
  });
  it("rejects a missing idempotency command", () => {
    const report = check({}, [event], [], [audit]);
    expect(report.findings.some(x =>
      x.code === "COMMAND_MISSING")).toBe(true);
  });
  it("rejects a missing audit record", () => {
    const report = check({}, [event], [command], []);
    expect(report.findings.some(x =>
      x.code === "AUDIT_MISSING")).toBe(true);
  });
  it("rejects a duplicated command record", () => {
    const report = check({}, [event], [command, command], [audit]);
    expect(report.findings.some(x =>
      x.code === "COMMAND_DUPLICATE")).toBe(true);
  });
  it("detects actor tampering", () => {
    const report = check({}, [event], [command], [{
      ...audit, actorUserId: "other-user",
    }]);
    expect(report.findings.some(x =>
      x.code === "AUDIT_ACTOR_MISMATCH")).toBe(true);
  });
  it("detects revision tampering", () => {
    const report = check({}, [event], [command], [{
      ...audit, metadata: {
        ...audit.metadata, revisionAfter: 3,
      },
    }]);
    expect(report.findings.some(x =>
      x.code === "AUDIT_REVISION_MISMATCH")).toBe(true);
  });
  it("detects stored revision drift", () => {
    const report = check({ revision: 5 });
    expect(report.findings.some(x =>
      x.code === "REVISION_MISMATCH")).toBe(true);
  });
  it("detects stored disposition drift", () => {
    const report = check({ disposition: "OPEN" });
    expect(report.findings.some(x =>
      x.code === "STATE_MISMATCH")).toBe(true);
  });
  it("detects stored owner drift", () => {
    const report = check({ ownerUserId: null });
    expect(report.findings.some(x =>
      x.code === "OWNER_MISMATCH")).toBe(true);
  });
  it("detects missing event actor", () => {
    const report = check({}, [{
      ...event, actorUserId: null,
    }]);
    expect(report.findings.some(x =>
      x.code === "EVENT_ACTOR_MISSING")).toBe(true);
  });
  it("detects a missing revision in the chain", () => {
    const report = check({}, [{
      ...event, revisionBefore: 3, revisionAfter: 4,
    }]);
    expect(report.findings.some(x =>
      x.code === "REVISION_GAP")).toBe(true);
  });
  it("detects invalid event transitions", () => {
    const report = check({}, [{
      ...event, after: "RESOLVED" as const,
    }]);
    expect(report.findings.some(x =>
      x.code === "INVALID_TRANSITION")).toBe(true);
  });
  it("detects invalid completion timestamps", () => {
    const report = check({
      completedAt: new Date(),
    });
    expect(report.findings.some(x =>
      x.code === "COMPLETION_MISMATCH")).toBe(true);
  });
  it("does not treat consistency as independent verification", () => {
    expect(check().limitations.join(" ")).toContain(
      "not independently verify");
  });
  it("requires a registration audit when inspecting persisted history", () => {
    const report = verifyPersistedReviewLedger(
      task, [event], [command], [audit],
      new Date("2026-11-03T10:00:00.000Z"), [],
    );
    expect(report.consistent).toBe(false);
    expect(report.findings.some(x =>
      x.code === "CREATION_AUDIT_MISSING")).toBe(true);
  });
  it("accepts the authenticated capture registration audit", () => {
    const report = verifyPersistedReviewLedger(
      task, [event], [command], [audit],
      new Date("2026-11-03T10:00:00.000Z"), [{
        action: "integrity.review.created",
        actorUserId: actor,
        metadata: { captureId: task.captureId },
      }],
    );
    expect(report.consistent).toBe(true);
  });
  it("detects duplicate task registration audits", () => {
    const creation = {
      action: "integrity.review.created",
      actorUserId: actor,
      metadata: { captureId: task.captureId },
    };
    const report = verifyPersistedReviewLedger(
      task, [event], [command], [audit],
      new Date("2026-11-03T10:00:00.000Z"), [creation, creation],
    );
    expect(report.findings.some(x =>
      x.code === "CREATION_AUDIT_DUPLICATE")).toBe(true);
  });

});
