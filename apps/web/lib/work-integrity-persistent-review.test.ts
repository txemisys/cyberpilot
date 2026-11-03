import { describe, expect, it } from "vitest";
import {
  parseReviewCreate, parseReviewCommand,
  parseReviewListQuery, parseReviewEventQuery,
  planReviewTransition, reviewCommandDigest,
} from "./work-integrity-persistent-review";
import {
  parseReviewBatchCreate, parseReviewDashboardQuery,
  summarizeReviewDashboard,
} from "./work-integrity-persistent-review-operations";

const captureId = "capture_12345";
const taskId = "review_12345";
const actor = "user_12345";
const command = {
  taskId, action: "RESOLVE" as const,
  expectedRevision: 3,
  idempotencyKey: "operation-123456",
  reason: "Reviewed supporting evidence",
  evidenceRefs: ["evidence_12345"],
};
describe("persistent review request validation", () => {
  it("accepts bounded review creation", () => {
    expect(parseReviewCreate({
      captureId, externalTaskId: "case-one",
      title: "Check evidence", severity: "ERROR",
    })).toMatchObject({
      captureId, required: true, severity: "ERROR",
    });
  });
  it("rejects arbitrary extra review fields", () => {
    expect(() => parseReviewCreate({
      captureId, externalTaskId: "case-one",
      title: "Check evidence", severity: "ERROR",
      disposition: "RESOLVED",
    })).toThrow();
  });
  it("requires evidence on resolution", () => {
    expect(() => parseReviewCommand({
      ...command, evidenceRefs: [],
    })).toThrow();
  });
  it("rejects evidence references on acknowledgment", () => {
    expect(() => parseReviewCommand({
      ...command, action: "ACKNOWLEDGE",
    })).toThrow();
  });
  it("requires a reason to reopen", () => {
    expect(() => parseReviewCommand({
      ...command, action: "REOPEN", reason: null,
      evidenceRefs: [],
    })).toThrow();
  });
  it("rejects duplicate evidence IDs", () => {
    expect(() => parseReviewCommand({
      ...command,
      evidenceRefs: ["evidence_12345", "evidence_12345"],
    })).toThrow();
  });
  it("requires positive optimistic revisions", () => {
    expect(() => parseReviewCommand({
      ...command, expectedRevision: 0,
    })).toThrow();
  });
  it("rejects unknown event filters", () => {
    expect(() => parseReviewEventQuery({
      taskId, includeOtherTenants: true,
    })).toThrow();
  });
  it("rejects unknown list dispositions", () => {
    expect(() => parseReviewListQuery({
      disposition: "VERIFIED",
    })).toThrow();
  });
  it("does not include the idempotency key in payload identity", () => {
    const first = reviewCommandDigest(command);
    const second = reviewCommandDigest({
      ...command, idempotencyKey: "another-operation",
    });
    expect(first).toBe(second);
    expect(first).toHaveLength(64);
  });
  it("changes the digest for changed evidence", () => {
    expect(reviewCommandDigest(command)).not.toBe(
      reviewCommandDigest({
        ...command, evidenceRefs: ["evidence_67890"],
      }));
  });
});
describe("authenticated review transitions", () => {
  it("acknowledges and binds the authenticated actor", () => {
    const planned = planReviewTransition("OPEN", {
      ...command, action: "ACKNOWLEDGE",
      reason: null, evidenceRefs: [],
    }, null, actor, "ERROR");
    expect(planned.disposition).toBe("ACKNOWLEDGED");
    expect(planned.ownerUserId).toBe(actor);
  });
  it("allows the owner to start a review", () => {
    const planned = planReviewTransition("ACKNOWLEDGED", {
      ...command, action: "START_REVIEW",
      reason: null, evidenceRefs: [],
    }, actor, actor, "ERROR");
    expect(planned.disposition).toBe("IN_REVIEW");
  });
  it("allows the owner to resolve a review", () => {
    const planned = planReviewTransition("IN_REVIEW",
      command, actor, actor, "ERROR");
    expect(planned.disposition).toBe("RESOLVED");
    expect(planned.resolutionRefs).toEqual(["evidence_12345"]);
  });
  it("prevents an unacknowledged actor from resolving", () => {
    expect(() => planReviewTransition("IN_REVIEW",
      command, actor, "different_user", "ERROR")).toThrow();
  });
  it("does not allow waiver of error reviews", () => {
    expect(() => planReviewTransition("IN_REVIEW", {
      ...command, action: "WAIVE",
      evidenceRefs: [],
    }, actor, actor, "ERROR")).toThrow();
  });
  it("allows a warning review to be waived by its owner", () => {
    const planned = planReviewTransition("IN_REVIEW", {
      ...command, action: "WAIVE",
      evidenceRefs: [],
    }, actor, actor, "WARNING");
    expect(planned.disposition).toBe("WAIVED");
  });
  it("prevents illegal state transitions", () => {
    expect(() => planReviewTransition("OPEN",
      command, actor, actor, "WARNING")).toThrow();
  });
  it("allows reopening completed reviews", () => {
    const planned = planReviewTransition("RESOLVED", {
      ...command, action: "REOPEN", evidenceRefs: [],
    }, actor, actor, "ERROR");
    expect(planned.disposition).toBe("REOPENED");
    expect(planned.completedAt).toBeNull();
  });
});
describe("bulk registration and persisted dashboard", () => {
  const item = {
    externalTaskId: "case-one", title: "Review controls",
    severity: "ERROR",
  };
  it("normalizes batch capture IDs", () => {
    const batch = parseReviewBatchCreate({
      captureId, tasks: [item],
    });
    expect(batch.tasks[0]?.captureId).toBe(captureId);
    expect(batch.rejectExisting).toBe(true);
  });
  it("rejects duplicate external IDs", () => {
    expect(() => parseReviewBatchCreate({
      captureId, tasks: [item, item],
    })).toThrow();
  });
  it("rejects empty batches", () => {
    expect(() => parseReviewBatchCreate({
      captureId, tasks: [],
    })).toThrow();
  });
  it("rejects invalid dashboard parameters", () => {
    expect(() => parseReviewDashboardQuery({
      overdueAfterHours: -1,
    })).toThrow();
  });
  const now = new Date("2026-11-03T12:00:00.000Z");
  const rows = [
    {
      id: "review-1", captureId, externalTaskId: "case-1",
      severity: "ERROR", required: true,
      disposition: "OPEN", ownerUserId: null,
      createdAt: new Date("2026-11-01T00:00:00.000Z"),
    },
    {
      id: "review-2", captureId, externalTaskId: "case-2",
      severity: "WARNING", required: true,
      disposition: "RESOLVED", ownerUserId: actor,
      createdAt: new Date("2026-11-02T00:00:00.000Z"),
    },
  ];
  it("counts outstanding and completed tasks separately", () => {
    const report = summarizeReviewDashboard(rows,
      parseReviewDashboardQuery({}), now);
    expect(report.totals.outstanding).toBe(1);
    expect(report.totals.resolved).toBe(1);
    expect(report.totals.unassigned).toBe(1);
    expect(report.totals.overdue).toBe(1);
  });
  it("does not call resolved reviews independently verified", () => {
    const report = summarizeReviewDashboard(rows,
      parseReviewDashboardQuery({}), now);
    expect(report.totals.completedWithoutVerification).toBe(1);
    expect(report.limitations.join(" ")).toContain(
      "not independent verification");
  });
  it("summarizes workload by owner", () => {
    const report = summarizeReviewDashboard(rows,
      parseReviewDashboardQuery({ includeOwners: true }), now);
    expect(report.owners).toEqual([{
      userId: actor, total: 1, outstanding: 0, completed: 1,
    }]);
  });
  it("supports disabling overdue diagnostics", () => {
    const report = summarizeReviewDashboard(rows,
      parseReviewDashboardQuery({ includeOverdue: false }), now);
    expect(report.totals.overdue).toBe(0);
  });
});
