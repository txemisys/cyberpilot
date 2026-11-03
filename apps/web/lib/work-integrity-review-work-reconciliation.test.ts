import { describe, expect, it } from "vitest";
import {
  parseReviewWorkConsistencyInput,
  reconcileReviewWorkLink,
} from "./work-integrity-review-work-reconciliation";
import {
  parseCaptureLineageQuery,
  summarizeCaptureLineage,
} from "./work-integrity-capture-lineage";

const link = {
  id: "link-item-12345",
  organizationId: "organization-12345",
  taskId: "review-task-12345",
  workItemId: "work-item-12345",
  revision: 1,
  unlinkedAt: null,
  task: {
    organizationId: "organization-12345",
    disposition: "IN_REVIEW",
  },
  workItem: {
    organizationId: "organization-12345",
    status: "IN_PROGRESS",
    remediation: { status: "EXECUTING" },
    finding: { status: "OPEN" },
    evidenceLinks: [{ id: "evidence-link-12345" }],
  },
};
const audit = {
  resourceId: link.id,
  action: "integrity.review.work.link",
  actorUserId: "admin-user-12345",
  metadata: {
    taskId: link.taskId,
    workItemId: link.workItemId,
    beforeRevision: 0,
    afterRevision: 1,
  },
};
describe("review-work consistency reconciliation", () => {
  it("accepts a consistent initial association", () => {
    expect(reconcileReviewWorkLink(link, [audit])).toEqual([]);
  });
  it("detects missing audit events", () => {
    expect(reconcileReviewWorkLink(link, []).map(x => x.code))
      .toContain("MISSING_LINK_AUDIT");
  });
  it("detects duplicate audit events", () => {
    expect(reconcileReviewWorkLink(link, [audit, audit]).map(x => x.code))
      .toContain("LINK_AUDIT_GAP");
  });
  it("detects cross-tenant work", () => {
    expect(reconcileReviewWorkLink({
      ...link, workItem: {
        ...link.workItem, organizationId: "another-org",
      },
    }, [audit]).map(x => x.code)).toContain("CROSS_TENANT_WORK");
  });
  it("detects cross-tenant review", () => {
    expect(reconcileReviewWorkLink({
      ...link, task: { ...link.task, organizationId: "another-org" },
    }, [audit]).map(x => x.code)).toContain("CROSS_TENANT_REVIEW");
  });
  it("detects a mismatched audit scope", () => {
    expect(reconcileReviewWorkLink(link, [{
      ...audit, metadata: { ...audit.metadata, taskId: "other-task" },
    }]).map(x => x.code)).toContain("LINK_AUDIT_SCOPE_MISMATCH");
  });
  it("detects a missing audit revision", () => {
    expect(reconcileReviewWorkLink(link, [{
      ...audit, metadata: { ...audit.metadata, afterRevision: 3 },
    }]).map(x => x.code)).toContain("LINK_AUDIT_GAP");
  });
  it("detects an invalid action chronology", () => {
    expect(reconcileReviewWorkLink(link, [{
      ...audit, action: "integrity.review.work.unlink",
    }]).map(x => x.code)).toContain("LINK_AUDIT_STATE_MISMATCH");
  });
  it("detects active work on resolved reviews", () => {
    expect(reconcileReviewWorkLink({
      ...link, task: { ...link.task, disposition: "RESOLVED" },
    }, [audit]).map(x => x.code))
      .toContain("RESOLVED_REVIEW_ACTIVE_WORK");
  });
  it("detects cancelled work with active association", () => {
    expect(reconcileReviewWorkLink({
      ...link, workItem: { ...link.workItem, status: "CANCELLED" },
    }, [audit]).map(x => x.code))
      .toContain("WORK_CANCELLED_ACTIVE_LINK");
  });
  it("detects done work without linked evidence", () => {
    expect(reconcileReviewWorkLink({
      ...link, workItem: {
        ...link.workItem, status: "DONE", evidenceLinks: [],
      },
    }, [audit]).map(x => x.code))
      .toContain("WORK_DONE_WITHOUT_EVIDENCE");
  });
  it("detects verified remediation with open finding", () => {
    expect(reconcileReviewWorkLink({
      ...link, workItem: {
        ...link.workItem, remediation: { status: "VERIFIED" },
      },
    }, [audit]).map(x => x.code))
      .toContain("VERIFIED_REMEDIATION_OPEN_FINDING");
  });
  it("does not infer operational inconsistency for inactive associations", () => {
    const inactive = {
      ...link, revision: 2,
      unlinkedAt: new Date("2026-01-01T00:00:00Z"),
      workItem: {
        ...link.workItem, status: "DONE",
        remediation: { status: "VERIFIED" },
        evidenceLinks: [],
      },
    };
    const audits = [
      audit,
      { ...audit, action: "integrity.review.work.unlink",
        metadata: { ...audit.metadata,
          beforeRevision: 1, afterRevision: 2 } },
    ];
    expect(reconcileReviewWorkLink(inactive, audits)).toEqual([]);
  });
});
describe("capture lineage parsing and summary", () => {
  it("parses a capture with defaults", () => {
    expect(parseCaptureLineageQuery({
      captureId: "capture-item-12345",
    })).toEqual({
      captureId: "capture-item-12345",
      offset: 0, limit: 50, includeInactive: false,
    });
  });
  it.each([
    { offset: -1 },
    { offset: "0" },
    { offset: 1000001 },
    { limit: 0 },
    { limit: 101 },
    { includeInactive: "true" },
    { unknown: true },
  ])("rejects invalid lineage query %j", patch => {
    expect(() => parseCaptureLineageQuery({
      captureId: "capture-item-12345", ...patch,
    })).toThrow();
  });
  it("reports no evidence and no work conservatively", () => {
    const summary = summarizeCaptureLineage([{
      review: { disposition: "OPEN", required: true },
      evidence: {
        gate: "NO_EVIDENCE", acceptedCount: 0, staleCount: 0,
      },
      work: [],
    }]);
    expect(summary.noEvidence).toBe(1);
    expect(summary.noLinkedWork).toBe(1);
    expect(summary.requiredTasks).toBe(1);
  });
  it("does not treat human acceptance as verified remediation", () => {
    const summary = summarizeCaptureLineage([{
      review: { disposition: "IN_REVIEW", required: true },
      evidence: {
        gate: "HUMAN_ACCEPTED", acceptedCount: 1, staleCount: 0,
      },
      work: [{
        active: true, status: "DONE", remediationStatus: "SUCCEEDED",
      }],
    }]);
    expect(summary.humanAccepted).toBe(1);
    expect(summary.activeWorkDone).toBe(1);
    expect(summary.verifiedRemediations).toBe(0);
  });
  it("rejects unbounded consistency inspection", () => {
    expect(() => parseReviewWorkConsistencyInput({
      captureId: "capture-item-12345", limit: 201,
    })).toThrow();
  });
});
