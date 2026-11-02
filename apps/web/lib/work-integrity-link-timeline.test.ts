import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  snapshotIntegrityReview, compareIntegritySnapshots,
  buildIntegrityReviewTimeline, summarizeIntegrityReviewAt,
} from "./work-integrity-link-timeline";

const first = "2026-11-01T10:00:00.000Z";
const second = "2026-11-02T10:00:00.000Z";
const third = "2026-11-03T10:00:00.000Z";
const captureId = "capture-one";
const linked: IntegrityLinkHistoryEvent = {
  auditId: "audit-one", originalAuditId: null, action: "LINK",
  captureId, caseKey: "case-one", workItemId: "work-one",
  actorUserId: "user-one", occurredAt: first,
};
const unlinked: IntegrityLinkHistoryEvent = {
  ...linked, auditId: "withdrawal-one", originalAuditId: "audit-one",
  action: "UNLINK", actorUserId: "user-two", occurredAt: second,
};
describe("historical integrity snapshots", () => {
  it("excludes audit events occurring after the requested checkpoint", () => {
    const snapshot = snapshotIntegrityReview(captureId, [unlinked, linked], first);
    expect(snapshot).toMatchObject({
      totalEvents: 1, active: 1, withdrawn: 0,
    });
    expect(snapshot.associations[0]?.state).toBe("ACTIVE");
  });
  it("reconstructs withdrawal state at later checkpoints", () => {
    const snapshot = snapshotIntegrityReview(captureId, [unlinked, linked], second);
    expect(snapshot).toMatchObject({
      totalEvents: 2, active: 0, withdrawn: 1,
    });
    expect(snapshot.associations[0]?.withdrawalAuditId).toBe("withdrawal-one");
  });
  it("computes creation and withdrawal deltas between snapshots", () => {
    const before = snapshotIntegrityReview(captureId, [linked, unlinked], first);
    const after = snapshotIntegrityReview(captureId, [linked, unlinked], second);
    expect(compareIntegritySnapshots(before, after)).toMatchObject({
      openingActive: 1, closingActive: 0,
      linksCreated: 0, linksWithdrawn: 1, netChange: -1,
      casesChanged: ["case-one"], workItemsChanged: ["work-one"],
    });
  });
  it("builds checkpoint timeline with cumulative active counts", () => {
    const timeline = buildIntegrityReviewTimeline(
      captureId, [unlinked, linked], [third, first, second]);
    expect(timeline.intervals.map(x => x.closingActive)).toEqual([1, 0, 0]);
    expect(timeline.finalActive).toBe(0);
  });
  it("summarizes distinct cases, work items and actors at a checkpoint", () => {
    const summary = summarizeIntegrityReviewAt(
      captureId, [linked, unlinked], second);
    expect(summary).toMatchObject({
      totalEvents: 2, active: 0, withdrawn: 1,
      cases: 1, workItems: 1, actors: 2,
    });
  });
  it("rejects malformed checkpoint timestamps", () => {
    expect(() => snapshotIntegrityReview(captureId, [], "2026-11-01")).toThrow();
    expect(() => snapshotIntegrityReview(captureId, [], "not-a-date")).toThrow();
  });
  it("rejects repeated timeline checkpoints", () => {
    expect(() => buildIntegrityReviewTimeline(captureId, [], [first, first])).toThrow();
  });
  it("rejects snapshots from different captures", () => {
    const before = snapshotIntegrityReview(captureId, [], first);
    const after = snapshotIntegrityReview("capture-two", [], second);
    expect(() => compareIntegritySnapshots(before, after)).toThrow();
  });
  it("rejects reverse chronological snapshot comparisons", () => {
    const before = snapshotIntegrityReview(captureId, [], second);
    const after = snapshotIntegrityReview(captureId, [], first);
    expect(() => compareIntegritySnapshots(before, after)).toThrow();
  });
  it("does not interpret withdrawn work as verified security", () => {
    const summary = summarizeIntegrityReviewAt(captureId, [linked, unlinked], third);
    expect(summary.active).toBe(0);
    expect(summary.withdrawn).toBe(1);
    expect("securityVerified" in summary).toBe(false);
  });
});
