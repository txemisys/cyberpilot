import { describe, expect, it } from "vitest";
import {
  normalizeTimelineEvent, reconcileTimeline, paginateTimeline,
  timelineDigest, exportTimelineCSV, exportTimelineJSON,
  validateTimelineQuery, verifyTimelineEvent, summarizeTimeline,
  type TimelineEvent,
} from "./incident-operational-timeline-domain";

const A = "a".repeat(64);
const B = "b".repeat(64);
const org = "org-timeline-test";
const incident = "incident-timeline-test";
const at = "2026-11-24T10:00:00.000Z";
function event(revision = 1, overrides: Partial<TimelineEvent> = {}):
  TimelineEvent {
  return normalizeTimelineEvent({
    organizationId: org, incidentId: incident,
    source: "INCIDENT", sourceId: incident, sourceRevision: revision,
    eventId: "event-" + revision, actorUserId: "owner-test",
    operation: revision === 1 ? "CREATE" : "REVIEW",
    occurredAt: new Date(Date.parse(at) + revision * 60000).toISOString(),
    priorState: revision === 1 ? null : "OPEN", nextState: "OPEN",
    priorDigest: revision === 1 ? null : A, nextDigest: A,
    sourceEventDigest: null, sourceIntegrity: "INCOMPLETE",
    ...overrides,
  });
}
const page = (events: TimelineEvent[], limit = 2, cursor?: string) =>
  paginateTimeline({
    organizationId: org, incidentId: incident, incidentRevision: 4,
    generatedAt: at, events, inventoryComplete: true,
    query: { limit, ...(cursor ? { cursor } : {}) },
  });
describe("operational timeline read model", () => {
  it("keeps source provenance and forbids forged provider outcomes", () => {
    const e = event();
    expect(e.providerWrites).toBe(0);
    expect(e.providerOutcomeIndependentlyVerified).toBe(false);
    expect(verifyTimelineEvent(e)).toEqual([]);
    expect(verifyTimelineEvent({ ...e,
      providerOutcomeIndependentlyVerified: true as never })).toContain(
        "TIMELINE_PROVIDER_ASSERTION_FORGED");
    expect(verifyTimelineEvent({ ...e,
      sourceRevision: 0 })).toContain("TIMELINE_REVISION_INVALID");
  });
  it("detects revision gaps without assuming a negative security result", () => {
    const checked = reconcileTimeline([event(1), event(3)]);
    expect(checked.integrity).toBe("INCOMPLETE");
    expect(checked.problems.some(x =>
      x.code === "TIMELINE_REVISION_GAP")).toBe(true);
    expect(checked.sourceStatus.find(x =>
      x.source === "INCIDENT")?.entries).toBe(2);
  });
  it("fails closed on reused event revisions", () => {
    const checked = reconcileTimeline([event(1), event(1, {
      eventId: "event-duplicate",
    })]);
    expect(checked.problems.some(x =>
      x.code === "TIMELINE_REVISION_DUPLICATE")).toBe(true);
  });
  it("detects source time regressions", () => {
    const checked = reconcileTimeline([event(1), event(2, {
      occurredAt: "2026-11-23T10:00:00.000Z",
    })]);
    expect(checked.integrity).toBe("CONFLICT");
    expect(checked.problems.some(x =>
      x.code === "TIMELINE_TIME_REGRESSION")).toBe(true);
  });
  it("detects a broken digest chain", () => {
    const checked = reconcileTimeline([event(1), event(2, {
      priorDigest: B,
    })]);
    expect(checked.integrity).toBe("CONFLICT");
    expect(checked.problems.some(x =>
      x.code === "TIMELINE_DIGEST_CHAIN_BROKEN")).toBe(true);
  });
  it("uses a deterministic tenant-scoped cursor and total", () => {
    const events = [event(1), event(2), event(3), event(4)];
    const first = page(events);
    expect(first.total).toBe(4);
    expect(first.entries.length).toBe(2);
    expect(first.nextCursor).not.toBeNull();
    const second = page(events, 2, first.nextCursor!);
    expect(second.entries.length).toBe(2);
    expect(second.nextCursor).toBeNull();
    expect(new Set([...first.entries, ...second.entries]
      .map(x => x.eventId)).size).toBe(4);
  });
  it("invalidates cursors when the event inventory changes", () => {
    const first = page([event(1), event(2), event(3)]);
    expect(() => page([event(1), event(2)], 2,
      first.nextCursor!)).toThrow("TIMELINE_CURSOR_INVALID");
  });
  it("rejects cross-tenant and cross-incident aggregation", () => {
    expect(() => page([event(1, {
      organizationId: "org-other-tenant",
    })])).toThrow("TIMELINE_CROSS_TENANT_OR_INCIDENT");
    expect(() => page([event(1, {
      incidentId: "incident-other",
    })])).toThrow("TIMELINE_CROSS_TENANT_OR_INCIDENT");
  });
  it("rejects unsupported query keys, filters and ranges", () => {
    expect(() => validateTimelineQuery({
      sources: ["INCIDENT", "INCIDENT"],
    })).toThrow("TIMELINE_SOURCES_INVALID");
    expect(() => validateTimelineQuery({
      from: "2026-11-24T12:00:00.000Z",
      to: "2026-11-23T12:00:00.000Z",
    })).toThrow("TIMELINE_RANGE_REVERSED");
    expect(() => validateTimelineQuery({ limit: 101 }))
      .toThrow("TIMELINE_LIMIT_INVALID");
  });
  it("handles JSONB property reorder without digest drift", () => {
    expect(timelineDigest({ b: { y: 1, x: 2 }, a: 0 }))
      .toBe(timelineDigest({ a: 0, b: { x: 2, y: 1 } }));
  });
  it("exports a page with formula-safe CSV and hashed JSON", () => {
    const p = page([event(1, { nextState: "=1+1" })]);
    expect(p.pageDigest).toBe(
      timelineDigest({ ...p, pageDigest: undefined }));
    expect(exportTimelineCSV(p)).toContain("'=1+1");
    expect(JSON.parse(exportTimelineJSON(p)).pageDigest)
      .toBe(p.pageDigest);
    expect(() => exportTimelineJSON({ ...p,
      pageDigest: B })).toThrow("TIMELINE_PAGE_DIGEST_MISMATCH");
  });
  it("does not label incomplete source evidence as verified", () => {
    const p = page([event(1)]);
    expect(p.completeness).toBe("PARTIAL");
    expect(p.integrity).toBe("INCOMPLETE");
    expect(summarizeTimeline(p).providerOutcomesVerified).toBe(false);
  });
});
