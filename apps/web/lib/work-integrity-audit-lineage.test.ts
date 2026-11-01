import { describe, expect, it } from "vitest";
import type { Prisma } from "@cyberpilot/database";
import {
  parseLineageFilters, reconstructAuditLineage, auditLineageCsv,
  type LineageSource,
} from "./work-integrity-audit-lineage";
const event = (id: string, prior: string | null, extra: Partial<LineageSource> = {}): LineageSource => ({
  id, organizationId: "tenant-a", resourceId: "work-123",
  actorUserId: "reviewer-123",
  occurredAt: new Date(id === "event-a" ? "2026-10-01T10:00:00Z" :
    id === "event-b" ? "2026-10-02T10:00:00Z" : "2026-10-03T10:00:00Z"),
  metadata: {
    code: "DONE_WITHOUT_COMPLETION",
    decision: "INVESTIGATE", resourceId: "work-123",
    rationale: "Reviewed stored source evidence", revision: 2,
    previousEventId: prior,
  } as Prisma.JsonValue,
  ...extra,
});
const report = (
  raw: LineageSource[] = [event("event-b", "event-a"), event("event-a", null)],
  maxDepth = 25, work: { id: string; title: string; revision: number } | null = {
    id: "work-123", title: "Review work", revision: 2,
  },
) => reconstructAuditLineage({
  organizationId: "tenant-a", generatedAt: "2026-11-01T10:00:00Z",
  eventId: raw[0]!.id, raw, completeToRoot: raw[raw.length - 1]?.id === "event-a",
  maxDepth, includeRationale: true, work,
});
const codes = (rows: LineageSource[]) => report(rows).issues.map(i => i.kind);
describe("bounded authoritative audit predecessor traversal", () => {
  it("accepts a complete linear chain", () => {
    const result = report();
    expect(result.terminal).toBe("ROOT");
    expect(result.sourceChainComplete).toBe(true);
    expect(result.inspectedEvents).toBe(2);
    expect(result.nodes.map(node => node.depth)).toEqual([0, 1]);
  });
  it("rejects untrusted caller options", () => {
    expect(() => parseLineageFilters({
      eventId: "event-b", organizationId: "other",
    })).toThrow();
    expect(() => parseLineageFilters({ eventId: "event-b", maxDepth: "51" })).toThrow();
  });
  it("supports bounded depths and rationale exclusion", () => {
    const filters = parseLineageFilters({
      eventId: "event-b", maxDepth: "250", includeRationale: "false",
    });
    expect(filters.maxDepth).toBe(250);
    expect(filters.includeRationale).toBe(false);
  });
  it("rejects foreign organization audit history", () => {
    expect(() => report([
      event("event-b", "event-a"),
      event("event-a", null, { organizationId: "foreign" }),
    ])).toThrow(/Cross-organization/);
  });
  it("detects missing source predecessors", () => {
    const result = report([event("event-b", "missing")]);
    expect(result.terminal).toBe("MISSING");
    expect(result.issues.map(i => i.kind)).toContain("MISSING_PREDECESSOR");
  });
  it("detects a lineage reaching the configured depth", () => {
    const result = report([event("event-b", "event-a")], 1);
    expect(result.terminal).toBe("LIMIT");
    expect(result.issues.map(i => i.kind)).toContain("DEPTH_LIMIT_REACHED");
  });
  it("flags unexpected source event ordering", () => {
    expect(codes([
      event("event-b", "event-a"),
      event("event-c", null),
    ])).toContain("EVENT_IDENTITY_MISMATCH");
  });
  it("flags cross-diagnostic case predecessor links", () => {
    expect(codes([
      event("event-b", "event-a"),
      event("event-a", null, {
        metadata: {
          code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
          resourceId: "different", revision: 2,
          rationale: "Reviewed source", previousEventId: null,
        },
      }),
    ])).toContain("CROSS_CASE_REFERENCE");
  });
  it("detects decreased revisions along linked events", () => {
    expect(codes([
      event("event-b", "event-a", { metadata: {
        code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
        resourceId: "work-123", revision: 1,
        rationale: "Reviewed source", previousEventId: "event-a",
      } }),
      event("event-a", null),
    ])).toContain("REVISION_DECREASE");
  });
  it("detects predecessor timestamps after successor timestamps", () => {
    expect(codes([
      event("event-b", "event-a"),
      event("event-a", null, { occurredAt: new Date("2026-10-04T10:00:00Z") }),
    ])).toContain("TIME_INVERSION");
  });
  it("marks missing reviewer attribution", () => {
    expect(codes([
      event("event-a", null, { actorUserId: null }),
    ])).toContain("MISSING_ACTOR");
  });
  it("marks missing rationale without reconstructing one", () => {
    expect(codes([
      event("event-a", null, { metadata: {
        code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
        resourceId: "work-123", revision: 2,
        rationale: "", previousEventId: null,
      } }),
    ])).toContain("MISSING_RATIONALE");
  });
  it("preserves missing work uncertainty", () => {
    const result = report([event("event-a", null)], 25, null);
    expect(result.latestReviewIsCurrent).toBeNull();
    expect(result.issues.map(i => i.kind)).toContain("WORK_ITEM_MISSING");
  });
  it("indicates a changed current work revision", () => {
    const result = report([event("event-a", null)], 25, {
      id: "work-123", title: "Review work", revision: 3,
    });
    expect(result.latestReviewIsCurrent).toBe(false);
    expect(result.issues.map(i => i.kind)).toContain("WORK_REVISION_DRIFT");
  });
  it("never exposes rationale when excluded", () => {
    const result = reconstructAuditLineage({
      organizationId: "tenant-a", generatedAt: "2026-11-01T10:00:00Z",
      eventId: "event-a", raw: [event("event-a", null)],
      completeToRoot: true, maxDepth: 25,
      includeRationale: false, work: null,
    });
    expect(result.nodes[0]?.rationale).toBeNull();
  });
  it("does not modify provided source records", () => {
    const rows = [event("event-b", "event-a"), event("event-a", null)];
    const before = JSON.stringify(rows);
    report(rows);
    expect(JSON.stringify(rows)).toBe(before);
  });
  it("exports source-linked human decisions as safe CSV", () => {
    const csv = auditLineageCsv(report());
    expect(csv).toContain("previousEventId");
    expect(csv).toContain("event-b");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
