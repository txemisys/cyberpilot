import { describe, expect, it } from "vitest";
import type { Prisma } from "@cyberpilot/database";
import {
  inspectAuditEventDetail, type AuditEventSource,
} from "./work-integrity-audit-event-detail";
const source = (id: string, predecessor: string | null, changes: Partial<AuditEventSource> = {}): AuditEventSource => ({
  id, organizationId: "org-a", resourceId: "work-123",
  actorUserId: "user-123",
  occurredAt: new Date(id === "audit-a" ?
    "2026-10-01T10:00:00.000Z" : "2026-10-02T10:00:00.000Z"),
  metadata: {
    code: "DONE_WITHOUT_COMPLETION",
    decision: "INVESTIGATE",
    resourceId: "work-123", revision: 2,
    rationale: "Checked task evidence",
    previousEventId: predecessor,
  } as Prisma.JsonValue,
  ...changes,
});
const detail = (
  selected = source("audit-b", "audit-a"),
  predecessor: AuditEventSource | null = source("audit-a", null),
  successors: AuditEventSource[] = [],
  truncated = false,
  work: { id: string; title: string; status: string; revision: number } | null = {
    id: "work-123", title: "Review evidence", status: "DONE", revision: 2,
  },
) => inspectAuditEventDetail({
  organizationId: "org-a",
  eventId: selected.id, generatedAt: "2026-11-01T10:00:00Z",
  selectedRaw: selected, predecessorRaw: predecessor,
  candidateSuccessors: successors, successorQueryTruncated: truncated,
  work,
});
const codes = (...args: Parameters<typeof detail>) =>
  detail(...args).problems.map(p => p.code);
describe("direct stored audit-event inspection", () => {
  it("retains one source event and the linked predecessor", () => {
    const result = detail();
    expect(result.selected?.id).toBe("audit-b");
    expect(result.predecessor?.id).toBe("audit-a");
    expect(result.problems).toEqual([]);
    expect(result.linkedEventCount).toBe(2);
  });
  it("refuses foreign selected audit records", () => {
    expect(() => detail(source("audit-b", "audit-a", {
      organizationId: "foreign",
    }))).toThrow(/Cross-organization/);
  });
  it("refuses foreign predecessor metadata", () => {
    expect(() => detail(undefined, source("audit-a", null, {
      organizationId: "foreign",
    }))).toThrow(/Cross-organization/);
  });
  it("refuses foreign successor metadata", () => {
    expect(() => detail(undefined, undefined, [
      source("audit-c", "audit-b", { organizationId: "foreign" }),
    ])).toThrow(/Cross-organization/);
  });
  it("flags a predecessor missing from the trusted source", () => {
    expect(codes(undefined, null)).toContain("MISSING_PREDECESSOR");
  });
  it("distinguishes a predecessor from another diagnostic case", () => {
    const predecessor = source("audit-a", null, {
      metadata: {
        code: "DONE_WITHOUT_COMPLETION", resourceId: "other",
        decision: "INVESTIGATE", revision: 2, rationale: "Checked",
      },
    });
    expect(codes(undefined, predecessor)).toContain("PREDECESSOR_DIFFERENT_CASE");
  });
  it("detects predecessor newer work revision", () => {
    const predecessor = source("audit-a", null, {
      metadata: {
        code: "DONE_WITHOUT_COMPLETION", resourceId: "work-123",
        decision: "INVESTIGATE", revision: 3, rationale: "Checked",
      },
    });
    expect(codes(undefined, predecessor)).toContain("REVIEW_REVISION_DECREASED");
  });
  it("detects inverted event times", () => {
    expect(codes(undefined, source("audit-a", null, {
      occurredAt: new Date("2026-10-03T10:00:00Z"),
    }))).toContain("REVIEW_TIME_REVERSED");
  });
  it("identifies changed work revisions", () => {
    expect(codes(undefined, undefined, [], false, {
      id: "work-123", title: "Review evidence", status: "DONE", revision: 3,
    })).toContain("OUTDATED_WORK_REVISION");
  });
  it("does not invent missing work state", () => {
    const result = detail(undefined, undefined, [], false, null);
    expect(result.currentWorkRevision).toBeNull();
    expect(result.problems.map(p => p.code)).toContain("WORK_ITEM_UNAVAILABLE");
  });
  it("flags absent review user attribution", () => {
    expect(codes(source("audit-b", "audit-a", {
      actorUserId: null,
    }))).toContain("REVIEW_ACTOR_UNAVAILABLE");
  });
  it("handles uninterpretable raw event metadata without approval", () => {
    const result = detail(source("audit-b", null, { metadata: { invalid: true } }));
    expect(result.selected).toBeNull();
    expect(result.sourceIsComplete).toBe(false);
    expect(result.problems[0]?.code).toBe("SOURCE_METADATA_UNINTERPRETABLE");
  });
  it("recognizes valid direct successor references", () => {
    const result = detail(undefined, undefined, [
      source("audit-c", "audit-b"),
    ]);
    expect(result.successors).toHaveLength(1);
    expect(result.problems).toHaveLength(0);
  });
  it("detects two review successors after the same decision", () => {
    expect(codes(undefined, undefined, [
      source("audit-c", "audit-b"), source("audit-d", "audit-b"),
    ])).toContain("REPEATED_REVIEW_SUCCESSOR");
  });
  it("rejects a successor referencing a different event", () => {
    expect(codes(undefined, undefined, [
      source("audit-c", "audit-a"),
    ])).toContain("SUCCESSOR_UNLINKED_FROM_SELECTED");
  });
  it("rejects successor references crossing case identities", () => {
    const child = source("audit-c", "audit-b", {
      metadata: {
        code: "DONE_WITHOUT_COMPLETION", resourceId: "different",
        decision: "INVESTIGATE", revision: 2, rationale: "Checked",
        previousEventId: "audit-b",
      },
    });
    expect(codes(undefined, undefined, [child]))
      .toContain("PREDECESSOR_DIFFERENT_CASE");
  });
  it("marks capped successor queries uncertain", () => {
    const result = detail(undefined, undefined, [], true);
    expect(result.successorQueryTruncated).toBe(true);
    expect(result.sourceIsComplete).toBe(false);
  });
  it("does not mutate the original source audit rows", () => {
    const selected = source("audit-b", "audit-a");
    const before = JSON.stringify(selected);
    detail(selected);
    expect(JSON.stringify(selected)).toBe(before);
  });
});
