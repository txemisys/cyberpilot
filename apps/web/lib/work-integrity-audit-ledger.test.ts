import { describe, expect, it } from "vitest";
import type { Prisma } from "@cyberpilot/database";
import {
  parseLedgerFilters, projectLedgerPage, auditLedgerCsv,
  type LedgerRawEvent, type LedgerWorkItem,
} from "./work-integrity-audit-ledger";
const raw = (id: string, extra: Partial<LedgerRawEvent> = {}): LedgerRawEvent => ({
  id, organizationId: "tenant-a", resourceId: "work-123",
  actorUserId: "user-123",
  occurredAt: new Date(id === "event-1" ?
    "2026-10-01T10:00:00Z" : "2026-10-02T10:00:00Z"),
  metadata: {
    schemaVersion: 1, code: "DONE_WITHOUT_COMPLETION",
    decision: id === "event-1" ? "INVESTIGATE" : "ACKNOWLEDGE",
    resourceId: "work-123", revision: 2,
    rationale: "Checking evidence status",
    previousEventId: id === "event-1" ? null : "event-1",
  } as Prisma.JsonValue,
  ...extra,
});
const work: LedgerWorkItem = {
  id: "work-123", title: "Review task", status: "DONE", revision: 2,
};
const filters = parseLedgerFilters({});
const page = (
  events: LedgerRawEvent[] = [raw("event-1")],
  overrides = filters, hasMore = false,
  works = new Map([[work.id, work]]),
) => projectLedgerPage(
  "tenant-a", "2026-10-03T00:00:00Z", overrides, events, works, hasMore,
);
describe("bounded persisted audit ledger options", () => {
  it("uses safe defaults and bounded raw page size", () => {
    expect(filters).toEqual({
      limit: 25, cursor: null, workItemId: null,
      actorUserId: null, decision: null, includeMalformed: false,
    });
  });
  it("allows known decisions with work and actor filters", () => {
    expect(parseLedgerFilters({
      limit: "50", workItemId: "work-123", actorUserId: "user-123",
      decision: "INVESTIGATE", includeMalformed: "true",
      cursor: "event_001",
    })).toMatchObject({
      limit: 50, decision: "INVESTIGATE", includeMalformed: true,
      cursor: "event_001",
    });
  });
  it.each([
    { limit: "5" }, { limit: "999" }, { limit: "3.5" },
    { workItemId: "x" }, { actorUserId: "x" },
    { decision: "APPROVED" }, { cursor: "../bad" },
    { includeMalformed: "yes" }, { organizationId: "foreign" },
  ])("rejects unsupported user input %j", options => {
    expect(() => parseLedgerFilters(options)).toThrow();
  });
  it("rejects foreign organization events instead of leaking metadata", () => {
    expect(() => page([raw("event-1", { organizationId: "tenant-b" })]))
      .toThrow(/Cross-organization/);
  });
  it("refuses duplicate raw event identities", () => {
    expect(() => page([raw("event-1"), raw("event-1")]))
      .toThrow(/Repeated event identity/);
  });
  it("treats missing linked work as unavailable, not verified", () => {
    const result = page([raw("event-1")], filters, false, new Map());
    expect(result.entries[0]?.reviewedRevisionIsCurrent).toBeNull();
    expect(result.entries[0]?.workTitle).toBeNull();
  });
  it("tracks work revision drift without changing history", () => {
    const works = new Map([[work.id, { ...work, revision: 3 }]]);
    expect(page([raw("event-1")], filters, false, works)
      .entries[0]?.reviewedRevisionIsCurrent).toBe(false);
  });
  it("retains authoritative event ID, actor and decision", () => {
    const item = page().entries[0]!;
    expect(item.source).toBe("AUDIT_EVENT");
    expect(item.eventId).toBe("event-1");
    expect(item.actorUserId).toBe("user-123");
    expect(item.decision).toBe("INVESTIGATE");
  });
  it("recognizes predecessor links inside the selected raw page", () => {
    const result = page([raw("event-2"), raw("event-1")]);
    const child = result.entries.find(item => item.eventId === "event-2")!;
    expect(child.predecessorInPage).toBe(true);
    expect(child.predecessorChronologicallyPrior).toBe(true);
  });
  it("never invents an absent predecessor", () => {
    const result = page([raw("event-2")]);
    expect(result.entries[0]?.predecessorInPage).toBe(false);
    expect(result.entries[0]?.predecessorChronologicallyPrior).toBeNull();
  });
  it("flags reversed predecessor chronology without silently changing timestamps", () => {
    const result = page([
      raw("event-2", { occurredAt: new Date("2026-10-01T09:00:00Z") }),
      raw("event-1"),
    ]);
    expect(result.entries.find(x => x.eventId === "event-2")
      ?.predecessorChronologicallyPrior).toBe(false);
  });
  it("filters decision after the bounded source page", () => {
    const result = page([raw("event-2"), raw("event-1")], {
      ...filters, decision: "INVESTIGATE",
    });
    expect(result.fetched).toBe(2);
    expect(result.matched).toBe(1);
    expect(result.entries[0]?.eventId).toBe("event-1");
  });
  it("filters by recorded actor without changing raw cursor coverage", () => {
    const result = page([
      raw("event-2", { actorUserId: "different" }), raw("event-1"),
    ], { ...filters, actorUserId: "user-123" });
    expect(result.entries.map(item => item.eventId)).toEqual(["event-1"]);
  });
  it("preserves a continuation cursor even with no matching filtered rows", () => {
    const result = page([raw("event-1")], {
      ...filters, decision: "DISMISS",
    }, true);
    expect(result.entries).toEqual([]);
    expect(result.nextCursor).toBe("event-1");
  });
  it("does not expose uninterpretable audit metadata by default", () => {
    const result = page([raw("event-1", { metadata: { bad: true } })]);
    expect(result.entries).toEqual([]);
    expect(result.malformed).toEqual([]);
  });
  it("surfaces malformed stored audit metadata only when selected", () => {
    const result = page([
      raw("event-1", { metadata: { bad: true } }),
    ], { ...filters, includeMalformed: true });
    expect(result.malformed[0]?.reason).toBe("MALFORMED_TRIAGE_PAYLOAD");
    expect(result.malformed[0]?.eventId).toBe("event-1");
  });
  it("sorts by occurrence time without mutating the database results", () => {
    const items = [raw("event-1"), raw("event-2")];
    const result = page(items);
    expect(result.entries.map(item => item.eventId))
      .toEqual(["event-2", "event-1"]);
    expect(items.map(item => item.id)).toEqual(["event-1", "event-2"]);
  });
  it("neutralizes spreadsheet formulas in exported human rationale", () => {
    const item = raw("event-1", {
      metadata: {
        schemaVersion: 1, code: "DONE_WITHOUT_COMPLETION",
        decision: "INVESTIGATE", resourceId: "work-123", revision: 2,
        rationale: "=HYPERLINK(1)", previousEventId: null,
      },
    });
    const csv = auditLedgerCsv(page([item]));
    expect(csv).toContain("'=HYPERLINK(1)");
    expect(csv).toContain("predecessorEventId");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
