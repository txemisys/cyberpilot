import { describe, expect, it } from "vitest";
import type { TriageEvent } from "./work-integrity-triage";
import {
  inspectAuditChain, auditChainCsv, parseAuditChainFilters, auditChainKey,
} from "./work-integrity-audit-chain";

const event = (id: string, previousEventId: string | null, extra: Partial<TriageEvent> = {}): TriageEvent => ({
  id,
  organizationId: "tenant-a",
  workItemId: "work-12345",
  code: "DONE_WITHOUT_COMPLETION",
  resourceId: "work-12345",
  actorUserId: "user-123",
  occurredAt: new Date(`2026-10-01T10:${id === "a" ? "00" : id === "b" ? "01" : "02"}:00Z`),
  revision: 2,
  decision: id === "a" ? "INVESTIGATE" : "ACKNOWLEDGE",
  rationale: "Reviewed as part of the audited workflow.",
  reference: null,
  previousEventId,
  ...extra,
});
const report = (events: TriageEvent[], bounded = false, malformedRecords = 0) =>
  inspectAuditChain({
    organizationId: "tenant-a",
    workItemId: "work-12345",
    workTitle: "Review completion evidence",
    currentRevision: 2,
    generatedAt: "2026-10-02T10:00:00.000Z",
    bounded,
    rawRecordsRead: events.length + malformedRecords,
    events,
    malformedRecords,
    includeEvents: true,
  });
const codes = (events: TriageEvent[], bounded = false) =>
  report(events, bounded).problems.map(problem => problem.code);

describe("tenant-scoped source audit chain boundary", () => {
  it("accepts a valid bounded identifier", () => {
    expect(parseAuditChainFilters({ workItemId: "work-12345" }))
      .toMatchObject({ workItemId: "work-12345", limit: 500, includeEvents: false });
  });
  it("accepts strict bounded limits and event display toggle", () => {
    expect(parseAuditChainFilters({
      workItemId: "work-12345", limit: "2000", includeEvents: "true",
    })).toMatchObject({ limit: 2000, includeEvents: true });
  });
  it.each([
    { workItemId: "bad" },
    { workItemId: "work-12345", limit: "9" },
    { workItemId: "work-12345", limit: "2001" },
    { workItemId: "work-12345", limit: "12.5" },
    { workItemId: "work-12345", includeEvents: "yes" },
    { workItemId: "work-12345", organizationId: "foreign" },
  ])("rejects unsafe query %j", values => {
    expect(() => parseAuditChainFilters(values)).toThrow();
  });
  it("does not accept events from a different organization", () => {
    expect(() => report([event("a", null, { organizationId: "tenant-b" })]))
      .toThrow(/Cross-tenant/);
  });
  it("does not accept events belonging to other work items", () => {
    expect(() => report([event("a", null, { workItemId: "work-other" })]))
      .toThrow(/cross-work-item/);
  });
  it("uses unambiguous case identities", () => {
    expect(auditChainKey(event("a", null))).toBe(JSON.stringify([
      "work-12345", "DONE_WITHOUT_COMPLETION", "work-12345",
    ]));
  });
});
describe("audit event predecessor graph", () => {
  it("recognizes a complete linear chain without attesting remediation", () => {
    const result = report([event("a", null), event("b", "a"), event("c", "b")]);
    expect(result.historyComplete).toBe(true);
    expect(result.cases[0]?.rootCount).toBe(1);
    expect(result.cases[0]?.headCount).toBe(1);
    expect(result.cases[0]?.chainLength).toBe(3);
    expect(result.totals.errors).toBe(0);
    expect(result.limitations.join(" ")).toMatch(/cannot certify remediation/);
  });
  it("preserves empty audit records without fabricating decisions", () => {
    const result = report([]);
    expect(result.cases).toEqual([]);
    expect(result.recordsRead).toBe(0);
    expect(result.totals.cases).toBe(0);
  });
  it("flags predecessor missing from a complete queried scope", () => {
    expect(codes([event("b", "missing")])).toContain("MISSING_PREDECESSOR");
    expect(report([event("b", "missing")]).totals.errors).toBeGreaterThan(0);
  });
  it("classifies a missing predecessor as unknown in a bounded window", () => {
    const result = report([event("b", "earlier")], true);
    expect(result.problems.find(p => p.code === "MISSING_PREDECESSOR")?.severity)
      .toBe("UNKNOWN");
    expect(result.historyComplete).toBe(false);
  });
  it("detects a cycle without looping indefinitely", () => {
    const result = report([event("a", "b"), event("b", "a")]);
    expect(result.problems.some(problem => problem.code === "CYCLE")).toBe(true);
    expect(result.historyComplete).toBe(false);
  });
  it("detects two concurrent branches sharing a predecessor", () => {
    expect(codes([event("a", null), event("b", "a"), event("c", "a")]))
      .toContain("FORK");
  });
  it("detects duplicate event identities", () => {
    expect(codes([event("a", null), event("a", null)]))
      .toContain("REPEATED_EVENT_ID");
  });
  it("detects multiple disconnected roots", () => {
    expect(codes([event("a", null), event("b", null)]))
      .toContain("MULTIPLE_ROOTS");
  });
  it("detects a predecessor linked to a different case", () => {
    const result = report([
      event("a", null),
      event("b", "a", { resourceId: "other-linked-resource" }),
    ]);
    expect(result.problems.some(p => p.code === "CROSS_CASE_PREDECESSOR")).toBe(true);
  });
  it("detects clock inversion between linked events", () => {
    const result = report([
      event("a", null, { occurredAt: new Date("2026-10-01T12:00:00Z") }),
      event("b", "a", { occurredAt: new Date("2026-10-01T11:00:00Z") }),
    ]);
    expect(result.problems.map(p => p.code)).toContain("EVENT_TIME_REVERSED");
  });
  it("detects reviewed revision decreasing through the audit chain", () => {
    const result = report([
      event("a", null, { revision: 2 }),
      event("b", "a", { revision: 1 }),
    ]);
    expect(result.problems.map(p => p.code)).toContain("REVISION_REVERSED");
  });
  it("does not treat future work revisions as verified", () => {
    expect(codes([event("a", null, { revision: 3 })]))
      .toContain("REVISION_REVERSED");
  });
  it("retains deleted-actor uncertainty rather than filling a user", () => {
    expect(codes([event("a", null, { actorUserId: null })]))
      .toContain("UNATTRIBUTED_REVIEW");
  });
  it("withholds complete history when malformed source events exist", () => {
    const result = report([event("a", null)], false, 1);
    expect(result.historyComplete).toBe(false);
    expect(result.malformedRecords).toBe(1);
    expect(result.problems.map(p => p.code)).toContain("INVALID_AUDIT_PAYLOAD");
  });
  it("withholds event identities when the user does not request them", () => {
    const result = inspectAuditChain({
      organizationId: "tenant-a", workItemId: "work-12345",
      workTitle: "Evidence review", currentRevision: 2,
      generatedAt: "2026-10-02T10:00:00.000Z", bounded: false,
      rawRecordsRead: 1, malformedRecords: 0,
      events: [event("a", null)], includeEvents: false,
    });
    expect(result.cases[0]?.eventIds).toEqual([]);
  });
  it("exports safe CSV rows without claiming completion", () => {
    const csv = auditChainCsv(report([event("a", null)]));
    expect(csv).toContain("completeHistory");
    expect(csv).toContain("DONE_WITHOUT_COMPLETION");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
  it("keeps the input event collection unmodified", () => {
    const events = [event("a", null), event("b", "a")];
    const before = events.map(e => e.id);
    report(events);
    expect(events.map(e => e.id)).toEqual(before);
  });
});
