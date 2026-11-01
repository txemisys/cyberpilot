import { describe, expect, it } from "vitest";
import type { Prisma } from "@cyberpilot/database";
import {
  aggregateAuditDigest, parseAuditDigestFilter, auditDigestCsv,
} from "./work-integrity-audit-digest";
const now = new Date("2026-11-01T12:00:00.000Z");
const filter = parseAuditDigestFilter({
  from: "2026-10-30T00:00:00.000Z",
  to: "2026-11-01T11:59:59.000Z",
}, now);
const raw = (id: string, decision = "INVESTIGATE",
  overrides: Record<string, unknown> = {}) => ({
  id, organizationId: "tenant-a", resourceId: "work-123",
  actorUserId: "reviewer-a",
  occurredAt: new Date("2026-10-31T10:00:00.000Z"),
  metadata: {
    code: "DONE_WITHOUT_COMPLETION", decision,
    resourceId: "work-123", revision: 2,
    rationale: "Reviewing source records", previousEventId: null,
  } as Prisma.JsonValue,
  ...overrides,
});
const digest = (rows: ReturnType<typeof raw>[], truncated = false) =>
  aggregateAuditDigest({
    organizationId: "tenant-a", generatedAt: now.toISOString(),
    filter, rows, truncated,
    work: new Map([["work-123", { id: "work-123", revision: 2 }]]),
  });
describe("bounded recorded decision digest validation", () => {
  it("accepts a bounded default week", () => {
    const result = parseAuditDigestFilter({}, now);
    expect(result.limit).toBe(2000);
    expect(result.to.toISOString()).toBe(now.toISOString());
  });
  it("enforces a maximum reporting window", () => {
    expect(() => parseAuditDigestFilter({
      from: "2026-01-01", to: "2026-11-01",
    }, now)).toThrow();
  });
  it("rejects future windows", () => {
    expect(() => parseAuditDigestFilter({
      to: "2030-01-01",
    }, now)).toThrow();
  });
  it("rejects reverse chronology", () => {
    expect(() => parseAuditDigestFilter({
      from: "2026-11-01", to: "2026-10-01",
    }, now)).toThrow();
  });
  it.each([
    { limit: "42" }, { limit: "-1" },
    { actorUserId: "?" }, { workItemId: "../other" },
    { organizationId: "foreign" },
  ])("rejects malformed digest filter %j", input => {
    expect(() => parseAuditDigestFilter(input, now)).toThrow();
  });
  it("refuses records from a foreign organization", () => {
    expect(() => digest([raw("e1", "INVESTIGATE", {
      organizationId: "foreign",
    })])).toThrow(/Foreign organization/);
  });
  it("refuses duplicate event identities", () => {
    expect(() => digest([raw("e1"), raw("e1")])).toThrow(/Duplicate audit event/);
  });
  it("refuses out-of-window audit records", () => {
    expect(() => digest([raw("e1", "INVESTIGATE", {
      occurredAt: new Date("2026-09-01T00:00:00Z"),
    })])).toThrow(/outside trusted digest range/);
  });
  it("preserves explicit zero-decision days", () => {
    const result = digest([]);
    expect(result.daily.some(day => day.recorded === 0)).toBe(true);
    expect(result.recorded).toBe(0);
  });
  it("counts actual decisions and distinct cases independently", () => {
    const result = digest([raw("e1"), raw("e2", "ACKNOWLEDGE")]);
    expect(result.recorded).toBe(2);
    expect(result.uniqueCases).toBe(1);
    expect(result.decisions.ACKNOWLEDGE).toBe(1);
  });
  it("counts human actors without inventing deleted users", () => {
    const result = digest([raw("e1", "INVESTIGATE", {
      actorUserId: null,
    })]);
    expect(result.daily.find(day => day.day === "2026-10-31")?.unknownActors).toBe(1);
    expect(result.actors[0]?.actorUserId).toBeNull();
  });
  it("marks outdated revisions without treating them as completed remediation", () => {
    const result = digest([raw("e1", "INVESTIGATE", {
      metadata: {
        code: "DONE_WITHOUT_COMPLETION",
        decision: "INVESTIGATE", resourceId: "work-123",
        revision: 1, rationale: "Old review",
      },
    })]);
    expect(result.daily.find(day => day.day === "2026-10-31")?.staleReviews).toBe(1);
    expect(result.cases[0]?.currentlyReviewed).toBe(false);
  });
  it("marks source truncation and does not claim global completeness", () => {
    const result = digest([raw("e1")], true);
    expect(result.historyTruncated).toBe(true);
    expect(result.limitations.join(" ")).toMatch(/lower bounds/);
  });
  it("withholds malformed events from decision totals", () => {
    const result = digest([raw("e1", "INVESTIGATE", {
      metadata: { unreadable: true },
    })]);
    expect(result.malformed).toBe(1);
    expect(result.recorded).toBe(0);
  });
  it("counts each reviewed actor's distinct work item identity", () => {
    const result = digest([raw("e1"), raw("e2", "DISMISS")]);
    expect(result.actors[0]?.recorded).toBe(2);
    expect(result.actors[0]?.workItems).toBe(1);
  });
  it("exports non-fabricated activity counts as CSV", () => {
    const csv = auditDigestCsv(digest([raw("e1")]));
    expect(csv).toContain("investigations");
    expect(csv).toContain("2026-10-31");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
