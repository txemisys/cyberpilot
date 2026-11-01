import { describe, expect, it } from "vitest";
import type { Prisma } from "@cyberpilot/database";
import {
  inspectAuditBranches, parseBranchFilters, auditBranchesCsv, type BranchRaw,
} from "./work-integrity-audit-branch-explorer";

const event = (id: string, previousEventId: string | null,
  overrides: Partial<BranchRaw> = {}): BranchRaw => ({
  id, organizationId: "tenant-a", resourceId: "work-123",
  actorUserId: "reviewer-123",
  occurredAt: new Date(id === "a" ? "2026-10-01T10:00:00Z" :
    id === "b" ? "2026-10-02T10:00:00Z" : "2026-10-03T10:00:00Z"),
  metadata: {
    code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
    resourceId: "work-123", revision: 2,
    rationale: "Checked underlying operational evidence",
    previousEventId,
  } as Prisma.JsonValue,
  ...overrides,
});
const inspect = (rows: BranchRaw[], truncated = false,
  includeRationale = true) => inspectAuditBranches({
  organizationId: "tenant-a", workItemId: "work-123",
  workTitle: "Review completion", workRevision: 2,
  generatedAt: "2026-11-01T11:00:00Z",
  rows, truncated, includeRationale,
});
const codes = (rows: BranchRaw[], truncated = false) =>
  inspect(rows, truncated).issues.map(issue => issue.code);
describe("tenant-scoped work audit branch graph", () => {
  it("accepts strict source caps and access-independent filters", () => {
    expect(parseBranchFilters({ workItemId: "work-123" }))
      .toMatchObject({ workItemId: "work-123", limit: 500, includeRationale: false });
    expect(parseBranchFilters({
      workItemId: "work-123", limit: "2000", includeRationale: "true",
    }).includeRationale).toBe(true);
  });
  it.each([
    { workItemId: "bad" },
    { workItemId: "work-123", limit: "101" },
    { workItemId: "work-123", includeRationale: "yes" },
    { workItemId: "work-123", organizationId: "another" },
  ])("rejects invalid parameters %j", raw => {
    expect(() => parseBranchFilters(raw)).toThrow();
  });
  it("refuses foreign organization event records", () => {
    expect(() => inspect([event("a", null, { organizationId: "tenant-b" })]))
      .toThrow(/outside the authorized work scope/);
  });
  it("refuses foreign work source rows", () => {
    expect(() => inspect([event("a", null, { resourceId: "work-other" })]))
      .toThrow(/outside the authorized work scope/);
  });
  it("refuses source metadata that disagrees with the work-item ID", () => {
    expect(() => inspect([event("a", null, {
      metadata: {
        code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
        resourceId: "resource-a", revision: 2, rationale: "Reviewed source",
      },
    })])).toThrow();
  });
  it("keeps a linear review graph without concurrency anomalies", () => {
    const result = inspect([event("c", "b"), event("b", "a"), event("a", null)]);
    expect(result.totals.errors).toBe(0);
    expect(result.totals.forks).toBe(0);
    expect(result.cases[0]?.roots).toBe(1);
    expect(result.cases[0]?.terminals).toBe(1);
    expect(result.cases[0]?.maxDepth).toBe(2);
  });
  it("identifies two concurrent human reviews referencing one predecessor", () => {
    const result = inspect([event("a", null), event("b", "a"), event("c", "a")]);
    expect(result.totals.forks).toBe(1);
    expect(result.issues.map(item => item.code)).toContain("MULTIPLE_SUCCESSORS");
    expect(result.nodes.find(item => item.id === "a")?.successorIds)
      .toEqual(["b", "c"]);
  });
  it("flags an absent predecessor in complete source coverage", () => {
    expect(codes([event("b", "missing")])).toContain("MISSING_PREDECESSOR");
    expect(inspect([event("b", "missing")]).totals.errors).toBeGreaterThan(0);
  });
  it("retains uncertainty when the source is truncated", () => {
    const result = inspect([event("b", "missing")], true);
    expect(result.issues.find(issue => issue.code === "MISSING_PREDECESSOR")
      ?.severity).toBe("UNKNOWN");
    expect(result.sourceTruncated).toBe(true);
  });
  it("detects multiple independent roots", () => {
    expect(codes([event("a", null), event("b", null)]))
      .toContain("DISCONNECTED_ROOTS");
  });
  it("detects cycles without unbounded recursion", () => {
    const result = inspect([event("a", "b"), event("b", "a")]);
    expect(result.issues.map(issue => issue.code)).toContain("PREDECESSOR_CYCLE");
    expect(result.cases[0]?.hasCycle).toBe(true);
  });
  it("identifies reversed predecessor timestamps", () => {
    expect(codes([
      event("a", null, { occurredAt: new Date("2026-10-04T10:00:00Z") }),
      event("b", "a"),
    ])).toContain("REVERSED_REVIEW_TIME");
  });
  it("identifies a work revision decrease", () => {
    expect(codes([
      event("a", null, {
        metadata: {
          code: "DONE_WITHOUT_COMPLETION", decision: "INVESTIGATE",
          resourceId: "work-123", revision: 3, rationale: "Reviewed",
        },
      }),
      event("b", "a"),
    ])).toContain("REVIEW_REVISION_DECREASED");
  });
  it("rejects repeated event identities from source", () => {
    expect(() => inspect([event("a", null), event("a", null)]))
      .toThrow(/Repeated source/);
  });
  it("counts malformed rows without manufacturing decisions", () => {
    const result = inspect([event("a", null), event("b", null, {
      metadata: { bad: true },
    })]);
    expect(result.malformedRows).toBe(1);
    expect(result.nodes).toHaveLength(1);
    expect(result.issues.map(x => x.code)).toContain("UNPARSEABLE_SOURCE");
  });
  it("hides rationales when the requester does not ask for them", () => {
    const result = inspect([event("a", null)], false, false);
    expect(result.nodes[0]?.rationale).toBeNull();
  });
  it("does not alter stored records during graph reconstruction", () => {
    const rows = [event("b", "a"), event("a", null)];
    const before = JSON.stringify(rows);
    inspect(rows);
    expect(JSON.stringify(rows)).toBe(before);
  });
  it("exports bounded source graph rows as CSV", () => {
    const csv = auditBranchesCsv(inspect([event("a", null)]));
    expect(csv).toContain("previousEventId");
    expect(csv).toContain("work-123");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
