import { describe, expect, it } from "vitest";
import type { BranchReport, BranchNode } from "./work-integrity-audit-branch-explorer";
import { summarizeBranchTopology } from "./work-integrity-audit-branch-topology";

const node = (id: string, previousEventId: string | null,
  changes: Partial<BranchNode> = {}): BranchNode => ({
  id, caseKey: '["work-123","DONE_WITHOUT_COMPLETION","work-123"]',
  decision: "INVESTIGATE", code: "DONE_WITHOUT_COMPLETION",
  resourceId: "work-123", previousEventId, revision: 2,
  occurredAt: id === "a" ? "2026-10-01T10:00:00Z" : "2026-10-02T10:00:00Z",
  actorUserId: "reviewer-1", rationale: null, successorIds: [],
  depthFromRoot: 0, isRoot: previousEventId === null, isTerminal: true,
  ...changes,
});
const report = (nodes: BranchNode[], overrides: Partial<BranchReport> = {}): BranchReport => ({
  organizationId: "org-a", workItemId: "work-123",
  workTitle: "Review", workRevision: 2,
  generatedAt: "2026-11-01T11:00:00Z", sourceRows: nodes.length,
  malformedRows: 0, sourceTruncated: false, nodes, cases: [], issues: [],
  totals: { cases: 1, nodes: nodes.length, errors: 0, warnings: 0, unknowns: 0, forks: 0 },
  limitations: [], ...overrides,
});
describe("source-backed audit review graph topology", () => {
  it("counts actual linked predecessors and review roots", () => {
    const summary = summarizeBranchTopology(report([
      node("a", null, { successorIds: ["b"], isTerminal: false }),
      node("b", "a", { depthFromRoot: 1 }),
    ]));
    expect(summary.linkedEdges).toBe(1);
    expect(summary.rootNodes).toBe(1);
    expect(summary.terminalNodes).toBe(1);
    expect(summary.maximumObservedDepth).toBe(1);
  });
  it("distinguishes missing bounded predecessors", () => {
    const summary = summarizeBranchTopology(report([node("b", "outside")]));
    expect(summary.unresolvedPredecessors).toBe(1);
    expect(summary.linkedEdges).toBe(0);
  });
  it("rejects inconsistent successor identities", () => {
    expect(() => summarizeBranchTopology(report([
      node("a", null, { successorIds: ["b"] }),
    ]))).toThrow(/successor linkage/);
  });
  it("distinguishes historical review revisions", () => {
    const summary = summarizeBranchTopology(report([
      node("a", null), node("b", null, { revision: 1, actorUserId: null }),
    ]));
    expect(summary.currentRevisionReviews).toBe(1);
    expect(summary.historicalRevisionReviews).toBe(1);
    expect(summary.missingActorReferences).toBe(1);
  });
  it("does not claim complete coverage for capped source rows", () => {
    const summary = summarizeBranchTopology(report([node("a", null)], {
      sourceTruncated: true,
    }));
    expect(summary.coverage).toBe("TRUNCATED_OR_MALFORMED");
  });
  it("withholds complete source status when metadata is unreadable", () => {
    const summary = summarizeBranchTopology(report([node("a", null)], {
      malformedRows: 1,
    }));
    expect(summary.coverage).toBe("TRUNCATED_OR_MALFORMED");
  });
  it("rejects duplicate event identifiers", () => {
    expect(() => summarizeBranchTopology(report([
      node("a", null), node("a", null),
    ]))).toThrow(/Duplicate source event/);
  });
  it("reports most recent event per diagnostic without changing the source", () => {
    const nodes = [node("b", "a"), node("a", null, {
      successorIds: ["b"], isTerminal: false,
    })];
    const before = JSON.stringify(nodes);
    const summary = summarizeBranchTopology(report(nodes));
    expect(summary.latestEventPerCase[0]?.eventId).toBe("b");
    expect(JSON.stringify(nodes)).toBe(before);
  });
});
