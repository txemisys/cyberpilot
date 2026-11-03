import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { inspectIntegrityEvidenceGraph } from "./work-integrity-evidence-graph";
import {
  shortestIntegrityLineagePath, integrityLineageNeighborhood,
  evaluateIntegrityLineageImpact, analyzeIntegrityLineage, inspectIntegrityLineage,
} from "./work-integrity-evidence-lineage";
const captureId = "capture-one";
function event(id: string, caseKey: string, workItemId: string):
  IntegrityLinkHistoryEvent {
  return {
    auditId: id, originalAuditId: null, action: "LINK",
    captureId, caseKey, workItemId, actorUserId: "user-one",
    occurredAt: "2026-11-01T10:00:00.000Z",
  };
}
const events = [
  event("audit-one", "case-one", "work-one"),
  event("audit-two", "case-two", "work-one"),
  event("audit-three", "case-two", "work-two"),
];
describe("integrity evidence lineage", () => {
  it("finds the shortest path across connected case/work associations", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    const path = shortestIntegrityLineagePath(graph, "case:case-one", "work:work-two");
    expect(path?.nodes).toEqual([
      "case:case-one", "work:work-one", "case:case-two", "work:work-two",
    ]);
    expect(path?.auditIds).toEqual(["audit-one", "audit-two", "audit-three"]);
    expect(path?.hops).toBe(3);
  });
  it("returns null for disconnected nodes", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, [
      ...events, event("audit-four", "case-three", "work-three"),
    ]).graph;
    expect(shortestIntegrityLineagePath(graph, "case:case-one", "case:case-three"))
      .toBeNull();
  });
  it("rejects unknown graph nodes", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    expect(() => shortestIntegrityLineagePath(graph, "case:missing", "work:work-one"))
      .toThrow();
  });
  it("computes bounded neighborhoods", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    const neighborhood = integrityLineageNeighborhood(graph, "case:case-one", 2);
    expect(neighborhood.nodes.map(x => x.id)).toEqual([
      "case:case-one", "case:case-two", "work:work-one",
    ]);
    expect(neighborhood.distances["case:case-two"]).toBe(2);
  });
  it("rejects excessive neighborhood depth", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    expect(() => integrityLineageNeighborhood(graph, "case:case-one", 21)).toThrow();
  });
  it("detects bridge associations in a tree-shaped graph", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    const impact = evaluateIntegrityLineageImpact(graph, "audit-two");
    expect(impact.disconnectedByRemoval).toBe(true);
    expect(impact.afterComponents).toBe(2);
  });
  it("summarizes lineage connectivity", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    const overview = analyzeIntegrityLineage(graph);
    expect(overview.activeEdgeCount).toBe(3);
    expect(overview.bridges).toHaveLength(3);
  });
  it("provides one combined lineage inspection result", () => {
    const result = inspectIntegrityLineage(captureId, events, {
      from: "case:case-one", to: "work:work-two",
      origin: "case:case-one", depth: 1,
    });
    expect(result.path?.hops).toBe(3);
    expect(result.neighborhood?.nodes).toHaveLength(2);
  });
});
