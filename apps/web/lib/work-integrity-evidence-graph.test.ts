import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  inspectIntegrityEvidenceGraph, parseIntegrityEvidenceQuery,
  queryIntegrityEvidence, summarizeIntegrityEvidenceCases,
  summarizeIntegrityEvidenceWork, buildIntegrityEvidenceGraph,
  connectedIntegrityEvidenceComponents, summarizeIntegrityEvidenceGraph,
} from "./work-integrity-evidence-graph";
import { reviewIntegrityLinks } from "./work-integrity-link-review";
const captureId = "capture-one";
const date = "2026-11-01T10:00:00.000Z";
function link(id: string, caseKey: string, workItemId: string): IntegrityLinkHistoryEvent {
  return {
    auditId: id, originalAuditId: null, action: "LINK", captureId,
    caseKey, workItemId, actorUserId: "user-one", occurredAt: date,
  };
}
const events = [
  link("audit-one", "case-one", "work-one"),
  link("audit-two", "case-one", "work-two"),
  link("audit-three", "case-two", "work-three"),
];
describe("integrity evidence graph and lineage", () => {
  it("parses bounded query filters", () => {
    expect(parseIntegrityEvidenceQuery({
      captureId, caseKeys: ["case-one"], states: ["ACTIVE"], limit: 20,
    })).toMatchObject({ caseKeys: ["case-one"], limit: 20 });
  });
  it("rejects unknown filters", () => {
    expect(() => parseIntegrityEvidenceQuery({
      captureId, unexpected: true,
    })).toThrow();
  });
  it("rejects inverted timestamp windows", () => {
    expect(() => parseIntegrityEvidenceQuery({
      captureId, after: "2026-11-03T00:00:00.000Z",
      before: "2026-11-01T00:00:00.000Z",
    })).toThrow();
  });
  it("filters by case and work item and paginates", () => {
    const report = reviewIntegrityLinks(captureId, events);
    const result = queryIntegrityEvidence(report, events, {
      captureId, caseKeys: ["case-one"], offset: 0, limit: 1,
      includeEvents: true,
    });
    expect(result).toMatchObject({ total: 2, hasMore: true });
    expect(result.events).toHaveLength(1);
    expect(result.cases[0]?.caseKey).toBe("case-one");
  });
  it("summarizes distinct work items per case", () => {
    const report = reviewIntegrityLinks(captureId, events);
    const cases = summarizeIntegrityEvidenceCases(report.associations);
    expect(cases.find(x => x.caseKey === "case-one")?.workItemIds)
      .toEqual(["work-one", "work-two"]);
  });
  it("summarizes distinct cases per work item", () => {
    const report = reviewIntegrityLinks(captureId, events);
    const works = summarizeIntegrityEvidenceWork(report.associations);
    expect(works).toHaveLength(3);
    expect(works[0]?.actors).toEqual(["user-one"]);
  });
  it("builds bipartite case/work graph", () => {
    const report = reviewIntegrityLinks(captureId, events);
    const graph = buildIntegrityEvidenceGraph(captureId, report.associations);
    expect(graph.nodes).toHaveLength(5);
    expect(graph.edges).toHaveLength(3);
    expect(graph.activeEdges).toBe(3);
  });
  it("finds disconnected evidence components", () => {
    const result = inspectIntegrityEvidenceGraph(captureId, events);
    expect(result.stats.connectedComponents).toBe(2);
    expect(result.stats.largestComponent).toBe(3);
    expect(result.components.map(x => x.edges).sort()).toEqual([1, 2]);
  });
  it("detects cases without active work after withdrawal", () => {
    const withdrawal: IntegrityLinkHistoryEvent = {
      ...events[2]!, auditId: "withdrawal-one",
      originalAuditId: "audit-three", action: "UNLINK",
      occurredAt: "2026-11-02T10:00:00.000Z",
    };
    const result = inspectIntegrityEvidenceGraph(captureId, [...events, withdrawal]);
    expect(result.stats.casesWithoutActiveWork).toEqual(["case-two"]);
    expect(result.stats.workWithoutActiveCases).toEqual(["work-three"]);
  });
  it("rejects cross-capture associations", () => {
    const report = reviewIntegrityLinks(captureId, events);
    expect(() => buildIntegrityEvidenceGraph("capture-other", report.associations))
      .toThrow();
  });
  it("calculates component summaries without modifying the graph", () => {
    const graph = inspectIntegrityEvidenceGraph(captureId, events).graph;
    const before = JSON.stringify(graph);
    const components = connectedIntegrityEvidenceComponents(graph);
    const stats = summarizeIntegrityEvidenceGraph(graph);
    expect(components).toHaveLength(2);
    expect(stats.totalCases).toBe(2);
    expect(JSON.stringify(graph)).toBe(before);
  });
});
