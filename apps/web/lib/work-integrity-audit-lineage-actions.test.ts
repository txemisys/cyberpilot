import { describe, expect, it } from "vitest";
import type { LineageReport } from "./work-integrity-audit-lineage";
import { planLineageActions, lineageActionsCsv } from "./work-integrity-audit-lineage-actions";

const base = (issues: LineageReport["issues"] = []): LineageReport => ({
  organizationId: "tenant-a", requestedEventId: "event-1",
  generatedAt: "2026-11-01T10:00:00Z", workItemId: "work-123",
  workTitle: "Review work", currentRevision: 2,
  nodes: [], issues, terminal: "ROOT", sourceChainComplete: issues.length === 0,
  inspectedEvents: 0, newestRecordedDecision: "INVESTIGATE",
  latestReviewedRevision: 2, latestReviewIsCurrent: true, limitations: [],
});
const issue = (kind: LineageReport["issues"][number]["kind"], eventId = "event-1") => ({
  kind, severity: "ERROR" as const, eventId, referencedEventId: "event-0",
  message: "Source review discrepancy", nextAction: "Inspect audit source",
});
describe("source-backed lineage investigation planning", () => {
  it("returns no fabricated tasks for consistent audit lineage", () => {
    expect(planLineageActions(base()).actions).toEqual([]);
  });
  it("prioritizes cross-case source integrity problems", () => {
    const plan = planLineageActions(base([
      issue("MISSING_ACTOR"), issue("CROSS_CASE_REFERENCE"),
    ]));
    expect(plan.actions[0]?.priority).toBe("P0");
    expect(plan.byPriority.P0).toBe(1);
  });
  it("deduplicates the same event and proposed investigation type", () => {
    const plan = planLineageActions(base([
      issue("PREDECESSOR_CYCLE"), issue("EVENT_IDENTITY_MISMATCH"),
    ]));
    expect(plan.itemCount).toBe(1);
    expect(plan.actions[0]?.occurrenceCount).toBe(2);
  });
  it("preserves the human decision boundary", () => {
    const plan = planLineageActions(base([issue("MISSING_RATIONALE")]));
    expect(plan.actions[0]?.requiresHumanDecision).toBe(true);
    expect(plan.actions[0]?.automaticClosurePermitted).toBe(false);
  });
  it("does not hide overall counts when returning a bounded selection", () => {
    const plan = planLineageActions(base([
      issue("MISSING_ACTOR"), issue("CROSS_CASE_REFERENCE"),
    ]), 1);
    expect(plan.actions).toHaveLength(1);
    expect(plan.itemCount).toBe(2);
    expect(plan.omitted).toBe(1);
  });
  it("rejects invalid action limits", () => {
    expect(() => planLineageActions(base(), 0)).toThrow();
    expect(() => planLineageActions(base(), 501)).toThrow();
  });
  it("exports human investigation CSV without security attestation", () => {
    const csv = lineageActionsCsv(planLineageActions(base([
      issue("MISSING_PREDECESSOR"),
    ])));
    expect(csv).toContain("REVIEW_SOURCE_RETENTION");
    expect(csv).toContain("automaticClosurePermitted");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
