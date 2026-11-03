import { describe, expect, it } from "vitest";
import {
  exportIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityExportOptions,
} from "./work-integrity-remediation-execution-capacity-export";
import type {
  IntegrityExecutionCapacityPlan,
} from "./work-integrity-remediation-execution-capacity";
const plan: IntegrityExecutionCapacityPlan = {
  schemaVersion: 1, captureId: "capture/one",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  limitation: "Analytical only",
  policy: {
    maximumAssignments: 10, maximumCandidatesPerCase: 10,
    defaultEffortPoints: 3, effortByAction: {},
    effortByStep: {}, enforceDistinctWorkItems: true,
    prioritizeUnassigned: false, allowReadyCandidates: false,
  },
  assignments: [{
    candidateId: "=SUM(1,2)", actorUserId: "actor-one",
    caseKey: "case-one", workItemId: "work-one",
    action: "LINK_REQUIRED_WORK",
    nextStep: "REVIEW_EXECUTION_CONTROLS",
    score: 100, effortPoints: 3,
    assignedAt: "2026-11-03T00:00:00.000Z",
    source: "PROPOSED",
  }],
  unassigned: [], members: [{
    actorUserId: "actor-one", assigned: 1, existing: 0,
    proposed: 1, consumedPoints: 3,
    remainingPoints: 2, remainingSlots: 0,
    utilizationPercent: 60,
    assignedCandidateIds: ["=SUM(1,2)"],
  }],
  totals: {
    queued: 1, assigned: 1, existing: 0,
    proposed: 1, unassigned: 0,
    totalEffortPoints: 3, assignedEffortPoints: 3,
    unassignedEffortPoints: 0, availablePoints: 5,
    remainingPoints: 2, availableSlots: 1,
    remainingSlots: 0, assignmentPercent: 100,
    byUnassignedReason: {
      READY: 0, QUEUE_LIMIT: 0, NO_CAPABLE_MEMBER: 0,
      CAPACITY_EXHAUSTED: 0, CASE_LIMIT: 0,
      DUPLICATE_WORK_ITEM: 0,
      CONFLICTING_EXISTING_ASSIGNMENT: 0,
    },
  },
};
describe("capacity export", () => {
  it("protects CSV from spreadsheet formula execution", () => {
    const result = exportIntegrityExecutionCapacity(
      plan, null, parseIntegrityExecutionCapacityExportOptions({
        format: "CSV", sections: ["ASSIGNMENTS"],
      }));
    expect(result.content).toContain("'=SUM(1,2)");
    expect(result.fileName).toBe("integrity-capacity-capture_one.csv");
  });
  it("exports deterministic JSON rows", () => {
    const result = exportIntegrityExecutionCapacity(
      plan, null, parseIntegrityExecutionCapacityExportOptions({
        format: "JSON", sections: ["ASSIGNMENTS"],
      }));
    const parsed = JSON.parse(result.content);
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.metadata.captureId).toBe("capture/one");
  });
  it("exports line-delimited records", () => {
    const result = exportIntegrityExecutionCapacity(
      plan, null, parseIntegrityExecutionCapacityExportOptions({
        format: "JSONL", sections: ["ASSIGNMENTS"],
      }));
    expect(result.content.split("\n").filter(Boolean)).toHaveLength(2);
  });
  it("rejects unsupported export sections", () => {
    expect(() => parseIntegrityExecutionCapacityExportOptions({
      sections: ["SECRET_DATA"],
    })).toThrow();
  });
  it("rejects forecast exports without forecast data", () => {
    expect(() => exportIntegrityExecutionCapacity(
      plan, null, parseIntegrityExecutionCapacityExportOptions({
        sections: ["FORECAST_TASKS"],
      }))).toThrow();
  });
});
