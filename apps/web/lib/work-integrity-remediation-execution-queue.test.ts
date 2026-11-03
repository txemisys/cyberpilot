import { describe, expect, it } from "vitest";
import {
  parseIntegrityExecutionRemediationQueuePolicy,
  parseIntegrityExecutionRemediationQueueQuery,
  prioritizeIntegrityExecutionRemediation,
  queryIntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
import type {
  IntegrityExecutionReadinessReport,
} from "./work-integrity-remediation-execution-readiness";
const readiness: IntegrityExecutionReadinessReport = {
  schemaVersion: 1, captureId: "capture-one",
  policy: {
    requireApprovedDecision: true,
    requireCompletedExecution: true,
    requireActiveAssociation: true,
    requireBoundWorkItem: false,
    requireCompletionReference: true,
    requireIndependentVerification: true,
    blockControlWarnings: false,
    blockProvenanceWarnings: false,
    maximumControlErrors: 0, maximumProvenanceErrors: 0,
  },
  limitation: "Analytical only",
  candidates: [{
    candidateId: "candidate-one", caseKey: "case-one",
    workItemId: "work-one", action: "LINK_REQUIRED_WORK",
    priority: "HIGH", executionState: "BLOCKED",
    approved: true, completed: false, independentlyVerified: false,
    provenanceComplete: false, activeAssociations: 0,
    controlErrors: 1, controlWarnings: 0,
    provenanceErrors: 0, provenanceWarnings: 0,
    blockers: ["CONTROL_ERROR", "EXECUTION_BLOCKED"],
    ready: false,
  }, {
    candidateId: "candidate-two", caseKey: "case-two",
    workItemId: "work-two", action: "REVIEW_AUDIT_ERROR",
    priority: "LOW", executionState: "COMPLETED",
    approved: true, completed: true, independentlyVerified: true,
    provenanceComplete: true, activeAssociations: 1,
    controlErrors: 0, controlWarnings: 0,
    provenanceErrors: 0, provenanceWarnings: 0,
    blockers: [], ready: true,
  }],
  totals: {
    candidates: 2, ready: 1, blocked: 1, completed: 1,
    approved: 2, verified: 1, withActiveAssociation: 1,
    withControlErrors: 1, withProvenanceErrors: 0,
    coveragePercent: 50, readinessPercent: 50,
    byBlocker: {
      UNKNOWN_CANDIDATE: 0, NOT_APPROVED: 0, CONTROL_ERROR: 1,
      CONTROL_WARNING: 0, PROVENANCE_ERROR: 0,
      PROVENANCE_WARNING: 0, NO_ACTIVE_ASSOCIATION: 0,
      NO_COMPLETION_REFERENCE: 0, EXECUTION_NOT_COMPLETED: 0,
      EXECUTION_FAILED: 0, EXECUTION_BLOCKED: 1,
      EXECUTION_CANCELLED: 0, UNVERIFIED_EVIDENCE: 0,
      UNBOUND_WORK_ITEM: 0, MISSING_EXECUTION_CONTROLS: 0,
      MISSING_PROVENANCE: 0,
    },
  },
};
describe("execution remediation queue", () => {
  it("prioritizes control errors and excludes already ready candidates", () => {
    const queue = prioritizeIntegrityExecutionRemediation(
      readiness, null, "2026-11-05T00:00:00.000Z");
    expect(queue.items.map(x => x.candidateId))
      .toEqual(["candidate-one"]);
    expect(queue.items[0]?.recommendedNextStep)
      .toBe("REVIEW_EXECUTION_CONTROLS");
  });
  it("allows explicit inclusion of ready candidates", () => {
    const queue = prioritizeIntegrityExecutionRemediation(
      readiness, null, "2026-11-05T00:00:00.000Z",
      parseIntegrityExecutionRemediationQueuePolicy({ includeReady: true }));
    expect(queue.items).toHaveLength(2);
  });
  it("validates configurable blocker weights", () => {
    expect(() => parseIntegrityExecutionRemediationQueuePolicy({
      blockerWeights: { FAKE_BLOCKER: 5 },
    })).toThrow();
  });
  it("rejects invalid score range", () => {
    expect(() => parseIntegrityExecutionRemediationQueueQuery({
      minimumScore: 200, maximumScore: 10,
    })).toThrow();
  });
  it("filters paginated queue by recommended next action", () => {
    const queue = prioritizeIntegrityExecutionRemediation(
      readiness, null, "2026-11-05T00:00:00.000Z");
    const page = queryIntegrityExecutionRemediationQueue(queue,
      parseIntegrityExecutionRemediationQueueQuery({
        nextSteps: ["REVIEW_EXECUTION_CONTROLS"], limit: 1,
      }));
    expect(page.total).toBe(1);
    expect(page.hasMore).toBe(false);
  });
});
