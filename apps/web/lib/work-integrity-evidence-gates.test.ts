import { describe, expect, it } from "vitest";
import {
  buildReviewEvidenceGate, classifyAssessment,
  parseGatePortfolioQuery,
} from "./work-integrity-evidence-gates";
import { observationSnapshot } from "./work-integrity-evidence-assessment";

const evidence = {
  id: "evidence-item-12345",
  organizationId: "organization-12345",
  source: "integration",
  domain: "example.invalid",
  controlId: "mfa",
  scope: "tenant",
  state: "OBSERVED",
  schemaVersion: 1,
  observedAt: new Date("2026-01-01T00:00:00Z"),
  updatedAt: new Date("2026-01-02T00:00:00Z"),
  details: { enabled: true },
};
const assessment = {
  id: "assessment-item-12345",
  evidenceId: evidence.id,
  decision: "ACCEPTED",
  observationDigest: observationSnapshot(evidence).digest,
  createdAt: new Date("2026-01-03T00:00:00Z"),
  assessorUserId: "admin-user-12345",
  revision: 1,
  source: evidence.source,
  controlId: evidence.controlId,
  observedAt: evidence.observedAt,
};
const task = {
  id: "review-task-12345",
  captureId: "capture-item-12345",
  disposition: "IN_REVIEW",
  required: true,
  revision: 3,
  assessmentRevision: 1,
};
describe("evidence gate classifications", () => {
  it("classifies matching accepted observation", () => {
    const result = classifyAssessment(assessment, evidence);
    expect(result.status).toBe("ACCEPTED_OBSERVATION");
    expect(result.assessmentId).toBe(assessment.id);
  });
  it("classifies missing assessment conservatively", () => {
    expect(classifyAssessment(null, evidence).status).toBe("NO_ASSESSMENT");
  });
  it("detects an unavailable evidence record", () => {
    expect(classifyAssessment(assessment, null).status).toBe("STALE_OBSERVATION");
  });
  it.each([
    { state: "ERROR" },
    { source: "another-source" },
    { domain: "other.invalid" },
    { controlId: "other-control" },
    { scope: "user" },
    { schemaVersion: 2 },
    { details: { enabled: false } },
    { observedAt: null },
    { updatedAt: new Date("2026-01-04T00:00:00Z") },
  ])("detects changed evidence snapshot %j", patch => {
    expect(classifyAssessment(assessment, {
      ...evidence, ...patch,
    }).status).toBe("STALE_OBSERVATION");
  });
  it("does not count rejected assessment as accepted", () => {
    expect(classifyAssessment({
      ...assessment, decision: "REJECTED",
    }, evidence).status).toBe("REJECTED");
  });
  it("does not count inconclusive assessment as accepted", () => {
    expect(classifyAssessment({
      ...assessment, decision: "INCONCLUSIVE",
    }, evidence).status).toBe("INCONCLUSIVE");
  });
});
describe("review evidence gate aggregation", () => {
  it("reports no evidence conservatively", () => {
    const result = buildReviewEvidenceGate(task, [], []);
    expect(result.gate).toBe("NO_EVIDENCE");
    expect(result.acceptedCount).toBe(0);
    expect(result.items).toHaveLength(0);
  });
  it("reports matching accepted evidence as human acceptance only", () => {
    const result = buildReviewEvidenceGate(task, [assessment], [evidence]);
    expect(result.gate).toBe("HUMAN_ACCEPTED");
    expect(result.acceptedCount).toBe(1);
    expect(result.limitations.join(" ")).toMatch(/not an independent/);
  });
  it("reports stale accepted observation as action required", () => {
    const result = buildReviewEvidenceGate(
      task, [assessment], [{ ...evidence, state: "ERROR" }],
    );
    expect(result.gate).toBe("ACTION_REQUIRED");
    expect(result.staleCount).toBe(1);
  });
  it("uses the latest assessment revision per evidence", () => {
    const result = buildReviewEvidenceGate(task, [
      assessment,
      { ...assessment, id: "assessment-second-12345",
        decision: "REJECTED", revision: 2 },
    ], [evidence]);
    expect(result.gate).toBe("ACTION_REQUIRED");
    expect(result.rejectedCount).toBe(1);
    expect(result.acceptedCount).toBe(0);
    expect(result.items).toHaveLength(1);
  });
  it("does not hide rejection behind a different accepted record", () => {
    const other = {
      ...evidence, id: "evidence-second-12345",
      controlId: "conditional-access",
    };
    const result = buildReviewEvidenceGate(task, [
      assessment,
      { ...assessment, id: "assessment-second-12345",
        evidenceId: other.id, decision: "REJECTED",
        revision: 2 },
    ], [evidence, other]);
    expect(result.gate).toBe("ACTION_REQUIRED");
    expect(result.rejectedCount).toBe(1);
  });
});
describe("gate portfolio query validation", () => {
  it("uses bounded defaults", () => {
    expect(parseGatePortfolioQuery({})).toEqual({
      offset: 0, limit: 50, includeResolved: false,
    });
  });
  it("accepts explicit scoped filters", () => {
    expect(parseGatePortfolioQuery({
      captureId: task.captureId, offset: 12, limit: 200,
      includeResolved: true,
    })).toEqual({
      captureId: task.captureId, offset: 12, limit: 200,
      includeResolved: true,
    });
  });
  it.each([
    { offset: -1 },
    { offset: 1000001 },
    { offset: "0" },
    { limit: 0 },
    { limit: 201 },
    { limit: 1.5 },
    { includeResolved: "true" },
    { captureId: "bad" },
    { unknown: true },
  ])("rejects invalid query %j", patch => {
    expect(() => parseGatePortfolioQuery(patch)).toThrow();
  });
});
