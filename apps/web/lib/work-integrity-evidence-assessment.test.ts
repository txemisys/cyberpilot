import { describe, expect, it } from "vitest";
import {
  assessEvidencePolicy, observationSnapshot,
  parseAssessment, parseAssessmentQuery,
} from "./work-integrity-evidence-assessment";

const valid = {
  taskId: "review-task-12345",
  evidenceId: "evidence-item-12345",
  expectedRevision: 0,
  decision: "ACCEPTED",
  rationale: "Evidence observation reviewed and compared with the task.",
  idempotencyKey: "assessment-request-12345",
};
describe("integrity evidence assessment input", () => {
  it("parses a valid first assessment", () => {
    expect(parseAssessment(valid)).toEqual(valid);
  });
  it("accepts subsequent assessment sequence revisions", () => {
    expect(parseAssessment({ ...valid, expectedRevision: 7 }).expectedRevision).toBe(7);
  });
  it.each([
    { expectedRevision: -1 },
    { expectedRevision: 1.5 },
    { expectedRevision: "0" },
    { expectedRevision: 2147483647 },
    { decision: "VERIFIED" },
    { decision: null },
    { rationale: "short" },
    { rationale: "x".repeat(4001) },
    { rationale: "Unsafe\nreason that must be rejected" },
    { idempotencyKey: "short" },
    { idempotencyKey: "x".repeat(161) },
    { taskId: "../other-tenant" },
    { evidenceId: "" },
    { unknown: true },
  ])("rejects invalid assessment payload %j", patch => {
    expect(() => parseAssessment({ ...valid, ...patch })).toThrow();
  });
  it("rejects arrays, null and missing fields", () => {
    for (const input of [null, [], {}, "text"]) {
      expect(() => parseAssessment(input)).toThrow();
    }
  });
  it("parses bounded pagination", () => {
    expect(parseAssessmentQuery({ taskId: valid.taskId })).toEqual({
      taskId: valid.taskId, offset: 0, limit: 50,
    });
    expect(parseAssessmentQuery({
      taskId: valid.taskId, offset: 17, limit: 200,
    })).toMatchObject({ offset: 17, limit: 200 });
  });
  it.each([
    { offset: -1 },
    { offset: 1000001 },
    { offset: "1" },
    { limit: 0 },
    { limit: 201 },
    { limit: 1.5 },
    { other: true },
  ])("rejects invalid pagination %j", patch => {
    expect(() => parseAssessmentQuery({
      taskId: valid.taskId, ...patch,
    })).toThrow();
  });
});
describe("evidence decision guardrails", () => {
  const observation = {
    decision: "ACCEPTED" as const,
    state: "OBSERVED",
    observedAt: new Date("2026-01-01T00:00:00Z"),
    taskDisposition: "IN_REVIEW",
  };
  it("accepts a timestamped observed record for active review", () => {
    expect(() => assessEvidencePolicy(observation)).not.toThrow();
  });
  it.each(["UNKNOWN", "ERROR", "DECLARED", "STALE"])(
    "does not accept %s as independently observed",
    state => {
      expect(() => assessEvidencePolicy({ ...observation, state })).toThrow();
    },
  );
  it("requires a timestamp to accept an observation", () => {
    expect(() => assessEvidencePolicy({
      ...observation, observedAt: null,
    })).toThrow();
  });
  it("allows rejection and inconclusive decisions on unknown records", () => {
    for (const decision of ["REJECTED", "INCONCLUSIVE"] as const) {
      expect(() => assessEvidencePolicy({
        ...observation, decision, state: "UNKNOWN", observedAt: null,
      })).not.toThrow();
    }
  });
  it("prevents assessments on resolved or waived tasks", () => {
    for (const taskDisposition of ["RESOLVED", "WAIVED"]) {
      expect(() => assessEvidencePolicy({
        ...observation, taskDisposition,
      })).toThrow();
    }
  });
});
describe("observation snapshot digest", () => {
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
    details: { result: true },
  };
  it("produces a deterministic SHA-256 digest", () => {
    const first = observationSnapshot(evidence);
    expect(first.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(first.digest).toBe(observationSnapshot({ ...evidence }).digest);
  });
  it.each([
    { state: "ERROR" },
    { source: "different-provider" },
    { organizationId: "other-org" },
    { controlId: "different-control" },
    { scope: "user" },
    { schemaVersion: 2 },
    { details: { result: false } },
    { updatedAt: new Date("2026-01-03T00:00:00Z") },
    { observedAt: null },
  ])("changes digest when observation changes %j", patch => {
    expect(observationSnapshot({ ...evidence, ...patch }).digest)
      .not.toBe(observationSnapshot(evidence).digest);
  });
});
