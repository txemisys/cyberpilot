import { describe, expect, it } from "vitest";
import {
  evaluateTechnicalGate, parseTechnicalGateQuery,
} from "./work-integrity-provider-gates";
import { observationSnapshot } from "./work-integrity-evidence-assessment";

const evidence = {
  id: "evidence-item-12345",
  organizationId: "organization-12345",
  source: "GOOGLE_WORKSPACE",
  domain: "example.invalid",
  controlId: "google_workspace.user_2sv",
  scope: "admin@example.invalid",
  state: "OBSERVED",
  schemaVersion: 1,
  observedAt: new Date("2026-11-03T09:00:00Z"),
  updatedAt: new Date("2026-11-03T09:05:00Z"),
  details: {
    customerId: "C123456789",
    subject: "admin@example.invalid",
  },
};
const check = {
  id: "provider-check-12345",
  evidenceId: evidence.id,
  provider: evidence.source,
  controlId: evidence.controlId,
  outcome: "PASS",
  checkedAt: new Date("2026-11-03T10:00:00Z"),
  observationDigest: observationSnapshot(evidence).digest,
  failureCode: null,
};
const now = new Date("2026-11-03T10:10:00Z");
const taskId = "review-task-12345";
describe("technical provider verification gate", () => {
  it("accepts fresh matching remote verification", () => {
    const result = evaluateTechnicalGate(taskId, check, evidence, now, 60);
    expect(result.gate).toBe("PROVIDER_PASS");
    expect(result.sourceVerified).toBe(true);
    expect(result.observationMatches).toBe(true);
  });
  it("does not imply verified security without a provider check", () => {
    const result = evaluateTechnicalGate(taskId, null, evidence, now, 60);
    expect(result.gate).toBe("NO_CHECK");
    expect(result.sourceVerified).toBe(false);
  });
  it.each([
    ["FAIL", "FAILED"],
    ["INCONCLUSIVE", "INCONCLUSIVE"],
    ["PROVIDER_ERROR", "PROVIDER_ERROR"],
  ])("maps provider %s to %s", (outcome, expected) => {
    const result = evaluateTechnicalGate(
      taskId, { ...check, outcome }, evidence, now, 60);
    expect(result.gate).toBe(expected);
    expect(result.sourceVerified).toBe(false);
  });
  it.each([
    { state: "ERROR" },
    { source: "OTHER" },
    { domain: "other.invalid" },
    { controlId: "other_control" },
    { scope: "another-user" },
    { schemaVersion: 2 },
    { observedAt: null },
    { updatedAt: new Date("2026-11-03T09:06:00Z") },
    { details: { subject: "another-user" } },
  ])("rejects changed evidence %j", patch => {
    const result = evaluateTechnicalGate(
      taskId, check, { ...evidence, ...patch }, now, 60);
    expect(result.gate).toBe("STALE");
    expect(result.sourceVerified).toBe(false);
  });
  it("expires provider checks outside freshness window", () => {
    const result = evaluateTechnicalGate(
      taskId, check, evidence, new Date("2026-11-03T12:00:00Z"), 60);
    expect(result.gate).toBe("EXPIRED");
  });
  it("rejects a future check timestamp", () => {
    const result = evaluateTechnicalGate(
      taskId, check, evidence, new Date("2026-11-03T09:00:00Z"), 60);
    expect(result.gate).toBe("INCONCLUSIVE");
  });
  it("rejects a missing evidence record", () => {
    const result = evaluateTechnicalGate(taskId, check, null, now, 60);
    expect(result.gate).toBe("STALE");
  });
  it("rejects an evidence record that is not observed", () => {
    const stale = { ...evidence, state: "DECLARED" };
    const result = evaluateTechnicalGate(
      taskId, { ...check,
        observationDigest: observationSnapshot(stale).digest,
      }, stale, now, 60);
    expect(result.gate).toBe("STALE");
  });
  it("does not treat a non-timestamped observation as verified", () => {
    const stale = { ...evidence, observedAt: null };
    const result = evaluateTechnicalGate(
      taskId, { ...check,
        observationDigest: observationSnapshot(stale).digest,
      }, stale, now, 60);
    expect(result.gate).toBe("STALE");
  });
});
describe("technical gate query", () => {
  it("uses 60-minute default freshness", () => {
    expect(parseTechnicalGateQuery({ taskId })).toEqual({
      taskId, maxAgeMinutes: 60,
    });
  });
  it("accepts explicit 24-hour maximum", () => {
    expect(parseTechnicalGateQuery({
      taskId, maxAgeMinutes: 1440,
    }).maxAgeMinutes).toBe(1440);
  });
  it.each([
    { maxAgeMinutes: 0 },
    { maxAgeMinutes: -1 },
    { maxAgeMinutes: 1441 },
    { maxAgeMinutes: "60" },
    { maxAgeMinutes: 0.5 },
    { taskId: "bad" },
    { extra: true },
  ])("rejects invalid technical gate query %j", patch => {
    expect(() => parseTechnicalGateQuery({ taskId, ...patch })).toThrow();
  });
}
);
