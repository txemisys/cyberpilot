import { describe, expect, it } from "vitest";
import {
  SCENARIO_IDS, fixtureForScenario,
  parseScenarioMatrixOptions,
  runOfflineScenarioMatrix,
  verifyOfflineScenarioMatrix,
  inspectScenarioMatrixCoverage,
} from "./assets-offline-scenario-matrix";

const now = new Date("2026-11-10T12:00:00.000Z");
describe("Fase 4 executable offline acceptance reference matrix", () => {
  it("covers every declared fixture and its safety gates", () => {
    const options = parseScenarioMatrixOptions();
    const report = runOfflineScenarioMatrix(options, now);
    expect(report.totalExecuted).toBe(SCENARIO_IDS.length);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(SCENARIO_IDS.length);
    expect(verifyOfflineScenarioMatrix(report).valid).toBe(true);
    const coverage = inspectScenarioMatrixCoverage(report);
    expect(coverage.verdict).toBe("COMPLETE_REFERENCE_SET");
    expect(coverage.untestedGateIds).toEqual([]);
  });
  it.each(SCENARIO_IDS)("runs %s through production acceptance logic", id => {
    const report = runOfflineScenarioMatrix(
      parseScenarioMatrixOptions({ scenarios: [id] }), now);
    expect(report.results).toHaveLength(1);
    expect(report.results[0]!.passed).toBe(true);
    expect(report.results[0]!.id).toBe(id);
    expect(report.externalProviderContacted).toBe(false);
    expect(report.customerDatabaseRead).toBe(false);
    expect(report.customerDatabaseWritten).toBe(false);
  });
  it("blocks a positive vulnerability candidate without a human case", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["NO_REVIEW"],
    }), now);
    expect(report.results[0]).toMatchObject({
      observedAccepted: false,
      actualBlockers: ["UNKNOWN_EVIDENCE"],
      candidateCount: 1, reviewCaseCount: 0,
    });
  });
  it("does not mistake unknown installed versions for package coverage gaps", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["AMBIGUOUS_VERSION"],
    }), now);
    expect(report.results[0]!.adviceStatuses)
      .toContain("REVIEW_UNKNOWN_VERSION");
    expect(report.results[0]!.passed).toBe(true);
  });
  it("refuses to accept a partial inventory read", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["INCOMPLETE_SNAPSHOT"],
    }), now);
    expect(report.results[0]).toMatchObject({
      passed: true, expectedException: true,
      observedException: true, errorCode: "CONFLICT",
    });
  });
  it("identifies conflicting human work state as an acceptance blocker", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["INVALID_CHECKLIST"],
    }), now);
    expect(report.results[0]!.actualBlockers)
      .toContain("CASE_LIFECYCLE");
  });
  it("preserves stable fingerprints for identical timestamp and fixture", () => {
    const input = parseScenarioMatrixOptions();
    expect(runOfflineScenarioMatrix(input, now).resultsDigest)
      .toBe(runOfflineScenarioMatrix(input, now).resultsDigest);
  });
  it("does not turn missing audit rows into a success", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["MISSING_AUDIT"],
    }), now);
    expect(report.results[0]!.actualBlockers).toContain("AUDIT_COVERAGE");
  });
  it("does not mistake a mismatched human evidence hash for current data", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["ALTERED_FINGERPRINT"],
    }), now);
    expect(report.results[0]!.actualBlockers)
      .toContain("CANDIDATE_PROVENANCE");
  });
  it("preserves cross-tenant case isolation as a mandatory gate", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["FOREIGN_TENANT"],
    }), now);
    expect(report.results[0]!.actualBlockers)
      .toContain("TENANT_ISOLATION");
  });
  it("returns only synthetic source IDs and no customer contents", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions(),
      now);
    expect(report.synthetic).toBe(true);
    expect(report.releaseAutomaticallyApproved).toBe(false);
    expect(report.organizationId).toBe("synthetic-assets-acceptance");
    expect(JSON.stringify(report)).not.toContain("secretHex");
    expect(JSON.stringify(report)).not.toContain("customerPassword");
  });
  it("fails report validation when the fingerprint is corrupted", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions(),
      now);
    report.resultsDigest = "a".repeat(64);
    expect(verifyOfflineScenarioMatrix(report).valid).toBe(false);
    expect(inspectScenarioMatrixCoverage(report).verdict)
      .toBe("FAILED");
  });
  it("calls partial suites incomplete even when every selected case passes", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["CLEAN_REVIEW", "NO_REVIEW"],
    }), now);
    expect(report.failed).toBe(0);
    expect(inspectScenarioMatrixCoverage(report).verdict)
      .toBe("PARTIAL_REFERENCE_SET");
  });
  it("keeps expected gate failures distinct from unexpected regressions", () => {
    const report = runOfflineScenarioMatrix(parseScenarioMatrixOptions({
      scenarios: ["CLEAN_REVIEW", "DUPLICATE_CASE"],
    }), now);
    expect(report.results[1]!.missingBlockers).toEqual([]);
    expect(report.results[1]!.actualBlockers)
      .toContain("REVIEW_CASE_PROVENANCE");
  });
  it.each([
    { scenarios: [] },
    { scenarios: ["UNRECOGNIZED"] },
    { scenarios: ["CLEAN_REVIEW", "CLEAN_REVIEW"] },
    { scenarios: ["CLEAN_REVIEW"], maximumScenarios: 0 },
    { scenarios: ["CLEAN_REVIEW", "NO_REVIEW"], maximumScenarios: 1 },
    { minimumMappedPercent: 101 },
    { maximumInventoryAgeDays: 0 },
    { requireCaseAudit: "false" },
    { requireAllCandidateReviews: null },
    { bypassApproval: true },
  ])("refuses malformed or unsafe matrix input %j", input => {
    expect(() => parseScenarioMatrixOptions(input)).toThrow();
  });
  it("rejects invalid synthetic evaluation dates", () => {
    expect(() => fixtureForScenario("CLEAN_REVIEW",
      new Date("invalid"))).toThrow();
    expect(() => runOfflineScenarioMatrix(parseScenarioMatrixOptions(),
      new Date("invalid"))).toThrow();
  });
});
