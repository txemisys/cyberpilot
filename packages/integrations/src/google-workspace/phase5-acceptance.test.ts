import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  evaluateGoogleScenarioAcceptance,
  buildGooglePhase5Matrix, verifyGooglePhase5Matrix,
  runGooglePhase5AcceptanceMatrix,
  summarizeGooglePhase5Acceptance,
} from "./phase5-acceptance-matrix";
import {
  runPhase5DevelopmentAcceptance,
  buildPhase5DevelopmentGate,
  verifyPhase5DevelopmentGate,
  phase5ReleaseManifest, verifyPhase5ReleaseManifest,
} from "./phase5-release-gate";
import { runGoogleLabJourney } from "./lab-journey";
import { GOOGLE_LAB_SCENARIOS } from "./lab-scenarios";
const organizationId = "phase5-test-tenant-12345";
const checkedAt = "2026-11-12T10:00:00.000Z";
describe("Phase 5 Google Workspace A+B acceptance policy", () => {
  it("executes the full synthetic matrix with all 17 provider scenarios", async () => {
    const matrix = await runGooglePhase5AcceptanceMatrix({
      organizationId, checkedAt,
    });
    expect(matrix.scenarioCount).toBe(GOOGLE_LAB_SCENARIOS.length);
    expect(matrix.cases.every(c => c.technicalPassed)).toBe(true);
    expect(matrix.missingScenarios).toEqual([]);
    expect(matrix.duplicateScenarios).toEqual([]);
    expect(matrix.failed).toBe(0);
    expect(matrix.verdict).toBe("OFFLINE_A_B_PASS");
    expect(verifyGooglePhase5Matrix(matrix).valid).toBe(true);
    expect(matrix.realGoogleProviderValidated).toBe(false);
    expect(matrix.oauthTokensPersisted).toBe(false);
    expect(matrix.canonicalCyberScoreChanged).toBe(false);
  });
  it("verifies release manifest with no fabricated customer approvals", async () => {
    const result = await runPhase5DevelopmentAcceptance({
      organizationId, checkedAt,
    });
    if (process.env.PHASE5_WRITE_ARTIFACTS === "true") {
      const target = join(process.cwd(), ".artifacts");
      mkdirSync(target, { recursive: true });
      writeFileSync(join(target,
        "phase5-google-development-acceptance.json"),
        JSON.stringify({
          schema: "cyberpilot.google.phase5.ci.attestation.v1",
          generatedAt: checkedAt,
          organizationId, matrix: result.matrix,
          gate: result.gate, manifest: result.manifest,
          technicalPass: result.technicalPass,
          verified: result.verified,
          googleLiveValidated: false,
          customerConsentVerified: false,
          githubMergeAuthorized: false,
        }, null, 2) + "\n", "utf8");
    }
    expect(result.verified).toBe(true);
    expect(result.technicalPass).toBe(true);
    expect(result.gate.gates).toHaveLength(21);
    expect(result.gate.developmentVerdict).toBe("OFFLINE_A_B_PASS");
    expect(result.gate.mergeAuthorizedAutomatically).toBe(false);
    expect(result.gate.customerDeploymentAccepted).toBe(false);
    expect(result.gate.externalGoogleVerified).toBe(false);
    expect(result.manifest.googleAdminConsentReceived).toBe(false);
    expect(result.manifest.clientApprovalInvented).toBe(false);
    expect(result.manifest.mergeAuthorizationGranted).toBe(false);
    expect(verifyPhase5DevelopmentGate(
      result.gate, result.matrix).valid).toBe(true);
    expect(verifyPhase5ReleaseManifest(
      result.manifest, result.gate).valid).toBe(true);
  });
  it("does not accept a missing scenario as a completed phase", async () => {
    const matrix = await runGooglePhase5AcceptanceMatrix({
      organizationId, checkedAt,
      scenarios: ["HEALTHY_REFERENCE", "MFA_GAPS"],
    });
    expect(matrix.verdict).toBe("OFFLINE_A_B_BLOCKED");
    expect(matrix.missingScenarios.length).toBeGreaterThan(0);
    const gate = buildPhase5DevelopmentGate(matrix);
    expect(gate.offlineReadyToConsiderMerge).toBe(false);
    expect(gate.outstanding.length).toBeGreaterThan(0);
    expect(verifyPhase5DevelopmentGate(gate, matrix).valid).toBe(true);
  });
  it("refuses mutated source digests after matrix construction", async () => {
    const matrix = await runGooglePhase5AcceptanceMatrix({
      organizationId, checkedAt, scenarios: ["HEALTHY_REFERENCE"],
    });
    const bad = JSON.parse(JSON.stringify(matrix)) as typeof matrix;
    bad.cases[0]!.requests = 999;
    expect(verifyGooglePhase5Matrix(bad).valid).toBe(false);
    expect(() => buildPhase5DevelopmentGate(bad)).toThrow();
  });
  it("cannot combine tenant scope in A/B matrix", async () => {
    const a = await runGoogleLabJourney({
      organizationId, checkedAt, scenario: "HEALTHY_REFERENCE",
    });
    const b = await runGoogleLabJourney({
      organizationId: "outside-google-tenant-12345",
      checkedAt, scenario: "MFA_GAPS",
    });
    const rows = [
      evaluateGoogleScenarioAcceptance(a),
      evaluateGoogleScenarioAcceptance(b),
    ];
    expect(() => buildGooglePhase5Matrix(
      organizationId, checkedAt, rows)).toThrow();
  });
  it("does not infer customer authentication from a green technical gate", async () => {
    const result = await runPhase5DevelopmentAcceptance({
      organizationId, checkedAt,
    });
    const summary = summarizeGooglePhase5Acceptance(result.matrix);
    expect(summary.technicalDevelopmentAccepted).toBe(true);
    expect(summary.requiresHumanSignatureForDevelopment).toBe(false);
    expect(summary.customerTenantConnected).toBe(false);
    expect(summary.providerLiveValidated).toBe(false);
    expect(summary.githubMergeAuthorizedByEvidence).toBe(false);
    expect(result.manifest.deploymentToClientAuthorized).toBe(false);
  });
  it("invalidates a release manifest with forged real Google consent", async () => {
    const result = await runPhase5DevelopmentAcceptance({
      organizationId, checkedAt,
    });
    const changed = JSON.parse(JSON.stringify(result.manifest)) as
      typeof result.manifest;
    (changed as unknown as Record<string, unknown>)
      .googleAdminConsentReceived = true;
    expect(verifyPhase5ReleaseManifest(changed,
      result.gate).valid).toBe(false);
  });
  it("cannot conceal a failing gate by changing verdict only", async () => {
    const result = await runPhase5DevelopmentAcceptance({
      organizationId, checkedAt,
    });
    const altered = JSON.parse(JSON.stringify(result.gate)) as
      typeof result.gate;
    altered.gates[0]!.state = "BLOCK";
    expect(verifyPhase5DevelopmentGate(altered,
      result.matrix).valid).toBe(false);
    expect(() => phase5ReleaseManifest(altered)).toThrow();
  });
});
