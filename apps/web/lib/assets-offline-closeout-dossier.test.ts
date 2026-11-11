import { describe, expect, it } from "vitest";
import { evaluateAssetOfflineAcceptance } from "./assets-offline-acceptance";
import { fixtureForScenario, runOfflineScenarioMatrix,
  parseScenarioMatrixOptions, inspectScenarioMatrixCoverage,
} from "./assets-offline-scenario-matrix";
import {
  parseCloseoutCommand, assembleCloseoutDossier, verifyCloseoutDossier,
  closeoutIssuePlaybook, closeoutEvidenceManifest,
} from "./assets-offline-closeout-dossier";
import type { PrivacyReadinessReport } from "./assets-privacy-readiness";
import type { CloseoutReleaseEvidence,
  CloseoutRetentionEvidence } from "./assets-offline-closeout-dossier";

const now = new Date("2026-11-11T12:00:00.000Z");
const organizationId = "scenario-fixtures";
const fixture = fixtureForScenario("CLEAN_REVIEW", now);
const acceptance = evaluateAssetOfflineAcceptance(fixture.dataset,
  fixture.policy);
const p = {
  organizationId,
  evaluatedAt: now.toISOString(),
  digest: "a".repeat(64),
  fullyExamined: true,
  importedCount: 1,
  imports: [],
  readiness: { blocked: 0, reviewNeeded: 2,
    pendingOperatorApproval: true },
  totalPotentialHostnames: 1, totalOwnerHashes: 0,
  openCasesBeyondPolicy: 0,
  gates: [
    { id: "BACKUP_PROCESS", severity: "REVIEW",
      rationale: "Backups not verified.", affectedImportIds: [] },
    { id: "RETENTION_APPROVAL", severity: "REVIEW",
      rationale: "Human signoff still required.",
      affectedImportIds: [] },
  ],
} as PrivacyReadinessReport;
const absentRelease: CloseoutReleaseEvidence = {
  present: false, reviewId: null, revision: null, state: "MISSING",
  digest: null, verified: false, independentIssues: [],
  recordedBy: null, decidedBy: null, decidedAt: null,
  exclusions: [], humanDecisionRecorded: false, acceptedOffline: false,
  auditEvents: 0, auditConsistent: false, auditDigest: null, auditIssues: [],
};
const absentRetention: CloseoutRetentionEvidence = {
  present: false, reviewId: null, state: "MISSING", revision: null,
  verified: false, reviewedBy: null, nextReviewAt: null,
  backupDisposition: "UNVERIFIED",
  personalDataDisposition: "REQUIRES_REVIEW",
  outstandingExceptions: 0, exceptions: [], legalApproved: false,
  erasureVerified: false, independentIssues: [],
};
function closeout(overrides: Record<string, unknown> = {}) {
  const scenario = runOfflineScenarioMatrix(parseScenarioMatrixOptions(), now);
  const coverage = inspectScenarioMatrixCoverage(scenario);
  return assembleCloseoutDossier({
    organizationId: acceptance.organizationId,
    acceptance, acceptanceValid: true, privacy: {
      ...p, organizationId: acceptance.organizationId,
    },
    scenario: {
      digest: scenario.resultsDigest, passed: scenario.passed,
      executed: scenario.totalExecuted, failed: scenario.failed,
      complete: coverage.verdict === "COMPLETE_REFERENCE_SET",
      mismatches: [],
    },
    release: absentRelease, retention: absentRetention, now,
    ...overrides,
  });
}
describe("Fase 4 reproducible offline closeout dossier", () => {
  it("requires an exactly scoped bounded input", () => {
    expect(parseCloseoutCommand({
      importId: "import_12345", inspectionId: "inspection_12345",
      bindings: [],
    })).toMatchObject({
      importId: "import_12345", inspectionId: "inspection_12345",
      maxAuditEvents: 250, includeHumanReasons: false,
    });
  });
  it.each([
    {},
    { importId: "../other" },
    { importId: "import_12345", inspectionId: "" },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: "[]" },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: [], organizationId: "foreign" },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: [], maxAuditEvents: 1001 },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: [], maxAuditEvents: 0 },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: [], includeHumanReasons: "true" },
    { importId: "import_12345", inspectionId: "inspect_12345",
      bindings: [], acceptedOffline: true },
  ])("rejects unsafe requests %j", value => {
    expect(() => parseCloseoutCommand(value)).toThrow();
  });
  it("reconstructs evidence with no automatic acceptance", () => {
    const result = closeout();
    expect(result.gates).toHaveLength(22);
    expect(result.privacy.pendingOperatorApproval).toBe(true);
    expect(result.scenario.notTenantAcceptance).toBe(true);
    expect(result.offlineProductAccepted).toBe(false);
    expect(result.mergeAuthorized).toBe(false);
    expect(result.liveProviderValidated).toBe(false);
    expect(result.destructiveWrites).toBe(0);
    expect(verifyCloseoutDossier(result).valid).toBe(true);
  });
  it("does not promote synthetic reference coverage to operator approval", () => {
    const result = closeout();
    expect(result.scenario.passed).toBe(13);
    expect(result.scenario.complete).toBe(true);
    expect(result.gates.find(g =>
      g.code === "SYNTHETIC_REFERENCE_SUITE")?.status).toBe("PASS");
    expect(result.gates.find(g =>
      g.code === "MANUAL_END_TO_END")?.status).toBe("REVIEW");
    expect(result.gates.find(g =>
      g.code === "RELEASE_HUMAN_DECISION")?.status).toBe("BLOCK");
    expect(result.offlineProductAccepted).toBe(false);
  });
  it("keeps privacy and backup/retention blockers visible", () => {
    const result = closeout();
    const codes = result.gates.filter(g => g.status === "BLOCK")
      .map(g => g.code);
    expect(codes).toContain("PRIVACY_REVIEW_BLOCKERS");
    expect(codes).toContain("BACKUP_HANDLING");
    expect(codes).toContain("RETENTION_EXCEPTION_REVIEW");
    expect(codes).toContain("RELEASE_REVIEW_PRESENT");
  });
  it("separates explicitly excluded LIVE validation from blocked privacy", () => {
    const result = closeout();
    const excluded = result.gates.filter(g =>
      g.status === "EXCLUDED").map(g => g.code);
    expect(excluded).toContain("LIVE_PROVIDER_VALIDATION");
    expect(excluded).toContain("BACKUP_DELETION_ATTESTATION");
    expect(result.counts.excluded).toBe(2);
  });
  it("recounts each gate class exactly and makes no implicit external claims", () => {
    const result = closeout();
    const counts = result.counts;
    expect(counts.total).toBe(counts.passed + counts.blocked +
      counts.manualReview + counts.excluded);
    expect(result.privacy.backupsErased).toBe(false);
    expect(result.retention.legalApproved).toBe(false);
    expect(result.legalSignoffConfirmed).toBe(false);
    expect(result.backupErasureConfirmed).toBe(false);
  });
  it("rejects a cross-tenant report when assembling the dossier", () => {
    expect(() => closeout({
      organizationId: "other-organization",
    })).toThrow();
  });
  it("detects modification of a hashed dossier field", () => {
    const result = closeout();
    result.inventory.deviceCount++;
    expect(verifyCloseoutDossier(result).valid).toBe(false);
  });
  it("detects false LIVE claims, backup erasure and fake merge approval", () => {
    for (const change of [
      { offlineProductAccepted: true },
      { mergeAuthorized: true },
      { liveProviderValidated: true },
      { legalSignoffConfirmed: true },
      { backupErasureConfirmed: true },
      { destructiveWrites: 1 },
    ]) {
      const report = Object.assign(closeout(), change);
      expect(verifyCloseoutDossier(report).valid).toBe(false);
    }
  });
  it("exports a locally verifiable provenance manifest", () => {
    const report = closeout();
    const manifest = closeoutEvidenceManifest(report);
    expect(manifest.noExternalSignatures).toBe(true);
    expect(manifest.productAcceptanceNotGranted).toBe(true);
    expect(manifest.sources.some(s =>
      s.type === "INVENTORY")).toBe(true);
    expect(manifest.sources.some(s =>
      s.type === "SCENARIOS_SYNTHETIC")).toBe(true);
  });
  it("rejects export of an altered report", () => {
    const report = closeout();
    report.sourceDigest = "f".repeat(64);
    expect(() => closeoutEvidenceManifest(report)).toThrow();
  });
  it("generates targeted and non-self-approving action instructions", () => {
    const report = closeout();
    const playbook = closeoutIssuePlaybook(report);
    expect(playbook.some(p =>
      p.gate === "EXTERNAL_PRIVACY_SIGNOFF" &&
      p.cannotSelfApprove)).toBe(true);
    expect(playbook.some(p =>
      p.gate === "RELEASE_HUMAN_DECISION")).toBe(true);
    expect(playbook.length).toBe(
      report.gates.filter(g => g.status !== "PASS").length);
  });
});
