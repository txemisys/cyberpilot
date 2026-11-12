import { describe, expect, it } from "vitest";
import {
  parseHandoffCommand, assemblePhase4Handoff,
  verifyPhase4Handoff, phase4HandoffManifest,
  phase4HandoffChecklist,
} from "./assets-phase4-handoff-package";
import type { Phase4HandoffInput } from "./assets-phase4-handoff-package";

const digest = "a".repeat(64);
const stamp = "2026-11-12T10:00:00.000Z";
const base: Phase4HandoffInput = {
  organizationId: "organization-test-12345",
  importId: "import-test-12345",
  inspectionId: "inspection-test-12345",
  operatorRunId: null,
  evaluatedAt: stamp,
  minimumReferenceCount: 9,
  base: {
    digest, importDigest: digest, inspectionDigest: digest,
    privacyDigest: digest, scenarioDigest: digest,
    scenarioPassed: 13, scenarioComplete: true,
    releaseId: null, releaseDigest: null,
    releaseAuditDigest: null, releaseAccepted: false,
    retentionId: null, retentionVerified: false,
    retentionState: "MISSING",
    privacyBlocked: 0, privacyReviewNeeded: 2,
    offlineBlocked: 3,
  },
  operations: {
    digest, blocked: 4, human: 4, excluded: 1,
    technicalReady: false, humanReady: false,
    operatorSteps: 0, reviewerChecks: 0,
    sourceOperatorDigest: null, auditDigest: null,
    pendingDependencies: 6, stages: [],
  },
  audits: {
    present: false, digest: null, runId: null,
    runEvents: 0, reviewEvents: 0, runComplete: false,
    reviewComplete: false, blockers: 1, integrity: false,
    independentlyReviewedSteps: 0,
  },
  independent: {
    present: false, totalSteps: 9, independentMatches: 0,
    missing: 9, stale: 0, disputed: 0,
    readyForHumanSignoff: false, digest: null,
  },
  generatedWithoutExternalCall: true,
};
function handoff(changes: Partial<Phase4HandoffInput> = {}) {
  return assemblePhase4Handoff({ ...base, ...changes });
}
describe("Phase 4 human acceptance package", () => {
  it("accepts bounded source selection with no tenant supplied by client", () => {
    expect(parseHandoffCommand({
      importId: base.importId, inspectionId: base.inspectionId,
      bindings: [],
    })).toMatchObject({
      runId: null, maxAuditEvents: 250,
      maxEvidenceAgeDays: 30,
    });
  });
  it.each([
    {}, { importId: "../foreign" },
    { importId: base.importId, inspectionId: "bad", bindings: [] },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: "[]" },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: [], organizationId: "forged" },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: [], maxAuditEvents: 1001 },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: [], maxEvidenceAgeDays: 0 },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: [], productAccepted: true },
    { importId: base.importId, inspectionId: base.inspectionId,
      bindings: [], githubMergeAuthorized: true },
  ])("rejects untrusted or unsafe request %j", value => {
    expect(() => parseHandoffCommand(value)).toThrow();
  });
  it("emits a complete provenance manifest without authenticating sources", () => {
    const result = handoff();
    expect(result.evidence).toHaveLength(12);
    expect(result.sections).toHaveLength(9);
    expect(result.milestones).toHaveLength(9);
    expect(result.dependencies.length).toBeGreaterThan(5);
    expect(result.evidence.some(x =>
      x.kind === "SCENARIO_MATRIX_SYNTHETIC" &&
      x.sourceClass === "SYNTHETIC")).toBe(true);
    expect(result.evidence.every(x =>
      x.independentlyAuthenticated === false)).toBe(true);
    expect(verifyPhase4Handoff(result).valid).toBe(true);
  });
  it("keeps real-world approvals separate from local hashes", () => {
    const result = handoff();
    expect(result.summary.phaseAccepted).toBe(false);
    expect(result.summary.mergeAuthorized).toBe(false);
    expect(result.databaseWrites).toBe(0);
    expect(result.providerRequests).toBe(0);
    expect(result.legalApproved).toBe(false);
    expect(result.backupDeletionVerified).toBe(false);
    expect(result.thirdPartySignaturesVerified).toBe(false);
    expect(result.scope.includesExternalTenants).toBe(false);
    expect(result.scope.includesLiveProviderCheck).toBe(false);
  });
  it("preserves real operator, independent reviewer and CI owners", () => {
    const result = handoff();
    const owners = new Set(result.milestones.map(s => s.owner));
    expect(owners).toContain("OPERATOR");
    expect(owners).toContain("INDEPENDENT_REVIEWER");
    expect(owners).toContain("PRIVACY_OWNER");
    expect(owners).toContain("BACKUP_OWNER");
    expect(owners).toContain("CI_MAINTAINER");
    expect(owners).toContain("PRODUCT_OWNER");
    expect(result.milestones.every(x =>
      !x.humanCompletionVerified && !x.phaseClosedByMilestone)).toBe(true);
  });
  it("distinguishes missing sources from locally available ones", () => {
    const result = handoff();
    expect(result.summary.sourcesAvailable).toBeLessThan(
      result.summary.sourcesListed);
    expect(result.evidence.find(x =>
      x.kind === "RELEASE_REVIEW")?.available).toBe(false);
    expect(result.evidence.find(x =>
      x.kind === "INVENTORY")?.available).toBe(true);
  });
  it("does not mistake a full synthetic matrix for final product acceptance", () => {
    const result = handoff();
    expect(result.sections.find(x =>
      x.id === "RISK_SCOPE")?.status).toBe("LOCAL_PASS");
    expect(result.sections.find(x =>
      x.id === "FINAL_DECISION")?.status).toBe("HUMAN");
    expect(result.concerns.some(x =>
      x.code === "MANUAL_PRODUCT_APPROVAL_REQUIRED")).toBe(true);
  });
  it("handles complete-looking local evidence conservatively", () => {
    const result = handoff({
      operatorRunId: "run-test-12345",
      base: {
        ...base.base, offlineBlocked: 0,
        releaseId: "release-test-12345",
        releaseDigest: digest, releaseAccepted: true,
        retentionId: "retention-test-12345",
        retentionVerified: true, privacyBlocked: 0,
        privacyReviewNeeded: 0,
      },
      operations: {
        ...base.operations, blocked: 0,
        operatorSteps: 9, reviewerChecks: 9,
        technicalReady: true, humanReady: true,
        sourceOperatorDigest: digest,
        pendingDependencies: 0,
      },
      audits: {
        ...base.audits, present: true, digest,
        runId: "run-test-12345",
        runEvents: 10, reviewEvents: 9,
        runComplete: true, reviewComplete: true,
        blockers: 0, integrity: true,
        independentlyReviewedSteps: 9,
      },
      independent: {
        ...base.independent, present: true, digest,
        independentMatches: 9, missing: 0,
        readyForHumanSignoff: true,
      },
    });
    expect(result.summary.preparedForIndependentHumanReview).toBe(true);
    expect(result.summary.phaseAccepted).toBe(false);
    expect(result.githubMergeAuthorized).toBe(false);
    expect(result.legalApproved).toBe(false);
  });
  it("does not permit automatic milestone completion", () => {
    const result = handoff();
    const checklist = phase4HandoffChecklist(result);
    expect(checklist).toHaveLength(9);
    expect(checklist.every(x => !x.canBeAutomaticallyApproved)).toBe(true);
    expect(checklist.every(x => x.actionNeeded)).toBe(true);
  });
  it("exports external-signature-neutral manifest with all source links", () => {
    const result = handoff();
    const manifest = phase4HandoffManifest(result);
    expect(manifest.packageDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest.sources).toHaveLength(12);
    expect(manifest.mergeAuthorized).toBe(false);
    expect(manifest.requiresIndependentSignatureVerification).toBe(true);
  });
  it("detects tampered source evidence and declines export", () => {
    const result = handoff();
    result.provenance.inventoryDigest = "f".repeat(64);
    expect(verifyPhase4Handoff(result).valid).toBe(false);
    expect(() => phase4HandoffManifest(result)).toThrow();
  });
  it("detects false legal, product and merge authorizations", () => {
    for (const change of [
      { legalApproved: true },
      { backupDeletionVerified: true },
      { productAccepted: true },
      { githubMergeAuthorized: true },
      { thirdPartySignaturesVerified: true },
      { databaseWrites: 1 },
      { providerRequests: 1 },
    ]) {
      const report = Object.assign(handoff(), change);
      expect(verifyPhase4Handoff(report).valid).toBe(false);
    }
  });
});
