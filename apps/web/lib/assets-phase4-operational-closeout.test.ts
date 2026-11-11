import { describe, expect, it } from "vitest";
import {
  parseOperationalCloseoutCommand, buildOperationalCloseout,
  verifyOperationalCloseout, operationalCloseoutExport,
  operationalCloseoutActionPlan,
} from "./assets-phase4-operational-closeout";
import type { OperationalCloseoutInput } from
  "./assets-phase4-operational-closeout";
const digest = "a".repeat(64);
const now = "2026-11-11T12:00:00.000Z";
const base: OperationalCloseoutInput = {
  organizationId: "org-test-12345",
  importId: "import-test-12345",
  inspectionId: "inspection-test-12345",
  evaluatedAt: now,
  dossier: {
    digest,
    counts: { blocked: 2, passed: 12,
      manualReview: 5, excluded: 2 },
    inventory: {
      deviceCount: 2, queryCount: 1,
      positiveWithoutReview: 0,
    },
    scenario: { complete: true, passed: 13 },
    privacy: {
      fullyExamined: true, blocked: 1, reviewNeeded: 1,
    },
    release: {
      present: false, verified: false,
      acceptedOffline: false, auditConsistent: false,
      reviewId: null,
    },
    retention: {
      present: false, verified: false,
      state: "MISSING", reviewId: null,
      backupDisposition: "UNVERIFIED", nextReviewAt: null,
    },
    gates: [],
  },
  operator: {
    id: null, state: "MISSING", revision: 0,
    complete: false, integrity: false,
    stepsRecorded: 0, blockedSteps: 0,
    sourceIdentityMatches: false,
  },
  independent: {
    reviewCount: 0, independentlyMatched: 0,
    readyForHumanSignoff: false, mismatchCount: 9,
  },
  audit: {
    checked: false, integrity: false,
    complete: false, blockers: 1, reviewEvents: 0,
  },
  releaseAudit: {
    checked: false, valid: false, events: 0,
  },
  retentionHumanApprovalDocumented: false,
  backupProcedureDocumented: false,
  manualProductSignoffConfirmed: false,
  currentCiHeadVerified: false,
  liveProviderValidated: false,
};
function report(changes: Partial<OperationalCloseoutInput> = {}) {
  return buildOperationalCloseout({ ...base, ...changes });
}
describe("Fase 4 human operational closeout decision board", () => {
  it("accepts only exact tenant-scoped offline source selection", () => {
    expect(parseOperationalCloseoutCommand({
      importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [],
    })).toMatchObject({
      maxAuditEvents: 250, runId: null,
      bindings: [],
    });
  });
  it.each([
    {}, { importId: "../foreign" },
    { importId: "import-test-12345", inspectionId: "bad",
      bindings: [] },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: "[]" },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [], organizationId: "foreign" },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [], maxAuditEvents: 0 },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [], maxAuditEvents: "10" },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [], maxAuditEvents: 1001 },
    { importId: "import-test-12345",
      inspectionId: "inspection-test-12345",
      bindings: [], mergeAuthorized: true },
  ])("rejects invalid operational request %j", value => {
    expect(() => parseOperationalCloseoutCommand(value)).toThrow();
  });
  it("creates a complete fourteen-area dependency graph", () => {
    const r = report();
    expect(r.stages).toHaveLength(14);
    expect(new Set(r.stages.map(s => s.area)).size).toBe(14);
    expect(r.dependencies.length).toBeGreaterThan(10);
    expect(r.overview.total).toBe(
      r.overview.passed + r.overview.blocked +
      r.overview.needsHuman + r.overview.excluded);
    expect(verifyOperationalCloseout(r).valid).toBe(true);
  });
  it("distinguishes local PASS checks from unverified manual approvals", () => {
    const r = report();
    expect(r.stages.find(s => s.area === "INVENTORY")?.state)
      .toBe("PASS_LOCAL");
    expect(r.stages.find(s => s.area === "OSV_STORED")?.state)
      .toBe("PASS_LOCAL");
    expect(r.stages.find(s => s.area === "OFFLINE_REFERENCE")?.state)
      .toBe("PASS_LOCAL");
    expect(r.stages.find(s => s.area === "MANUAL_APPROVAL")?.state)
      .toBe("HUMAN_REVIEW");
    expect(r.stages.find(s => s.area === "CI_HEAD_VERIFICATION")?.state)
      .toBe("HUMAN_REVIEW");
    expect(r.stages.find(s => s.area === "LIVE_EXCLUSION")?.state)
      .toBe("EXCLUDED");
    expect(r.overview.authorizationToMerge).toBe(false);
    expect(r.overview.operationallyAccepted).toBe(false);
  });
  it("does not infer retention approval from a documented exception", () => {
    const r = report({
      dossier: {
        ...base.dossier,
        retention: {
          present: true, verified: true,
          state: "DOCUMENTED_WITH_EXCEPTIONS",
          reviewId: "retention-test-12345",
          backupDisposition: "PROCEDURE_DOCUMENTED",
          nextReviewAt: "2026-12-11T12:00:00.000Z",
        },
      },
      retentionHumanApprovalDocumented: true,
      backupProcedureDocumented: true,
    });
    expect(r.stages.find(s => s.area === "RETENTION")?.state)
      .toBe("HUMAN_REVIEW");
    expect(r.stages.find(s => s.area === "BACKUP_AND_EXPORTS")?.state)
      .toBe("HUMAN_REVIEW");
    expect(r.legalSignoffVerified).toBe(false);
    expect(r.backupDeletionVerified).toBe(false);
    expect(r.mergeAuthorized).toBe(false);
  });
  it("does not treat nine local reviewer matches as legal signoff", () => {
    const r = report({
      operator: { id: "operator-run-12345",
        state: "EVIDENCE_CAPTURED", revision: 11,
        complete: true, integrity: true,
        stepsRecorded: 9, blockedSteps: 0,
        sourceIdentityMatches: true },
      independent: {
        reviewCount: 9, independentlyMatched: 9,
        readyForHumanSignoff: true, mismatchCount: 0,
      },
      audit: {
        checked: true, integrity: true,
        complete: true, blockers: 0, reviewEvents: 9,
      },
      releaseAudit: {
        checked: true, valid: true, events: 3,
      },
    });
    expect(r.stages.find(s =>
      s.area === "OPERATOR_WALKTHROUGH")?.state).toBe("PASS_LOCAL");
    expect(r.stages.find(s =>
      s.area === "INDEPENDENT_EVIDENCE")?.state).toBe("HUMAN_REVIEW");
    expect(r.stages.find(s =>
      s.area === "AUDIT_RECONCILIATION")?.state).toBe("PASS_LOCAL");
    expect(r.mergeAuthorized).toBe(false);
    expect(r.overview.operationallyAccepted).toBe(false);
  });
  it("keeps dependent stages open if a prior gate is unresolved", () => {
    const r = report();
    const blocked = r.dependencies.filter(x => !x.satisfied);
    expect(blocked.length).toBeGreaterThan(0);
    expect(blocked.some(x => x.source === "PRIVACY" &&
      x.target === "RETENTION")).toBe(true);
    expect(r.overview.dependencyBlocked).toBe(blocked.length);
  });
  it("generates an actionable owner-scoped closure plan", () => {
    const r = report();
    const actions = operationalCloseoutActionPlan(r);
    expect(actions.length).toBe(r.actions.length);
    expect(actions.some(a => a.ownerRole === "PRIVACY_OWNER")).toBe(true);
    expect(actions.some(a => a.ownerRole === "BACKUP_OWNER")).toBe(true);
    expect(actions.every(a => !a.automaticApprovalPossible)).toBe(true);
    expect(actions.every(a => a.actualCompletionUnknown)).toBe(true);
  });
  it("preserves explicit external LIVE and GitHub check exclusions", () => {
    const r = report();
    expect(r.policy.providerLiveTestExcluded).toBe(true);
    expect(r.liveProviderRequests).toBe(0);
    expect(r.stages.find(s =>
      s.area === "CI_HEAD_VERIFICATION")?.state)
      .toBe("HUMAN_REVIEW");
    expect(r.policy.offlineOnly).toBe(true);
    expect(r.localDatabaseWrites).toBe(0);
  });
  it("fails independent verification after modifying a report body", () => {
    const r = report();
    r.stages[0]!.state = "EXCLUDED";
    expect(verifyOperationalCloseout(r).valid).toBe(false);
    expect(() => operationalCloseoutExport(r)).toThrow();
  });
  it("rejects fabricated legal and GitHub authorization", () => {
    for (const data of [
      { legalSignoffVerified: true },
      { backupDeletionVerified: true },
      { mergeAuthorized: true },
      { liveProviderRequests: 1 },
      { localDatabaseWrites: 1 },
    ]) {
      const r = Object.assign(report(), data);
      expect(verifyOperationalCloseout(r).valid).toBe(false);
    }
  });
  it("refuses removal of human and LIVE exclusions", () => {
    const r = report();
    r.stages.find(s => s.area === "MANUAL_APPROVAL")!.state = "PASS_LOCAL";
    expect(verifyOperationalCloseout(r).valid).toBe(false);
    const s = report();
    s.stages.find(x => x.area === "LIVE_EXCLUSION")!.state = "PASS_LOCAL";
    expect(verifyOperationalCloseout(s).valid).toBe(false);
  });
  it("exports a signed-off-neutral plan with explicit verified hash", () => {
    const value = operationalCloseoutExport(report());
    expect(value.sha256NotDigitalSignature).toBe(true);
    expect(value.cannotAuthorizeMerge).toBe(true);
    expect(value.requiresIndependentHumanApproval).toBe(true);
    expect(value.sourceDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});
