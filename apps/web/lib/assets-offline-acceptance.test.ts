import { describe, expect, it } from "vitest";
import {
  evaluateAssetOfflineAcceptance, parseAcceptancePolicy,
} from "./assets-offline-acceptance";
import type { AcceptanceDataset } from "./assets-offline-acceptance";
import { buildAssetAdviceRows } from "./assets-action-guidance";
import type { CaseRow } from "./assets-action-case-service";

const at = new Date("2026-11-10T12:00:00.000Z");
const org = "acceptance-tenant-12345";
const importId = "acceptance-import-12345";
const inspectionId = "acceptance-osv-12345";
const bindings = [{
  inventoryProduct: "Sample Package",
  ecosystem: "npm", packageName: "sample-package",
  expectedPurl: null,
}];
function fixture(): AcceptanceDataset {
  const snapshot = {
    importId, inspectionId, importedCount: 2,
    inventoryDigest: "a".repeat(64),
    inspectionDigest: "b".repeat(64),
    inspectionStatus: "COMPLETE",
    inspectionCompletedAt: new Date("2026-11-09T12:00:00.000Z"),
    devices: [{
      externalId: "sample-asset-1",
      softwareName: "Sample Package",
      softwareVersion: "1.0.0",
      normalizedProductKey: "sample package",
      versionStatus: "EXACT", freshnessStatus: "FRESH",
      observedAt: new Date("2026-11-08T12:00:00.000Z"),
      sourceRow: 2,
    }, {
      externalId: "sample-asset-2",
      softwareName: "Other Package",
      softwareVersion: null,
      normalizedProductKey: "other package",
      versionStatus: "MISSING", freshnessStatus: "FRESH",
      observedAt: new Date("2026-11-08T12:00:00.000Z"),
      sourceRow: 3,
    }],
    queries: [{
      ecosystem: "npm", packageName: "sample-package",
      version: "1.0.0", providerStatus: "COMPLETE",
      possibleIds: ["GHSA-abcd-1234-efgh"],
      providerOnlyIds: [], unresolvedIds: [], withdrawnIds: [],
    }],
  };
  const candidate = buildAssetAdviceRows(snapshot, bindings, 30, at)[0]!;
  const caseRow: CaseRow = {
    id: "accepted-review-case-12345",
    organizationId: org, importId, inspectionId,
    evidenceFingerprint: candidate.evidenceFingerprint,
    inventoryDigest: snapshot.inventoryDigest,
    inspectionDigest: snapshot.inspectionDigest,
    externalId: candidate.assetId,
    normalizedProductKey: candidate.normalizedProductKey,
    softwareVersion: candidate.version,
    status: "IN_REVIEW", category: candidate.status,
    priority: candidate.priority, revision: 2,
    title: "Sample Package investigation",
    rationale: { reasons: candidate.reasons },
    actions: candidate.actions,
    advisoryIds: candidate.possibleIds,
    openedAt: "2026-11-09T12:00:00.000Z",
    lastDecisionAt: "2026-11-09T12:30:00.000Z",
    lastDecisionReason: "Human review opened with evidence.",
    lastDecisionUserId: "test-operator-12345",
    steps: candidate.actions.map((action, n) => ({
      id: "review-step-" + n,
      actionCode: action.code, status: "TODO",
      revision: 1, note: null,
      completedAt: null, completedByUserId: null,
    })),
  };
  return {
    organizationId: org, snapshot, bindings,
    cases: [caseRow],
    auditCaseIds: [caseRow.id],
    checkedAt: at,
  };
}
function evaluate(dataset = fixture(), policy = parseAcceptancePolicy()) {
  return evaluateAssetOfflineAcceptance(dataset, policy);
}
describe("Fase 4 offline acceptance gate engine", () => {
  it("defaults to explicit local safety policies", () => {
    expect(parseAcceptancePolicy()).toMatchObject({
      maximumInventoryAgeDays: 30,
      minimumMappedPercent: 80,
      allowIncompleteInspections: false,
      requireCaseAudit: true,
      requireAllCandidateReviews: true,
      maximumCaseAgeDays: 90,
      maxCases: 500,
    });
  });
  it.each([
    { maximumInventoryAgeDays: 0 },
    { maximumInventoryAgeDays: 366 },
    { minimumMappedPercent: -1 },
    { minimumMappedPercent: 101 },
    { allowIncompleteInspections: "false" },
    { requireCaseAudit: 1 },
    { requireAllCandidateReviews: "yes" },
    { maximumCaseAgeDays: 0 },
    { maxCases: 1001 },
    { unexpectedProvider: "LIVE" },
  ])("rejects unbounded or unsupported acceptance settings %j", patch => {
    expect(() => parseAcceptancePolicy(patch)).toThrow();
  });
  it("blocks missing package mappings without calling the provider", () => {
    const result = evaluate();
    expect(result.gates.find(x => x.id === "MAPPING_COVERAGE")?.level)
      .toBe("BLOCK");
    expect(result.providerRequests).toBe(0);
    expect(result.databaseWrites).toBe(0);
  });
  it("can satisfy the release gates for a fully mapped synthetic sample", () => {
    const data = fixture();
    const result = evaluate(data, parseAcceptancePolicy({
      minimumMappedPercent: 50,
    }));
    expect(result.acceptanceEligible).toBe(true);
    expect(result.scorecard.blocked).toBe(0);
    expect(result.manualAcceptanceStillRequired).toBe(true);
    expect(result.source.positiveCandidateCount).toBe(1);
    expect(result.source.unknownEvidenceCount).toBe(1);
  });
  it("never concludes that candidate review proves an exposed endpoint", () => {
    const result = evaluate();
    expect(result.warnings.join(" ")).toMatch(/not prove installed software/i);
    expect(result.findingsModified).toBe(false);
    expect(result.cyberScoreModified).toBe(false);
  });
  it("rejects truncated saved inventories instead of silently dropping data", () => {
    const data = fixture();
    data.snapshot.importedCount = 3;
    expect(() => evaluate(data)).toThrow();
  });
  it("detects incomplete source inspections", () => {
    const data = fixture();
    data.snapshot.inspectionStatus = "PARTIAL";
    const result = evaluate(data);
    expect(result.gates.find(x => x.id === "INSPECTION_COMPLETE")?.level)
      .toBe("BLOCK");
  });
  it("can downgrade incomplete inspection only to an explicit advisory", () => {
    const data = fixture();
    data.snapshot.inspectionStatus = "PARTIAL";
    const result = evaluate(data, parseAcceptancePolicy({
      minimumMappedPercent: 50, allowIncompleteInspections: true,
    }));
    expect(result.gates.find(x => x.id === "INSPECTION_COMPLETE")?.level)
      .toBe("ADVISORY");
    expect(result.source.completeWithinSnapshot).toBe(false);
  });
  it("blocks missing human investigations for positive candidates", () => {
    const data = fixture();
    data.cases = [];
    data.auditCaseIds = [];
    const result = evaluate(data, parseAcceptancePolicy({
      minimumMappedPercent: 50,
    }));
    expect(result.gates.find(x => x.id === "UNKNOWN_EVIDENCE")?.level)
      .toBe("BLOCK");
    expect(result.scorecard.possibleCandidatesWithoutReview).toBe(1);
  });
  it("detects an altered evidence fingerprint after a review was opened", () => {
    const data = fixture();
    data.cases[0]!.evidenceFingerprint = "f".repeat(64);
    const result = evaluate(data);
    expect(result.gates.find(x => x.id === "CANDIDATE_PROVENANCE")?.level)
      .toBe("BLOCK");
  });
  it("detects cross-tenant case contamination even with matching advisory", () => {
    const data = fixture();
    data.cases[0]!.organizationId = "foreign-tenant-12345";
    const result = evaluate(data);
    expect(result.gates.find(x => x.id === "TENANT_ISOLATION")?.level)
      .toBe("BLOCK");
  });
  it("blocks a WORK_COMPLETED case with unfinished human steps", () => {
    const data = fixture();
    data.cases[0]!.status = "WORK_COMPLETED";
    const result = evaluate(data);
    expect(result.gates.find(x => x.id === "CASE_LIFECYCLE")?.level)
      .toBe("BLOCK");
  });
  it("blocks cases whose audit records are missing", () => {
    const data = fixture();
    data.auditCaseIds = [];
    expect(evaluate(data).gates.find(x => x.id === "AUDIT_COVERAGE")?.level)
      .toBe("BLOCK");
  });
  it("does not fabricate audit events when audit enforcement is relaxed", () => {
    const data = fixture();
    data.auditCaseIds = [];
    const result = evaluate(data, parseAcceptancePolicy({
      minimumMappedPercent: 50, requireCaseAudit: false,
    }));
    expect(result.gates.find(x => x.id === "AUDIT_COVERAGE")?.level)
      .toBe("ADVISORY");
    expect(result.source.auditCount).toBe(0);
  });
  it("rejects missing or unexpected action steps", () => {
    const data = fixture();
    data.cases[0]!.steps = [];
    expect(evaluate(data).gates.find(x => x.id === "CHECKLIST_INTEGRITY")?.level)
      .toBe("BLOCK");
  });
  it("reports aged observations as advisory without claiming fresh proof", () => {
    const data = fixture();
    data.snapshot.devices[0]!.observedAt =
      new Date("2026-01-01T12:00:00.000Z");
    expect(evaluate(data).gates.find(x => x.id === "AGE_POLICY")?.level)
      .toBe("ADVISORY");
  });
  it("refuses to assess a collection beyond its policy bound", () => {
    const data = fixture();
    const result = parseAcceptancePolicy({ maxCases: 1 });
    data.cases.push({ ...data.cases[0]!, id: "case-duplicate-12345" });
    expect(() => evaluate(data, result)).toThrow();
  });
  it("preserves deterministic source reports for the same evidence and clock", () => {
    expect(evaluate().reportDigest).toBe(evaluate().reportDigest);
    expect(evaluate().reportDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});
