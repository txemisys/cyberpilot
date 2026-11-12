import { describe, expect, it } from "vitest";
import {
  parseAssetAdviceInput, buildAssetAdviceRows,
  buildAssetAdviceReport, actionsForAssetAdvice,
  summarizeAssetAdvice,
} from "./assets-action-guidance";
import {
  validateAdvicePresentation,
} from "./assets-action-guidance-service";
import type { AdviceSnapshot } from "./assets-action-guidance";

const now = new Date("2026-11-10T12:00:00.000Z");
const importId = "asset-import-12345";
const inspectionId = "osv-inspection-12345";
const org = "asset-org-12345";
const mapping = [{
  inventoryProduct: "Example Package", ecosystem: "npm",
  packageName: "example-package", expectedPurl: null,
}];
const raw = () => ({
  importId, inspectionId, bindings: mapping,
  offset: 0, limit: 50, maxObservationAgeDays: 30,
  onlyReviewable: false, status: null,
});
const snapshot = (): AdviceSnapshot => ({
  importId, inspectionId,
  inspectionDigest: "a".repeat(64),
  inventoryDigest: "b".repeat(64),
  inspectionStatus: "COMPLETE",
  inspectionCompletedAt: new Date("2026-11-09T12:00:00.000Z"),
  importedCount: 2,
  devices: [{
    externalId: "endpoint-001", softwareName: "Example Package",
    softwareVersion: "1.2.3", normalizedProductKey: "example package",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    sourceRow: 2, versionStatus: "EXACT", freshnessStatus: "FRESH",
  }, {
    externalId: "endpoint-002", softwareName: "Example Package",
    softwareVersion: "1.2.4", normalizedProductKey: "example package",
    observedAt: new Date("2026-11-07T10:00:00.000Z"),
    sourceRow: 3, versionStatus: "EXACT", freshnessStatus: "FRESH",
  }],
  queries: [{
    ecosystem: "npm", packageName: "example-package",
    version: "1.2.3", providerStatus: "COMPLETE",
    possibleIds: ["GHSA-aaaa-bbbb-cccc"],
    providerOnlyIds: [], unresolvedIds: [], withdrawnIds: [],
  }, {
    ecosystem: "npm", packageName: "example-package",
    version: "1.2.4", providerStatus: "COMPLETE",
    possibleIds: [], providerOnlyIds: [],
    unresolvedIds: [], withdrawnIds: [],
  }],
});
const run = (input = raw(), state = snapshot()) =>
  buildAssetAdviceReport(org, parseAssetAdviceInput(input), state, now);
describe("asset evidence-to-action input boundary", () => {
  it("parses complete explicit import and provider evidence input", () => {
    expect(parseAssetAdviceInput(raw())).toMatchObject({
      importId, inspectionId, limit: 50, onlyReviewable: false,
    });
  });
  it.each([
    { importId: "bad/path" }, { inspectionId: "short" },
    { offset: -1 }, { offset: 1.5 }, { limit: 0 },
    { limit: 101 }, { maxObservationAgeDays: 0 },
    { maxObservationAgeDays: 366 }, { onlyReviewable: "false" },
    { status: "VERIFIED_SAFE" }, { extra: "value" },
  ])("rejects invalid or unsafe data %j", patch => {
    expect(() => parseAssetAdviceInput({ ...raw(), ...patch }))
      .toThrow();
  });
  it("never marks a positive OSV package query as confirmed exploitation", () => {
    const report = run();
    expect(report.summary.possible).toBe(1);
    expect(report.rows[0]).toMatchObject({
      status: "REVIEW_POSSIBLE_ADVISORY",
      priority: "URGENT_REVIEW",
      possibleIds: ["GHSA-aaaa-bbbb-cccc"],
      confidence: "DECLARED_POSSIBLE",
      notRemediationProof: true,
    });
    expect(report.changesCommitted).toBe(false);
    expect(report.providerQueried).toBe(false);
  });
  it("classifies no positive match strictly within a bounded inspection", () => {
    const result = run().rows.find(row => row.assetId === "endpoint-002");
    expect(result?.status).toBe("NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION");
    expect(result?.confidence).toBe("NO_POSITIVE_MATCH_IN_SCOPE");
    expect(result?.priority).toBe("INFORMATION");
    expect(result?.actions.every(x => x.requiresHumanReview))
      .toBe(true);
  });
  it("distinguishes incomplete provider queries from no advisory matches", () => {
    const state = snapshot();
    state.queries[1]!.providerStatus = "PARTIAL";
    const row = run(raw(), state).rows.find(x => x.assetId === "endpoint-002");
    expect(row?.status).toBe("REVIEW_PROVIDER_UNCERTAINTY");
  });
  it("classifies unresolved IDs without treating the source as safe", () => {
    const state = snapshot();
    state.queries[1]!.unresolvedIds = ["CVE-2026-1234"];
    expect(run(raw(), state).rows.find(x =>
      x.assetId === "endpoint-002")?.status)
      .toBe("REVIEW_PROVIDER_UNCERTAINTY");
  });
  it("does not invent package mapping when none was supplied", () => {
    const input = raw();
    input.bindings = [];
    const result = run(input);
    expect(result.summary.missingMappings).toBe(2);
    expect(result.summary.possible).toBe(0);
  });
  it("separates ambiguous versions from provider lookup", () => {
    const state = snapshot();
    state.devices[0]!.versionStatus = "AMBIGUOUS";
    const result = run(raw(), state);
    expect(result.summary.unknownVersions).toBe(1);
  });
  it("flags old customer inventory even when provider has no positive ID", () => {
    const state = snapshot();
    state.devices[1]!.observedAt = new Date("2026-01-01T00:00:00.000Z");
    expect(run(raw(), state).summary.staleObservations).toBe(1);
  });
  it("never treats a partial inspection as complete provider coverage", () => {
    const state = snapshot();
    state.inspectionStatus = "PARTIAL";
    expect(run(raw(), state).summary.sourceIntegrity).toBe(2);
  });
  it("fails closed when a saved snapshot was truncated", () => {
    const state = snapshot();
    state.importedCount = 3;
    expect(() => run(raw(), state)).toThrow();
  });
  it("rejects duplicate device identities from persisted evidence", () => {
    const state = snapshot();
    state.devices[1]!.externalId = state.devices[0]!.externalId;
    expect(() => run(raw(), state)).toThrow();
  });
  it("rejects inconsistent inspection and inventory relation", () => {
    const state = snapshot();
    state.inspectionId = "different-inspection-12345";
    expect(() => run(raw(), state)).toThrow();
  });
  it("keeps full inventory counts despite filtered pagination", () => {
    const input = raw();
    input.onlyReviewable = true;
    input.limit = 1;
    const result = run(input);
    expect(result.summary.examined).toBe(2);
    expect(result.rows).toHaveLength(1);
    expect(result.totalRows).toBe(1);
    expect(result.hasMore).toBe(false);
  });
  it("does not allow evidence ID to vary between repeated evaluations", () => {
    const first = run();
    const second = run();
    expect(first.rows[0]!.evidenceFingerprint)
      .toBe(second.rows[0]!.evidenceFingerprint);
    expect(first.reportDigest).toBe(second.reportDigest);
  });
  it("includes actionable instructions but requires verification", () => {
    for (const category of [
      "REVIEW_POSSIBLE_ADVISORY",
      "REVIEW_PROVIDER_UNCERTAINTY",
      "REVIEW_MISSING_MAPPING",
      "REVIEW_UNKNOWN_VERSION",
      "REVIEW_SOURCE_INTEGRITY",
      "REVIEW_STALE_OBSERVATION",
      "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION",
    ] as const) {
      const actions = actionsForAssetAdvice(category);
      expect(actions.length).toBeGreaterThan(0);
      expect(actions.every(a => a.requiresHumanReview &&
        a.instruction.length > 30)).toBe(true);
    }
  });
  it("verifies the derived report before the API returns it", () => {
    const report = run();
    expect(validateAdvicePresentation(report)).toMatchObject({
      valid: true, missingEvidence: 0, unacceptableClaims: 0,
    });
    report.rows[0]!.inspectionDigest = "f".repeat(64);
    expect(validateAdvicePresentation(report).valid).toBe(false);
  });
  it("does not claim that a completed action verifies remediation", () => {
    const row = run().rows[0]!;
    expect(JSON.stringify(row.actions)).not.toMatch(/verified remediated/i);
  });
});
