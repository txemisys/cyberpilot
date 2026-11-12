import { describe, expect, it } from "vitest";
import {
  type V2AdapterContext, type V2AdapterObservation,
  buildV2Intake, createV2AdapterBatch,
  assembleV2Intake, reviewV2IntakeSourceReadiness,
  importV2SourceAuditManifest,
  convertLegacyV1Evidence,
} from "./multisource-v2-adapters";
import {
  defaultV2Controls, emptyV2Manifest,
} from "./multisource-v2-contract";
import {
  buildV2ExecutiveReport, verifyV2ExecutiveReport,
  exportV2Report, verifyV2ReportExport,
  compareV2ExecutiveReports,
} from "./multisource-v2-report";
import { calculateMultiSourceCyberScoreV2 } from "./multisource-v2-score";
import { computeV2Coverage } from "./multisource-v2-coverage";
const organizationId = "tenant-without-m365-12345";
const checkedAt = "2026-11-12T10:00:00.000Z";
const digest = "f".repeat(64);
function context(overrides: Partial<V2AdapterContext> = {}):
V2AdapterContext {
  return {
    organizationId, evaluatedAt: checkedAt,
    snapshotId: "baseline-snapshot-12345",
    authority: "offline-unit-source",
    sourceReference: "approved-local-source",
    sourceDigest: digest,
    scope: "company-wide",
    scopeKind: "ORGANIZATION",
    observedSubjects: 3, expectedSubjects: 3,
    pagesRead: 1, expectedPages: 1,
    status: "COMPLETE",
    providerAuthenticated: false,
    scopeAuthenticityVerified: false,
    sourceIsSynthetic: true,
    allowTechnicalProof: false,
    maxAgeDays: 30, ...overrides,
  };
}
function observation(
  controlId: string, domain: V2AdapterObservation["domain"],
  scope: string,
): V2AdapterObservation {
  return {
    schema: "cyberpilot.multisource.adapter.observation.v2",
    externalId: "fixture-" + controlId.toLowerCase(),
    subjectId: "anonymous-company-scope",
    controlId, domain,
    state: "OBSERVED", confidence: "MEDIUM",
    observedAt: checkedAt, checkedAt, scope,
    details: { observed: true },
    provenance: "synthetic-fixture-no-customer-proof",
  };
}
function m365less() {
  const webContext = context({
    scope: "example.invalid",
    scopeKind: "DOMAIN",
    sourceDigest: "a".repeat(64),
  });
  const baselineContext = context({
    sourceDigest: "b".repeat(64),
  });
  const assetsContext = context({
    sourceDigest: "c".repeat(64),
  });
  const web = createV2AdapterBatch("EXPOSURE", webContext, [
    observation("WEB_TLS", "WEB", "example.invalid"),
  ]);
  const baseline = createV2AdapterBatch("BASELINE",
    baselineContext, [
      observation("BACKUP_POLICY", "BACKUP", "company-wide"),
      observation("GOVERNANCE_INCIDENT_PLAN",
        "GOVERNANCE", "company-wide"),
    ]);
  const assets = createV2AdapterBatch("ASSETS",
    assetsContext, [
      observation("ENDPOINT_DEVICE_INVENTORY",
        "ENDPOINT", "company-wide"),
    ]);
  const intake = buildV2Intake(context(), [
    web, baseline, assets,
  ]);
  return assembleV2Intake(intake);
}
describe("Phase 1 v2 organizations without Microsoft 365", () => {
  it("assembles Exposure, Baseline and Assets without M365 dependencies", () => {
    const result = m365less();
    expect(result.acceptedSources).toEqual([
      "EXPOSURE", "BASELINE", "ASSETS",
    ]);
    expect(result.importedEvidence).toBe(4);
    expect(result.manifest.evidence.some(x =>
      x.source === "MICROSOFT_365")).toBe(false);
    expect(result.scoreCalculated).toBe(false);
  });
  it("produces a 14-section executive report with explicit missing coverage", () => {
    const result = m365less();
    const report = buildV2ExecutiveReport(result.manifest);
    const coverage = computeV2Coverage(result.manifest);
    const score = calculateMultiSourceCyberScoreV2(result.manifest);
    expect(report.sections).toHaveLength(14);
    expect(report.summary.noMicrosoft365RequiredToGenerate).toBe(true);
    expect(report.summary.numericScore).toBe(null);
    expect(score.score).toBe(null);
    expect(coverage.healthClaimPermitted).toBe(false);
    expect(report.gaps.length).toBeGreaterThan(10);
    expect(verifyV2ExecutiveReport(report,
      result.manifest).verified).toBe(true);
  });
  it("returns exportable JSON, CSV and Markdown without invented certification", () => {
    const report = buildV2ExecutiveReport(m365less().manifest);
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const exported = exportV2Report(report, format);
      expect(exported.content.length).toBeGreaterThan(100);
      expect(exported.customerCertificationClaimed).toBe(false);
      expect(exported.containsOauthTokens).toBe(false);
      expect(verifyV2ReportExport(exported).valid).toBe(true);
    }
  });
  it("does not grant TECHNICALLY_VERIFIED to baseline self-declarations", () => {
    const result = m365less();
    expect(result.manifest.evidence.every(x =>
      x.verification === "SYNTHETIC_FIXTURE")).toBe(true);
    expect(computeV2Coverage(result.manifest).verifiedControls)
      .toBe(0);
    expect(reviewV2IntakeSourceReadiness(result)
      .automaticallyMigratedLegacyScore).toBe(false);
  });
  it("blocks real-proof promotion from fixture source flags", () => {
    expect(() => createV2AdapterBatch("EXPOSURE", context({
      allowTechnicalProof: true,
      sourceIsSynthetic: true,
    }), [])).toThrow();
  });
  it("blocks cross-tenant content from intake", () => {
    const result = m365less();
    const batch = createV2AdapterBatch("BASELINE",
      context(), [
        observation("BACKUP_POLICY", "BACKUP", "company-wide"),
      ]);
    expect(() => buildV2Intake(context(), [
      { ...batch, organizationId: "foreign-tenant-12345" },
    ])).toThrow();
    expect(result.manifest.organizationId).toBe(organizationId);
  });
  it("does not coerce legacy V1 observations to genuine live provider security", () => {
    const old = [{
      schemaVersion: 1 as const, organizationId,
      source: "DOMAIN" as const,
      domain: "WEB" as const, controlId: "WEB_TLS",
      state: "OBSERVED" as const, observedAt: new Date(checkedAt),
      scope: "company-wide", details: { enabled: true },
    }];
    const converted = convertLegacyV1Evidence(old, context());
    expect(converted).toHaveLength(1);
    expect(converted[0]!.technicalEvidence).toBe(false);
    expect(converted[0]!.source).toBe("EXPOSURE");
    expect(converted[0]!.providerAuthenticated).toBe(false);
  });
  it("exports source fingerprints without writing legacy scoring history", () => {
    const ctx = context();
    const batch = createV2AdapterBatch("BASELINE", ctx, [
      observation("BACKUP_POLICY", "BACKUP", "company-wide"),
    ]);
    const audit = importV2SourceAuditManifest(
      buildV2Intake(ctx, [batch]));
    expect(audit.historicalCyberScoreV1Touched).toBe(false);
    expect(audit.securityActionsPerformed).toBe(0);
    expect(audit.sourceFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
  it("rejects tampered report with local digest mismatch", () => {
    const manifest = m365less().manifest;
    const report = buildV2ExecutiveReport(manifest);
    report.summary.coveragePercent = 100;
    expect(verifyV2ExecutiveReport(report).verified).toBe(false);
    expect(() => exportV2Report(report, "JSON")).toThrow();
  });
  it("prevents reporting trends between two organizations", () => {
    const first = buildV2ExecutiveReport(m365less().manifest);
    const second = buildV2ExecutiveReport(emptyV2Manifest(
      "some-other-tenant-12345", checkedAt,
      "second-snapshot-12345", defaultV2Controls()));
    expect(() => compareV2ExecutiveReports(first, second)).toThrow();
  });
});
