import { describe, expect, it } from "vitest";
import {
  defaultV2Controls, emptyV2Manifest,
  validateV2Manifest, type V2Evidence, type V2Scope,
} from "./multisource-v2-contract";
import {
  computeV2Coverage, coverageV2Gaps,
  deduplicateV2Evidence, compareV2Coverage,
  summarizeV2CoverageExecutive,
} from "./multisource-v2-coverage";
const organizationId = "core-v2-tenant-12345";
const time = "2026-11-12T10:00:00.000Z";
const hash = "a".repeat(64);
const control = defaultV2Controls().find(x =>
  x.id === "IDENTITY_PRIVILEGED_MFA")!;
function source(): V2Evidence {
  return {
    schema: "cyberpilot.multisource.evidence.v2",
    organizationId, evidenceId: "evidence-mfa-0001",
    source: "MICROSOFT_365",
    domain: "IDENTITY", controlId: control.id,
    scope: "tenant-users", scopeKind: "ORGANIZATION",
    subjectHash: hash, state: "OBSERVED",
    confidence: "HIGH",
    verification: "TECHNICALLY_VERIFIED",
    observedAt: time, checkedAt: time,
    validUntil: "2026-11-19T10:00:00.000Z",
    sourceDigest: hash, sourceReference: "local.fixture",
    authority: "test-adapter", sourceCoverage: "COMPLETE",
    details: { twoFactorEnabled: false },
    rawPersonalDataStored: false,
    providerAccountModified: false,
    customerApprovalInferred: false,
  };
}
function coverage(): V2Scope {
  return {
    organizationId, source: "MICROSOFT_365",
    domain: "IDENTITY", scopeKind: "ORGANIZATION",
    scope: "tenant-users", expectedSubjects: 2,
    observedSubjects: 2, totalPages: 1, pagesObserved: 1,
    status: "COMPLETE", checkedAt: time,
    validUntil: "2026-11-19T10:00:00.000Z",
    sourceDigest: hash, customerTenantAuthenticated: true,
    scopeAuthenticityVerified: true, errors: [],
  };
}
describe("CyberScore v2 multi-source control coverage", () => {
  it("unknown cannot become healthy with an empty organization", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001");
    const data = computeV2Coverage(manifest);
    expect(data.coveragePercent).toBe(0);
    expect(data.verifiedControls).toBe(0);
    expect(data.fullTenantCoverageProven).toBe(false);
    expect(data.healthClaimPermitted).toBe(false);
    expect(coverageV2Gaps(data).length).toBeGreaterThan(10);
  });
  it("counts a complete authenticated technical observation only for one control", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [source()];
    manifest.scopes = [coverage()];
    manifest.sourceDigests = [hash];
    expect(validateV2Manifest(manifest).valid).toBe(true);
    const data = computeV2Coverage(manifest);
    expect(data.coveragePercent).toBe(100);
    expect(data.verifiedControls).toBe(1);
    expect(data.canonicalV1ScoreChanged).toBe(false);
    expect(data.healthClaimPermitted).toBe(false);
  });
  it("does not accept fixtures as verified customer security", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [{
      ...source(), verification: "SYNTHETIC_FIXTURE",
    }];
    manifest.scopes = [{
      ...coverage(), customerTenantAuthenticated: false,
    }];
    manifest.sourceDigests = [hash];
    const data = computeV2Coverage(manifest);
    expect(data.verifiedControls).toBe(0);
    expect(data.syntheticDataPresent).toBe(true);
  });
  it("rejects cross-tenant evidence before calculating", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [{
      ...source(), organizationId: "another-tenant-12345",
    }];
    manifest.sourceDigests = [hash];
    expect(validateV2Manifest(manifest).valid).toBe(false);
    expect(() => computeV2Coverage(manifest)).toThrow();
  });
  it("does not infer technical coverage from declarations", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [{
      ...source(), state: "DECLARED", observedAt: null,
      verification: "OPERATOR_DECLARED",
    }];
    manifest.scopes = [coverage()];
    manifest.sourceDigests = [hash];
    const data = computeV2Coverage(manifest);
    expect(data.controls[0]!.status).toBe("DECLARED");
    expect(data.verifiedControls).toBe(0);
  });
  it("rejects expired scope or freshness even if source says COMPLETE", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [source()];
    manifest.scopes = [{
      ...coverage(), validUntil: "2026-11-11T10:00:00.000Z",
    }];
    manifest.sourceDigests = [hash];
    const data = computeV2Coverage(manifest);
    expect(data.verifiedControls).toBe(0);
  });
  it("rejects partial provider pagination as tenant-wide scope", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [source()];
    manifest.scopes = [{
      ...coverage(), totalPages: 2, pagesObserved: 1,
      status: "PARTIAL",
    }];
    manifest.sourceDigests = [hash];
    const data = computeV2Coverage(manifest);
    expect(data.verifiedControls).toBe(0);
  });
  it("does not mix independent organizations in coverage trends", () => {
    const first = computeV2Coverage(emptyV2Manifest(
      organizationId, time, "snapshot-mfa-0001", [control]));
    const second = computeV2Coverage(emptyV2Manifest(
      "other-tenant-12345", time, "snapshot-mfa-0002", [control]));
    expect(() => compareV2Coverage(first, second)).toThrow();
  });
  it("retains non-certifying executive scope with missing controls", () => {
    const data = computeV2Coverage(emptyV2Manifest(
      organizationId, time, "snapshot-mfa-0001", [control]));
    const report = summarizeV2CoverageExecutive(data);
    expect(report.customerCertification).toBe(false);
    expect(report.reliableHealthyClaim).toBe(false);
    expect(report.oldCyberScorePreserved).toBe(true);
  });
  it("deduplicates only within same provider and subject", () => {
    const manifest = emptyV2Manifest(organizationId, time,
      "snapshot-mfa-0001", [control]);
    manifest.evidence = [source(), {
      ...source(), evidenceId: "evidence-mfa-0002",
    }];
    manifest.scopes = [coverage()];
    manifest.sourceDigests = [hash];
    const result = deduplicateV2Evidence(manifest);
    expect(result.evidence).toHaveLength(1);
    expect(result.supersededEvidenceIds).toHaveLength(1);
    expect(result.inferredHealth).toBe(false);
  });
});
