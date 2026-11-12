import { describe, expect, it } from "vitest";
import { normalizeBatch } from "./directory-contract";
import { assessGoogleWorkspace } from "./risk-assessment";
import {
  buildNeutralGoogleBundle, verifyNeutralGoogleBundle,
  translateGoogleEvidence, translateGoogleFindings,
  compareNeutralGoogleBundles, verifyNeutralGoogleComparison,
  neutralGoogleJson, neutralGoogleCsv,
} from "./neutral-evidence";

const org = "neutral-org-12345";
const at = "2026-11-12T10:00:00.000Z";
const at2 = "2026-11-13T10:00:00.000Z";
function observation(timestamp = at, options: {
  organizationId?: string;
  enrolled?: boolean;
  partial?: boolean;
} = {}) {
  return normalizeBatch({
    organizationId: options.organizationId ?? org,
    checkedAt: timestamp, source: "SYNTHETIC_FIXTURE",
    users: [{
      id: "google-user-12345",
      primaryEmail: "admin@example.invalid",
      isAdmin: true, suspended: false,
      isEnrolledIn2Sv: options.enrolled ?? false,
      isEnforcedIn2Sv: options.enrolled ?? false,
      lastLoginTime: "2026-11-11T10:00:00.000Z",
    }],
    domains: [{
      domainName: "example.invalid", isPrimary: true,
      verified: false,
    }],
    coverage: {
      DIRECTORY_USERS: "AVAILABLE",
      DIRECTORY_DOMAINS: "AVAILABLE",
      USER_MFA_ATTRIBUTES: options.partial ?
        "REQUIRES_PERMISSION" : "AVAILABLE",
      REPORTS_LOGIN: "UNKNOWN",
      REPORTS_ADMIN: "UNKNOWN",
      DIRECTORY_ORGANIZATION_UNITS: "UNKNOWN",
    },
  });
}
function bundle(timestamp = at, opts = {}) {
  return buildNeutralGoogleBundle(
    assessGoogleWorkspace(observation(timestamp, opts),
      { referenceDate: timestamp }, new Date(timestamp)));
}
describe("Google Workspace neutral multi-provider evidence bridge", () => {
  it("projects versioned control IDs without mutating historical CyberScore", () => {
    const result = bundle();
    expect(result.controls.length).toBeGreaterThan(0);
    expect(result.controls.every(x =>
      x.schema === "cyberpilot.neutral.provider.control.v1")).toBe(true);
    expect(result.summary.canonicalScore).toBe(null);
    expect(result.summary.canonicalScoreUpdated).toBe(false);
    expect(result.coverage.canonicalCyberScoreChanged).toBe(false);
    expect(result.coverage.externalProviderVerified).toBe(false);
    expect(verifyNeutralGoogleBundle(result).valid).toBe(true);
  });
  it("does not export raw email addresses or Google credentials", () => {
    const result = bundle();
    const json = neutralGoogleJson(result);
    const csv = neutralGoogleCsv(result);
    expect(json).not.toContain("admin@example.invalid");
    expect(csv).not.toContain("admin@example.invalid");
    expect(result.exportRestrictions.oauthCredentialIncluded).toBe(false);
    expect(result.exportRestrictions.rawEmailIncluded).toBe(false);
    expect(csv).toContain("sourceDigest");
  });
  it("keeps partial MFA coverage UNKNOWN instead of observed healthy", () => {
    const result = bundle(at, { partial: true });
    const mfa = result.controls.find(c =>
      c.providerCapability === "USER_MFA_ATTRIBUTES");
    expect(mfa?.state).toBe("UNKNOWN");
    expect(mfa?.sourceCoverage).toBe("DENIED");
    expect(result.coverage.capabilities.find(x =>
      x.capability === "USER_MFA_ATTRIBUTES")?.status).toBe("DENIED");
  });
  it("converts risk findings into potential work, not resolved incidents", () => {
    const result = bundle();
    expect(result.findings.some(f =>
      f.state === "POTENTIAL")).toBe(true);
    expect(result.findings.every(f =>
      !f.resolved && !f.GoogleAccountMutated &&
      !f.customerApproved)).toBe(true);
    expect(result.findings.every(f =>
      f.organizationId === org)).toBe(true);
  });
  it("comparison never describes missing findings as verified remediation", () => {
    const previous = bundle();
    const current = bundle(at2, { enrolled: true });
    const report = compareNeutralGoogleBundles(previous, current);
    expect(report.officialRemediationClaimed).toBe(false);
    expect(report.canonicalCyberScoreRecomputed).toBe(false);
    expect(report.absentFromNewSnapshot.length).toBeGreaterThan(0);
    expect(verifyNeutralGoogleComparison(report).valid).toBe(true);
  });
  it("rejects cross-tenant snapshot comparison", () => {
    const first = bundle();
    const second = bundle(at2, {
      organizationId: "neutral-other-org-12345",
    });
    expect(() => compareNeutralGoogleBundles(first, second)).toThrow();
  });
  it("rejects altered controls even when the visible title is unchanged", () => {
    const result = bundle();
    result.controls[0]!.state = "OBSERVED";
    expect(verifyNeutralGoogleBundle(result).valid).toBe(false);
    expect(() => neutralGoogleCsv(result)).toThrow();
  });
  it("keeps source and license limitations in the exported bundle", () => {
    const result = bundle();
    expect(result.limitations.length).toBeGreaterThan(6);
    expect(result.provenance.sourceSignatureVerified).toBe(false);
    expect(result.provenance.licensingVerified).toBe(false);
    expect(result.coverage.fullTenantScopeVerified).toBe(false);
  });
  it("projection is deterministic for identical tenant and observation", () => {
    const input = assessGoogleWorkspace(observation(),
      { referenceDate: at }, new Date(at));
    const a = buildNeutralGoogleBundle(input);
    const b = buildNeutralGoogleBundle(input);
    expect(a.digest).toBe(b.digest);
    expect(translateGoogleEvidence(input)).toEqual(a.controls);
    expect(translateGoogleFindings(input)).toEqual(a.findings);
  });
});
