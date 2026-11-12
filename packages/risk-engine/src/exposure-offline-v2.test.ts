import { describe, expect, it } from "vitest";
import {
  assessExposureOffline, normalizeExposureDomain,
  isPublicExposureAddress, validateExposureTargetAddresses,
  validateExposureOfflineEnvelope,
  verifyExposureOfflineAssessment,
  type ExposureOfflineEnvelope,
} from "./exposure-offline-v2";
import {
  buildExposureReportV2, verifyExposureReportV2,
  exportExposureReportV2, compareExposureReportsV2,
} from "./exposure-offline-report-v2";
const at = "2026-11-12T14:00:00.000Z";
const org = "exposure-org-12345";
function fixture(): ExposureOfflineEnvelope {
  return {
    schema: "cyberpilot.exposure.offline.v2",
    organizationId: org, snapshotId: "exposure-snap-12345",
    domain: "example.com", assessedAt: at,
    authorization: {
      schema: "cyberpilot.exposure.authorization.v2",
      organizationId: org, domain: "example.com",
      purpose: "PASSIVE_ASSESSMENT",
      verificationMethod: "DECLARATION",
      verified: false, verifiedAt: null, expiresAt: null,
      challengeDigest: null,
      collectorIdentity: "offline-fixture",
      consentRecordId: "consent-fixture-12345",
      canPerformActiveScanning: false,
      externalOwnershipIndependentlyVerified: false,
    },
    dns: [
      {
        id: "dns-spf-0001", kind: "SPF", status: "OBSERVED",
        queriedName: "example.com",
        records: ["v=spf1 mx -all"], collectedAt: at,
        elapsedMs: 12, resolver: "offline-fixture",
        observedFromAuthorizedScope: true,
        queriedExternalNames: [],
      },
      {
        id: "dns-dmarc-0001", kind: "DMARC", status: "OBSERVED",
        queriedName: "_dmarc.example.com",
        records: ["v=DMARC1; p=none; pct=100"],
        collectedAt: at,
        elapsedMs: 12, resolver: "offline-fixture",
        observedFromAuthorizedScope: true,
        queriedExternalNames: [],
      },
      {
        id: "dns-dkim-0001", kind: "DKIM", status: "NOT_COLLECTED",
        queriedName: "selector._domainkey.example.com",
        records: [], collectedAt: null, elapsedMs: null,
        resolver: "offline-fixture",
        observedFromAuthorizedScope: true,
        queriedExternalNames: [],
      },
    ],
    tls: [{
      id: "tls-main-0001", status: "OBSERVED",
      hostname: "example.com", port: 443,
      collectedAt: at, negotiatedProtocol: "TLSv1.3",
      certificatePresent: true,
      certificateNotBefore: "2026-01-01T00:00:00.000Z",
      certificateNotAfter: "2027-01-01T00:00:00.000Z",
      certificateDnsNames: ["example.com"],
      validatedByTrustedCA: true,
      handshakeError: null,
      remoteAddress: "8.8.8.8",
    }],
    http: [{
      id: "http-main-0001", status: "OBSERVED",
      url: "https://example.com/", collectedAt: at,
      statusCode: 200,
      headers: [["content-type", "text/html"]],
      redirectLocation: null,
      resolvedAddresses: ["8.8.8.8"], finalAddress: "8.8.8.8",
      attempts: 1, durationMs: 100, bodyCollected: false,
    }],
    collectionMode: "IMPORTED_PASSIVE_EVIDENCE",
    networkRequestsByEvaluator: 0,
    dynamicLookupsByEvaluator: 0,
    thirdPartyScanningAuthorized: false,
    sourceIsSynthetic: true,
    claimsVerifiedProductionSecurity: false,
  };
}
describe("Exposure passive offline authorization and findings", () => {
  it("normalizes ordinary domain names but blocks local and private targets", () => {
    expect(normalizeExposureDomain(" Example.COM. ")).toBe("example.com");
    for (const invalid of ["localhost", "server.local", "127.0.0.1",
      "10.0.0.1", "something..com", "foo_test.com",
      "foo.invalid", "192.168.1.1"]) {
      expect(() => normalizeExposureDomain(invalid)).toThrow();
    }
  });
  it("blocks private resolved targets and protects against rebinding", () => {
    for (const ip of ["127.0.0.1", "10.0.0.1",
      "172.19.1.1", "192.168.0.1", "169.254.20.20",
      "100.64.1.1", "203.0.113.8"]) {
      expect(isPublicExposureAddress(ip)).toBe(false);
    }
    expect(isPublicExposureAddress("8.8.8.8")).toBe(true);
    expect(validateExposureTargetAddresses(["8.8.8.8",
      "127.0.0.1"]).valid).toBe(false);
  });
  it("analyzes passive SPF DMARC TLS HTTP but leaves DKIM unknown", () => {
    const input = fixture();
    const result = assessExposureOffline(input);
    expect(result.findings.some(x =>
      x.control === "EMAIL_DMARC")).toBe(true);
    expect(result.findings.some(x =>
      x.control === "WEB_SECURITY_HEADERS")).toBe(true);
    expect(result.checks.find(x =>
      x.control === "EMAIL_DKIM")?.state).toBe("UNKNOWN");
    expect(result.authorization.status).toBe("DECLARED");
    expect(result.trafficGenerated).toBe(0);
    expect(result.coverage.healthyClaimAllowed).toBe(false);
    expect(verifyExposureOfflineAssessment(result, input).valid).toBe(true);
  });
  it("keeps timeout and missing observations unknown rather than healthy", () => {
    const input = fixture();
    input.dns[0]!.status = "TIMEOUT";
    input.dns[0]!.records = [];
    input.dns[0]!.collectedAt = null;
    const report = assessExposureOffline(input);
    const spf = report.checks.find(x => x.control === "EMAIL_SPF")!;
    expect(spf.state).toBe("ERROR");
    expect(spf.findings).toEqual([]);
  });
  it("blocks cross-tenant consent or unauthorized active scanning", () => {
    const input = fixture();
    input.authorization.organizationId = "other-org-12345";
    expect(validateExposureOfflineEnvelope(input).valid).toBe(false);
    expect(() => assessExposureOffline(input)).toThrow();
    input.authorization.organizationId = org;
    (input as unknown as Record<string, unknown>).thirdPartyScanningAuthorized = true;
    expect(() => assessExposureOffline(input)).toThrow();
  });
  it("rejects private HTTP resolution without performing any network calls", () => {
    const input = fixture();
    input.http[0]!.resolvedAddresses = ["8.8.8.8", "127.0.0.1"];
    expect(validateExposureOfflineEnvelope(input).valid).toBe(false);
  });
  it("rejects a final HTTP connection address outside pinned DNS answers", () => {
    const input = fixture();
    input.http[0]!.finalAddress = "1.1.1.1";
    const result = validateExposureOfflineEnvelope(input);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("HTTP_SCOPE_OR_ADDRESS_INVALID");
  });
  it("raises a candidate TLS identity mismatch rather than considering the certificate trusted", () => {
    const input = fixture();
    input.tls[0]!.certificateDnsNames = ["unrelated.example.net"];
    const result = assessExposureOffline(input);
    const tls = result.checks.find(x => x.control === "WEB_TLS")!;
    expect(tls.findings).toHaveLength(1);
    expect(tls.details.hostnameMatched).toBe("NO_MATCH");
    expect(tls.interpretation).toBe("RISK");
    expect(result.coverage.healthyClaimAllowed).toBe(false);
  });
  it("builds auditable 10-section report and exports", () => {
    const assessment = assessExposureOffline(fixture());
    const report = buildExposureReportV2(assessment);
    expect(report.sections).toHaveLength(10);
    expect(report.summary.securityGrade).toBeNull();
    expect(verifyExposureReportV2(report, assessment).verified).toBe(true);
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const exported = exportExposureReportV2(report, format);
      expect(exported.payload.length).toBeGreaterThan(100);
      expect(exported.hasNetworkActivity).toBe(false);
      expect(exported.securityCertified).toBe(false);
    }
  });
  it("rejects cross-organization report trend", () => {
    const first = buildExposureReportV2(assessExposureOffline(fixture()));
    const input = fixture();
    input.organizationId = "foreign-org-12345";
    input.authorization.organizationId = "foreign-org-12345";
    input.assessedAt = "2026-11-13T14:00:00.000Z";
    const second = buildExposureReportV2(assessExposureOffline(input));
    expect(() => compareExposureReportsV2(first, second)).toThrow();
  });
});
