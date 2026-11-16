import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  validateIndependentConsent,
  verifyIndependentConsentReport,
  compareConsentChecks,
  exportIndependentConsentReport,
  type ConsentGrant,
  type DetachedConsentEnvelope,
  type TrustedConsentKey,
  type IndependentConsentContext,
} from "./exposure-independent-consent";
const t = "2026-11-16T11:00:00.000Z";
const pair = generateKeyPairSync("ed25519");
const publicKeyPem = pair.publicKey.export({
  type: "spki", format: "pem",
}).toString();
const canonical = (value: unknown): string => {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.entries(value)
    .sort(([a],[b]) => a.localeCompare(b))
    .map(([k,v]) => JSON.stringify(k) + ":" + canonical(v)).join(",") + "}";
};
const sha = (value: string) =>
  requireHash(value);
function requireHash(value: string) {
  return (globalHash(value));
}
import { createHash } from "node:crypto";
function globalHash(s: string) {
  return createHash("sha256").update(s).digest("hex");
}
function grant(): ConsentGrant {
  return {
    schema: "cyberpilot.exposure.legal.grant.v1",
    grantId: "grant-001",
    authorityId: "legal-authority",
    keyId: "trustkey-001",
    organizationId: "org-example",
    authorizationId: "authorization-001",
    authorizationRevision: 2,
    domain: "example.com",
    subjectOrganizationId: "org-example",
    subjectLegalNameDigest: "a".repeat(64),
    actorUserId: "actor-example",
    purpose: "PASSIVE_EXTERNAL_EXPOSURE_ASSESSMENT",
    sources: ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"],
    allowedDnsNames: ["example.com","_dmarc.example.com"],
    allowedTlsHostnames: ["example.com"],
    allowedHttpUrls: ["https://example.com/"],
    maxRequests: 7,
    maxDailyRequests: 8,
    notBefore: "2026-11-16T10:00:00.000Z",
    expiresAt: "2026-11-16T12:00:00.000Z",
    approvedAt: "2026-11-16T09:00:00.000Z",
    approvedByIndependentAuthority: true,
    activeScanningAllowed: false,
    credentialsAllowed: false,
    redirectionAllowed: false,
    subdomainDiscoveryAllowed: false,
    socketPeerValidationRequired: true,
    withdrawalEndpointDigest: "b".repeat(64),
    nonce: "consentnonce-1234567890123456789",
  };
}
function envelope(raw: ConsentGrant = grant()):
  DetachedConsentEnvelope {
  const text = canonical(raw);
  return {
    schema: "cyberpilot.exposure.legal.envelope.v1",
    grant: raw, signatureAlgorithm: "Ed25519",
    signatureBase64Url: sign(
      null, Buffer.from(text), pair.privateKey,
    ).toString("base64url"),
    signedCanonicalDigest: sha(text),
    issuedAt: "2026-11-16T10:00:00.000Z",
  };
}
function context(): IndependentConsentContext {
  const keys: TrustedConsentKey[] = [{
    authorityId: "legal-authority",
    keyId: "trustkey-001",
    publicKeyPem,
    enabled: true,
    notBefore: "2026-11-16T08:00:00.000Z",
    notAfter: "2026-11-16T13:00:00.000Z",
    trustedForPassiveExposure: true,
  }];
  return {
    organizationId: "org-example",
    authorizationId: "authorization-001",
    authorizationRevision: 2,
    domain: "example.com",
    actorUserId: "actor-example",
    requestedSources: ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"],
    requestedAt: t,
    trustedKeys: keys,
    withdrawal: {
      schema: "cyberpilot.exposure.legal.withdrawal.v1",
      grantId: "grant-001",
      organizationId: "org-example",
      authorityId: "legal-authority",
      revision: 1, revoked: false,
      checkedAt: "2026-11-16T10:59:45.000Z",
      validUntil: "2026-11-16T11:00:30.000Z",
      source: "INDEPENDENT_AUTHORITY",
      remotelyVerified: true,
    },
  };
}
describe("detached independent legal consent verification", () => {
  it("verifies a genuinely signed scope without allowing traffic", () => {
    const result = validateIndependentConsent(envelope(), context());
    expect(result.decision).toBe("VALIDATED_FOR_PLANNING");
    expect(result.signatureAuthenticity).toBe(true);
    expect(result.revocationCurrent).toBe(true);
    expect(result.allowsExternalNetworkByItself).toBe(false);
    expect(result.legalConsentUnconditionallyProven).toBe(false);
    expect(verifyIndependentConsentReport(result,"org-example").valid)
      .toBe(true);
  });
  it("rejects a grant without independently registered keys", () => {
    const ctx = context();
    ctx.trustedKeys = [];
    const result = validateIndependentConsent(envelope(), ctx);
    expect(result.decision).toBe("DENIED");
    expect(result.denialCodes).toContain("TRUSTED_AUTHORITY_KEY_NOT_UNIQUE");
  });
  it("rejects missing trusted revocation status", () => {
    const ctx = context();
    ctx.withdrawal = null;
    expect(validateIndependentConsent(envelope(),ctx).denialCodes)
      .toContain("WITHDRAWAL_CHECK_MISSING");
  });
  it("rejects stale revocation status", () => {
    const ctx = context();
    ctx.withdrawal!.validUntil = "2026-11-16T10:59:59.000Z";
    expect(validateIndependentConsent(envelope(),ctx).denialCodes)
      .toContain("WITHDRAWAL_NOT_FRESH");
  });
  it("rejects a recalled authority approval", () => {
    const ctx = context();
    ctx.withdrawal!.revoked = true;
    expect(validateIndependentConsent(envelope(),ctx).denialCodes)
      .toContain("GRANT_WITHDRAWN");
  });
  it("rejects a mutation to scope after signature", () => {
    const signed = envelope();
    signed.grant.maxRequests = 9;
    expect(validateIndependentConsent(signed,context()).denialCodes)
      .toContain("SIGNATURE_INVALID");
  });
  it("rejects a forged legal approval flag", () => {
    const raw = grant();
    raw.activeScanningAllowed = true as false;
    expect(validateIndependentConsent(envelope(raw),context()).denialCodes)
      .toContain("FORBIDDEN_GRANT_CAPABILITY");
  });
  it("rejects a grant for another tenant or revision", () => {
    const ctx = context();
    ctx.organizationId = "org-foreign";
    ctx.authorizationRevision = 3;
    const report = validateIndependentConsent(envelope(),ctx);
    expect(report.denialCodes).toContain("SCOPE_MISMATCH");
    expect(report.denialCodes).toContain("AUTH_REVISION_MISMATCH");
  });
  it("rejects source escalation to arbitrary URL", () => {
    const raw = grant();
    raw.allowedHttpUrls = ["https://example.com/admin"];
    const report = validateIndependentConsent(envelope(raw),context());
    expect(report.denialCodes).toContain("GRANT_TARGET_ESCALATION");
  });
  it("rejects duplicate keys even if one is valid", () => {
    const ctx = context();
    ctx.trustedKeys.push(ctx.trustedKeys[0]!);
    expect(validateIndependentConsent(envelope(),ctx).denialCodes)
      .toContain("TRUSTED_AUTHORITY_KEY_NOT_UNIQUE");
  });
  it("rejects expired grants", () => {
    const ctx = context();
    ctx.requestedAt = "2026-11-16T13:00:00.000Z";
    expect(validateIndependentConsent(envelope(),ctx).denialCodes)
      .toContain("CONSENT_EXPIRED");
  });
  it("detects tampering and never confuses report hash with authority signature", () => {
    const report = validateIndependentConsent(envelope(),context());
    report.allowsExternalNetworkByItself = true as false;
    const check = verifyIndependentConsentReport(report);
    expect(check.errors).toContain("REPORT_DIGEST_INVALID");
    expect(check.errors).toContain("CONSENT_FALSE_AUTHORIZATION");
  });
  it("generates a conservative audit diff and bounded exports", () => {
    const before = validateIndependentConsent(envelope(),context());
    const ctx = context();
    ctx.requestedAt = "2026-11-16T11:00:10.000Z";
    ctx.withdrawal!.revoked = true;
    const after = validateIndependentConsent(envelope(),ctx);
    const comparison = compareConsentChecks(before,after);
    expect(comparison.addedDenials).toContain("GRANT_WITHDRAWN");
    expect(comparison.newNetworkAuthorizationCreated).toBe(false);
    expect(exportIndependentConsentReport(before,"CSV").content)
      .toContain("SIGNATURE_INVALID");
    expect(exportIndependentConsentReport(before,"MARKDOWN").content)
      .toContain("VALIDATED_FOR_PLANNING");
    expect(JSON.parse(exportIndependentConsentReport(before,"JSON")
      .content).allowsExternalNetworkByItself).toBe(false);
  });
});
