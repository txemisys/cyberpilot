import {
  createHash, createPublicKey, verify as verifySignature,
  type KeyObject,
} from "node:crypto";

/**
 * CyberPilot never signs legal consent. A separately operated consent
 * authority must issue a detached Ed25519 signature over a canonical,
 * immutable scope grant. This validator does not make that authority
 * trustworthy: keys must be registered out-of-band by the operator,
 * never supplied by the requester or inferred from DNS ownership.
 *
 * This is a verifier, not a collector, issuer or customer signature UI.
 */
export type ConsentSource = "DNS" | "TLS_HANDSHAKE" | "HTTPS_HEADERS";
export type ConsentGrant = {
  schema: "cyberpilot.exposure.legal.grant.v1";
  grantId: string;
  authorityId: string;
  keyId: string;
  organizationId: string;
  authorizationId: string;
  authorizationRevision: number;
  domain: string;
  subjectOrganizationId: string;
  subjectLegalNameDigest: string;
  actorUserId: string;
  purpose: "PASSIVE_EXTERNAL_EXPOSURE_ASSESSMENT";
  sources: ConsentSource[];
  allowedDnsNames: string[];
  allowedTlsHostnames: string[];
  allowedHttpUrls: string[];
  maxRequests: number;
  maxDailyRequests: number;
  notBefore: string;
  expiresAt: string;
  approvedAt: string;
  approvedByIndependentAuthority: true;
  activeScanningAllowed: false;
  credentialsAllowed: false;
  redirectionAllowed: false;
  subdomainDiscoveryAllowed: false;
  socketPeerValidationRequired: true;
  withdrawalEndpointDigest: string;
  nonce: string;
};
export type DetachedConsentEnvelope = {
  schema: "cyberpilot.exposure.legal.envelope.v1";
  grant: ConsentGrant;
  signatureAlgorithm: "Ed25519";
  signatureBase64Url: string;
  signedCanonicalDigest: string;
  issuedAt: string;
};
export type TrustedConsentKey = {
  authorityId: string;
  keyId: string;
  publicKeyPem: string;
  enabled: boolean;
  notBefore: string;
  notAfter: string;
  trustedForPassiveExposure: true;
};
export type ConsentRevocationStatus = {
  schema: "cyberpilot.exposure.legal.withdrawal.v1";
  grantId: string;
  organizationId: string;
  authorityId: string;
  revision: number;
  revoked: boolean;
  checkedAt: string;
  validUntil: string;
  source: "INDEPENDENT_AUTHORITY";
  remotelyVerified: true;
};
export type IndependentConsentContext = {
  organizationId: string;
  authorizationId: string;
  authorizationRevision: number;
  domain: string;
  actorUserId: string;
  requestedSources: ConsentSource[];
  requestedAt: string;
  trustedKeys: TrustedConsentKey[];
  withdrawal: ConsentRevocationStatus | null;
};
export type ConsentVerificationGate = {
  code: string;
  passed: boolean;
  reason: string;
};
export type IndependentConsentVerification = {
  schema: "cyberpilot.exposure.legal.verification.v1";
  decision: "DENIED" | "VALIDATED_FOR_PLANNING";
  organizationId: string;
  domain: string;
  grantId: string | null;
  verifiedAt: string;
  authorityId: string | null;
  checkedKeyId: string | null;
  grantDigest: string | null;
  signatureAuthenticity: boolean;
  revocationCurrent: boolean;
  matchesCurrentDomainProof: boolean;
  legalConsentUnconditionallyProven: false;
  allowsExternalNetworkByItself: false;
  requiresExecutableLease: true;
  requiresSocketGuard: true;
  requiresIndependentAuthorityOperations: true;
  gates: ConsentVerificationGate[];
  denialCodes: string[];
  limitations: string[];
  integrityDigest: string;
};
const sources: readonly ConsentSource[] = [
  "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS",
];
const iso = (s: unknown): s is string =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const safeId = (s: unknown): s is string =>
  typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const hex = (s: unknown): s is string =>
  typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const finiteLimit = (n: unknown, max: number): n is number =>
  Number.isSafeInteger(n) && (n as number) > 0 && (n as number) <= max;
const unique = <T>(xs: readonly T[]) => new Set(xs).size === xs.length;
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.entries(value)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => JSON.stringify(k) + ":" + canonical(v))
    .join(",") + "}";
}
function sha(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function isDomain(value: string): boolean {
  return typeof value === "string" &&
    value.length > 3 && value.length <= 253 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(value) &&
    value.includes(".") && !value.includes("..") &&
    !value.startsWith("xn--") &&
    !value.endsWith(".local") && !value.endsWith(".internal");
}
function expectedScope(domain: string, selected: ConsentSource[]) {
  return {
    dns: selected.includes("DNS") ? [domain, "_dmarc." + domain] : [],
    tls: selected.includes("TLS_HANDSHAKE") ? [domain] : [],
    http: selected.includes("HTTPS_HEADERS") ?
      ["https://" + domain + "/"] : [],
  };
}
function exactStrings(a: readonly string[], b: readonly string[]) {
  return a.length === b.length && a.every((s, i) => s === b[i]);
}
function grantShape(grant: ConsentGrant): string[] {
  const problems: string[] = [];
  if (!grant || typeof grant !== "object")
    return ["GRANT_MALFORMED"];
  if (grant.schema !== "cyberpilot.exposure.legal.grant.v1")
    problems.push("GRANT_SCHEMA");
  for (const [field, value] of [
    ["grantId", grant.grantId],
    ["authorityId", grant.authorityId],
    ["keyId", grant.keyId],
    ["organizationId", grant.organizationId],
    ["authorizationId", grant.authorizationId],
    ["subjectOrganizationId", grant.subjectOrganizationId],
    ["actorUserId", grant.actorUserId],
  ] as const)
    if (!safeId(value)) problems.push("GRANT_ID_" + field);
  if (!safeId(grant.nonce) || grant.nonce.length < 24)
    problems.push("GRANT_NONCE");
  if (!hex(grant.subjectLegalNameDigest))
    problems.push("LEGAL_SUBJECT_DIGEST");
  if (!hex(grant.withdrawalEndpointDigest))
    problems.push("WITHDRAWAL_REFERENCE_DIGEST");
  if (!isDomain(grant.domain)) problems.push("GRANT_DOMAIN");
  if (!Number.isSafeInteger(grant.authorizationRevision) ||
      grant.authorizationRevision < 1)
    problems.push("GRANT_AUTH_REVISION");
  if (grant.purpose !== "PASSIVE_EXTERNAL_EXPOSURE_ASSESSMENT")
    problems.push("GRANT_PURPOSE");
  if (!Array.isArray(grant.sources) ||
      !grant.sources.length || !unique(grant.sources) ||
      grant.sources.some(s => !sources.includes(s)))
    problems.push("GRANT_SOURCES");
  if (!finiteLimit(grant.maxRequests, 10) ||
      !finiteLimit(grant.maxDailyRequests, 100) ||
      grant.maxDailyRequests < grant.maxRequests)
    problems.push("GRANT_QUOTA");
  if (!iso(grant.notBefore) || !iso(grant.expiresAt) ||
      !iso(grant.approvedAt))
    problems.push("GRANT_TIMESTAMPS");
  else if (grant.approvedAt > grant.notBefore ||
           grant.notBefore >= grant.expiresAt ||
           Date.parse(grant.expiresAt) - Date.parse(grant.notBefore) >
             7 * 86400000)
    problems.push("GRANT_LIFETIME");
  if (grant.approvedByIndependentAuthority !== true ||
      grant.activeScanningAllowed !== false ||
      grant.credentialsAllowed !== false ||
      grant.redirectionAllowed !== false ||
      grant.subdomainDiscoveryAllowed !== false ||
      grant.socketPeerValidationRequired !== true)
    problems.push("FORBIDDEN_GRANT_CAPABILITY");
  if (!problems.includes("GRANT_SOURCES") &&
      !problems.includes("GRANT_DOMAIN")) {
    const scope = expectedScope(grant.domain, grant.sources);
    if (!Array.isArray(grant.allowedDnsNames) ||
        !Array.isArray(grant.allowedTlsHostnames) ||
        !Array.isArray(grant.allowedHttpUrls) ||
        !exactStrings(grant.allowedDnsNames, scope.dns) ||
        !exactStrings(grant.allowedTlsHostnames, scope.tls) ||
        !exactStrings(grant.allowedHttpUrls, scope.http))
      problems.push("GRANT_TARGET_ESCALATION");
  }
  return [...new Set(problems)];
}
function trustedKey(
  keys: TrustedConsentKey[], authorityId: string, keyId: string,
  now: string,
): { key: KeyObject | null; errors: string[] } {
  const errors: string[] = [];
  const matches = keys.filter(x =>
    x.authorityId === authorityId && x.keyId === keyId);
  if (matches.length !== 1) {
    errors.push("TRUSTED_AUTHORITY_KEY_NOT_UNIQUE");
    return { key: null, errors };
  }
  const candidate = matches[0]!;
  if (!candidate.enabled ||
      candidate.trustedForPassiveExposure !== true ||
      !iso(candidate.notBefore) || !iso(candidate.notAfter) ||
      candidate.notBefore > now || candidate.notAfter <= now) {
    errors.push("TRUSTED_AUTHORITY_KEY_INACTIVE");
    return { key: null, errors };
  }
  try {
    const key = createPublicKey(candidate.publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519")
      errors.push("TRUSTED_KEY_NOT_ED25519");
    return { key: errors.length ? null : key, errors };
  } catch {
    errors.push("TRUSTED_PUBLIC_KEY_INVALID");
    return { key: null, errors };
  }
}
function verifyDetachedSignature(
  envelope: DetachedConsentEnvelope,
  key: KeyObject,
): boolean {
  if (envelope.signatureAlgorithm !== "Ed25519" ||
      typeof envelope.signatureBase64Url !== "string" ||
      !/^[A-Za-z0-9_-]{86}$/.test(envelope.signatureBase64Url))
    return false;
  const message = canonical(envelope.grant);
  if (sha(message) !== envelope.signedCanonicalDigest)
    return false;
  try {
    const signature = Buffer.from(envelope.signatureBase64Url, "base64url");
    return signature.length === 64 &&
      verifySignature(null, Buffer.from(message, "utf8"),
        key, signature);
  } catch { return false; }
}
function validateWithdrawal(
  state: ConsentRevocationStatus | null,
  grant: ConsentGrant,
  now: string,
): string[] {
  const errors: string[] = [];
  if (!state) return ["WITHDRAWAL_CHECK_MISSING"];
  if (state.schema !== "cyberpilot.exposure.legal.withdrawal.v1" ||
      state.source !== "INDEPENDENT_AUTHORITY" ||
      state.remotelyVerified !== true)
    errors.push("WITHDRAWAL_AUTHORITY_UNVERIFIED");
  if (state.grantId !== grant.grantId ||
      state.organizationId !== grant.organizationId ||
      state.authorityId !== grant.authorityId)
    errors.push("WITHDRAWAL_SCOPE_MISMATCH");
  if (!Number.isSafeInteger(state.revision) || state.revision < 1)
    errors.push("WITHDRAWAL_REVISION_INVALID");
  if (!iso(state.checkedAt) || !iso(state.validUntil) ||
      state.checkedAt > now || state.validUntil <= now ||
      Date.parse(state.validUntil) - Date.parse(state.checkedAt) > 60000)
    errors.push("WITHDRAWAL_NOT_FRESH");
  if (state.revoked !== false) errors.push("GRANT_WITHDRAWN");
  return errors;
}
function reasonFor(code: string): string {
  const known: Record<string, string> = {
    GRANT_MISSING: "A detached consent envelope must be presented.",
    GRANT_SCHEMA: "Consent grant schema does not match.",
    SCOPE_MISMATCH: "Grant belongs to a different tenant, actor or domain.",
    AUTH_REVISION_MISMATCH:
      "The domain ownership proof changed since the consent grant.",
    REQUESTED_SOURCE_NOT_GRANTED:
      "A source is requested outside the signed grant.",
    CONSENT_NOT_YET_ACTIVE:
      "The grant is not yet valid at the requested time.",
    CONSENT_EXPIRED: "The grant has expired.",
    SIGNED_SCOPE_HASH_MISMATCH:
      "The canonical signed scope digest was modified.",
    SIGNATURE_INVALID:
      "The independent authority signature cannot be verified.",
    WITHDRAWAL_CHECK_MISSING:
      "A fresh independently authenticated revocation check is required.",
    WITHDRAWAL_NOT_FRESH:
      "The revocation record was not retrieved recently enough.",
    GRANT_WITHDRAWN:
      "The independent authority has withdrawn this grant.",
    REPLAYED_GRANT_NONCE:
      "A prior workflow already consumed this grant nonce.",
  };
  return known[code] ??
    "Independent consent cannot be accepted: " + code;
}
export function validateIndependentConsent(
  envelope: DetachedConsentEnvelope | null,
  context: IndependentConsentContext,
): IndependentConsentVerification {
  const errors: string[] = [];
  const conditions: Array<{ name: string; valid: boolean }> = [];
  const requireGate = (name: string, valid: boolean) => {
    conditions.push({ name, valid });
    if (!valid) errors.push(name);
  };
  if (!iso(context.requestedAt))
    throw Error("Consent verification requires a strict ISO timestamp");
  const grant = envelope?.grant;
  requireGate("GRANT_MISSING", Boolean(grant));
  if (grant) {
    const shape = grantShape(grant);
    for (const code of shape) requireGate(code, false);
    requireGate("SCOPE_MISMATCH",
      grant.organizationId === context.organizationId &&
      grant.subjectOrganizationId === context.organizationId &&
      grant.domain === context.domain &&
      grant.actorUserId === context.actorUserId &&
      grant.authorizationId === context.authorizationId);
    requireGate("AUTH_REVISION_MISMATCH",
      grant.authorizationRevision === context.authorizationRevision);
    requireGate("REQUESTED_SOURCE_NOT_GRANTED",
      context.requestedSources.length > 0 &&
      unique(context.requestedSources) &&
      context.requestedSources.every(s => grant.sources.includes(s)));
    requireGate("CONSENT_NOT_YET_ACTIVE",
      iso(grant.notBefore) && grant.notBefore <= context.requestedAt);
    requireGate("CONSENT_EXPIRED",
      iso(grant.expiresAt) && grant.expiresAt > context.requestedAt);
    requireGate("APPROVAL_IN_FUTURE",
      iso(grant.approvedAt) && grant.approvedAt <= context.requestedAt);
    requireGate("ENVELOPE_SCHEMA_INVALID",
      envelope?.schema === "cyberpilot.exposure.legal.envelope.v1");
    requireGate("ENVELOPE_ISSUE_TIME_INVALID",
      iso(envelope?.issuedAt) &&
      envelope.issuedAt <= context.requestedAt &&
      envelope.issuedAt >= grant.approvedAt);
    const lookedUp = trustedKey(
      context.trustedKeys, grant.authorityId, grant.keyId,
      context.requestedAt,
    );
    for (const code of lookedUp.errors) requireGate(code, false);
    requireGate("SIGNATURE_INVALID",
      Boolean(envelope && lookedUp.key &&
        verifyDetachedSignature(envelope, lookedUp.key)));
    for (const code of validateWithdrawal(
      context.withdrawal, grant, context.requestedAt,
    )) requireGate(code, false);
  }
  const gates: ConsentVerificationGate[] = conditions.map(x => ({
    code: x.name, passed: x.valid, reason: reasonFor(x.name),
  }));
  const verified = errors.length === 0;
  const base = {
    schema: "cyberpilot.exposure.legal.verification.v1" as const,
    decision: (verified ?
      "VALIDATED_FOR_PLANNING" : "DENIED") as
        IndependentConsentVerification["decision"],
    organizationId: context.organizationId,
    domain: context.domain,
    grantId: grant?.grantId ?? null,
    verifiedAt: context.requestedAt,
    authorityId: grant?.authorityId ?? null,
    checkedKeyId: grant?.keyId ?? null,
    grantDigest: grant ? sha(canonical(grant)) : null,
    signatureAuthenticity: verified,
    revocationCurrent: verified,
    matchesCurrentDomainProof: verified,
    legalConsentUnconditionallyProven: false as const,
    allowsExternalNetworkByItself: false as const,
    requiresExecutableLease: true as const,
    requiresSocketGuard: true as const,
    requiresIndependentAuthorityOperations: true as const,
    gates, denialCodes: [...new Set(errors)],
    limitations: [
      "Local signature validation cannot prove the legal authority's identity.",
      "Trust keys must originate outside the requesting customer and domain.",
      "A separately authenticated revocation service is mandatory.",
      "A signed grant does not authorize any request without durable quota.",
      "This verifier cannot issue consent, a socket lease or LIVE traffic.",
      "DNS ownership evidence alone is not independent legal consent.",
      "No CyberScore or customer security certification is produced.",
    ],
  };
  return { ...base, integrityDigest: sha(canonical(base)) };
}
export function verifyIndependentConsentReport(
  report: IndependentConsentVerification,
  organizationId?: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const { integrityDigest, ...base } = report;
  if (sha(canonical(base)) !== integrityDigest)
    errors.push("REPORT_DIGEST_INVALID");
  if (organizationId && report.organizationId !== organizationId)
    errors.push("TENANT_MISMATCH");
  if (report.allowsExternalNetworkByItself !== false ||
      report.legalConsentUnconditionallyProven !== false ||
      report.requiresExecutableLease !== true ||
      report.requiresSocketGuard !== true ||
      report.requiresIndependentAuthorityOperations !== true)
    errors.push("CONSENT_FALSE_AUTHORIZATION");
  if (report.decision === "VALIDATED_FOR_PLANNING" &&
      (report.denialCodes.length !== 0 ||
       report.gates.some(x => !x.passed)))
    errors.push("OVERSTATED_CONSENT");
  return { valid: errors.length === 0, errors };
}
export function compareConsentChecks(
  before: IndependentConsentVerification,
  after: IndependentConsentVerification,
) {
  if (!verifyIndependentConsentReport(before).valid ||
      !verifyIndependentConsentReport(after).valid ||
      before.organizationId !== after.organizationId ||
      before.domain !== after.domain ||
      before.verifiedAt >= after.verifiedAt)
    throw Error("Invalid or cross-tenant consent comparison");
  return {
    organizationId: after.organizationId,
    domain: after.domain,
    priorDigest: before.integrityDigest,
    latestDigest: after.integrityDigest,
    addedDenials: after.denialCodes.filter(x =>
      !before.denialCodes.includes(x)),
    resolvedDenials: before.denialCodes.filter(x =>
      !after.denialCodes.includes(x)),
    sameGrantId: before.grantId === after.grantId,
    newNetworkAuthorizationCreated: false as const,
    independentAuthorityStillRequired: true as const,
  };
}
export function exportIndependentConsentReport(
  report: IndependentConsentVerification,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  if (!verifyIndependentConsentReport(report).valid)
    throw Error("Cannot export tampered consent verification");
  const stem = "exposure-consent-verification-" +
    report.verifiedAt.slice(0, 10);
  if (format === "JSON") return {
    filename: stem + ".json", mime: "application/json",
    content: JSON.stringify(report, null, 2),
  };
  if (format === "CSV") {
    const quoted = (s: string) =>
      '"' + s.replaceAll('"', '""') + '"';
    return {
      filename: stem + ".csv", mime: "text/csv",
      content: [
        "code,passed,reason",
        ...report.gates.map(x => [
          quoted(x.code), quoted(String(x.passed)),
          quoted(x.reason),
        ].join(",")),
      ].join("\n"),
    };
  }
  if (format !== "MARKDOWN") throw Error("Unsupported consent report format");
  return {
    filename: stem + ".md", mime: "text/markdown",
    content: [
      "# Exposure detached consent verification",
      "",
      "Organization: " + report.organizationId,
      "Domain: " + report.domain,
      "Decision: " + report.decision,
      "Digest: " + report.integrityDigest,
      "",
      ...report.gates.map(x => "- " + x.code + ": " +
        (x.passed ? "PASS" : "DENIED")),
      "",
      ...report.limitations.map(x => "- " + x),
    ].join("\n"),
  };
}
