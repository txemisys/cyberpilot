import { normalizeExposureDomain,
  isPublicExposureAddress } from "./exposure-offline-v2";
import { sha256V2 } from "./multisource-v2-history";
import { canonicalV2 } from "./multisource-v2-contract";

/**
 * Read-only authorization lifecycle and collection planning.
 * No supplied DNS/HTTP payload becomes independent proof merely
 * because it matches the challenge: a trusted collector is required.
 */
export type ExposureAuthorizationMethod = "DNS_TOKEN" | "HTTP_TOKEN";
export type ExposureAuthorizationState =
  "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
export type ExposureAuthorizationRequest = {
  schema: "cyberpilot.exposure.domain.authorization.request.v1";
  organizationId: string;
  domain: string;
  method: ExposureAuthorizationMethod;
  token: string;
  issuedAt: string;
  expiresAt: string;
  issuedBy: string;
  purpose: "PASSIVE_EXTERNAL_OBSERVATION";
  allowActivePortScanning: false;
  allowSubdomainEnumeration: false;
  allowThirdPartyHost: false;
};
export type ExposureAuthorizationChallenge = {
  schema: "cyberpilot.exposure.domain.authorization.challenge.v1";
  organizationId: string;
  domain: string;
  method: ExposureAuthorizationMethod;
  challengeDigest: string;
  expectedName: string;
  expectedValue: string;
  issuedAt: string;
  expiresAt: string;
  status: "PENDING";
  mayTriggerNetworkScan: false;
  exposesSecretCredential: false;
};
export type ExposureVerificationEvidence = {
  schema: "cyberpilot.exposure.authorization.evidence.v1";
  organizationId: string; domain: string;
  method: ExposureAuthorizationMethod;
  requestedName: string;
  observedValues: string[];
  observedAt: string;
  collectionStatus: "COMPLETE" | "PARTIAL" | "ERROR" |
    "TIMEOUT" | "NXDOMAIN";
  collectorTrusted: boolean;
  networkOriginVerified: boolean;
  originIp: string | null;
  redirectFollowed: false;
  pagesRead: number;
  expectedPages: number;
  recordDigest: string;
};
export type ExposureAuthorizationDecision = {
  schema: "cyberpilot.exposure.authorization.decision.v1";
  organizationId: string; domain: string;
  requestDigest: string;
  evidenceDigest: string | null;
  state: ExposureAuthorizationState;
  verifiedAt: string | null;
  verifiedByTrustedCollector: boolean;
  evidenceComplete: boolean;
  challengeMatched: boolean;
  signedExternalApprovalEstablished: false;
  activeScanPermissionGranted: false;
  requiredFollowUp: string[];
  checkedAt: string;
  digest: string;
};
export type ExposureTargetPolicy = {
  schema: "cyberpilot.exposure.target.policy.v1";
  organizationId: string; domain: string;
  verifiedAuthorizationDigest: string;
  observationMode: "PASSIVE_ALLOWLISTED";
  maxDomains: number;
  maxDnsQueries: number;
  maxHttpRequests: number;
  maxRedirects: number;
  maxResponseBytes: number;
  maxDurationMs: number;
  minIntervalMs: number;
  maxConcurrent: number;
  permitPortScanning: false;
  permitSubdomainEnumeration: false;
  allowCredentials: false;
  allowNonPublicAddresses: false;
  directConnectionsAuthorizedByPolicyAlone: false;
  status: "DRY_RUN_REQUIRES_TRUSTED_COLLECTOR";
};
export type ExposureCollectionBudget = {
  organizationId: string;
  authorizationDigest: string;
  domain: string;
  periodStart: string; periodEnd: string;
  usedDns: number;
  usedHttp: number;
  reservations: Array<{
    requestId: string;
    kind: "DNS" | "HTTP" | "TLS";
    estimatedCost: number;
    decision: "ALLOWED_BY_QUOTA" | "DENIED_QUOTA" |
      "DENIED_SCOPE" | "DENIED_CREDENTIALS" |
      "DENIED_PRIVATE_ADDRESS";
    doesNotExecuteRequest: true;
  }>;
  dnsQuota: number;
  httpQuota: number;
  trafficExecuted: 0;
  digest: string;
};
export type ExposureRedirectReview = {
  url: string;
  target: string | null;
  decision: "SAME_AUTHORIZED_ORIGIN" |
    "CROSS_ORIGIN_DENIED" | "SCHEME_DOWNGRADE_DENIED" |
    "PRIVATE_ADDRESS_DENIED" | "INVALID_REDIRECT";
  requiresFreshDNSPinning: true;
  mayFollowAutomatically: false;
  potentialSSRF: boolean;
};
function validId(x: unknown) {
  return typeof x === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
}
function time(x: unknown): x is string {
  return typeof x === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(x) &&
    Number.isFinite(Date.parse(x)) &&
    new Date(x).toISOString() === x;
}
function sha(value: unknown) {
  return sha256V2(canonicalV2(value));
}
export function validateExposureAuthorizationRequest(
  request: ExposureAuthorizationRequest,
) {
  const errors: string[] = [];
  let domain: string | null = null;
  try { domain = normalizeExposureDomain(request.domain); }
  catch { errors.push("INVALID_DOMAIN"); }
  if (!validId(request.organizationId) ||
      !validId(request.issuedBy) ||
      request.schema !==
        "cyberpilot.exposure.domain.authorization.request.v1" ||
      request.purpose !== "PASSIVE_EXTERNAL_OBSERVATION" ||
      request.allowActivePortScanning ||
      request.allowSubdomainEnumeration ||
      request.allowThirdPartyHost)
    errors.push("UNSUPPORTED_AUTHORIZATION_SCOPE");
  if (!["DNS_TOKEN","HTTP_TOKEN"].includes(request.method))
    errors.push("UNSUPPORTED_CHALLENGE_METHOD");
  if (!time(request.issuedAt) || !time(request.expiresAt) ||
      request.issuedAt >= request.expiresAt ||
      Date.parse(request.expiresAt) -
        Date.parse(request.issuedAt) > 24 * 3600000)
    errors.push("INVALID_CHALLENGE_EXPIRY");
  if (typeof request.token !== "string" ||
      !/^[a-f0-9]{64}$/.test(request.token))
    errors.push("INVALID_RANDOM_TOKEN");
  if (domain !== request.domain)
    errors.push("NON_CANONICAL_DOMAIN");
  return {
    valid: errors.length === 0, errors,
    domain, authorizesNetworkProbe: false as const,
    sourceAuthenticityProven: false as const,
  };
}
export function prepareExposureAuthorizationChallenge(
  request: ExposureAuthorizationRequest,
): ExposureAuthorizationChallenge {
  const result = validateExposureAuthorizationRequest(request);
  if (!result.valid)
    throw Error("Invalid Exposure authorization challenge: " +
      result.errors.join(","));
  const expectedName = request.method === "DNS_TOKEN" ?
    "_cyberpilot-verification." + request.domain :
    "https://" + request.domain +
      "/.well-known/cyberpilot-verification";
  const expectedValue = "cyberpilot-domain-verification=" +
    request.token;
  return {
    schema: "cyberpilot.exposure.domain.authorization.challenge.v1",
    organizationId: request.organizationId,
    domain: request.domain, method: request.method,
    challengeDigest: sha256V2(request.organizationId + "\u0000" +
      request.domain + "\u0000" + request.method + "\u0000" +
      request.token),
    expectedName, expectedValue,
    issuedAt: request.issuedAt, expiresAt: request.expiresAt,
    status: "PENDING",
    mayTriggerNetworkScan: false,
    exposesSecretCredential: false,
  };
}
function safeRecord(value: string) {
  return value.length < 4096 &&
    !/[\u0000-\u001f\u007f]/.test(value);
}
function statusReason(evidence: ExposureVerificationEvidence,
  expectedName: string) {
  const reasons: string[] = [];
  if (evidence.collectionStatus !== "COMPLETE")
    reasons.push("DNS/HTTP collection has not completed.");
  if (!evidence.collectorTrusted)
    reasons.push("Evidence was not collected by a trusted provider.");
  if (!evidence.networkOriginVerified)
    reasons.push("Network origin and DNS pinning are unverified.");
  if (evidence.requestedName !== expectedName)
    reasons.push("The requested proof endpoint differs from the challenge.");
  if (evidence.redirectFollowed)
    reasons.push("Redirect-based proof cannot be trusted.");
  if (evidence.pagesRead < 1 ||
      evidence.pagesRead !== evidence.expectedPages)
    reasons.push("Evidence pagination is incomplete.");
  if (evidence.originIp && !isPublicExposureAddress(evidence.originIp))
    reasons.push("Private, reserved or unexpected source address.");
  if (!/^[a-f0-9]{64}$/.test(evidence.recordDigest))
    reasons.push("Observation digest invalid.");
  return reasons;
}
export function evaluateExposureAuthorization(
  request: ExposureAuthorizationRequest,
  evidence: ExposureVerificationEvidence | null,
  checkedAt: string,
): ExposureAuthorizationDecision {
  const valid = validateExposureAuthorizationRequest(request);
  if (!valid.valid || !time(checkedAt))
    throw Error("Unusable authorization request or evaluation timestamp.");
  const challenge = prepareExposureAuthorizationChallenge(request);
  const expired = checkedAt > request.expiresAt;
  const issues: string[] = [];
  let matched = false, complete = false;
  if (!evidence) issues.push("Independent verification evidence is missing.");
  else {
    if (evidence.schema !==
        "cyberpilot.exposure.authorization.evidence.v1" ||
        evidence.organizationId !== request.organizationId ||
        evidence.domain !== request.domain ||
        evidence.method !== request.method ||
        !time(evidence.observedAt) ||
        evidence.observedAt > checkedAt ||
        evidence.observedAt < request.issuedAt ||
        evidence.observedAt > request.expiresAt)
      issues.push("Cross-tenant, stale or invalid proof provenance.");
    issues.push(...statusReason(evidence, challenge.expectedName));
    if (evidence.observedValues.length > 32 ||
        evidence.observedValues.some(x => !safeRecord(x)))
      issues.push("Oversized, malformed proof records.");
    matched = evidence.observedValues.includes(challenge.expectedValue);
    if (!matched) issues.push("The challenge token was not observed.");
    complete = issues.length === 0;
  }
  if (expired) issues.push("Authorization challenge expired.");
  const authorized = complete && matched && !expired;
  const canonical = {
    schema: "cyberpilot.exposure.authorization.decision.v1" as const,
    organizationId: request.organizationId,
    domain: request.domain,
    requestDigest: sha(request),
    evidenceDigest: evidence?.recordDigest ?? null,
    state: expired ? "EXPIRED" as const :
      authorized ? "VERIFIED" as const : "PENDING" as const,
    verifiedAt: authorized ? checkedAt : null,
    verifiedByTrustedCollector: authorized,
    evidenceComplete: complete,
    challengeMatched: matched,
    signedExternalApprovalEstablished: false as const,
    activeScanPermissionGranted: false as const,
    requiredFollowUp: [...new Set(issues)],
    checkedAt,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyExposureAuthorizationDecision(
  decision: ExposureAuthorizationDecision,
  request?: ExposureAuthorizationRequest,
  evidence?: ExposureVerificationEvidence | null,
) {
  const { digest, ...canonical } = decision;
  const issues: string[] = [];
  if (sha(canonical) !== digest)
    issues.push("AUTHORIZATION_DIGEST_MISMATCH");
  if (decision.activeScanPermissionGranted ||
      decision.signedExternalApprovalEstablished)
    issues.push("UNSUPPORTED_ACTIVE_OR_CUSTOMER_APPROVAL");
  if (decision.state === "VERIFIED" &&
      (!decision.verifiedByTrustedCollector ||
       !decision.evidenceComplete ||
       !decision.challengeMatched))
    issues.push("FORGED_VERIFIED_STATE");
  if (request &&
      evaluateExposureAuthorization(request, evidence ?? null,
        decision.checkedAt).digest !== digest)
    issues.push("EVIDENCE_NOT_BOUND_TO_DECISION");
  return { valid: issues.length === 0, issues };
}
export function buildExposureTargetPolicy(
  decision: ExposureAuthorizationDecision,
): ExposureTargetPolicy {
  if (!verifyExposureAuthorizationDecision(decision).valid ||
      decision.state !== "VERIFIED")
    throw Error("A trusted, verified proof is required for collection policy.");
  return {
    schema: "cyberpilot.exposure.target.policy.v1",
    organizationId: decision.organizationId,
    domain: decision.domain,
    verifiedAuthorizationDigest: decision.digest,
    observationMode: "PASSIVE_ALLOWLISTED",
    maxDomains: 1, maxDnsQueries: 18,
    maxHttpRequests: 4,
    maxRedirects: 0, maxResponseBytes: 8192,
    maxDurationMs: 15000, minIntervalMs: 60000,
    maxConcurrent: 1,
    permitPortScanning: false,
    permitSubdomainEnumeration: false,
    allowCredentials: false,
    allowNonPublicAddresses: false,
    directConnectionsAuthorizedByPolicyAlone: false,
    status: "DRY_RUN_REQUIRES_TRUSTED_COLLECTOR",
  };
}
export function inspectExposureRedirect(
  raw: string, location: string,
  authorizedDomain: string,
): ExposureRedirectReview {
  const base = new URL(raw);
  let target: URL | null = null;
  try { target = new URL(location, base); }
  catch { /* preserve unknown target */ }
  const result: ExposureRedirectReview = {
    url: raw, target: target?.href ?? null,
    decision: "INVALID_REDIRECT",
    requiresFreshDNSPinning: true,
    mayFollowAutomatically: false, potentialSSRF: true,
  };
  if (!target || !["http:", "https:"].includes(target.protocol))
    return result;
  if (target.hostname !== authorizedDomain ||
      target.port && target.port !== "443") {
    result.decision = "CROSS_ORIGIN_DENIED";
    return result;
  }
  if (target.protocol !== "https:") {
    result.decision = "SCHEME_DOWNGRADE_DENIED";
    return result;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target.hostname) ||
      target.hostname.includes(":")) {
    result.decision = "PRIVATE_ADDRESS_DENIED";
    return result;
  }
  result.decision = "SAME_AUTHORIZED_ORIGIN";
  result.potentialSSRF = false;
  return result;
}
export function planExposureCollectionQuota(
  policy: ExposureTargetPolicy,
  periodStart: string,
  requests: Array<{
    requestId: string;
    kind: "DNS" | "TLS" | "HTTP";
    target: string;
    resolvedIps: string[];
    hasCredentials: boolean;
  }>,
): ExposureCollectionBudget {
  if (!time(periodStart) || requests.length > 200)
    throw Error("Invalid quota evaluation period or reservation batch.");
  const periodEnd = new Date(Date.parse(periodStart) +
    86400000).toISOString();
  const seen = new Set<string>();
  let usedDns = 0, usedHttp = 0;
  const reservations: ExposureCollectionBudget["reservations"] = [];
  for (const item of requests) {
    if (!validId(item.requestId) || seen.has(item.requestId))
      throw Error("Invalid or duplicate quota request id.");
    seen.add(item.requestId);
    let decision: ExposureCollectionBudget["reservations"][number]["decision"];
    const kind = item.kind;
    const expected = kind === "DNS" ? policy.domain :
      "https://" + policy.domain;
    if (item.hasCredentials)
      decision = "DENIED_CREDENTIALS";
    else if (item.target !== expected ||
        !["DNS","HTTP","TLS"].includes(kind))
      decision = "DENIED_SCOPE";
    else if (item.resolvedIps.length < 1 ||
        item.resolvedIps.length > 32 ||
        item.resolvedIps.some(x => !isPublicExposureAddress(x)))
      decision = "DENIED_PRIVATE_ADDRESS";
    else if (kind === "DNS" && usedDns >= policy.maxDnsQueries ||
        kind !== "DNS" && usedHttp >= policy.maxHttpRequests)
      decision = "DENIED_QUOTA";
    else {
      decision = "ALLOWED_BY_QUOTA";
      if (kind === "DNS") usedDns++;
      else usedHttp++;
    }
    reservations.push({
      requestId: item.requestId, kind,
      estimatedCost: 1, decision,
      doesNotExecuteRequest: true,
    });
  }
  const canonical = {
    organizationId: policy.organizationId,
    authorizationDigest: policy.verifiedAuthorizationDigest,
    domain: policy.domain, periodStart, periodEnd,
    usedDns, usedHttp, reservations,
    dnsQuota: policy.maxDnsQueries,
    httpQuota: policy.maxHttpRequests,
    trafficExecuted: 0 as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyExposureCollectionBudget(
  quota: ExposureCollectionBudget,
) {
  const { digest, ...canonical } = quota;
  const errors: string[] = [];
  if (sha(canonical) !== digest)
    errors.push("BUDGET_DIGEST_INVALID");
  if (quota.usedDns > quota.dnsQuota ||
      quota.usedHttp > quota.httpQuota ||
      quota.trafficExecuted !== 0)
    errors.push("BUDGET_OR_NETWORK_LIMIT_EXCEEDED");
  return { valid: errors.length === 0, errors };
}
