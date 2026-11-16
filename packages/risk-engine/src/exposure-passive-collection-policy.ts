import {
  normalizeExposureDomain, isPublicExposureAddress,
  type ExposureDnsObservation, type ExposureHttpObservation,
  type ExposureTlsObservation,
} from "./exposure-offline-v2";
import { sha256V2 } from "./multisource-v2-history";
import { canonicalV2 } from "./multisource-v2-contract";

/**
 * Passive collection acceptance contract. Every network operation must
 * be preceded by authorization, per-tenant admission and IP pinning.
 * Planning and validation NEVER initiate traffic themselves.
 */
export type PassiveSource = "DNS" | "HTTPS_HEADERS" | "TLS_HANDSHAKE";
export type PassiveProof = {
  organizationId: string;
  domain: string;
  authorizationId: string;
  authorizationRevision: number;
  verificationMethod: "DNS_TOKEN" | "HTTP_TOKEN";
  verifiedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  currentState: "VERIFIED" | "PENDING" | "REVOKED" | "EXPIRED";
  actorUserId: string;
  consentRecordId: string;
  legalConsentIndependentlyVerified: boolean;
};
export type PassiveAdmissionPolicy = {
  schema: "cyberpilot.exposure.passive.admission.v1";
  organizationId: string;
  domain: string;
  sources: PassiveSource[];
  maxDnsQueries: number;
  maxTlsConnections: number;
  maxHttpHeadRequests: number;
  maxTotalRequests: number;
  maxConcurrent: 1;
  maxResponseHeaderBytes: number;
  maxDnsResponseBytes: number;
  maxHandshakeMs: number;
  maxRequestMs: number;
  minimumIntervalMs: number;
  maxDurationMs: number;
  maxAddresses: number;
  expiresAfterMs: number;
  allowRedirectFollowing: false;
  allowCookies: false;
  allowAuthentication: false;
  allowPostPutDelete: false;
  allowSubdomainDiscovery: false;
  allowPortScanning: false;
  allowPrivateAddresses: false;
  requirePinnedAddress: true;
};
export type PassiveCollectorRequest = {
  schema: "cyberpilot.exposure.passive.request.v1";
  organizationId: string;
  domain: string;
  requestId: string;
  actorUserId: string;
  requestedAt: string;
  proof: PassiveProof;
  sources: PassiveSource[];
  allowedDnsNames: string[];
  allowedTlsHostnames: string[];
  allowedHttpUrls: string[];
  policy: PassiveAdmissionPolicy;
  explicitlyOptedIn: boolean;
  tokenInRequest: false;
  credentialsSupplied: false;
  activeScanningRequested: false;
};
export type PassiveDnsAnswer = {
  question: string;
  kind: "TXT" | "MX" | "A" | "AAAA";
  status: "OBSERVED" | "NXDOMAIN" | "TIMEOUT" | "ERROR";
  records: string[];
  resolvedAddresses: string[];
  observedAt: string | null;
  resolverId: string;
  attempts: number;
  elapsedMs: number | null;
  bytesRead: number;
};
export type PassiveTlsAnswer = {
  host: string;
  address: string;
  port: 443;
  status: "OBSERVED" | "TIMEOUT" | "ERROR";
  version: string | null;
  certificatePresent: boolean | null;
  notBefore: string | null;
  notAfter: string | null;
  certificateDnsNames: string[];
  trustedByTLSClient: boolean | null;
  observedAt: string | null;
  elapsedMs: number | null;
  errorCode: string | null;
  verifiedPeerAddress: string | null;
  handshakeOnly: true;
};
export type PassiveHttpAnswer = {
  url: string;
  requestMethod: "HEAD";
  pinnedAddress: string;
  peerAddress: string | null;
  status: "OBSERVED" | "TIMEOUT" | "ERROR";
  statusCode: number | null;
  headers: Array<[string, string]>;
  redirectLocation: string | null;
  responseBodyBytes: 0;
  redirectsFollowed: 0;
  requestBytes: number;
  responseHeaderBytes: number;
  observedAt: string | null;
  durationMs: number | null;
  cookiesSent: false;
  credentialsSent: false;
  verifiedRemotePeer: boolean;
};
export type PassiveCollectionAttempt = {
  requestId: string;
  source: PassiveSource;
  target: string;
  startedAt: string;
  completedAt: string | null;
  result: "OBSERVED" | "TIMEOUT" | "ERROR" |
    "DENIED" | "UNKNOWN";
  denialCode: string | null;
  bytesRead: number;
  pinnedAddresses: string[];
  verifiedPeerAddress: string | null;
  networkCalls: number;
  durableReservationId: string | null;
  evidenceIds: string[];
};
export type PassiveCollectionLedger = {
  schema: "cyberpilot.exposure.passive.ledger.v1";
  organizationId: string;
  domain: string;
  requestId: string;
  authorizationId: string;
  authorizationRevision: number;
  startedAt: string;
  finishedAt: string;
  manifest: {
    requested: PassiveSource[];
    completed: PassiveSource[];
    unknown: PassiveSource[];
    denied: PassiveSource[];
    dnsQueries: number;
    tlsConnections: number;
    httpHeadRequests: number;
    totalNetworkCalls: number;
    noActiveScanning: true;
    noCredentials: true;
    noPostPutDelete: true;
    noRedirectFollow: true;
    allPeersPinned: boolean;
    signedLegalApprovalClaimed: false;
    securityCertified: false;
    historicalCyberScoreUpdated: false;
  };
  dns: ExposureDnsObservation[];
  tls: ExposureTlsObservation[];
  http: ExposureHttpObservation[];
  attempts: PassiveCollectionAttempt[];
  limitations: string[];
  integrityDigest: string;
};
export type AdmissionVerdict = {
  eligible: boolean;
  issues: string[];
  organizationId: string;
  domain: string;
  verifiedAuthorization: boolean;
  technicalOwnershipProof: boolean;
  legalAuthorizationProven: boolean;
  activeScanningPermitted: false;
  plannedCalls: number;
  permittedSources: PassiveSource[];
  expiresAt: string | null;
  recommendedNextStep: string;
};
const iso = (x: string) =>
  typeof x === "string" && /^\d{4}-\d\d-\d\dT/.test(x) &&
  Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const id = (x: string) =>
  typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const unique = <T,>(xs: readonly T[]) => [...new Set(xs)];
const digest = (value: unknown) => sha256V2(canonicalV2(value));
export function defaultPassiveAdmissionPolicy(
  organizationId: string, domain: string,
): PassiveAdmissionPolicy {
  return {
    schema: "cyberpilot.exposure.passive.admission.v1",
    organizationId, domain,
    sources: ["DNS", "HTTPS_HEADERS", "TLS_HANDSHAKE"],
    maxDnsQueries: 8, maxTlsConnections: 1, maxHttpHeadRequests: 1,
    maxTotalRequests: 10, maxConcurrent: 1,
    maxResponseHeaderBytes: 8192, maxDnsResponseBytes: 8192,
    maxHandshakeMs: 4000, maxRequestMs: 4000,
    minimumIntervalMs: 60000, maxDurationMs: 20000,
    maxAddresses: 8, expiresAfterMs: 1800000,
    allowRedirectFollowing: false, allowCookies: false,
    allowAuthentication: false, allowPostPutDelete: false,
    allowSubdomainDiscovery: false, allowPortScanning: false,
    allowPrivateAddresses: false, requirePinnedAddress: true,
  };
}
export function validatePassivePolicy(
  policy: PassiveAdmissionPolicy,
): string[] {
  const issues: string[] = [];
  if (policy.schema !== "cyberpilot.exposure.passive.admission.v1")
    issues.push("POLICY_SCHEMA_INVALID");
  try {
    if (normalizeExposureDomain(policy.domain) !== policy.domain)
      issues.push("DOMAIN_NON_CANONICAL");
  } catch { issues.push("DOMAIN_UNSAFE"); }
  if (!id(policy.organizationId))
    issues.push("ORGANIZATION_INVALID");
  if (!Array.isArray(policy.sources) ||
      unique(policy.sources).length !== policy.sources.length ||
      policy.sources.length === 0 ||
      policy.sources.some(x => ![
        "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS"].includes(x)))
    issues.push("SOURCE_SET_INVALID");
  for (const [name, value, floor, cap] of [
    ["maxDnsQueries", policy.maxDnsQueries, 0, 8],
    ["maxTlsConnections", policy.maxTlsConnections, 0, 1],
    ["maxHttpHeadRequests", policy.maxHttpHeadRequests, 0, 1],
    ["maxTotalRequests", policy.maxTotalRequests, 1, 10],
    ["maxConcurrent", policy.maxConcurrent, 1, 1],
    ["maxResponseHeaderBytes", policy.maxResponseHeaderBytes, 1, 8192],
    ["maxDnsResponseBytes", policy.maxDnsResponseBytes, 1, 8192],
    ["maxHandshakeMs", policy.maxHandshakeMs, 250, 4000],
    ["maxRequestMs", policy.maxRequestMs, 250, 4000],
    ["minimumIntervalMs", policy.minimumIntervalMs, 60000, 86400000],
    ["maxDurationMs", policy.maxDurationMs, 1000, 20000],
    ["maxAddresses", policy.maxAddresses, 1, 8],
    ["expiresAfterMs", policy.expiresAfterMs, 1000, 1800000],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < floor || value > cap)
      issues.push("POLICY_LIMIT_" + name);
  }
  if (policy.allowRedirectFollowing || policy.allowCookies ||
      policy.allowAuthentication || policy.allowPostPutDelete ||
      policy.allowSubdomainDiscovery || policy.allowPortScanning ||
      policy.allowPrivateAddresses || !policy.requirePinnedAddress)
    issues.push("FORBIDDEN_NETWORK_CAPABILITY");
  if (policy.maxDnsQueries + policy.maxTlsConnections +
      policy.maxHttpHeadRequests > policy.maxTotalRequests)
    issues.push("AGGREGATE_QUOTA_INCONSISTENT");
  return unique(issues);
}
export function planPassiveDomainTargets(
  domain: string,
  sources: PassiveSource[],
) {
  if (normalizeExposureDomain(domain) !== domain)
    throw Error("Noncanonical target domain");
  if (unique(sources).length !== sources.length ||
      sources.some(s => ![
        "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS"].includes(s)))
    throw Error("Unsupported or duplicate sources");
  return {
    allowedDnsNames: sources.includes("DNS") ?
      [domain, "_dmarc." + domain] : [],
    allowedTlsHostnames: sources.includes("TLS_HANDSHAKE") ?
      [domain] : [],
    allowedHttpUrls: sources.includes("HTTPS_HEADERS") ?
      ["https://" + domain + "/"] : [],
    enumerationPermitted: false as const,
    extraSubdomainsPermitted: false as const,
    arbitraryPathsPermitted: false as const,
    redirectFollowPermitted: false as const,
  };
}
export function checkPassiveAdmission(
  request: PassiveCollectorRequest,
  currentTime: string,
): AdmissionVerdict {
  const issues: string[] = [];
  const proof = request.proof;
  const policy = request.policy;
  if (request.schema !== "cyberpilot.exposure.passive.request.v1")
    issues.push("REQUEST_SCHEMA_INVALID");
  if (!id(request.organizationId) || !id(request.actorUserId) ||
      !id(request.requestId))
    issues.push("REQUEST_ID_INVALID");
  if (!iso(currentTime) || !iso(request.requestedAt) ||
      request.requestedAt > currentTime)
    issues.push("REQUEST_TIME_INVALID");
  if (!request.explicitlyOptedIn || request.tokenInRequest ||
      request.credentialsSupplied || request.activeScanningRequested)
    issues.push("EXPLICIT_OPT_IN_OR_SECRETS_INVALID");
  if (request.organizationId !== policy.organizationId ||
      request.organizationId !== proof.organizationId ||
      request.domain !== policy.domain || request.domain !== proof.domain ||
      request.actorUserId !== proof.actorUserId)
    issues.push("SCOPE_MISMATCH");
  issues.push(...validatePassivePolicy(policy));
  const listed = planPassiveDomainTargets(policy.domain,
    request.sources);
  if (JSON.stringify(request.allowedDnsNames) !==
      JSON.stringify(listed.allowedDnsNames) ||
      JSON.stringify(request.allowedTlsHostnames) !==
      JSON.stringify(listed.allowedTlsHostnames) ||
      JSON.stringify(request.allowedHttpUrls) !==
      JSON.stringify(listed.allowedHttpUrls))
    issues.push("ARBITRARY_COLLECTION_TARGET");
  if (unique(request.sources).length !== request.sources.length ||
      request.sources.length === 0 ||
      request.sources.some(x => !policy.sources.includes(x)))
    issues.push("SOURCE_NOT_ALLOWED");
  const verifiedAuthorization = proof.currentState === "VERIFIED" &&
    iso(proof.verifiedAt) && iso(proof.expiresAt) &&
    currentTime <= proof.expiresAt &&
    proof.revokedAt === null &&
    id(proof.authorizationId) && id(proof.consentRecordId) &&
    proof.authorizationRevision >= 1 &&
    ["DNS_TOKEN", "HTTP_TOKEN"].includes(proof.verificationMethod);
  if (!verifiedAuthorization)
    issues.push("VERIFIED_NONREVOKED_PROOF_REQUIRED");
  const age = Date.parse(currentTime) - Date.parse(proof.verifiedAt);
  if (!Number.isFinite(age) || age < 0 ||
      age > policy.expiresAfterMs)
    issues.push("PROOF_STALE");
  // Verification of a DNS token is not legal consent to test systems.
  if (!proof.legalConsentIndependentlyVerified)
    issues.push("LEGAL_SCOPE_APPROVAL_NOT_VERIFIED");
  // TXT apex + TXT _dmarc + MX are three DNS operations.
  // Each TLS/HEAD peer pinning requires two additional DNS queries.
  const plannedDns =
    (request.sources.includes("DNS") ? 3 : 0) +
    (request.sources.includes("TLS_HANDSHAKE") ? 2 : 0) +
    (request.sources.includes("HTTPS_HEADERS") ? 2 : 0);
  const plannedCalls = plannedDns +
    Number(request.sources.includes("TLS_HANDSHAKE")) +
    Number(request.sources.includes("HTTPS_HEADERS"));
  if (plannedCalls > policy.maxTotalRequests ||
      plannedDns > policy.maxDnsQueries ||
      Number(request.sources.includes("TLS_HANDSHAKE")) >
        policy.maxTlsConnections ||
      Number(request.sources.includes("HTTPS_HEADERS")) >
        policy.maxHttpHeadRequests)
    issues.push("QUOTA_EXCEEDED");
  return {
    eligible: issues.length === 0,
    issues: unique(issues),
    organizationId: request.organizationId,
    domain: request.domain,
    verifiedAuthorization,
    technicalOwnershipProof: verifiedAuthorization,
    legalAuthorizationProven:
      proof.legalConsentIndependentlyVerified,
    activeScanningPermitted: false,
    plannedCalls,
    permittedSources: issues.length ? [] : request.sources,
    expiresAt: verifiedAuthorization ? proof.expiresAt : null,
    recommendedNextStep: issues.length ?
      "Resolve authorization, consent and scope before collecting." :
      "Reserve durable quota and verify pinned public IPs before each call.",
  };
}
export function inspectPinnedAddresses(
  hostname: string,
  expectedDomain: string,
  before: readonly string[],
  after: readonly string[],
  peerAddress: string | null,
) {
  const issues: string[] = [];
  if (hostname !== expectedDomain)
    issues.push("HOST_OUTSIDE_AUTHORIZED_SCOPE");
  if (!before.length || before.length > 8 ||
      !after.length || after.length > 8)
    issues.push("ADDRESS_SET_INVALID");
  if ([...before, ...after].some(x =>
      !isPublicExposureAddress(x)))
    issues.push("PRIVATE_OR_RESERVED_IP");
  const b = new Set(before), a = new Set(after);
  if (b.size !== before.length || a.size !== after.length)
    issues.push("DUPLICATE_IP");
  if (!before.every(x => a.has(x)) ||
      !after.every(x => b.has(x)))
    issues.push("DNS_REBINDING_DETECTED");
  if (!peerAddress || !b.has(peerAddress) ||
      !a.has(peerAddress))
    issues.push("UNPINNED_SOCKET_PEER");
  return {
    valid: !issues.length, issues,
    hostname, pinned: unique(before).sort(),
    verifiedPeer: !issues.length ? peerAddress : null,
    permitsConnectionByItself: false as const,
    requiresFreshAuthorization: true as const,
  };
}
export function acceptPassiveDnsAnswer(
  request: PassiveCollectorRequest,
  answer: PassiveDnsAnswer,
): ExposureDnsObservation {
  const planned = planPassiveDomainTargets(
    request.domain, request.sources);
  if (!planned.allowedDnsNames.includes(answer.question) ||
      !["TXT", "MX", "A", "AAAA"].includes(answer.kind) ||
      !["OBSERVED", "NXDOMAIN", "TIMEOUT", "ERROR"].includes(
        answer.status) || answer.attempts !== 1 ||
      answer.records.length > 30 ||
      answer.bytesRead > request.policy.maxDnsResponseBytes ||
      answer.records.some(x => typeof x !== "string" ||
        x.length > 4096 || /[\u0000-\u001f\u007f]/.test(x)) ||
      answer.resolvedAddresses.some(x =>
        !isPublicExposureAddress(x)) ||
      answer.observedAt &&
        (!iso(answer.observedAt) ||
         answer.observedAt < request.requestedAt))
    throw Error("Out-of-scope, non-public or malformed passive DNS");
  const kind: ExposureDnsObservation["kind"] =
    answer.kind === "MX" ? "MX" :
      answer.question.startsWith("_dmarc.") ? "DMARC" : "SPF";
  return {
    id: "dns-" + sha256V2(
      request.requestId + ":" + answer.kind + ":" +
      answer.question).slice(0, 32),
    kind,
    status: answer.status,
    queriedName: answer.question,
    records: answer.records,
    collectedAt: answer.observedAt,
    elapsedMs: answer.elapsedMs,
    resolver: answer.resolverId.slice(0, 80),
    observedFromAuthorizedScope: true,
    queriedExternalNames: [],
  };
}
export function acceptPassiveTlsAnswer(
  request: PassiveCollectorRequest,
  answer: PassiveTlsAnswer,
  before: string[], after: string[],
): ExposureTlsObservation {
  if (!request.sources.includes("TLS_HANDSHAKE") ||
      answer.host !== request.domain || answer.port !== 443 ||
      !["OBSERVED", "TIMEOUT", "ERROR"].includes(answer.status) ||
      !answer.handshakeOnly ||
      answer.certificateDnsNames.length > 24 ||
      answer.certificateDnsNames.some(x => x.length > 253) ||
      answer.observedAt &&
        (!iso(answer.observedAt) ||
         answer.observedAt < request.requestedAt))
    throw Error("Invalid passive TLS collection");
  const pinned = inspectPinnedAddresses(answer.host,
    request.domain, before, after, answer.verifiedPeerAddress);
  if (!pinned.valid || answer.address !== answer.verifiedPeerAddress)
    throw Error("TLS peer address was not independently pinned");
  return {
    id: "tls-" + sha256V2(
      request.requestId + ":" + answer.host).slice(0, 32),
    status: answer.status, hostname: answer.host, port: 443,
    collectedAt: answer.observedAt,
    negotiatedProtocol: answer.version,
    certificatePresent: answer.certificatePresent,
    certificateNotBefore: answer.notBefore,
    certificateNotAfter: answer.notAfter,
    certificateDnsNames: answer.certificateDnsNames,
    validatedByTrustedCA: answer.trustedByTLSClient,
    handshakeError: answer.errorCode?.slice(0, 100) ?? null,
    remoteAddress: answer.verifiedPeerAddress,
  };
}
export function acceptPassiveHttpAnswer(
  request: PassiveCollectorRequest,
  answer: PassiveHttpAnswer,
  before: string[], after: string[],
): ExposureHttpObservation {
  if (!request.sources.includes("HTTPS_HEADERS") ||
      answer.url !== "https://" + request.domain + "/" ||
      answer.requestMethod !== "HEAD" ||
      answer.responseBodyBytes !== 0 ||
      answer.redirectsFollowed !== 0 ||
      answer.cookiesSent || answer.credentialsSent ||
      !answer.verifiedRemotePeer ||
      answer.responseHeaderBytes > request.policy.maxResponseHeaderBytes ||
      answer.requestBytes > 4096 ||
      answer.headers.length > 64 ||
      answer.headers.some(([name, value]) =>
        name.length > 128 || value.length > 4096 ||
        /[\u0000-\u001f\u007f]/.test(name)) ||
      answer.observedAt &&
        (!iso(answer.observedAt) ||
         answer.observedAt < request.requestedAt))
    throw Error("Unauthorized or oversized passive HTTP response");
  const pin = inspectPinnedAddresses(request.domain,
    request.domain, before, after, answer.peerAddress);
  if (!pin.valid || !answer.pinnedAddress ||
      answer.pinnedAddress !== answer.peerAddress)
    throw Error("HTTP response not bound to pinned socket");
  return {
    id: "http-" + sha256V2(
      request.requestId + ":" + answer.url).slice(0, 32),
    status: answer.status, url: answer.url,
    collectedAt: answer.observedAt,
    statusCode: answer.statusCode,
    headers: answer.headers,
    redirectLocation: answer.redirectLocation,
    resolvedAddresses: [...before],
    finalAddress: answer.peerAddress,
    attempts: 1,
    durationMs: answer.durationMs,
    bodyCollected: false,
  };
}
export function finalizePassiveLedger(
  request: PassiveCollectorRequest,
  attempts: PassiveCollectionAttempt[],
  dns: ExposureDnsObservation[],
  tls: ExposureTlsObservation[],
  http: ExposureHttpObservation[],
  finishedAt: string,
): PassiveCollectionLedger {
  if (!iso(finishedAt) || finishedAt < request.requestedAt ||
      attempts.some(x => x.requestId !== request.requestId ||
        x.networkCalls > 1 || x.networkCalls < 0 ||
        x.startedAt > finishedAt) ||
      attempts.length > request.policy.maxTotalRequests)
    throw Error("Invalid collection activity ledger");
  const count = (s: PassiveSource) => attempts.filter(x =>
    x.source === s).reduce((v, x) => v + x.networkCalls, 0);
  const dnsQueries = count("DNS");
  const tlsConnections = count("TLS_HANDSHAKE");
  const httpHeadRequests = count("HTTPS_HEADERS");
  const totalNetworkCalls = dnsQueries + tlsConnections + httpHeadRequests;
  if (dnsQueries > request.policy.maxDnsQueries ||
      tlsConnections > request.policy.maxTlsConnections ||
      httpHeadRequests > request.policy.maxHttpHeadRequests ||
      totalNetworkCalls > request.policy.maxTotalRequests)
    throw Error("Passive collection exceeded agreed quota");
  const completed = unique(attempts.filter(x =>
    x.result === "OBSERVED").map(x => x.source));
  const denied = unique(attempts.filter(x =>
    x.result === "DENIED").map(x => x.source));
  const unknown = unique(request.sources.filter(x =>
    !completed.includes(x)));
  const allPeersPinned = attempts.filter(x =>
    x.source !== "DNS" && x.networkCalls > 0).every(x =>
    x.verifiedPeerAddress !== null &&
    x.pinnedAddresses.includes(x.verifiedPeerAddress));
  const canonical = {
    schema: "cyberpilot.exposure.passive.ledger.v1" as const,
    organizationId: request.organizationId,
    domain: request.domain, requestId: request.requestId,
    authorizationId: request.proof.authorizationId,
    authorizationRevision: request.proof.authorizationRevision,
    startedAt: request.requestedAt, finishedAt,
    manifest: {
      requested: request.sources,
      completed, unknown, denied,
      dnsQueries, tlsConnections, httpHeadRequests,
      totalNetworkCalls,
      noActiveScanning: true as const,
      noCredentials: true as const,
      noPostPutDelete: true as const,
      noRedirectFollow: true as const,
      allPeersPinned,
      signedLegalApprovalClaimed: false as const,
      securityCertified: false as const,
      historicalCyberScoreUpdated: false as const,
    },
    dns, tls, http, attempts,
    limitations: [
      "A single passive collection does not certify overall security.",
      "A domain proof is not the same as independently validated legal consent.",
      "Uncollected, denied and failed sources remain UNKNOWN.",
      "Results are local technical observations requiring separate review.",
      "No active scanning, write, redirected requests or remediation.",
    ],
  };
  return { ...canonical, integrityDigest: digest(canonical) };
}
export function verifyPassiveLedger(
  ledger: PassiveCollectionLedger,
  expectedTenant?: string,
) {
  const { integrityDigest, ...canonical } = ledger;
  const errors: string[] = [];
  if (digest(canonical) !== integrityDigest)
    errors.push("LEDGER_DIGEST_INVALID");
  if (expectedTenant && ledger.organizationId !== expectedTenant)
    errors.push("CROSS_TENANT_LEDGER");
  if (!ledger.manifest.allPeersPinned ||
      !ledger.manifest.noActiveScanning ||
      !ledger.manifest.noRedirectFollow ||
      !ledger.manifest.noCredentials ||
      !ledger.manifest.noPostPutDelete ||
      ledger.manifest.signedLegalApprovalClaimed ||
      ledger.manifest.securityCertified ||
      ledger.manifest.historicalCyberScoreUpdated)
    errors.push("INCONSISTENT_SECURITY_CLAIMS");
  if (ledger.attempts.some(x =>
    x.source === "DNS" && x.verifiedPeerAddress ||
    x.networkCalls > 1))
    errors.push("UNEXPECTED_COLLECTOR_ACTIVITY");
  return { valid: errors.length === 0, errors,
    externalLegalAuthorizationVerifiedByLedger: false as const };
}
export function comparePassiveLedgers(
  older: PassiveCollectionLedger,
  newer: PassiveCollectionLedger,
) {
  if (!verifyPassiveLedger(older).valid ||
      !verifyPassiveLedger(newer).valid ||
      older.organizationId !== newer.organizationId ||
      older.domain !== newer.domain ||
      older.finishedAt >= newer.finishedAt)
    throw Error("Cross-tenant, tampered or reverse-time collection comparison");
  const oldKeys = new Set(older.attempts.filter(x =>
    x.result === "OBSERVED").map(x => x.source + ":" + x.target));
  const newKeys = new Set(newer.attempts.filter(x =>
    x.result === "OBSERVED").map(x => x.source + ":" + x.target));
  return {
    organizationId: newer.organizationId,
    domain: newer.domain, before: older.requestId,
    after: newer.requestId,
    newObservations: [...newKeys].filter(x => !oldKeys.has(x)),
    missingObservations: [...oldKeys].filter(x => !newKeys.has(x)),
    trafficDelta: newer.manifest.totalNetworkCalls -
      older.manifest.totalNetworkCalls,
    riskReductionProven: false as const,
    securityCertificationProduced: false as const,
  };
}
