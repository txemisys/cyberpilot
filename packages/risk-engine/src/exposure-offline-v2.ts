import { sha256V2 } from "./multisource-v2-history";
import { canonicalV2 } from "./multisource-v2-contract";
import { inventorySpfTxtRecords, extractSpfAllQualifier,
  extractSpfIncludes, extractSpfRedirect } from "./exposure-spf";
import { inventoryDmarcTxtRecords, extractDmarcPolicy,
  extractDmarcPercentage, extractDmarcAlignment } from "./exposure-dmarc";
import { inventoryDkimTxtRecords } from "./exposure-dkim";
import { inventoryHttpSecurityHeaders } from "./exposure-http";
import { tlsNameMatches } from "./exposure-tls-names";
import { inspectRedirect,
  inventoryResponseHeaders } from "./exposure-http-observation";

/** Fully offline authorized-domain observation. No DNS/fetch/HTTP I/O. */
export type ExposureProbeStatus =
  "OBSERVED" | "NXDOMAIN" | "TIMEOUT" | "ERROR" |
  "DENIED" | "NOT_COLLECTED" | "PARTIAL";
export type ExposureProtocol = "DNS" | "TLS" | "HTTP";
export type ExposureControl =
  "DOMAIN_OWNERSHIP" | "EMAIL_SPF" | "EMAIL_DMARC" |
  "EMAIL_DKIM" | "WEB_TLS" | "WEB_SECURITY_HEADERS" |
  "WEB_REDIRECT";
export type ExposureSeverity =
  "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ExposureFinding = {
  id: string; control: ExposureControl;
  severity: ExposureSeverity;
  status: "POTENTIAL_RISK" | "REQUIRES_REVIEW" | "UNKNOWN";
  title: string; rationale: string; recommendation: string;
  sourceIds: string[]; observedAt: string;
  verifiedByExternalAuthority: false;
  automaticallyRemediated: false;
};
export type ExposureAuthorization = {
  schema: "cyberpilot.exposure.authorization.v2";
  organizationId: string;
  domain: string;
  purpose: "PASSIVE_ASSESSMENT";
  verificationMethod: "DNS_TOKEN" | "HTTP_TOKEN" | "DECLARATION";
  verified: boolean;
  verifiedAt: string | null;
  expiresAt: string | null;
  challengeDigest: string | null;
  collectorIdentity: string;
  consentRecordId: string;
  canPerformActiveScanning: false;
  externalOwnershipIndependentlyVerified: boolean;
};
export type ExposureDnsObservation = {
  id: string; kind: "SPF" | "DMARC" | "DKIM" | "MX";
  status: ExposureProbeStatus;
  queriedName: string; records: string[];
  collectedAt: string | null;
  elapsedMs: number | null;
  resolver: string;
  observedFromAuthorizedScope: boolean;
  queriedExternalNames: string[];
};
export type ExposureTlsObservation = {
  id: string; status: ExposureProbeStatus;
  hostname: string; port: 443;
  collectedAt: string | null;
  negotiatedProtocol: string | null;
  certificatePresent: boolean | null;
  certificateNotBefore: string | null;
  certificateNotAfter: string | null;
  certificateDnsNames: string[];
  validatedByTrustedCA: boolean | null;
  handshakeError: string | null;
  remoteAddress: string | null;
};
export type ExposureHttpObservation = {
  id: string; status: ExposureProbeStatus;
  url: string;
  collectedAt: string | null;
  statusCode: number | null;
  headers: Array<[string, string]>;
  redirectLocation: string | null;
  resolvedAddresses: string[];
  finalAddress: string | null;
  attempts: number;
  durationMs: number | null;
  bodyCollected: false;
};
export type ExposureOfflineEnvelope = {
  schema: "cyberpilot.exposure.offline.v2";
  organizationId: string;
  snapshotId: string;
  domain: string;
  assessedAt: string;
  authorization: ExposureAuthorization;
  dns: ExposureDnsObservation[];
  tls: ExposureTlsObservation[];
  http: ExposureHttpObservation[];
  collectionMode: "IMPORTED_PASSIVE_EVIDENCE";
  networkRequestsByEvaluator: 0;
  dynamicLookupsByEvaluator: 0;
  thirdPartyScanningAuthorized: false;
  sourceIsSynthetic: boolean;
  claimsVerifiedProductionSecurity: false;
};
export type ExposureCheck = {
  control: ExposureControl;
  state: "OBSERVED" | "UNKNOWN" | "ERROR" |
    "CONFLICT" | "OUT_OF_SCOPE" | "STALE";
  interpretation: "RISK" | "REQUIRES_REVIEW" |
    "NOT_DETERMINED" | "CONFIGURATION_OBSERVED";
  coverage: "COMPLETE" | "PARTIAL" | "UNASSESSED";
  sourceIds: string[];
  findings: ExposureFinding[];
  details: Record<string, string | number | boolean | null>;
  explanations: string[];
  observedAt: string | null;
  independentlyVerified: false;
};
export type ExposureAssessment = {
  schema: "cyberpilot.exposure.assessment.v2";
  organizationId: string;
  snapshotId: string;
  domain: string;
  assessedAt: string;
  authorization: {
    status: "VERIFIED" | "DECLARED" | "EXPIRED" |
      "UNVERIFIED";
    activeProbesAllowed: false;
    sourceOwnerIndependentlyVerified: boolean;
  };
  checks: ExposureCheck[];
  findings: ExposureFinding[];
  coverage: {
    totalControls: number;
    observedControls: number;
    unknownControls: number;
    errorControls: number;
    coveragePercent: number;
    scoreEligible: false;
    healthyClaimAllowed: false;
  };
  limitations: string[];
  source: "OFFLINE_IMPORTED_PASSIVE";
  trafficGenerated: 0;
  tenantIsolationPreserved: true;
  customerComplianceCertified: false;
  historicalCyberScoreModified: false;
  digest: string;
};
export type ExposureValidation = {
  valid: boolean; errors: string[];
  warnings: string[];
  evidenceCount: number;
  foreignScopeDenied: boolean;
  networkRequestsPerformed: 0;
};
const MAX_OBSERVATIONS = 256;
const MAX_RECORDS = 100;
const MAX_NAME = 253;
function time(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/
      .test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}
export function normalizeExposureDomain(raw: string): string {
  if (typeof raw !== "string") throw Error("DOMAIN_NOT_STRING");
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  if (value.length < 4 || value.length > MAX_NAME ||
      value.includes("..") || !value.includes(".") ||
      /^\d+\.\d+\.\d+\.\d+$/.test(value) ||
      value.includes(":") ||
      value.split(".").some(label => label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)))
    throw Error("DOMAIN_INVALID_OR_PRIVATE_TARGET");
  const suffix = value.split(".").at(-1)!;
  if (["local", "localhost", "internal", "invalid", "test"].includes(suffix))
    throw Error("DOMAIN_RESERVED_OR_INTERNAL");
  return value;
}
function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some(x =>
    !/^\d{1,3}$/.test(x) || +x > 255))
    return true;
  const [a, b, c, d] = parts.map(Number) as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 ||
      a === 192 && b === 168 ||
      a === 100 && b >= 64 && b <= 127 ||
      a === 192 && b === 0 && c === 0 ||
      a === 198 && (b === 18 || b === 19) ||
      a === 192 && b === 0 && c === 2 ||
      a === 198 && b === 51 && c === 100 ||
      a === 203 && b === 0 && c === 113 ||
      a === 255 || d === undefined)
    return true;
  return false;
}
export function isPublicExposureAddress(raw: string): boolean {
  if (typeof raw !== "string" || !raw ||
      raw.includes("%") || raw.includes("/"))
    return false;
  if (raw.includes(".")) return !isPrivateIpv4(raw);
  // IPv6: refuse unspecified, local, mapped and documentation ranges;
  // this heuristic is conservative and does not itself authorize traffic.
  if (!/^[a-fA-F0-9:]+$/.test(raw) || !raw.includes(":"))
    return false;
  const normalized = raw.toLowerCase();
  return !/^(:|0{0,4}:)*(:|0{0,4})$/.test(normalized) &&
    !normalized.startsWith("fe8") &&
    !normalized.startsWith("fe9") &&
    !normalized.startsWith("fea") &&
    !normalized.startsWith("feb") &&
    !normalized.startsWith("fc") &&
    !normalized.startsWith("fd") &&
    !normalized.startsWith("ff") &&
    normalized !== "::1" &&
    !normalized.startsWith("2001:db8");
}
export function validateExposureTargetAddresses(
  addresses: readonly string[],
) {
  const entries = [...new Set(addresses)];
  return {
    valid: entries.length > 0 && entries.length <= 32 &&
      entries.every(isPublicExposureAddress),
    uniqueAddresses: entries,
    privateOrUntrusted: entries.filter(x =>
      !isPublicExposureAddress(x)),
    mayConnect: false as const,
  };
}
function validText(value: unknown, max = 512) {
  return typeof value === "string" &&
    value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value);
}
function authorizationStatus(a: ExposureAuthorization,
  at: string): ExposureAssessment["authorization"]["status"] {
  if (a.verificationMethod === "DECLARATION")
    return "DECLARED";
  if (!a.verified || !a.verifiedAt) return "UNVERIFIED";
  if (a.expiresAt && a.expiresAt < at) return "EXPIRED";
  return "VERIFIED";
}
export function validateExposureOfflineEnvelope(
  input: ExposureOfflineEnvelope,
): ExposureValidation {
  const errors: string[] = [], warnings: string[] = [];
  let domain = "";
  try { domain = normalizeExposureDomain(input.domain); }
  catch { errors.push("INVALID_DOMAIN"); }
  const a = input.authorization;
  if (input.schema !== "cyberpilot.exposure.offline.v2" ||
      !validText(input.organizationId, 128) ||
      !validText(input.snapshotId, 128) ||
      !time(input.assessedAt))
    errors.push("INVALID_ENVELOPE_IDENTITY");
  if (!a || a.schema !== "cyberpilot.exposure.authorization.v2" ||
      a.organizationId !== input.organizationId ||
      a.domain !== domain ||
      a.purpose !== "PASSIVE_ASSESSMENT" ||
      a.canPerformActiveScanning !== false ||
      !validText(a.collectorIdentity, 128) ||
      !validText(a.consentRecordId, 128))
    errors.push("UNAUTHORIZED_OR_CROSS_TENANT_SCOPE");
  if (input.collectionMode !== "IMPORTED_PASSIVE_EVIDENCE" ||
      input.networkRequestsByEvaluator !== 0 ||
      input.dynamicLookupsByEvaluator !== 0 ||
      input.thirdPartyScanningAuthorized ||
      input.claimsVerifiedProductionSecurity)
    errors.push("ACTIVE_OR_FALSE_ASSURANCE_CLAIM");
  if (!Array.isArray(input.dns) ||
      !Array.isArray(input.tls) ||
      !Array.isArray(input.http) ||
      input.dns.length + input.tls.length + input.http.length > MAX_OBSERVATIONS)
    errors.push("OBSERVATION_LIMIT");
  const ids = new Set<string>();
  for (const item of [...input.dns, ...input.tls, ...input.http]) {
    if (!validText(item.id, 128) || ids.has(item.id))
      errors.push("DUPLICATE_OR_INVALID_SOURCE_ID");
    ids.add(item.id);
    if (!["OBSERVED", "NXDOMAIN", "TIMEOUT", "ERROR",
      "DENIED", "NOT_COLLECTED", "PARTIAL"].includes(item.status))
      errors.push("INVALID_PROBE_STATUS");
    if (item.status === "OBSERVED" &&
        (!item.collectedAt || !time(item.collectedAt) ||
         item.collectedAt > input.assessedAt))
      errors.push("OBSERVATION_NOT_TIMESTAMPED");
    if (item.status !== "OBSERVED")
      warnings.push("Some source probes were unavailable or partial.");
    if (item.collectedAt !== null &&
        (!time(item.collectedAt) ||
         item.collectedAt > input.assessedAt))
      errors.push("INVALID_SOURCE_TIMESTAMP");
  }
  for (const item of input.dns) {
    if (!["SPF", "DMARC", "DKIM", "MX"].includes(item.kind) ||
        item.records.length > MAX_RECORDS ||
        item.records.some(x => typeof x !== "string" || x.length > 4096) ||
        !validText(item.resolver, 128) ||
        !validText(item.queriedName, 253) ||
        !item.observedFromAuthorizedScope ||
        item.queriedExternalNames.length > 32)
      errors.push("DNS_PROVENANCE_INVALID");
    if (item.queriedExternalNames.length)
      warnings.push("External DNS dependencies have not been followed.");
  }
  for (const item of input.tls) {
    if (item.hostname !== domain || item.port !== 443 ||
        item.certificateDnsNames.length > 100 ||
        item.remoteAddress !== null &&
          !isPublicExposureAddress(item.remoteAddress) ||
        item.certificateNotBefore !== null &&
          !time(item.certificateNotBefore) ||
        item.certificateNotAfter !== null &&
          !time(item.certificateNotAfter))
      errors.push("TLS_SCOPE_OR_ADDRESS_INVALID");
  }
  for (const item of input.http) {
    let parsed: URL | null = null;
    try { parsed = new URL(item.url); } catch { /* fail */ }
    if (!parsed || parsed.protocol !== "https:" ||
        parsed.hostname !== domain ||
        parsed.port && parsed.port !== "443" ||
        item.bodyCollected ||
        item.attempts < 0 || item.attempts > 5 ||
        item.headers.length > MAX_RECORDS ||
        !validateExposureTargetAddresses(
          item.resolvedAddresses).valid &&
          item.status === "OBSERVED" ||
        item.finalAddress !== null &&
          (!isPublicExposureAddress(item.finalAddress) ||
           !item.resolvedAddresses.includes(item.finalAddress)))
      errors.push("HTTP_SCOPE_OR_ADDRESS_INVALID");
  }
  if (a && authorizationStatus(a, input.assessedAt) !== "VERIFIED")
    warnings.push("Independent authorized ownership is not established.");
  return {
    valid: errors.length === 0, errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
    evidenceCount: input.dns.length + input.tls.length +
      input.http.length, foreignScopeDenied: errors.includes(
        "UNAUTHORIZED_OR_CROSS_TENANT_SCOPE"),
    networkRequestsPerformed: 0,
  };
}
function check(
  control: ExposureControl, input: ExposureOfflineEnvelope,
  sources: Array<ExposureDnsObservation | ExposureTlsObservation |
    ExposureHttpObservation>,
  interpretation: ExposureCheck["interpretation"],
  details: ExposureCheck["details"],
  explanation: string[],
  risky?: { severity: ExposureSeverity; title: string;
    recommendation: string },
): ExposureCheck {
  const observed = sources.filter(s => s.status === "OBSERVED");
  const error = sources.some(s =>
    ["ERROR", "TIMEOUT", "DENIED", "NXDOMAIN"].includes(s.status));
  const allObserved = sources.length > 0 &&
    observed.length === sources.length;
  const stale = observed.some(s =>
    s.collectedAt && Date.parse(input.assessedAt) -
      Date.parse(s.collectedAt) > 30 * 86400000);
  const state: ExposureCheck["state"] = stale ? "STALE" :
    error ? "ERROR" : allObserved ? "OBSERVED" : "UNKNOWN";
  const coverage: ExposureCheck["coverage"] =
    state === "OBSERVED" ? "COMPLETE" :
    observed.length ? "PARTIAL" : "UNASSESSED";
  const findings: ExposureFinding[] = risky && state === "OBSERVED" ?
    [{
      id: "exposure-" + sha256V2(input.organizationId +
        input.snapshotId + control + risky.title).slice(0, 24),
      control, severity: risky.severity,
      status: "POTENTIAL_RISK", title: risky.title,
      rationale: explanation.join(" "),
      recommendation: risky.recommendation,
      sourceIds: sources.map(s => s.id),
      observedAt: input.assessedAt,
      verifiedByExternalAuthority: false,
      automaticallyRemediated: false,
    }] : [];
  return {
    control, state, interpretation:
      state === "OBSERVED" ? interpretation :
        state === "ERROR" ? "REQUIRES_REVIEW" : "NOT_DETERMINED",
    coverage, sourceIds: sources.map(s => s.id),
    findings, details, explanations: explanation,
    observedAt: observed[0]?.collectedAt ?? null,
    independentlyVerified: false,
  };
}
function matchDns(input: ExposureOfflineEnvelope,
  kind: ExposureDnsObservation["kind"]) {
  return input.dns.filter(x => x.kind === kind);
}
function collectDns(
  input: ExposureOfflineEnvelope,
  kind: ExposureDnsObservation["kind"],
  control: ExposureControl,
): ExposureCheck {
  const matches = matchDns(input, kind);
  const observed = matches.filter(x => x.status === "OBSERVED");
  const all = observed.flatMap(x => x.records);
  const conflict = observed.length > 1;
  let interpretation: ExposureCheck["interpretation"] =
    "NOT_DETERMINED";
  const details: ExposureCheck["details"] = {
    recordCount: all.length,
    sourceCount: matches.length,
  };
  const explanation: string[] = [];
  let risky: { severity: ExposureSeverity; title: string;
    recommendation: string } | undefined;
  if (kind === "SPF" && observed.length === 1) {
    const inv = inventorySpfTxtRecords(all);
    const allQualifier = extractSpfAllQualifier(all);
    details.spfStatus = inv.status;
    details.allQualifier = allQualifier;
    details.includes = extractSpfIncludes(all)?.length ?? null;
    details.redirect = extractSpfRedirect(all);
    if (inv.status === "MISSING") {
      interpretation = "RISK";
      risky = { severity: "MEDIUM", title: "No SPF record observed",
        recommendation: "Confirm authorized senders and publish SPF if applicable." };
    } else if (inv.status === "MULTIPLE") {
      interpretation = "RISK";
      risky = { severity: "HIGH", title: "Multiple SPF policies",
        recommendation: "Consolidate SPF to one valid policy." };
    } else if (allQualifier === "pass" || allQualifier === "neutral") {
      interpretation = "REQUIRES_REVIEW";
      risky = { severity: "LOW", title: "Permissive SPF all mechanism",
        recommendation: "Review sender inventories before tightening SPF." };
    } else interpretation = "CONFIGURATION_OBSERVED";
    explanation.push("SPF TXT interpreted from supplied DNS evidence only.");
  } else if (kind === "DMARC" && observed.length === 1) {
    const inv = inventoryDmarcTxtRecords(all);
    const policy = extractDmarcPolicy(all);
    details.dmarcStatus = inv.status;
    details.policy = policy;
    details.pct = extractDmarcPercentage(all);
    details.aspf = extractDmarcAlignment(all, "aspf");
    details.adkim = extractDmarcAlignment(all, "adkim");
    if (inv.status === "MISSING") {
      interpretation = "RISK";
      risky = { severity: "MEDIUM", title: "No DMARC policy observed",
        recommendation: "Evaluate SPF/DKIM alignment and deploy DMARC." };
    } else if (inv.status === "MULTIPLE" || policy === null) {
      interpretation = "REQUIRES_REVIEW";
      risky = { severity: "HIGH", title: "Ambiguous DMARC configuration",
        recommendation: "Validate and resolve conflicting DMARC TXT policies." };
    } else if (policy === "none") {
      interpretation = "REQUIRES_REVIEW";
      risky = { severity: "MEDIUM", title: "DMARC monitor-only policy",
        recommendation: "Review authentication alignment and enforcement readiness." };
    } else interpretation = "CONFIGURATION_OBSERVED";
    explanation.push("DMARC observation does not prove email authentication success.");
  } else if (kind === "DKIM" && observed.length === 1) {
    const inv = inventoryDkimTxtRecords(all);
    details.dkimStatus = inv.status;
    interpretation = "CONFIGURATION_OBSERVED";
    explanation.push("Only the queried DKIM selector is observable; unqueried selectors are UNKNOWN.");
  } else {
    explanation.push("No single unambiguous DNS observation is available.");
  }
  const base = check(control, input, matches, interpretation, details,
    explanation, risky);
  if (conflict) return {
    ...base, state: "CONFLICT", coverage: "PARTIAL",
    interpretation: "REQUIRES_REVIEW", findings: [],
    explanations: [...base.explanations, "Multiple independent DNS snapshots conflict."],
  };
  return base;
}
function evaluateTls(input: ExposureOfflineEnvelope): ExposureCheck {
  const observations = input.tls;
  const observed = observations.filter(x => x.status === "OBSERVED");
  const main = observed[0];
  const details: ExposureCheck["details"] = {
    certificatePresent: main?.certificatePresent ?? null,
    caTrusted: main?.validatedByTrustedCA ?? null,
    protocol: main?.negotiatedProtocol ?? null,
  };
  let risky: { severity: ExposureSeverity; title: string;
    recommendation: string } | undefined;
  const explanations: string[] = [];
  let interpretation: ExposureCheck["interpretation"] =
    "NOT_DETERMINED";
  if (main) {
    const hostnameMatched = tlsNameMatches(
      main.hostname, main.certificateDnsNames);
    details.hostnameMatched = hostnameMatched;
    if (main.certificatePresent === false ||
        main.validatedByTrustedCA === false ||
        hostnameMatched === "NO_MATCH") {
      interpretation = "RISK";
      risky = { severity: "HIGH",
        title: "TLS trust or certificate invalid",
        recommendation: "Review the certificate chain and server identity." };
    } else if (main.certificateNotAfter &&
        main.certificateNotAfter < input.assessedAt) {
      interpretation = "RISK";
      risky = { severity: "HIGH", title: "TLS certificate expired",
        recommendation: "Renew the expired TLS certificate." };
    } else if (!main.negotiatedProtocol || !main.certificatePresent) {
      interpretation = "REQUIRES_REVIEW";
    } else interpretation = "CONFIGURATION_OBSERVED";
    explanations.push("Passive TLS metadata cannot establish browser-wide safety.");
  }
  const base = check("WEB_TLS", input, observations,
    interpretation, details, explanations, risky);
  if (observed.length > 1) return {
    ...base, state: "CONFLICT", coverage: "PARTIAL",
    interpretation: "REQUIRES_REVIEW", findings: [],
    explanations: [...explanations, "Multiple TLS observations require reconciliation."],
  };
  return base;
}
function evaluateHttp(input: ExposureOfflineEnvelope):
  [ExposureCheck, ExposureCheck] {
  const observations = input.http;
  const observed = observations.filter(x => x.status === "OBSERVED");
  const main = observed[0];
  const headers = main ? inventoryResponseHeaders(main.headers) : null;
  const security = main ? inventoryHttpSecurityHeaders(
    Object.fromEntries(main.headers)) : null;
  const findings: string[] = [];
  if (headers?.state === "COLLECTED" &&
      !headers.names.includes("strict-transport-security"))
    findings.push("HSTS header is not present in supplied response.");
  const h = check("WEB_SECURITY_HEADERS", input, observations,
    findings.length ? "REQUIRES_REVIEW" : "CONFIGURATION_OBSERVED",
    { headerCount: headers?.names.length ?? null,
      observedSecurityHeaders: security ? Object.keys(security).length : null,
      missingHsts: !!findings.length },
    findings.length ? findings :
      ["Response security headers were inventoried without security certification."],
    findings.length ? { severity: "LOW",
      title: "HSTS not observed",
      recommendation: "Review TLS-only deployment before publishing HSTS." } : undefined);
  const redirect = main ? inspectRedirect({
    url: main.url, status: main.statusCode,
    location: main.redirectLocation,
    headers: main.headers,
  }) : null;
  const downgrade = redirect?.downgrade === true;
  const r = check("WEB_REDIRECT", input, observations,
    downgrade ? "RISK" : "CONFIGURATION_OBSERVED",
    { redirectStatus: redirect?.state ?? null,
      redirectsAcrossOrigins: redirect?.crossOrigin ?? null,
      downgrade: redirect?.downgrade ?? null },
    downgrade ? ["HTTPS redirect downgrades to HTTP."] :
      ["No redirect downgrade established from the supplied response."],
    downgrade ? { severity: "HIGH",
      title: "HTTPS downgrade redirect",
      recommendation: "Keep authenticated application redirects on HTTPS." } : undefined);
  return [h, r];
}
export function assessExposureOffline(
  input: ExposureOfflineEnvelope,
): ExposureAssessment {
  const validation = validateExposureOfflineEnvelope(input);
  if (!validation.valid)
    throw Error("Exposure offline input rejected: " + validation.errors.join(","));
  const authorized = authorizationStatus(input.authorization,
    input.assessedAt);
  const checks = [
    check("DOMAIN_OWNERSHIP", input, [],
      authorized === "VERIFIED" ?
        "CONFIGURATION_OBSERVED" : "NOT_DETERMINED",
      { authorization: authorized },
      ["This check only records supplied authorization provenance."]),
    collectDns(input, "SPF", "EMAIL_SPF"),
    collectDns(input, "DMARC", "EMAIL_DMARC"),
    collectDns(input, "DKIM", "EMAIL_DKIM"),
    evaluateTls(input), ...evaluateHttp(input),
  ];
  const findings = checks.flatMap(x => x.findings);
  const observedControls = checks.filter(x =>
    x.state === "OBSERVED").length;
  const canonical = {
    schema: "cyberpilot.exposure.assessment.v2" as const,
    organizationId: input.organizationId,
    snapshotId: input.snapshotId,
    domain: input.domain, assessedAt: input.assessedAt,
    authorization: {
      status: authorized, activeProbesAllowed: false as const,
      sourceOwnerIndependentlyVerified:
        authorized === "VERIFIED" &&
        input.authorization.externalOwnershipIndependentlyVerified,
    },
    checks, findings,
    coverage: {
      totalControls: checks.length, observedControls,
      unknownControls: checks.filter(x =>
        ["UNKNOWN", "OUT_OF_SCOPE", "STALE"].includes(x.state)).length,
      errorControls: checks.filter(x =>
        ["ERROR", "CONFLICT"].includes(x.state)).length,
      coveragePercent: Math.round(100 * observedControls /
        checks.length),
      scoreEligible: false as const, healthyClaimAllowed: false as const,
    },
    limitations: [...new Set([
      ...validation.warnings,
      "Evaluation uses already supplied offline observations.",
      "A provider LIVE probe is not executed or independently attested.",
      "Unobserved domain/subdomain/selector coverage is UNKNOWN.",
      "Findings are candidates requiring authorized verification.",
    ])],
    source: "OFFLINE_IMPORTED_PASSIVE" as const,
    trafficGenerated: 0 as const,
    tenantIsolationPreserved: true as const,
    customerComplianceCertified: false as const,
    historicalCyberScoreModified: false as const,
  };
  return { ...canonical,
    digest: sha256V2(canonicalV2(canonical)) };
}
export function verifyExposureOfflineAssessment(
  result: ExposureAssessment,
  input?: ExposureOfflineEnvelope,
) {
  const { digest, ...canonical } = result;
  const issues: string[] = [];
  if (sha256V2(canonicalV2(canonical)) !== digest)
    issues.push("ASSESSMENT_DIGEST_MISMATCH");
  if (result.trafficGenerated !== 0 ||
      result.customerComplianceCertified ||
      result.historicalCyberScoreModified ||
      result.coverage.healthyClaimAllowed)
    issues.push("FALSE_LIVE_OR_COMPLIANCE_CLAIM");
  if (input) {
    if (!validateExposureOfflineEnvelope(input).valid ||
        input.organizationId !== result.organizationId ||
        input.snapshotId !== result.snapshotId ||
        assessExposureOffline(input).digest !== digest)
      issues.push("SOURCE_NOT_BOUND_TO_REPORT");
  }
  return { valid: issues.length === 0, issues };
}
