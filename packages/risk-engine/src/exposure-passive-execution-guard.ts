import {
  checkPassiveAdmission,
  inspectPinnedAddresses,
  planPassiveDomainTargets,
  type PassiveCollectorRequest,
  type PassiveSource,
} from "./exposure-passive-collection-policy";

/**
 * Execution is capability-injected. There is intentionally no default
 * DNS, socket or HTTP implementation: importing this module never
 * enables network access. The caller must supply an independently
 * authorized, network-isolated worker and an atomic quota reservation.
 */
export type PassiveExecutionLease = {
  schema: "cyberpilot.exposure.execution.lease.v1";
  organizationId: string;
  requestId: string;
  domain: string;
  authorizationId: string;
  authorizationRevision: number;
  consentRecordId: string;
  reservationId: string;
  issuedAt: string;
  expiresAt: string;
  grantedSources: PassiveSource[];
  budget: { DNS: number; TLS_HANDSHAKE: number; HTTPS_HEADERS: number };
  approvedByIndependentAuthority: true;
  approvedScopeDigest: string;
};
export type PassiveExecutionEvent = {
  sequence: number;
  kind: "ADMISSION" | "SOURCE" | "DENIAL" | "ABORT" | "COMPLETE";
  source: PassiveSource | null;
  target: string | null;
  code: string;
  callsReserved: number;
  callsObserved: number;
  observedAt: string;
};
export type PassiveExecutionResult = {
  schema: "cyberpilot.exposure.execution.result.v1";
  organizationId: string;
  requestId: string;
  domain: string;
  state: "DENIED" | "PARTIAL" | "COMPLETED";
  sourceResults: Array<{
    source: PassiveSource;
    status: "OBSERVED" | "UNKNOWN" | "DENIED";
    code: string;
    target: string;
    peer: string | null;
    bytes: number;
  }>;
  events: PassiveExecutionEvent[];
  calls: { DNS: number; TLS_HANDSHAKE: number; HTTPS_HEADERS: number };
  independentConsentWasRequired: true;
  securityOrRemediationCertified: false;
  legacyCyberScoreModified: false;
  outboundRequestsAllowedWithoutLease: false;
};
export type PassiveExecutionTransport = {
  resolve(host: string, timeoutMs: number): Promise<readonly string[]>;
  collectDns(host: string, names: readonly string[], timeoutMs: number):
    Promise<{ records: readonly string[]; bytes: number }>;
  collectTls(host: string, pinnedIp: string, timeoutMs: number):
    Promise<{ peer: string; bytes: number; handshakeOnly: true }>;
  collectHead(url: string, pinnedIp: string, timeoutMs: number):
    Promise<{
      peer: string;
      bytes: number;
      method: "HEAD";
      redirectCount: 0;
      bodyBytes: 0;
      authenticated: false;
    }>;
};
export type PassiveExecutionAuthority = {
  /**
   * This must read a trusted consent record, not user-submitted
   * request fields. Revocation is rechecked before each operation.
   */
  verifyIndependentConsent(
    lease: PassiveExecutionLease, source: PassiveSource,
  ): Promise<boolean>;
  /**
   * This must atomically consume a previously-issued durable
   * reservation; a local counter alone is not sufficient.
   */
  consumeReservedCall(
    reservationId: string, source: PassiveSource, sequence: number,
  ): Promise<boolean>;
};
const allowed: readonly PassiveSource[] = [
  "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS",
];
const isIso = (value: string) =>
  typeof value === "string" &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const isDigest = (value: string) =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const isId = (value: string) =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
function distinct<T>(values: readonly T[]): boolean {
  return new Set(values).size === values.length;
}
function emptyResult(request: PassiveCollectorRequest):
  PassiveExecutionResult {
  return {
    schema: "cyberpilot.exposure.execution.result.v1",
    organizationId: request.organizationId,
    requestId: request.requestId, domain: request.domain,
    state: "DENIED", sourceResults: [], events: [],
    calls: { DNS: 0, TLS_HANDSHAKE: 0, HTTPS_HEADERS: 0 },
    independentConsentWasRequired: true,
    securityOrRemediationCertified: false,
    legacyCyberScoreModified: false,
    outboundRequestsAllowedWithoutLease: false,
  };
}
export function verifyPassiveExecutionLease(
  request: PassiveCollectorRequest,
  lease: PassiveExecutionLease | null,
  now: string,
): string[] {
  const problems: string[] = [];
  if (!isIso(now)) return ["CLOCK_INVALID"];
  if (!lease) return ["INDEPENDENT_LEASE_REQUIRED"];
  if (lease.schema !== "cyberpilot.exposure.execution.lease.v1")
    problems.push("LEASE_SCHEMA_INVALID");
  if (lease.approvedByIndependentAuthority !== true ||
      !isDigest(lease.approvedScopeDigest))
    problems.push("INDEPENDENT_APPROVAL_INVALID");
  if (!isId(lease.reservationId) ||
      !isId(lease.authorizationId) ||
      !isId(lease.consentRecordId))
    problems.push("LEASE_ID_INVALID");
  if (lease.organizationId !== request.organizationId ||
      lease.requestId !== request.requestId ||
      lease.domain !== request.domain ||
      lease.authorizationId !== request.proof.authorizationId ||
      lease.authorizationRevision !== request.proof.authorizationRevision ||
      lease.consentRecordId !== request.proof.consentRecordId)
    problems.push("LEASE_SCOPE_MISMATCH");
  if (!isIso(lease.issuedAt) || !isIso(lease.expiresAt) ||
      lease.issuedAt > now || lease.expiresAt <= now ||
      Date.parse(lease.expiresAt) - Date.parse(lease.issuedAt) > 300000)
    problems.push("LEASE_EXPIRED_OR_UNBOUNDED");
  if (!Array.isArray(lease.grantedSources) ||
      !distinct(lease.grantedSources) ||
      !lease.grantedSources.length ||
      lease.grantedSources.some(source =>
        !allowed.includes(source) || !request.sources.includes(source)))
    problems.push("LEASE_SOURCES_INVALID");
  for (const source of allowed) {
    const value = lease.budget?.[source];
    const maximum = source === "DNS" ?
      request.policy.maxDnsQueries : source === "TLS_HANDSHAKE" ?
        request.policy.maxTlsConnections :
        request.policy.maxHttpHeadRequests;
    if (!Number.isSafeInteger(value) || value < 0 ||
        value > maximum ||
        (!lease.grantedSources.includes(source) && value !== 0) ||
        (lease.grantedSources.includes(source) && value === 0))
      problems.push("LEASE_BUDGET_" + source);
  }
  const requiredDns = (lease.grantedSources.includes("DNS") ? 3 : 0) +
    (lease.grantedSources.includes("TLS_HANDSHAKE") ? 2 : 0) +
    (lease.grantedSources.includes("HTTPS_HEADERS") ? 2 : 0);
  if (lease.budget.DNS < requiredDns ||
      ((lease.grantedSources.includes("TLS_HANDSHAKE") ||
        lease.grantedSources.includes("HTTPS_HEADERS")) &&
       (!request.sources.includes("DNS") ||
        !lease.grantedSources.includes("DNS"))))
    problems.push("DNS_RESOLUTION_QUOTA_REQUIRED");
  const total = allowed.reduce((sum, source) =>
    sum + (lease.budget?.[source] || 0), 0);
  if (total > request.policy.maxTotalRequests)
    problems.push("LEASE_TOTAL_QUOTA");
  return [...new Set(problems)];
}
export type PassiveExecutionOptions = {
  /** One monotonic timestamp provider, injected for deterministic tests. */
  now(): string;
  /**
   * Never supply a network transport from an unauthenticated web route.
   * This function deliberately has no concrete transport implementation.
   */
  transport: PassiveExecutionTransport;
  authority: PassiveExecutionAuthority;
};
export async function executePassiveCollection(
  request: PassiveCollectorRequest,
  lease: PassiveExecutionLease | null,
  options: PassiveExecutionOptions,
): Promise<PassiveExecutionResult> {
  const output = emptyResult(request);
  let sequence = 0;
  const record = (
    kind: PassiveExecutionEvent["kind"],
    source: PassiveSource | null, target: string | null,
    code: string, reserved: number, observed: number,
  ) => {
    output.events.push({
      sequence: ++sequence, kind, source, target, code,
      callsReserved: reserved, callsObserved: observed,
      observedAt: options.now(),
    });
  };
  const begin = options.now();
  const denial = verifyPassiveExecutionLease(request, lease, begin);
  try {
    const admission = checkPassiveAdmission(request, begin);
    denial.push(...admission.issues);
  } catch {
    denial.push("ADMISSION_PARSER_REJECTED");
  }
  if (denial.length) {
    record("DENIAL", null, null, [...new Set(denial)].join(","), 0, 0);
    return output;
  }
  if (!lease) return output;
  record("ADMISSION", null, request.domain, "LEASE_VALIDATED", 0, 0);
  let exhausted = false;
  const issued = Date.parse(begin);
  const withinWindow = () => {
    const now = options.now();
    return isIso(now) && now >= begin &&
      now < lease.expiresAt &&
      Date.parse(now) - issued <= request.policy.maxDurationMs;
  };
  const available = async (
    source: PassiveSource, target: string,
  ): Promise<boolean> => {
    if (!withinWindow()) {
      record("DENIAL", source, target, "TIME_WINDOW_CLOSED", 0, 0);
      exhausted = true;
      return false;
    }
    let consent = false;
    try {
      consent = await options.authority.verifyIndependentConsent(
        lease, source,
      );
    } catch { consent = false; }
    if (!consent) {
      record("DENIAL", source, target, "CONSENT_REVOKED_OR_UNVERIFIED", 0, 0);
      exhausted = true;
      return false;
    }
    if (output.calls[source] >= lease.budget[source]) {
      record("DENIAL", source, target, "SOURCE_BUDGET_EXHAUSTED", 0, 0);
      exhausted = true;
      return false;
    }
    if (Object.values(output.calls).reduce((a, b) => a + b, 0) >=
        request.policy.maxTotalRequests) {
      record("DENIAL", source, target, "TOTAL_BUDGET_EXHAUSTED", 0, 0);
      exhausted = true;
      return false;
    }
    let consumed = false;
    try {
      consumed = await options.authority.consumeReservedCall(
        lease.reservationId, source, sequence + 1,
      );
    } catch { consumed = false; }
    if (!consumed) {
      record("DENIAL", source, target, "DURABLE_RESERVATION_DENIED", 0, 0);
      exhausted = true;
      return false;
    }
    output.calls[source] += 1;
    record("SOURCE", source, target, "DURABLE_QUOTA_RESERVED", 1, 0);
    return true;
  };
  const note = (
    source: PassiveSource, target: string,
    status: "OBSERVED" | "UNKNOWN" | "DENIED",
    code: string, bytes = 0, peer: string | null = null,
  ) => {
    output.sourceResults.push({
      source, target, status, code, bytes, peer,
    });
    record(status === "DENIED" ? "DENIAL" : "SOURCE",
      source, target, code, 0,
      status === "OBSERVED" ? 1 : 0);
  };
  const targets = planPassiveDomainTargets(
    request.domain, request.sources,
  );
  for (const source of lease.grantedSources) {
    if (exhausted) break;
    const target = source === "DNS" ?
      request.domain : source === "TLS_HANDSHAKE" ?
        request.domain : "https://" + request.domain + "/";
    if (source === "DNS") {
      let dnsAdmitted = true;
      // TXT apex, TXT _dmarc and MX each consume a durable DNS
      // budget reservation. Partial reservation is never refunded;
      // no DNS request is executed if a source cannot reserve all 3.
      for (let query = 0; query < 3; query++) {
        if (!await available(source, target)) {
          dnsAdmitted = false;
          break;
        }
      }
      if (!dnsAdmitted) {
        note(source, target, "DENIED", "DNS_NOT_AUTHORIZED");
        continue;
      }
      try {
        const data = await options.transport.collectDns(
          request.domain, targets.allowedDnsNames,
          request.policy.maxRequestMs,
        );
        if (data.bytes < 0 ||
            data.bytes > request.policy.maxDnsResponseBytes ||
            data.records.length > 30 ||
            data.records.some(record =>
              record.length > 4096 || /[\u0000-\u001f\u007f]/.test(record)))
          throw Error("DNS_RESPONSE_INVALID");
        note(source, target, "OBSERVED", "DNS_COLLECTED", data.bytes);
      } catch {
        note(source, target, "UNKNOWN", "DNS_UNVERIFIED_OR_ERROR");
      }
      continue;
    }
    // Address resolution is itself charged as an authorized DNS operation.
    const resolveWithQuota = async () => {
      if (!await available("DNS", request.domain))
        throw Error("DNS_RESOLUTION_QUOTA_DENIED");
      const addresses = await options.transport.resolve(
        request.domain, request.policy.maxRequestMs,
      );
      record("SOURCE", "DNS", request.domain,
        "DNS_RESOLUTION_ATTEMPTED", 0, 1);
      return addresses;
    };
    if (!await available(source, target)) {
      note(source, target, "DENIED", "SOURCE_NOT_AUTHORIZED");
      continue;
    }
    try {
      const before = await resolveWithQuota();
      if (!before.length || before.length > request.policy.maxAddresses)
        throw Error("DNS_ADDRESS_COUNT_INVALID");
      const pinnedIp = before[0];
      if (!pinnedIp) throw Error("NO_PINNED_ADDRESS");
      if (source === "TLS_HANDSHAKE") {
        const result = await options.transport.collectTls(
          request.domain, pinnedIp, request.policy.maxHandshakeMs,
        );
        const after = await resolveWithQuota();
        if (!result.handshakeOnly ||
            result.peer !== pinnedIp ||
            !inspectPinnedAddresses(
              request.domain, request.domain,
              [...before], [...after], result.peer,
            ).valid) throw Error("TLS_PEER_INVALID");
        note(source, target, "OBSERVED", "TLS_COLLECTED",
          result.bytes, result.peer);
      } else {
        const result = await options.transport.collectHead(
          target, pinnedIp, request.policy.maxRequestMs,
        );
        const after = await resolveWithQuota();
        if (result.method !== "HEAD" ||
            result.redirectCount !== 0 ||
            result.bodyBytes !== 0 ||
            result.authenticated !== false ||
            result.peer !== pinnedIp ||
            result.bytes > request.policy.maxResponseHeaderBytes ||
            !inspectPinnedAddresses(
              request.domain, request.domain,
              [...before], [...after], result.peer,
            ).valid) throw Error("HTTP_PEER_OR_METHOD_INVALID");
        note(source, target, "OBSERVED", "HEAD_COLLECTED",
          result.bytes, result.peer);
      }
    } catch {
      note(source, target, "UNKNOWN", "PEER_OR_COLLECTION_UNVERIFIED");
    }
  }
  output.state = output.sourceResults.length ===
    lease.grantedSources.length &&
    output.sourceResults.every(x => x.status === "OBSERVED") ?
      "COMPLETED" : "PARTIAL";
  record("COMPLETE", null, null, output.state, 0, 0);
  return output;
}
