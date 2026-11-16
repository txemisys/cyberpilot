import { canonicalV2 } from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";
import {
  verifyPassiveExecutionLease,
  type PassiveExecutionLease,
  type PassiveExecutionResult,
  type PassiveExecutionEvent,
} from "./exposure-passive-execution-guard";
import {
  type PassiveCollectorRequest,
  type PassiveSource,
} from "./exposure-passive-collection-policy";

/**
 * Verification of execution metadata, not verification of remote security.
 * A network transport can be injected without proving legal consent;
 * independent lease + source scope are therefore checked separately.
 */
export type PassiveExecutionGate = {
  id: string;
  state: "PASS" | "BLOCK" | "ADVISORY";
  reason: string;
  expected: number;
  actual: number;
  affectedSources: PassiveSource[];
};
export type PassiveExecutionEvidence = {
  schema: "cyberpilot.exposure.execution.evidence.v1";
  organizationId: string;
  requestId: string;
  domain: string;
  evaluatedAt: string;
  verdict: "INVALID" | "DENIED" | "PARTIAL" | "TRACEABLE";
  sourceSummary: {
    requested: PassiveSource[];
    observed: PassiveSource[];
    denied: PassiveSource[];
    unknown: PassiveSource[];
    missing: PassiveSource[];
  };
  consumedCalls: {
    DNS: number;
    TLS_HANDSHAKE: number;
    HTTPS_HEADERS: number;
    total: number;
  };
  gates: PassiveExecutionGate[];
  blockers: string[];
  advisory: string[];
  eventsChecked: number;
  returnedEvidenceCount: number;
  limitations: string[];
  integrityDigest: string;
  independentLegalAuthorizationApprovedByVerifier: false;
  remoteEndpointSecurityCertified: false;
  actualRemediationVerified: false;
  historicalScoreChanged: false;
};
const sources: readonly PassiveSource[] = [
  "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS",
];
const isISO = (s: string): boolean =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const distinct = <T>(values: readonly T[]) => [...new Set(values)];
const digest = (value: unknown) => sha256V2(canonicalV2(value));
const order = (a: PassiveSource, b: PassiveSource) =>
  sources.indexOf(a) - sources.indexOf(b);
const ordered = (values: readonly PassiveSource[]) =>
  distinct(values).sort(order);
function gate(
  id: string, state: PassiveExecutionGate["state"],
  reason: string, expected: number,
  actual: number, affectedSources: PassiveSource[] = [],
): PassiveExecutionGate {
  return {
    id, state, reason, expected, actual,
    affectedSources: ordered(affectedSources),
  };
}
function sourceState(
  result: PassiveExecutionResult,
  source: PassiveSource,
): "OBSERVED" | "UNKNOWN" | "DENIED" | "MISSING" {
  const found = result.sourceResults.filter(x => x.source === source);
  if (found.length !== 1) return "MISSING";
  return found[0]!.status;
}
function sourceEventCount(
  events: readonly PassiveExecutionEvent[], source: PassiveSource,
): number {
  return events.filter(e => e.source === source &&
    e.kind === "SOURCE" &&
    e.callsReserved > 0).length;
}
function totalCalls(result: PassiveExecutionResult): number {
  return result.calls.DNS + result.calls.TLS_HANDSHAKE +
    result.calls.HTTPS_HEADERS;
}
function reconstructCharges(
  events: readonly PassiveExecutionEvent[],
): Record<PassiveSource, number> {
  const totals: Record<PassiveSource, number> = {
    DNS: 0, TLS_HANDSHAKE: 0, HTTPS_HEADERS: 0,
  };
  for (const event of events) {
    if (event.source && sources.includes(event.source)) {
      totals[event.source] += event.callsReserved;
    }
  }
  return totals;
}
function hasProtocolClaims(result: PassiveExecutionResult): boolean {
  return result.independentConsentWasRequired === true &&
    result.securityOrRemediationCertified === false &&
    result.legacyCyberScoreModified === false &&
    result.outboundRequestsAllowedWithoutLease === false;
}
function isReportedTarget(
  request: PassiveCollectorRequest, source: PassiveSource,
  target: string,
): boolean {
  if (source === "DNS" || source === "TLS_HANDSHAKE")
    return target === request.domain;
  return target === "https://" + request.domain + "/";
}
function validEvent(
  event: PassiveExecutionEvent, current: number,
  request: PassiveCollectorRequest,
): boolean {
  return event.sequence === current &&
    ["ADMISSION","SOURCE","DENIAL","ABORT","COMPLETE"]
      .includes(event.kind) &&
    typeof event.code === "string" &&
    event.code.length >= 1 && event.code.length <= 500 &&
    isISO(event.observedAt) &&
    event.observedAt >= request.requestedAt &&
    Number.isSafeInteger(event.callsReserved) &&
    event.callsReserved >= 0 &&
    event.callsReserved <= 1 &&
    Number.isSafeInteger(event.callsObserved) &&
    event.callsObserved >= 0 &&
    event.callsObserved <= 1 &&
    (event.source === null &&
      (event.target === null || event.target === request.domain) ||
      event.source !== null &&
      sources.includes(event.source) &&
      event.target !== null &&
      isReportedTarget(request, event.source, event.target));
}
function collectStatusErrors(
  request: PassiveCollectorRequest,
  result: PassiveExecutionResult,
): PassiveSource[] {
  return result.sourceResults.filter(x =>
    !sources.includes(x.source) ||
    !request.sources.includes(x.source) ||
    !isReportedTarget(request, x.source, x.target) ||
    !["OBSERVED","UNKNOWN","DENIED"].includes(x.status) ||
    !Number.isSafeInteger(x.bytes) || x.bytes < 0 ||
    (x.peer !== null && x.peer.length > 80))
    .map(x => x.source);
}
function hasDuplicates(result: PassiveExecutionResult): boolean {
  return result.sourceResults.length !==
    new Set(result.sourceResults.map(x => x.source)).size;
}
function resultSummary(result: PassiveExecutionResult,
  requested: PassiveSource[]) {
  return {
    requested: ordered(requested),
    observed: ordered(result.sourceResults.filter(x =>
      x.status === "OBSERVED").map(x => x.source)),
    denied: ordered(result.sourceResults.filter(x =>
      x.status === "DENIED").map(x => x.source)),
    unknown: ordered(result.sourceResults.filter(x =>
      x.status === "UNKNOWN").map(x => x.source)),
    missing: ordered(requested.filter(x =>
      !result.sourceResults.some(y => y.source === x))),
  };
}
export function reconcilePassiveExecution(
  request: PassiveCollectorRequest,
  lease: PassiveExecutionLease | null,
  result: PassiveExecutionResult,
  evaluatedAt: string,
): PassiveExecutionEvidence {
  if (!isISO(evaluatedAt) ||
      !isISO(request.requestedAt) ||
      request.organizationId.length < 4)
    throw Error("Invalid execution evidence scope or clock.");
  const gates: PassiveExecutionGate[] = [];
  const expected = lease?.grantedSources ?? [];
  const tenantMatch =
    result.organizationId === request.organizationId &&
    result.domain === request.domain &&
    result.requestId === request.requestId;
  gates.push(gate("TENANT_REQUEST_BINDING",
    tenantMatch ? "PASS" : "BLOCK",
    "Execution and request must identify the exact tenant and request.",
    1, tenantMatch ? 1 : 0));
  const leaseIssues = lease ?
    verifyPassiveExecutionLease(request, lease, request.requestedAt) :
    ["INDEPENDENT_LEASE_REQUIRED"];
  // A missing lease is a lawful DENIED result; it must never become
  // a passing execution, even if the transport claims success.
  gates.push(gate("INDEPENDENT_LEASE",
    leaseIssues.length ? (result.state === "DENIED" ?
      "ADVISORY" : "BLOCK") : "PASS",
    "An issued lease is required for any network observation.",
    0, leaseIssues.length));
  const protocol = hasProtocolClaims(result) &&
    result.schema === "cyberpilot.exposure.execution.result.v1";
  gates.push(gate("NO_FALSE_SECURITY_CLAIMS",
    protocol ? "PASS" : "BLOCK",
    "No network result can certify security or historical remediation.",
    1, protocol ? 1 : 0));
  const uniqueSources = !hasDuplicates(result) &&
    result.sourceResults.length <= 3;
  gates.push(gate("UNIQUE_SOURCE_OUTCOMES",
    uniqueSources ? "PASS" : "BLOCK",
    "At most one source outcome may be reported for each protocol.",
    result.sourceResults.length,
    new Set(result.sourceResults.map(x => x.source)).size));
  const malformedSources = collectStatusErrors(request, result);
  gates.push(gate("SOURCE_TARGET_AND_LIMITS",
    malformedSources.length ? "BLOCK" : "PASS",
    "Returned targets, source states and byte counts must remain bounded.",
    result.sourceResults.length,
    result.sourceResults.length - malformedSources.length,
    malformedSources));
  const events = result.events;
  const badEvents = events.filter((e, i) =>
    !validEvent(e, i + 1, request));
  gates.push(gate("SEQUENTIAL_EVENT_PROVENANCE",
    badEvents.length ? "BLOCK" : "PASS",
    "Every execution event must be ordered, scoped and time bounded.",
    events.length, events.length - badEvents.length,
    badEvents.map(x => x.source).filter(
      (x): x is PassiveSource => x !== null)));
  const prematureTerminal = events.some((e, i) =>
    (e.kind === "COMPLETE" || e.kind === "ABORT") &&
    i < events.length - 1);
  gates.push(gate("TERMINAL_EVENT_ORDER",
    prematureTerminal ? "BLOCK" : "PASS",
    "An execution may not emit more activity after terminal status.",
    0, prematureTerminal ? 1 : 0));
  const deniedPure = result.state !== "DENIED" ||
    totalCalls(result) === 0 &&
    result.sourceResults.length === 0 &&
    !events.some(x => x.kind === "SOURCE");
  gates.push(gate("DENIED_MEANS_NO_NETWORK",
    deniedPure ? "PASS" : "BLOCK",
    "A denied execution must not have consumed a network reservation.",
    0, deniedPure ? 0 : totalCalls(result)));
  const countsValid = sources.every(s =>
    Number.isSafeInteger(result.calls[s]) &&
    result.calls[s] >= 0 &&
    result.calls[s] <= request.policy.maxTotalRequests);
  const budgetValid = countsValid && sources.every(s =>
    result.calls[s] <= (lease?.budget[s] ?? 0)) &&
    totalCalls(result) <= request.policy.maxTotalRequests;
  gates.push(gate("DURABLE_NETWORK_BUDGET",
    budgetValid ? "PASS" : "BLOCK",
    "DNS resolution calls and socket operations count against one budget.",
    lease ? sources.reduce((v, s) => v + lease.budget[s], 0) : 0,
    totalCalls(result)));
  const reconstructed = reconstructCharges(events);
  const chargesMatched = sources.every(s =>
    reconstructed[s] <= result.calls[s]);
  gates.push(gate("EVENT_CHARGES_NOT_OVERCOUNTED",
    chargesMatched ? "PASS" : "BLOCK",
    "Event reservations must not exceed recorded durable quotas.",
    totalCalls(result),
    sources.reduce((v, s) => v + reconstructed[s], 0)));
  const peerClaims = result.sourceResults.filter(x =>
    x.source !== "DNS" && x.status === "OBSERVED" &&
    (!x.peer || x.peer.length > 80));
  gates.push(gate("SOCKET_PEER_RECORDED",
    peerClaims.length ? "BLOCK" : "PASS",
    "Positive TLS and HEAD operation metadata require a peer address.",
    result.sourceResults.filter(x =>
      x.source !== "DNS" && x.status === "OBSERVED").length,
    result.sourceResults.filter(x =>
      x.source !== "DNS" && x.status === "OBSERVED").length -
      peerClaims.length,
    peerClaims.map(x => x.source)));
  // Each TLS or HTTPS operation must account for two independently
  // reserved DNS resolution calls, before and after the socket use.
  const network = result.sourceResults.filter(x =>
    x.source !== "DNS" && x.status === "OBSERVED");
  const originalDns = result.sourceResults.filter(x =>
    x.source === "DNS" && x.status === "OBSERVED").length;
  const resolutionDemand = 2 * network.length + originalDns;
  const dnsCount = result.calls.DNS;
  gates.push(gate("PRE_POST_DNS_QUOTA",
    dnsCount >= resolutionDemand ? "PASS" : "BLOCK",
    "Pre/post socket resolutions must be counted, never free traffic.",
    resolutionDemand, dnsCount,
    dnsCount >= resolutionDemand ? [] : network.map(x => x.source)));
  const eventCoverage = result.sourceResults.filter(x =>
    x.status === "OBSERVED" &&
    sourceEventCount(events, x.source) === 0);
  gates.push(gate("OBSERVED_HAS_CHARGED_EVENT",
    eventCoverage.length ? "BLOCK" : "PASS",
    "No observed operation exists without a charged source event.",
    result.sourceResults.filter(x =>
      x.status === "OBSERVED").length,
    result.sourceResults.filter(x =>
      x.status === "OBSERVED").length - eventCoverage.length,
    eventCoverage.map(x => x.source)));
  const missing = expected.filter(source =>
    sourceState(result, source) === "MISSING");
  gates.push(gate("PLANNED_SOURCE_COMPLETENESS",
    missing.length ? "ADVISORY" : "PASS",
    "Unexecuted sources remain unknown, never implicitly safe.",
    expected.length, expected.length - missing.length, missing));
  const statuses = result.sourceResults;
  const completedHonest = result.state !== "COMPLETED" ||
    expected.length > 0 &&
    statuses.length === expected.length &&
    statuses.every(x => x.status === "OBSERVED");
  gates.push(gate("COMPLETED_REQUIRES_ALL_OBSERVED",
    completedHonest ? "PASS" : "BLOCK",
    "A partial or unknown source may not promote the run to COMPLETE.",
    expected.length, statuses.filter(x =>
      x.status === "OBSERVED").length));
  const stateKnown = ["DENIED","PARTIAL","COMPLETED"]
    .includes(result.state);
  gates.push(gate("RESULT_STATE_RECOGNIZED",
    stateKnown ? "PASS" : "BLOCK",
    "An unknown state may not be interpreted as successful.",
    1, stateKnown ? 1 : 0));
  const noLeaseTraffic = lease !== null || totalCalls(result) === 0;
  gates.push(gate("NO_TRAFFIC_WITHOUT_LEASE",
    noLeaseTraffic ? "PASS" : "BLOCK",
    "Without an independently issued lease, calls must be zero.",
    0, noLeaseTraffic ? 0 : totalCalls(result)));
  const honestStatus = result.state === "DENIED" ?
    statuses.length === 0 :
    result.state === "COMPLETED" ?
      statuses.length === expected.length &&
      statuses.every(s => s.status === "OBSERVED") :
      true;
  gates.push(gate("RESULT_STATUS_COHERENCE",
    honestStatus ? "PASS" : "BLOCK",
    "Run state must agree with the actual source outcomes.",
    1, honestStatus ? 1 : 0));
  const blockers = gates.filter(g => g.state === "BLOCK").map(g => g.id);
  const advisory = gates.filter(g => g.state === "ADVISORY")
    .map(g => g.id);
  const canonical = {
    schema: "cyberpilot.exposure.execution.evidence.v1" as const,
    organizationId: request.organizationId,
    requestId: request.requestId,
    domain: request.domain, evaluatedAt,
    verdict: (blockers.length ? "INVALID" :
      result.state === "DENIED" ? "DENIED" :
      advisory.length || result.state === "PARTIAL" ?
        "PARTIAL" : "TRACEABLE") as PassiveExecutionEvidence["verdict"],
    sourceSummary: resultSummary(result, request.sources),
    consumedCalls: {
      ...result.calls, total: totalCalls(result),
    },
    gates, blockers, advisory,
    eventsChecked: events.length,
    returnedEvidenceCount: statuses.length,
    limitations: [
      "This report only reconciles local execution metadata.",
      "A transport can report success without proving endpoint security.",
      "SHA-256 digests detect local changes, not false external origin.",
      "No DNS ownership proof substitutes for independent legal consent.",
      "Missing, denied and failed sources remain UNKNOWN or DENIED.",
      "Nothing in this report modifies CyberScore or certifies remediation.",
      "No remote network access is performed by the verifier.",
    ],
    independentLegalAuthorizationApprovedByVerifier: false as const,
    remoteEndpointSecurityCertified: false as const,
    actualRemediationVerified: false as const,
    historicalScoreChanged: false as const,
  };
  return { ...canonical, integrityDigest: digest(canonical) };
}
export function verifyPassiveExecutionEvidence(
  evidence: PassiveExecutionEvidence,
  expectedOrganizationId?: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const { integrityDigest, ...canonical } = evidence;
  if (digest(canonical) !== integrityDigest)
    errors.push("EVIDENCE_DIGEST_INVALID");
  if (expectedOrganizationId &&
      evidence.organizationId !== expectedOrganizationId)
    errors.push("FOREIGN_TENANT_EVIDENCE");
  if (evidence.independentLegalAuthorizationApprovedByVerifier !== false ||
      evidence.remoteEndpointSecurityCertified !== false ||
      evidence.actualRemediationVerified !== false ||
      evidence.historicalScoreChanged !== false)
    errors.push("SECURITY_OVERCLAIM");
  if (evidence.verdict === "TRACEABLE" &&
      evidence.gates.some(x => x.state !== "PASS"))
    errors.push("FALSE_TRACEABILITY_VERDICT");
  if (evidence.gates.length !==
      new Set(evidence.gates.map(x => x.id)).size)
    errors.push("DUPLICATE_VERIFICATION_GATE");
  return { valid: errors.length === 0, errors };
}
export function comparePassiveExecutionEvidence(
  older: PassiveExecutionEvidence,
  newer: PassiveExecutionEvidence,
) {
  if (!verifyPassiveExecutionEvidence(older).valid ||
      !verifyPassiveExecutionEvidence(newer).valid ||
      older.organizationId !== newer.organizationId ||
      older.domain !== newer.domain ||
      older.evaluatedAt >= newer.evaluatedAt)
    throw Error("Invalid or foreign tenant execution comparison.");
  const prev = new Set(older.blockers);
  const next = new Set(newer.blockers);
  return {
    organizationId: newer.organizationId,
    domain: newer.domain,
    beforeDigest: older.integrityDigest,
    afterDigest: newer.integrityDigest,
    blockersAdded: newer.blockers.filter(x => !prev.has(x)),
    blockersResolved: older.blockers.filter(x => !next.has(x)),
    networkCallsDelta: newer.consumedCalls.total -
      older.consumedCalls.total,
    missingSourcesDelta: newer.sourceSummary.missing.length -
      older.sourceSummary.missing.length,
    independentlyVerifiedRiskReduction: false as const,
    customerConsentAutomaticallyRenewed: false as const,
  };
}
export function exportPassiveExecutionEvidence(
  evidence: PassiveExecutionEvidence,
  format: "JSON" | "CSV" | "MARKDOWN",
): { filename: string; mime: string; text: string } {
  if (!verifyPassiveExecutionEvidence(evidence).valid)
    throw Error("Tampered execution evidence cannot be exported.");
  const stem = "exposure-passive-execution-" +
    evidence.evaluatedAt.slice(0, 10);
  if (format === "JSON") return {
    filename: stem + ".json",
    mime: "application/json",
    text: JSON.stringify(evidence, null, 2),
  };
  if (format === "CSV") {
    const quote = (value: string | number) =>
      '"' + String(value).replaceAll('"', '""') + '"';
    const entries = [
      ["gate", "state", "expected", "actual", "reason"],
      ...evidence.gates.map(g => [
        g.id, g.state, g.expected, g.actual, g.reason,
      ]),
    ];
    return {
      filename: stem + ".csv", mime: "text/csv",
      text: entries.map(row => row.map(quote).join(",")).join("\n"),
    };
  }
  if (format !== "MARKDOWN")
    throw Error("Invalid execution evidence export format.");
  return {
    filename: stem + ".md", mime: "text/markdown",
    text: [
      "# Exposure passive execution evidence",
      "",
      "Domain: " + evidence.domain,
      "Organization: " + evidence.organizationId,
      "Evaluated: " + evidence.evaluatedAt,
      "Verdict: " + evidence.verdict,
      "Digest: " + evidence.integrityDigest,
      "",
      "| Gate | State | Expected | Actual |",
      "| --- | --- | ---: | ---: |",
      ...evidence.gates.map(x => "| " + x.id + " | " +
        x.state + " | " + x.expected + " | " + x.actual + " |"),
      "",
      "No remote security, remediation or customer authorization " +
        "is established by this report.",
      ...evidence.limitations.map(x => "- " + x),
    ].join("\n"),
  };
}
