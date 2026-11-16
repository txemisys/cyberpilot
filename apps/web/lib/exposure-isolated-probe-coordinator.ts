import {
  inspectPinnedAddresses,
  type PassiveCollectorRequest,
  type PassiveSource,
} from "@cyberpilot/risk-engine";
import {
  ExposureExecutionLedgerService,
  type ExecutionLedgerActor,
  type ExecutionLeaseRequest,
  type ExecutionLeaseView,
  type ExecutionLedgerSource,
  type LedgerAuthority,
} from "./exposure-execution-ledger-service";
import {
  createIsolatedPassiveSocketTransport,
  type IsolatedNetworkAction,
  type IsolatedNetworkAuthorization,
  type IsolatedNetworkMetrics,
  type IsolatedNetworkOperator,
  type IsolatedNetworkScope,
  type IsolatedSocketTransport,
} from "./exposure-isolated-network-transport";
import { createHash } from "node:crypto";

/**
 * Internal operator-only coordinator for authorized passive observations.
 * The public web app DOES NOT expose a route that calls this module.
 * Injection deliberately prevents creating a working collector from
 * customer-provided tokens, DNS challenge or unsigned browser state.
 *
 * Never use this for penetration testing, enumeration or remediation.
 */
export type PassiveProbeDisposition =
  "DENIED" | "PARTIAL" | "COMPLETED" | "FAILED";
export type PassiveProbeInput = {
  actor: ExecutionLedgerActor;
  command: ExecutionLeaseRequest;
  request: PassiveCollectorRequest;
  operator: IsolatedNetworkOperator;
};
export type PassiveProbeObservation = {
  source: PassiveSource;
  status: "OBSERVED" | "UNKNOWN" | "DENIED";
  target: string;
  peer: string | null;
  bytes: number;
  errorCode: string | null;
  startedAt: string;
  finishedAt: string;
  networkCallCount: number;
  verifiedPinnedPeer: boolean;
  externalSecurityPostureVerified: false;
};
export type PassiveProbeExecutionReport = {
  schema: "cyberpilot.exposure.isolated.probe.v1";
  organizationId: string;
  requestId: string;
  domain: string;
  state: PassiveProbeDisposition;
  leaseId: string | null;
  issuedByIndependentAuthority: boolean;
  startedAt: string;
  completedAt: string;
  sourcesRequested: PassiveSource[];
  observations: PassiveProbeObservation[];
  consumedNetworkCalls: number;
  pendingQuotaCharges: number;
  metrics: IsolatedNetworkMetrics | null;
  limitations: string[];
  denialCodes: string[];
  digest: string;
  legalConsentIssuedByCyberPilot: false;
  successfulScanMeansCompliant: false;
  historicalCyberScoreChanged: false;
  externalRemediationPerformed: false;
};
export type ProbeTransportFactory = (
  operator: IsolatedNetworkOperator,
  scope: IsolatedNetworkScope,
  authority: IsolatedNetworkAuthorization,
) => IsolatedSocketTransport;
export type ProbeOrchestrationDependencies = {
  ledger: ExposureExecutionLedgerService;
  authority: LedgerAuthority;
  transport: ProbeTransportFactory;
  now(): string;
};
export class PassiveProbeError extends Error {
  constructor(public readonly code: string) {
    super("Authorized passive probe: " + code);
  }
}
const sources: readonly PassiveSource[] = [
  "DNS","TLS_HANDSHAKE","HTTPS_HEADERS",
];
const isIso = (s: string) =>
  typeof s === "string" &&
  Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const sha = (data: string) =>
  createHash("sha256").update(data).digest("hex");
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.entries(value)
    .sort(([a],[b]) => a.localeCompare(b))
    .map(([key,entry]) => JSON.stringify(key) + ":" +
      canonical(entry)).join(",") + "}";
}
function reportBase(input: PassiveProbeInput,
  startedAt: string): Omit<PassiveProbeExecutionReport,"digest"> {
  return {
    schema: "cyberpilot.exposure.isolated.probe.v1",
    organizationId: input.actor.organizationId,
    requestId: input.command.requestId,
    domain: input.command.domain,
    state: "DENIED", leaseId: null,
    issuedByIndependentAuthority: false,
    startedAt, completedAt: startedAt,
    sourcesRequested: [...input.request.sources],
    observations: [], consumedNetworkCalls: 0,
    pendingQuotaCharges: 0, metrics: null,
    limitations: [
      "A verified domain does not imply legal authorization to scan.",
      "Only an independently signed scope and revocation check can be accepted.",
      "No credentials, active tests, redirects, POST or persistent HTTP bodies.",
      "Public IP and socket-peer pinning are mandatory for TLS/HEAD.",
      "Unknown/error states do not count as healthy remote controls.",
      "Network completion does not imply customer security certification.",
      "No application route currently starts this network worker.",
    ],
    denialCodes: [],
    legalConsentIssuedByCyberPilot: false,
    successfulScanMeansCompliant: false,
    historicalCyberScoreChanged: false,
    externalRemediationPerformed: false,
  };
}
function finalize(
  report: Omit<PassiveProbeExecutionReport,"digest">,
): PassiveProbeExecutionReport {
  return {...report, digest:sha(canonical(report))};
}
export function verifyPassiveProbeReport(
  report: PassiveProbeExecutionReport,
  expectedTenant?: string,
) {
  const errors: string[] = [];
  const { digest, ...content } = report;
  if (sha(canonical(content)) !== digest)
    errors.push("PROBE_REPORT_DIGEST_MISMATCH");
  if (expectedTenant && report.organizationId !== expectedTenant)
    errors.push("PROBE_FOREIGN_TENANT");
  if (report.legalConsentIssuedByCyberPilot !== false ||
      report.successfulScanMeansCompliant !== false ||
      report.historicalCyberScoreChanged !== false ||
      report.externalRemediationPerformed !== false)
    errors.push("PROBE_FALSE_SECURITY_CLAIM");
  if (report.state === "COMPLETED" &&
      (report.observations.length !== report.sourcesRequested.length ||
       report.observations.some(x => x.status !== "OBSERVED") ||
       report.pendingQuotaCharges !== 0))
    errors.push("PROBE_COMPLETION_OVERSTATED");
  if (report.state === "DENIED" &&
      (report.leaseId !== null || report.consumedNetworkCalls !== 0))
    errors.push("DENIED_PROBE_HAS_NETWORK_ACTIVITY");
  if (report.observations.some(x =>
    x.source !== "DNS" && x.status === "OBSERVED" &&
    (!x.verifiedPinnedPeer || x.peer === null)))
    errors.push("OBSERVED_SOCKET_NOT_PINNED");
  return { valid: errors.length === 0, errors };
}
function validateInput(input: PassiveProbeInput, now: string) {
  if (!isIso(now) ||
      input.actor.organizationId !== input.command.organizationId ||
      input.actor.userId !== input.command.actorUserId ||
      input.command.organizationId !== input.request.organizationId ||
      input.command.authorizationId !== input.request.proof.authorizationId ||
      input.command.authorizationRevision !==
        input.request.proof.authorizationRevision ||
      input.command.domain !== input.request.domain ||
      input.command.requestId !== input.request.requestId ||
      input.request.sources.length !== input.command.requiredSources.length ||
      input.request.sources.some(x =>
        !input.command.requiredSources.includes(x)) ||
      input.request.sources.some(x => !sources.includes(x)))
    throw new PassiveProbeError("CROSS_SCOPE_OR_MALFORMED_INPUT");
  if (input.request.proof.currentState !== "VERIFIED" ||
      !input.request.proof.legalConsentIndependentlyVerified ||
      !input.request.explicitlyOptedIn ||
      input.request.activeScanningRequested ||
      input.request.credentialsSupplied ||
      input.request.tokenInRequest)
    throw new PassiveProbeError("NO_VERIFIED_INDEPENDENT_CONSENT");
  if (input.command.quotas.DNS < (
      (input.request.sources.includes("DNS") ? 3 : 0) +
      (input.request.sources.includes("TLS_HANDSHAKE") ? 2 : 0) +
      (input.request.sources.includes("HTTPS_HEADERS") ? 2 : 0)))
    throw new PassiveProbeError("NETWORK_DNS_QUOTA_INSUFFICIENT");
}
function classifyCode(cause: unknown) {
  if (cause instanceof PassiveProbeError) return cause.code;
  const raw = cause instanceof Error ? cause.message : "";
  if (/QUOTA|RESERVATION|CONFLICT/.test(raw))
    return "DURABLE_QUOTA_DENIED";
  if (/REVOKED|CONSENT|AUTHORITY/.test(raw))
    return "INDEPENDENT_CONSENT_WITHDRAWN";
  if (/DNS|ADDRESS|PRIVATE/.test(raw))
    return "DNS_OR_PINNING_UNVERIFIED";
  if (/TLS|CERTIFICATE|PEER/.test(raw))
    return "TLS_PEER_OR_CERTIFICATE_UNVERIFIED";
  if (/HEAD|HTTP|REDIRECT/.test(raw))
    return "HTTP_RESPONSE_UNVERIFIED";
  return "NETWORK_COLLECTION_UNVERIFIED";
}
function requiredTarget(domain: string, source: PassiveSource) {
  return source === "HTTPS_HEADERS" ?
    "https://" + domain + "/" : domain;
}
function chargedSource(action: IsolatedNetworkAction):
  ExecutionLedgerSource {
  return action === "TLS_CONNECT" ? "TLS_HANDSHAKE" :
    action === "HTTPS_HEAD" ? "HTTPS_HEADERS" : "DNS";
}
function snapshotMetrics(
  metrics: IsolatedNetworkMetrics,
): IsolatedNetworkMetrics {
  return {...metrics};
}
/**
 * In-process bridge. Sequence IDs are generated serially and every
 * consumption goes through the trusted ledger, which uses PostgreSQL
 * SERIALIZABLE and a CAS update before the network request.
 */
class LedgerNetworkBridge implements IsolatedNetworkAuthorization {
  readonly independentlyOperated = true as const;
  private sequence = 0;
  private readonly pending: Array<{
    sequence: number;
    source: ExecutionLedgerSource;
  }> = [];
  constructor(
    private readonly ledger: ExposureExecutionLedgerService,
    private readonly scope: IsolatedNetworkScope,
    private readonly now: () => string,
  ) {}
  async authorizeNetworkAction(
    requested: IsolatedNetworkScope,
    action: IsolatedNetworkAction,
    hostname: string,
    pinnedIp: string | null,
  ): Promise<boolean> {
    if (requested.leaseId !== this.scope.leaseId ||
        requested.requestId !== this.scope.requestId ||
        requested.organizationId !== this.scope.organizationId ||
        requested.consentDigest !== this.scope.consentDigest ||
        requested.authorizationId !== this.scope.authorizationId ||
        requested.authorizationRevision !==
          this.scope.authorizationRevision ||
        hostname !== this.scope.domain &&
          !(action === "DNS_TXT" &&
            hostname === "_dmarc." + this.scope.domain))
      return false;
    const sequence = this.sequence + 1;
    if (sequence > this.scope.maximumOperations)
      return false;
    try {
      const charge = await this.ledger.consumeWithAuthority({
        organizationId: this.scope.organizationId,
        leaseId: this.scope.leaseId,
        sequence, source: chargedSource(action),
        targetDigest: sha(JSON.stringify({
          action, hostname, pinnedIp,
          requestId: this.scope.requestId,
          sequence,
        })),
        at: this.now(),
      });
      if (charge.duplicate) return false;
      this.sequence = sequence;
      this.pending.push({
        sequence, source: chargedSource(action),
      });
      return true;
    } catch { return false; }
  }
  get usedCalls() {
    return this.sequence;
  }
  get pendingCount() {
    return this.pending.length;
  }
  async settlePending(status: "OBSERVED" | "UNKNOWN" | "ERROR") {
    const pending = this.pending.splice(0);
    const failures: number[] = [];
    for (const entry of pending) {
      try {
        await this.ledger.settleWithAuthority({
          organizationId: this.scope.organizationId,
          leaseId: this.scope.leaseId,
          sequence: entry.sequence,
          status,
          resultDigest: sha(JSON.stringify({
            sequence: entry.sequence,
            source: entry.source, status,
          })),
          peerDigest: null,
          errorCode: status === "OBSERVED" ?
            null : "INCOMPLETE_EVIDENCE",
          finishedAt: this.now(),
        });
      } catch {
        failures.push(entry.sequence);
        this.pending.push(entry);
      }
    }
    return failures;
  }
}
export class IsolatedExposureProbeCoordinator {
  constructor(private readonly dependencies: ProbeOrchestrationDependencies) {}
  async run(input: PassiveProbeInput): Promise<PassiveProbeExecutionReport> {
    const startedAt = this.dependencies.now();
    const base = reportBase(input, startedAt);
    if (!this.dependencies.authority ||
        this.dependencies.authority.independentlyOperated !== true) {
      base.denialCodes.push("INDEPENDENT_AUTHORITY_MISSING");
      return finalize(base);
    }
    try { validateInput(input, startedAt); }
    catch (cause) {
      base.denialCodes.push(classifyCode(cause));
      return finalize(base);
    }
    let lease: ExecutionLeaseView;
    try {
      const issued = await this.dependencies.ledger.issueWithAuthority(
        input.actor, input.command,
      );
      lease = issued.lease;
    } catch (cause) {
      base.denialCodes.push(classifyCode(cause));
      return finalize(base);
    }
    if (lease.state !== "ACTIVE" ||
        lease.organizationId !== input.actor.organizationId ||
        lease.requestId !== input.command.requestId ||
        lease.authorizationId !== input.command.authorizationId) {
      base.denialCodes.push("LEASE_NOT_ACTIVE_OR_FOREIGN");
      return finalize(base);
    }
    base.state = "FAILED";
    base.leaseId = lease.id;
    base.issuedByIndependentAuthority = true;
    const scope: IsolatedNetworkScope = {
      organizationId: lease.organizationId,
      requestId: lease.requestId,
      domain: lease.domain,
      authorizationId: lease.authorizationId,
      authorizationRevision: lease.authorizationRevision,
      grantId: lease.grantId,
      consentDigest: lease.consentDigest,
      leaseId: lease.id,
      leaseExpiresAt: lease.expiresAt,
      maximumOperations: lease.quota.maximum,
      executableByIndependentAuthority: true,
    };
    const bridge = new LedgerNetworkBridge(
      this.dependencies.ledger, scope, this.dependencies.now,
    );
    let transport: IsolatedSocketTransport;
    try {
      transport = this.dependencies.transport(
        input.operator,scope,bridge,
      );
    } catch (cause) {
      base.denialCodes.push(classifyCode(cause));
      await this.dependencies.ledger.closeWithAuthority(
        scope.organizationId,scope.leaseId,"FAILED",
      ).catch(() => undefined);
      base.completedAt = this.dependencies.now();
      return finalize(base);
    }
    for (const source of input.request.sources) {
      const started = this.dependencies.now();
      const target = requiredTarget(scope.domain,source);
      const beforeCount = bridge.usedCalls;
      let status: PassiveProbeObservation["status"] = "UNKNOWN";
      let peer: string | null = null;
      let bytes = 0;
      let pinned = false;
      let code: string | null = null;
      try {
        if (source === "DNS") {
          const answer = await transport.collectDns(
            scope.domain,
            [scope.domain, "_dmarc." + scope.domain],
            input.request.policy.maxRequestMs,
          );
          bytes = answer.bytes;
          if (!answer.records.length || answer.records.length > 30 ||
              bytes > 8192)
            throw new PassiveProbeError("DNS_RESPONSE_OVERSIZED");
          status = "OBSERVED";
        } else {
          const before = await transport.resolve(
            scope.domain, input.request.policy.maxRequestMs,
          );
          if (!before.length)
            throw new PassiveProbeError("NO_PUBLIC_RESOLVED_IP");
          const pinnedIp = before[0]!;
          if (source === "TLS_HANDSHAKE") {
            const result = await transport.collectTls(
              scope.domain,pinnedIp,input.request.policy.maxHandshakeMs,
            );
            const after = await transport.resolve(
              scope.domain,input.request.policy.maxRequestMs,
            );
            const review = inspectPinnedAddresses(
              scope.domain,scope.domain,
              [...before],[...after],result.peer,
            );
            if (!result.handshakeOnly || !review.valid)
              throw new PassiveProbeError("TLS_PEER_PINNING_FAILED");
            peer = result.peer;
            bytes = result.bytes;
            pinned = true;
            status = "OBSERVED";
          } else {
            const result = await transport.collectHead(
              target,pinnedIp,input.request.policy.maxRequestMs,
            );
            const after = await transport.resolve(
              scope.domain,input.request.policy.maxRequestMs,
            );
            const review = inspectPinnedAddresses(
              scope.domain,scope.domain,
              [...before],[...after],result.peer,
            );
            if (!review.valid || result.method !== "HEAD" ||
                result.redirectCount !== 0 ||
                result.bodyBytes !== 0 ||
                result.authenticated !== false ||
                result.bytes > 8192)
              throw new PassiveProbeError("HEAD_PROTOCOL_OR_PINNING_FAILED");
            peer = result.peer; bytes = result.bytes;
            pinned = true; status = "OBSERVED";
          }
        }
      } catch (cause) {
        status = "UNKNOWN";
        code = classifyCode(cause);
        base.denialCodes.push(code);
      }
      const settlement = await bridge.settlePending(
        status === "OBSERVED" ? "OBSERVED" : "UNKNOWN",
      );
      if (settlement.length) {
        status = "UNKNOWN";
        code = "UNSETTLED_DURABLE_NETWORK_CHARGE";
        base.denialCodes.push(code);
      }
      base.observations.push({
        source, status, target, peer: status === "OBSERVED" ? peer : null,
        bytes: status === "OBSERVED" ? bytes : 0,
        errorCode: code,
        startedAt:started,
        finishedAt:this.dependencies.now(),
        networkCallCount:bridge.usedCalls-beforeCount,
        verifiedPinnedPeer:status === "OBSERVED" && pinned,
        externalSecurityPostureVerified:false,
      });
      if (settlement.length) break;
    }
    base.pendingQuotaCharges = bridge.pendingCount;
    base.consumedNetworkCalls = bridge.usedCalls;
    base.metrics = snapshotMetrics(transport.metrics);
    base.state = base.observations.length === input.request.sources.length &&
      base.observations.every(x => x.status === "OBSERVED") &&
      base.pendingQuotaCharges === 0 ? "COMPLETED" : "PARTIAL";
    try {
      await this.dependencies.ledger.closeWithAuthority(
        scope.organizationId,scope.leaseId,
        base.state === "COMPLETED" ? "COMPLETED" : "FAILED",
      );
    } catch {
      base.state = "FAILED";
      base.denialCodes.push("LEASE_TERMINAL_SETTLEMENT_FAILED");
    }
    base.completedAt = this.dependencies.now();
    return finalize(base);
  }
}
export function comparePassiveProbeReports(
  before: PassiveProbeExecutionReport,
  after: PassiveProbeExecutionReport,
) {
  if (!verifyPassiveProbeReport(before).valid ||
      !verifyPassiveProbeReport(after).valid ||
      before.organizationId !== after.organizationId ||
      before.domain !== after.domain ||
      before.completedAt >= after.completedAt)
    throw new PassiveProbeError("INVALID_PROBE_COMPARISON");
  const oldObserved = new Set(before.observations
    .filter(x => x.status === "OBSERVED").map(x => x.source));
  const newObserved = new Set(after.observations
    .filter(x => x.status === "OBSERVED").map(x => x.source));
  return {
    organizationId: after.organizationId,
    domain: after.domain,
    beforeDigest: before.digest,
    afterDigest: after.digest,
    newlyObserved: [...newObserved].filter(x => !oldObserved.has(x)),
    noLongerObserved: [...oldObserved].filter(x => !newObserved.has(x)),
    quotaDelta: after.consumedNetworkCalls-before.consumedNetworkCalls,
    riskReductionIndependentlyProven: false as const,
    legalConsentAutomaticallyRenewed: false as const,
  };
}
export function exportPassiveProbeReport(
  report: PassiveProbeExecutionReport,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  if (!verifyPassiveProbeReport(report).valid)
    throw new PassiveProbeError("PROBE_EXPORT_INTEGRITY_FAILURE");
  const filename = "isolated-exposure-" +
    report.startedAt.slice(0,10);
  if (format === "JSON") return {
    filename:filename+".json",mime:"application/json",
    content:JSON.stringify(report,null,2),
  };
  const quote = (s:string|number) =>
    '"' + String(s).replaceAll('"','""') + '"';
  if (format === "CSV") return {
    filename:filename+".csv",mime:"text/csv",
    content:[
      "source,status,target,bytes,networkCalls,peerPinned",
      ...report.observations.map(x => [
        quote(x.source),quote(x.status),quote(x.target),
        quote(x.bytes),quote(x.networkCallCount),
        quote(String(x.verifiedPinnedPeer)),
      ].join(",")),
    ].join("\n"),
  };
  if (format !== "MARKDOWN")
    throw new PassiveProbeError("PROBE_EXPORT_FORMAT_INVALID");
  return {
    filename:filename+".md",mime:"text/markdown",
    content:[
      "# Isolated passive Exposure probe",
      "",
      "Organization: "+report.organizationId,
      "Domain: "+report.domain,
      "State: "+report.state,
      "Digest: "+report.digest,
      "Durable network calls: "+report.consumedNetworkCalls,
      "",
      ...report.observations.map(x =>
        "- "+x.source+": "+x.status+
        " (socket pinned: "+String(x.verifiedPinnedPeer)+")"),
      "",
      "No remote security certification or remediation is inferred.",
      ...report.limitations.map(x=>"- "+x),
    ].join("\n"),
  };
}
export function productionProbeTransportFactory():
  ProbeTransportFactory {
  return (operator,scope,authority) =>
    createIsolatedPassiveSocketTransport(operator,scope,authority);
}
