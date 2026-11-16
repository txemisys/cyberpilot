import { db, type Prisma } from "@cyberpilot/database";
import { createHash } from "node:crypto";
import {
  verifyIndependentConsentReport,
  type IndependentConsentVerification,
} from "./exposure-independent-consent";

/**
 * Executable quota ledger. Unlike schedule dry-runs, all charges persist
 * before a transport gets called. A trusted authority is an injected
 * dependency and has NO default implementation. Public API routes
 * expose READ/LIST/RECONCILE only; never issue or spend quotas.
 */
export type ExecutionLedgerSource =
  "DNS" | "TLS_HANDSHAKE" | "HTTPS_HEADERS";
export type ExecutionLedgerActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type ExecutionLeaseView = {
  id: string;
  organizationId: string;
  requestId: string;
  domain: string;
  scheduleId: string;
  authorizationId: string;
  authorizationRevision: number;
  grantId: string;
  consentDigest: string;
  scopeDigest: string;
  state: "DENIED" | "ACTIVE" | "CANCELLED" |
    "EXPIRED" | "COMPLETED" | "FAILED";
  quota: {
    reserved: Record<ExecutionLedgerSource, number>;
    used: Record<ExecutionLedgerSource, number>;
    maximum: number;
    remaining: Record<ExecutionLedgerSource, number>;
    totalUsed: number;
  };
  revision: number;
  expiresAt: string;
  finishedAt: string | null;
  denialCode: string | null;
  issuedById: string;
  createdAt: string;
  updatedAt: string;
  customerApprovalCreatedByLedger: false;
  automaticallyVerifiedSecurity: false;
};
export type ExecutionChargeView = {
  id: string; leaseId: string; organizationId: string;
  sequence: number; source: ExecutionLedgerSource;
  status: "RESERVED" | "OBSERVED" | "UNKNOWN" | "ERROR" | "DENIED";
  targetDigest: string;
  resultDigest: string | null;
  peerDigest: string | null;
  errorCode: string | null;
  startedAt: string;
  finishedAt: string | null;
  networkOperationNotInferredFromRecord: true;
};
export type ExecutionLeaseRequest = {
  requestId: string;
  organizationId: string;
  domain: string;
  scheduleId: string;
  authorizationId: string;
  authorizationRevision: number;
  consentReport: IndependentConsentVerification;
  requiredSources: ExecutionLedgerSource[];
  quotas: Record<ExecutionLedgerSource, number>;
  maxTotal: number;
  expiresAt: string;
  actorUserId: string;
};
export type ExecutionChargeCommand = {
  organizationId: string;
  leaseId: string;
  sequence: number;
  source: ExecutionLedgerSource;
  targetDigest: string;
  at: string;
};
export type ExecutionChargeSettlement = {
  organizationId: string;
  leaseId: string;
  sequence: number;
  status: "OBSERVED" | "UNKNOWN" | "ERROR";
  resultDigest: string | null;
  peerDigest: string | null;
  errorCode: string | null;
  finishedAt: string;
};
export type LedgerAuthority = {
  independentlyOperated: true;
  /**
   * MUST re-read source-of-truth legal grant, key rotation and withdrawal
   * (never accept browser-supplied statuses). This returns a Boolean only
   * after independent verification. Every call is checked before spending.
   */
  authorizeExecution(
    command: ExecutionLeaseRequest,
    at: string,
  ): Promise<boolean>;
  authorizeCharge(
    lease: ExecutionLeaseView,
    source: ExecutionLedgerSource,
    at: string,
  ): Promise<boolean>;
};
export type LedgerReadResult = {
  schema: "cyberpilot.exposure.execution.ledger.read.v1";
  organizationId: string;
  leases: ExecutionLeaseView[];
  charges: ExecutionChargeView[];
  totalReservations: number;
  sourceConsumption: Record<ExecutionLedgerSource, number>;
  denied: number;
  terminal: number;
  unclosed: number;
  auditIntegrityIssues: string[];
  sampleTruncated: boolean;
  externalNetworkCallsPerformedByReader: 0;
  legalAuthorizationIssuedByReader: false;
  CyberScoreChanged: false;
};
export class ExecutionLedgerError extends Error {
  constructor(public readonly code: string) {
    super("Execution ledger: " + code);
  }
}
const sources: readonly ExecutionLedgerSource[] = [
  "DNS","TLS_HANDSHAKE","HTTPS_HEADERS",
];
const sha = (s: string) =>
  createHash("sha256").update(s).digest("hex");
const iso = (s: unknown): s is string =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const safeId = (s: unknown): s is string =>
  typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const digest = (s: unknown): s is string =>
  typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const validDomain = (s: unknown): s is string =>
  typeof s === "string" &&
  s.length > 3 && s.length <= 253 &&
  /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(s) &&
  s.includes(".") && !s.includes("..");
function fail(code: string): never {
  throw new ExecutionLedgerError(code);
}
function sums(x: Record<ExecutionLedgerSource,number>) {
  return sources.reduce((n,s) => n + x[s],0);
}
function view(row: {
  id: string; organizationId: string; requestId: string; domain: string;
  scheduleId: string; authorizationId: string;
  authorizationRevision: number; grantId: string;
  consentDigest: string; scopeDigest: string; state: string;
  reservedDns: number; reservedTls: number; reservedHttp: number;
  usedDns: number; usedTls: number; usedHttp: number;
  maxTotal: number; revision: number; expiresAt: Date;
  finishedAt: Date | null; denialCode: string | null;
  issuedById: string; createdAt: Date; updatedAt: Date;
}): ExecutionLeaseView {
  const reserved = {
    DNS: row.reservedDns, TLS_HANDSHAKE: row.reservedTls,
    HTTPS_HEADERS: row.reservedHttp,
  };
  const used = {
    DNS: row.usedDns, TLS_HANDSHAKE: row.usedTls,
    HTTPS_HEADERS: row.usedHttp,
  };
  if (!["DENIED","ACTIVE","CANCELLED","EXPIRED",
        "COMPLETED","FAILED"].includes(row.state) ||
      !sources.every(s => Number.isSafeInteger(used[s]) &&
        Number.isSafeInteger(reserved[s]) &&
        used[s] >= 0 && reserved[s] >= 0 &&
        used[s] <= reserved[s]) ||
      sums(reserved) > row.maxTotal)
    fail("STORED_LEASE_INTEGRITY_INVALID");
  return {
    id: row.id, organizationId: row.organizationId,
    requestId: row.requestId, domain: row.domain,
    scheduleId: row.scheduleId, authorizationId: row.authorizationId,
    authorizationRevision: row.authorizationRevision,
    grantId: row.grantId, consentDigest: row.consentDigest,
    scopeDigest: row.scopeDigest,
    state: row.state as ExecutionLeaseView["state"],
    quota: {
      reserved, used, maximum: row.maxTotal,
      remaining: {
        DNS: reserved.DNS - used.DNS,
        TLS_HANDSHAKE: reserved.TLS_HANDSHAKE - used.TLS_HANDSHAKE,
        HTTPS_HEADERS: reserved.HTTPS_HEADERS - used.HTTPS_HEADERS,
      },
      totalUsed: sums(used),
    },
    revision: row.revision,
    expiresAt: row.expiresAt.toISOString(),
    finishedAt: row.finishedAt?.toISOString() ?? null,
    denialCode: row.denialCode,
    issuedById: row.issuedById,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    customerApprovalCreatedByLedger: false,
    automaticallyVerifiedSecurity: false,
  };
}
function chargeView(row: {
  id: string; leaseId: string; organizationId: string;
  sequence: number; source: string; status: string;
  targetDigest: string; resultDigest: string | null;
  peerDigest: string | null; errorCode: string | null;
  startedAt: Date; finishedAt: Date | null;
}): ExecutionChargeView {
  if (!sources.includes(row.source as ExecutionLedgerSource) ||
      !["RESERVED","OBSERVED","UNKNOWN","ERROR","DENIED"]
        .includes(row.status) ||
      !digest(row.targetDigest))
    fail("STORED_CHARGE_INTEGRITY_INVALID");
  return {
    id: row.id, organizationId: row.organizationId,
    leaseId: row.leaseId, sequence: row.sequence,
    source: row.source as ExecutionLedgerSource,
    status: row.status as ExecutionChargeView["status"],
    targetDigest: row.targetDigest,
    resultDigest: row.resultDigest,
    peerDigest: row.peerDigest, errorCode: row.errorCode,
    startedAt: row.startedAt.toISOString(),
    finishedAt: row.finishedAt?.toISOString() ?? null,
    networkOperationNotInferredFromRecord: true,
  };
}
async function member(actor: ExecutionLedgerActor,
  mutate: boolean) {
  if (!safeId(actor.organizationId) || !safeId(actor.userId))
    fail("INVALID_ACTOR");
  const matched = await db.membership.findFirst({
    where: { organizationId: actor.organizationId,
      userId: actor.userId },
    select: { role: true },
  });
  if (!matched || actor.role !== matched.role)
    fail("ACTIVE_MEMBERSHIP_REQUIRED");
  if (mutate && !["OWNER","ADMIN"].includes(matched.role))
    fail("ADMIN_PERMISSION_REQUIRED");
}
function validateRequest(command: ExecutionLeaseRequest) {
  if (!safeId(command.organizationId) ||
      !safeId(command.requestId) ||
      !safeId(command.scheduleId) ||
      !safeId(command.authorizationId) ||
      !safeId(command.actorUserId) ||
      !validDomain(command.domain) ||
      !Number.isSafeInteger(command.authorizationRevision) ||
      command.authorizationRevision < 1 ||
      !iso(command.expiresAt))
    fail("LEASE_REQUEST_INVALID");
  if (!Array.isArray(command.requiredSources) ||
      !command.requiredSources.length ||
      command.requiredSources.some(s => !sources.includes(s)) ||
      new Set(command.requiredSources).size !==
        command.requiredSources.length)
    fail("LEASE_SOURCE_SET_INVALID");
  for (const source of sources) {
    const n = command.quotas[source];
    const max = source === "DNS" ? 8 : 1;
    if (!Number.isSafeInteger(n) || n < 0 || n > max)
      fail("LEASE_QUOTA_" + source);
  }
  if (!Number.isSafeInteger(command.maxTotal) ||
      command.maxTotal < 1 || command.maxTotal > 10 ||
      sums(command.quotas) > command.maxTotal)
    fail("LEASE_TOTAL_QUOTA_INVALID");
  if (command.requiredSources.includes("TLS_HANDSHAKE") ||
      command.requiredSources.includes("HTTPS_HEADERS")) {
    const requiredDns = 2 *
      Number(command.requiredSources.includes("TLS_HANDSHAKE")) +
      2 * Number(command.requiredSources.includes("HTTPS_HEADERS")) +
      Number(command.requiredSources.includes("DNS"));
    if (command.quotas.DNS < requiredDns)
      fail("SOCKET_PINNING_DNS_BUDGET_MISSING");
  }
  if (!verifyIndependentConsentReport(
    command.consentReport, command.organizationId).valid ||
      command.consentReport.decision !== "VALIDATED_FOR_PLANNING" ||
      command.consentReport.domain !== command.domain ||
      !digest(command.consentReport.grantDigest))
    fail("INDEPENDENT_CONSENT_INVALID");
}
/**
 * This is deliberately NOT instantiated by the public API with a
 * trusted authority. Without one, all attempts to issue or consume
 * executable quotas fail before entering a database transaction.
 */
export class ExposureExecutionLedgerService {
  constructor(private readonly authority: LedgerAuthority | null = null) {}
  async list(actor: ExecutionLedgerActor, limit = 100):
    Promise<LedgerReadResult> {
    await member(actor, false);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200)
      fail("INVALID_READ_LIMIT");
    const [leases, charges] = await Promise.all([
      db.exposureExecutionLease.findMany({
        where: { organizationId: actor.organizationId },
        take: limit + 1, orderBy: { createdAt: "desc" },
      }),
      db.exposureExecutionCharge.findMany({
        where: { organizationId: actor.organizationId },
        take: Math.min(limit * 10, 2000) + 1,
        orderBy: { createdAt: "desc" },
      }),
    ]);
    const full = leases.length > limit ||
      charges.length > Math.min(limit * 10, 2000);
    const selected = leases.slice(0, limit).map(view);
    const entries = charges.slice(0,
      Math.min(limit * 10, 2000)).map(chargeView);
    const issues = this.checkLedger(selected, entries);
    return {
      schema: "cyberpilot.exposure.execution.ledger.read.v1",
      organizationId: actor.organizationId,
      leases: selected,
      charges: entries,
      totalReservations: selected.length,
      sourceConsumption: {
        DNS: selected.reduce((n,x) => n + x.quota.used.DNS,0),
        TLS_HANDSHAKE: selected.reduce((n,x) =>
          n + x.quota.used.TLS_HANDSHAKE,0),
        HTTPS_HEADERS: selected.reduce((n,x) =>
          n + x.quota.used.HTTPS_HEADERS,0),
      },
      denied: selected.filter(x => x.state === "DENIED").length,
      terminal: selected.filter(x =>
        ["DENIED","COMPLETED","CANCELLED","EXPIRED","FAILED"]
          .includes(x.state)).length,
      unclosed: selected.filter(x => x.state === "ACTIVE").length,
      auditIntegrityIssues: issues,
      sampleTruncated: full,
      externalNetworkCallsPerformedByReader: 0,
      legalAuthorizationIssuedByReader: false,
      CyberScoreChanged: false,
    };
  }
  checkLedger(leases: ExecutionLeaseView[],
    charges: ExecutionChargeView[]): string[] {
    const issues: string[] = [];
    const known = new Map(leases.map(x => [x.id, x]));
    for (const charge of charges) {
      const parent = known.get(charge.leaseId);
      if (!parent ||
          parent.organizationId !== charge.organizationId)
        issues.push("ORPHAN_OR_FOREIGN_CHARGE");
      if (charge.status !== "RESERVED" &&
          !charge.finishedAt)
        issues.push("CHARGE_WITHOUT_TERMINAL_TIMESTAMP");
      if (!digest(charge.targetDigest))
        issues.push("CHARGE_TARGET_DIGEST_INVALID");
    }
    for (const lease of leases) {
      const attached = charges.filter(x => x.leaseId === lease.id);
      const seen = new Set(attached.map(x => x.sequence));
      if (seen.size !== attached.length)
        issues.push("DUPLICATE_CHARGE_SEQUENCE");
      for (const source of sources) {
        if (attached.filter(x => x.source === source).length >
            lease.quota.used[source])
          issues.push("CHARGE_COUNT_EXCEEDS_DURABLE_QUOTA");
      }
      if (lease.state === "DENIED" &&
          (lease.quota.totalUsed !== 0 ||
           attached.length !== 0))
        issues.push("DENIED_LEASE_WITH_TRAFFIC");
      if (lease.state !== "ACTIVE" && lease.state !== "DENIED" &&
          !lease.finishedAt)
        issues.push("TERMINAL_LEASE_WITHOUT_TIMESTAMP");
    }
    return [...new Set(issues)].sort();
  }
  async read(actor: ExecutionLedgerActor, leaseId: string) {
    await member(actor, false);
    if (!safeId(leaseId)) fail("LEASE_ID_INVALID");
    const row = await db.exposureExecutionLease.findFirst({
      where: { id: leaseId, organizationId: actor.organizationId },
    });
    if (!row) fail("LEASE_NOT_FOUND_IN_TENANT");
    const charges = await db.exposureExecutionCharge.findMany({
      where: { organizationId: actor.organizationId,
        leaseId: row.id },
      orderBy: { sequence: "asc" },
      take: 100,
    });
    return {
      lease: view(row),
      charges: charges.map(chargeView),
      externalNetworkQueries: 0 as const,
      customerConsentCreatedByReader: false as const,
    };
  }
  async recordDenied(
    actor: ExecutionLedgerActor,
    command: {
      requestId: string; domain: string; scheduleId: string;
      authorizationId: string; authorizationRevision: number;
      reason: string;
    },
  ) {
    await member(actor, true);
    if (!safeId(command.requestId) ||
        !safeId(command.authorizationId) ||
        !safeId(command.scheduleId) ||
        !validDomain(command.domain) ||
        !/^[A-Z][A-Z0-9_]{3,79}$/.test(command.reason) ||
        !Number.isSafeInteger(command.authorizationRevision) ||
        command.authorizationRevision < 1)
      fail("DENIED_RECORD_INVALID");
    const existing = await db.exposureExecutionLease.findUnique({
      where: {
        organizationId_requestId: {
          organizationId: actor.organizationId,
          requestId: command.requestId,
        },
      },
    });
    if (existing) {
      if (existing.domain !== command.domain ||
          existing.authorizationId !== command.authorizationId ||
          existing.scheduleId !== command.scheduleId)
        fail("IDEMPOTENCY_SCOPE_COLLISION");
      return { lease: view(existing), alreadyExists: true };
    }
    const now = new Date();
    const row = await db.exposureExecutionLease.create({
      data: {
        organizationId: actor.organizationId,
        requestId: command.requestId,
        domain: command.domain,
        scheduleId: command.scheduleId,
        authorizationId: command.authorizationId,
        authorizationRevision: command.authorizationRevision,
        grantId: "unverified-none",
        consentDigest: sha("not-consented:" + command.requestId),
        scopeDigest: sha(command.domain + ":" + command.requestId),
        state: "DENIED",
        reservedDns: 0, reservedTls: 0, reservedHttp: 0,
        usedDns: 0, usedTls: 0, usedHttp: 0, maxTotal: 0,
        expiresAt: now, finishedAt: now,
        denialCode: command.reason,
        issuedById: actor.userId,
      },
    });
    return { lease: view(row), alreadyExists: false };
  }
  async issueWithAuthority(
    actor: ExecutionLedgerActor,
    command: ExecutionLeaseRequest,
  ) {
    await member(actor, true);
    if (!this.authority ||
        this.authority.independentlyOperated !== true)
      fail("INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE");
    validateRequest(command);
    if (actor.organizationId !== command.organizationId ||
        actor.userId !== command.actorUserId)
      fail("ISSUER_ACTOR_MISMATCH");
    const now = new Date().toISOString();
    if (command.expiresAt <= now ||
        Date.parse(command.expiresAt) - Date.parse(now) > 300000)
      fail("LEASE_EXPIRY_UNSAFE");
    const independentlyApproved =
      await this.authority.authorizeExecution(command,now)
        .catch(() => false);
    if (!independentlyApproved)
      fail("INDEPENDENT_AUTHORITY_DENIED");
    const result = await db.$transaction(async tx => {
      const previous = await tx.exposureExecutionLease.findUnique({
        where: { organizationId_requestId: {
          organizationId: actor.organizationId,
          requestId: command.requestId,
        } },
      });
      if (previous) {
        if (previous.domain !== command.domain ||
            previous.authorizationId !== command.authorizationId)
          fail("LEASE_IDEMPOTENCY_SCOPE_CONFLICT");
        return previous;
      }
      const schedule = await tx.exposurePassiveSchedule.findUnique({
        where: { id: command.scheduleId },
      });
      const authorization = await tx.exposureDomainAuthorization.findFirst({
        where: {
          id: command.authorizationId,
          organizationId: actor.organizationId,
          domain: command.domain,
          revision: command.authorizationRevision,
          state: "VERIFIED",
          revokedAt: null,
          challengeExpiresAt: { gt: new Date() },
        },
      });
      if (!schedule || !authorization ||
          schedule.organizationId !== actor.organizationId ||
          schedule.domain !== command.domain ||
          schedule.authorizationId !== command.authorizationId ||
          schedule.state !== "READY" ||
          schedule.legalConsentVerified !== true)
        fail("SCHEDULE_OR_DOMAIN_NOT_INDEPENDENTLY_ENABLED");
      // Count ACTIVE reservations for current UTC day, inside the
      // serializable transaction. This prevents cross-worker overbooking.
      const start = new Date(now);
      start.setUTCHours(0,0,0,0);
      const recent = await tx.exposureExecutionLease.findMany({
        where: {
          organizationId: actor.organizationId,
          scheduleId: schedule.id,
          createdAt: { gte: start },
          state: { in: ["ACTIVE","COMPLETED","FAILED"] },
        },
      });
      const totals = {
        DNS: recent.reduce((n,x) => n + x.reservedDns,0),
        TLS_HANDSHAKE: recent.reduce((n,x) => n + x.reservedTls,0),
        HTTPS_HEADERS: recent.reduce((n,x) => n + x.reservedHttp,0),
      };
      if (totals.DNS + command.quotas.DNS > schedule.dailyDnsLimit ||
          totals.TLS_HANDSHAKE + command.quotas.TLS_HANDSHAKE >
            schedule.dailyTlsLimit ||
          totals.HTTPS_HEADERS + command.quotas.HTTPS_HEADERS >
            schedule.dailyHttpLimit)
        fail("DAILY_DURABLE_QUOTA_EXCEEDED");
      const grantId = command.consentReport.grantId;
      const grantDigest = command.consentReport.grantDigest;
      if (!safeId(grantId) || !digest(grantDigest))
        fail("SIGNED_GRANT_BINDING_INVALID");
      return tx.exposureExecutionLease.create({
        data: {
          organizationId: actor.organizationId,
          requestId: command.requestId,
          domain: command.domain,
          scheduleId: schedule.id,
          authorizationId: authorization.id,
          authorizationRevision: command.authorizationRevision,
          grantId, consentDigest: grantDigest,
          scopeDigest: sha(JSON.stringify({
            domain: command.domain,
            authorizationRevision: command.authorizationRevision,
            requiredSources: command.requiredSources,
            quotas: command.quotas,
          })),
          state: "ACTIVE",
          reservedDns: command.quotas.DNS,
          reservedTls: command.quotas.TLS_HANDSHAKE,
          reservedHttp: command.quotas.HTTPS_HEADERS,
          maxTotal: command.maxTotal,
          expiresAt: new Date(command.expiresAt),
          issuedById: actor.userId,
        },
      });
    }, { isolationLevel: "Serializable" });
    return {
      lease: view(result),
      networkOperationPerformed: false as const,
      independentAuthorityRecheckRequired: true as const,
    };
  }
  async consumeWithAuthority(command: ExecutionChargeCommand) {
    if (!this.authority ||
        this.authority.independentlyOperated !== true)
      fail("INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE");
    if (!safeId(command.organizationId) ||
        !safeId(command.leaseId) ||
        !Number.isSafeInteger(command.sequence) ||
        command.sequence < 1 || command.sequence > 10 ||
        !sources.includes(command.source) ||
        !digest(command.targetDigest) || !iso(command.at))
      fail("CHARGE_COMMAND_INVALID");
    const row = await db.exposureExecutionLease.findFirst({
      where: { id: command.leaseId,
        organizationId: command.organizationId },
    });
    if (!row || row.state !== "ACTIVE" ||
        row.expiresAt <= new Date(command.at))
      fail("LEASE_NOT_ACTIVE_OR_EXPIRED");
    const authorized = await this.authority.authorizeCharge(
      view(row), command.source, command.at,
    ).catch(() => false);
    if (!authorized) fail("INDEPENDENT_CONSENT_REVOKED");
    return db.$transaction(async tx => {
      const current = await tx.exposureExecutionLease.findFirst({
        where: { id: command.leaseId,
          organizationId: command.organizationId },
      });
      if (!current || current.state !== "ACTIVE" ||
          current.expiresAt <= new Date())
        fail("LEASE_RECHECK_FAILED");
      const before = view(current);
      if (before.quota.remaining[command.source] < 1 ||
          before.quota.totalUsed >= before.quota.maximum)
        fail("DURABLE_QUOTA_EXCEEDED");
      const existing = await tx.exposureExecutionCharge.findUnique({
        where: { leaseId_sequence: {
          leaseId: current.id, sequence: command.sequence,
        } },
      });
      if (existing) {
        if (existing.source !== command.source ||
            existing.targetDigest !== command.targetDigest)
          fail("CHARGE_SEQUENCE_COLLISION");
        return {
          charge: chargeView(existing), duplicate: true,
          networkPermittedOnDuplicate: false as const,
        };
      }
      const field = command.source === "DNS" ?
        "usedDns" : command.source === "TLS_HANDSHAKE" ?
          "usedTls" : "usedHttp";
      const changed = await tx.exposureExecutionLease.updateMany({
        where: {
          id: current.id, organizationId: command.organizationId,
          revision: current.revision, state: "ACTIVE",
        },
        data: {
          [field]: { increment: 1 },
          revision: { increment: 1 },
        },
      });
      if (changed.count !== 1) fail("CONCURRENT_LEASE_REVISION_CONFLICT");
      const charge = await tx.exposureExecutionCharge.create({
        data: {
          leaseId: current.id,
          organizationId: command.organizationId,
          sequence: command.sequence,
          source: command.source,
          status: "RESERVED",
          targetDigest: command.targetDigest,
        },
      });
      return {
        charge: chargeView(charge), duplicate: false,
        networkPermittedOnDuplicate: false as const,
      };
    }, { isolationLevel: "Serializable" });
  }
  async settleWithAuthority(command: ExecutionChargeSettlement) {
    if (!this.authority ||
        this.authority.independentlyOperated !== true)
      fail("INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE");
    if (!safeId(command.organizationId) ||
        !safeId(command.leaseId) ||
        !Number.isSafeInteger(command.sequence) ||
        command.sequence < 1 || command.sequence > 10 ||
        !["OBSERVED","UNKNOWN","ERROR"].includes(command.status) ||
        !iso(command.finishedAt) ||
        command.resultDigest !== null && !digest(command.resultDigest) ||
        command.peerDigest !== null && !digest(command.peerDigest) ||
        command.errorCode !== null &&
          !/^[A-Z][A-Z0-9_]{2,79}$/.test(command.errorCode))
      fail("SETTLEMENT_INVALID");
    const result = await db.exposureExecutionCharge.updateMany({
      where: {
        organizationId: command.organizationId,
        leaseId: command.leaseId,
        sequence: command.sequence,
        status: "RESERVED",
      },
      data: {
        status: command.status,
        resultDigest: command.resultDigest,
        peerDigest: command.peerDigest,
        errorCode: command.errorCode,
        finishedAt: new Date(command.finishedAt),
      },
    });
    if (result.count !== 1)
      fail("CHARGE_SETTLEMENT_CONFLICT");
    return {
      sequence: command.sequence, state: command.status,
      outcomeIsIndependentSecurityProof: false as const,
      scoreUpdated: false as const,
    };
  }
  async closeWithAuthority(
    organizationId: string, leaseId: string,
    state: "COMPLETED" | "FAILED" | "CANCELLED",
  ) {
    if (!this.authority ||
        this.authority.independentlyOperated !== true)
      fail("INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE");
    if (!safeId(organizationId) || !safeId(leaseId))
      fail("LEASE_IDENTIFIER_INVALID");
    const row = await db.exposureExecutionLease.findFirst({
      where: { id: leaseId, organizationId },
    });
    if (!row || row.state !== "ACTIVE")
      fail("LEASE_TERMINAL_STATE_CONFLICT");
    const open = await db.exposureExecutionCharge.count({
      where: { leaseId, organizationId, status: "RESERVED" },
    });
    if (open > 0 && state === "COMPLETED")
      fail("UNSETTLED_NETWORK_CHARGES");
    const updated = await db.exposureExecutionLease.updateMany({
      where: { id: leaseId, organizationId,
        revision: row.revision, state: "ACTIVE" },
      data: { state, revision: { increment: 1 },
        finishedAt: new Date() },
    });
    if (updated.count !== 1) fail("LEASE_TERMINAL_CAS_CONFLICT");
    return {
      state, leaseId, networkWorkerCreated: false as const,
    };
  }
}
