import { db, type Prisma } from "@cyberpilot/database";
import {
  defaultPassiveAdmissionPolicy,
  validatePassivePolicy, planPassiveDomainTargets,
  sha256V2, canonicalV2,
  type PassiveSource,
} from "@cyberpilot/risk-engine";

/**
 * Durable scheduling and quota accounting. This service cannot issue
 * an actual network lease while legal consent has no trustworthy
 * independent verification. It is useful for safe dry-run planning,
 * reporting, cancellation, RBAC and future collector integration.
 */
export type PassiveScheduleActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type PassiveScheduleCommand = {
  operation: "CREATE" | "UPDATE" | "READ" | "LIST" |
    "PAUSE" | "REVOKE" | "HISTORY" | "SIMULATE" |
    "RESERVE" | "QUOTA" | "RESERVATIONS";
  domain?: string;
  sources?: PassiveSource[];
  expectedRevision?: number;
  requestId?: string;
  limit?: number;
};
export type PassiveScheduleView = {
  organizationId: string;
  scheduleId: string;
  authorizationId: string;
  domain: string;
  state: "DISABLED" | "PAUSED" | "READY" | "REVOKED";
  revision: number;
  sources: PassiveSource[];
  policyDigest: string;
  legalConsentVerified: boolean;
  minimumIntervalMs: number;
  nextEligibleAt: string | null;
  lastAttemptAt: string | null;
  dailyDnsLimit: number;
  dailyTlsLimit: number;
  dailyHttpLimit: number;
  activeNetworkConnections: 0;
  legalApprovalClaimed: false;
  automaticRemediationPerformed: false;
};
export type PassiveScheduleResult = {
  schema: "cyberpilot.exposure.passive.schedule.service.v1";
  organizationId: string;
  operation: PassiveScheduleCommand["operation"];
  data: unknown;
  networkRequestsExecuted: 0;
  activeScansPerformed: 0;
  legalConsentProven: false;
  historicalCyberScoreChanged: false;
};
export class PassiveScheduleConflict extends Error {
  constructor() { super("Passive schedule was modified concurrently."); }
}
const validStatuses = ["DISABLED", "PAUSED", "READY", "REVOKED"];
const validSources: PassiveSource[] = [
  "DNS", "TLS_HANDSHAKE", "HTTPS_HEADERS",
];
function fail(message: string): never {
  throw Error("Exposure schedule: " + message);
}
function validId(raw: unknown): raw is string {
  return typeof raw === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(raw);
}
function parse(raw: unknown): PassiveScheduleCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected operation object.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(key =>
      !["operation","domain","sources","expectedRevision",
        "requestId","limit"].includes(key)))
    fail("Unrecognized command field.");
  const operations: PassiveScheduleCommand["operation"][] = [
    "CREATE","UPDATE","READ","LIST","PAUSE","REVOKE",
    "HISTORY","SIMULATE","RESERVE","QUOTA","RESERVATIONS",
  ];
  if (!operations.includes(x.operation as PassiveScheduleCommand["operation"]))
    fail("Unsupported command.");
  const c: PassiveScheduleCommand = {
    operation: x.operation as PassiveScheduleCommand["operation"],
  };
  if (x.domain !== undefined) {
    if (typeof x.domain !== "string")
      fail("Domain must be a string.");
    c.domain = x.domain;
  }
  if (x.sources !== undefined) {
    if (!Array.isArray(x.sources) || x.sources.length < 1 ||
        x.sources.length > 3 ||
        new Set(x.sources).size !== x.sources.length ||
        x.sources.some(source => !validSources.includes(source)))
      fail("Invalid source selection.");
    c.sources = x.sources as PassiveSource[];
  }
  if (x.expectedRevision !== undefined) {
    if (typeof x.expectedRevision !== "number" ||
        !Number.isSafeInteger(x.expectedRevision) ||
        x.expectedRevision < 0 || x.expectedRevision > 1e7)
      fail("Invalid revision.");
    c.expectedRevision = x.expectedRevision;
  }
  if (x.requestId !== undefined) {
    if (!validId(x.requestId))
      fail("Invalid request identifier.");
    c.requestId = x.requestId;
  }
  if (x.limit !== undefined) {
    if (typeof x.limit !== "number" ||
        !Number.isSafeInteger(x.limit) ||
        x.limit < 1 || x.limit > 100)
      fail("Invalid list length.");
    c.limit = x.limit;
  }
  if (c.operation !== "LIST" && !c.domain)
    fail("Domain identifier required.");
  if (["CREATE","UPDATE","PAUSE","REVOKE"].includes(c.operation) &&
      c.expectedRevision === undefined)
    fail("Optimistic revision is mandatory.");
  if (c.operation === "CREATE" && (!c.sources ||
      c.expectedRevision !== 0))
    fail("Initial schedule requires source selection and revision zero.");
  if (c.operation === "RESERVE" && !c.requestId)
    fail("Idempotent request identifier required for quota reservation.");
  return c;
}
function view(row: {
  id: string; organizationId: string; domain: string;
  authorizationId: string; state: string; revision: number;
  sources: unknown; policyDigest: string;
  legalConsentVerified: boolean; minimumIntervalMs: number;
  nextEligibleAt: Date | null; lastAttemptAt: Date | null;
  dailyDnsLimit: number; dailyTlsLimit: number;
  dailyHttpLimit: number;
}): PassiveScheduleView {
  if (!validStatuses.includes(row.state) ||
      !Array.isArray(row.sources) ||
      row.sources.some(x => !validSources.includes(x)) ||
      row.sources.length === 0 ||
      new Set(row.sources).size !== row.sources.length ||
      !/^[a-f0-9]{64}$/.test(row.policyDigest))
    fail("Stored schedule integrity invalid.");
  return {
    organizationId: row.organizationId,
    scheduleId: row.id, authorizationId: row.authorizationId,
    domain: row.domain,
    state: row.state as PassiveScheduleView["state"],
    revision: row.revision,
    sources: row.sources as PassiveSource[],
    policyDigest: row.policyDigest,
    legalConsentVerified: row.legalConsentVerified,
    minimumIntervalMs: row.minimumIntervalMs,
    nextEligibleAt: row.nextEligibleAt?.toISOString() ?? null,
    lastAttemptAt: row.lastAttemptAt?.toISOString() ?? null,
    dailyDnsLimit: row.dailyDnsLimit,
    dailyTlsLimit: row.dailyTlsLimit,
    dailyHttpLimit: row.dailyHttpLimit,
    activeNetworkConnections: 0,
    legalApprovalClaimed: false,
    automaticRemediationPerformed: false,
  };
}
async function authorization(actor: PassiveScheduleActor,
  domain: string) {
  const row = await db.exposureDomainAuthorization.findFirst({
    where: { organizationId: actor.organizationId, domain },
  });
  if (!row) fail("Domain authorization not found.");
  return row;
}
async function checkMember(actor: PassiveScheduleActor,
  write: boolean) {
  if (!validId(actor.organizationId) || !validId(actor.userId))
    fail("Invalid actor or organization.");
  const membership = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId, userId: actor.userId,
    }, select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("Current organization membership required.");
  if (write && !["OWNER", "ADMIN"].includes(membership.role))
    fail("Only administrators can configure passive collection.");
}
function dayStart(now: Date) {
  return new Date(Date.UTC(now.getUTCFullYear(),
    now.getUTCMonth(), now.getUTCDate()));
}
async function auditEvent(
  tx: Prisma.TransactionClient,
  actor: PassiveScheduleActor,
  schedule: {
    id: string; revision: number; state: string;
    domain: string; legalConsentVerified: boolean;
  },
  priorState: string, action: string,
  metadata: Record<string, string | number | boolean | null> = {},
) {
  await tx.exposurePassiveEvent.create({
    data: {
      organizationId: actor.organizationId,
      scheduleId: schedule.id, revision: schedule.revision,
      action, priorState, currentState: schedule.state,
      actorUserId: actor.userId,
      metadata: {
        ...metadata, domain: schedule.domain,
        actualNetworkRequests: 0,
        legalConsentIndependentlyVerified:
          schedule.legalConsentVerified,
        customerSecurityCertified: false,
      },
    },
  });
  await tx.auditEvent.create({
    data: {
      organizationId: actor.organizationId,
      actorType: "USER", actorUserId: actor.userId,
      action: "EXPOSURE_PASSIVE_" + action,
      resourceType: "EXPOSURE_PASSIVE_SCHEDULE",
      resourceId: schedule.id,
      metadata: {
        revision: schedule.revision, priorState,
        newState: schedule.state, networkRequests: 0,
        domain: schedule.domain,
        independentLegalConsentEstablished: false,
      },
    },
  });
}
export class ExposurePassiveScheduleService {
  async execute(actor: PassiveScheduleActor,
    raw: unknown): Promise<PassiveScheduleResult> {
    const command = parse(raw);
    const writes = ["CREATE","UPDATE","PAUSE","REVOKE","RESERVE"]
      .includes(command.operation);
    await checkMember(actor, writes);
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.exposure.passive.schedule.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation, data,
      networkRequestsExecuted: 0, activeScansPerformed: 0,
      legalConsentProven: false, historicalCyberScoreChanged: false,
    };
  }
  private async dispatch(actor: PassiveScheduleActor,
    command: PassiveScheduleCommand): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (command.operation === "LIST") {
      const rows = await db.exposurePassiveSchedule.findMany({
        where: { organizationId },
        orderBy: { updatedAt: "desc" },
        take: command.limit ?? 30,
      });
      return {
        items: rows.map(view),
        unseenOrganizationsExcluded: true,
      };
    }
    const current = await db.exposurePassiveSchedule.findUnique({
      where: { organizationId_domain: {
        organizationId, domain: command.domain!,
      } },
    });
    if (command.operation === "CREATE") {
      if (current) fail("Schedule already exists.");
      const auth = await authorization(actor, command.domain!);
      const policy = defaultPassiveAdmissionPolicy(
        organizationId, auth.domain);
      if (validatePassivePolicy(policy).length)
        fail("Default policy invalid.");
      const sources = command.sources!;
      planPassiveDomainTargets(auth.domain, sources);
      const fingerprint = sha256V2(canonicalV2(policy));
      return db.$transaction(async tx => {
        const created = await tx.exposurePassiveSchedule.create({
          data: {
            organizationId, authorizationId: auth.id,
            domain: auth.domain, state: "DISABLED",
            revision: 1, sources: sources as Prisma.InputJsonValue,
            policyDigest: fingerprint,
            legalConsentVerified: false,
            createdById: actor.userId,
            updatedById: actor.userId,
          },
        });
        await auditEvent(tx, actor, created, "NONE", "CREATE");
        return {
          schedule: view(created), created: true,
          requiresLegalConsentBeforeExecution: true,
        };
      }, { isolationLevel: "Serializable" });
    }
    if (!current) fail("No schedule registered for this domain.");
    if (command.operation === "READ")
      return {
        schedule: view(current),
        legalAuthorizationIndependentlyEstablished: false,
      };
    if (command.operation === "HISTORY") {
      const events = await db.exposurePassiveEvent.findMany({
        where: { organizationId, scheduleId: current.id },
        orderBy: { revision: "desc" },
        take: command.limit ?? 50,
      });
      return {
        schedule: view(current),
        events: events.map(x => ({
          revision: x.revision, action: x.action,
          priorState: x.priorState,
          currentState: x.currentState,
          actorUserId: x.actorUserId,
          at: x.createdAt.toISOString(),
          customerApprovalVerified: false,
          externalNetworkRequests: 0,
        })),
      };
    }
    if (command.operation === "RESERVATIONS") {
      const rows = await db.exposurePassiveReservation.findMany({
        where: { organizationId, scheduleId: current.id },
        orderBy: { createdAt: "desc" },
        take: command.limit ?? 50,
      });
      return {
        requests: rows.map(x => ({
          requestId: x.requestId, state: x.status,
          createdAt: x.createdAt.toISOString(),
          quotaCounts: {
            dns: x.reservedDns, tls: x.reservedTls,
            http: x.reservedHttp,
          },
          rejected: x.rejectionCode,
          didNotGenerateTraffic: true,
        })),
      };
    }
    if (command.operation === "QUOTA" ||
        command.operation === "SIMULATE" ||
        command.operation === "RESERVE") {
      const since = dayStart(new Date());
      const attempts = await db.exposurePassiveReservation.findMany({
        where: {
          organizationId, scheduleId: current.id,
          periodStart: { gte: since },
        },
      });
      const usage = {
        dns: attempts.reduce((a, x) => a + x.reservedDns, 0),
        tls: attempts.reduce((a, x) => a + x.reservedTls, 0),
        http: attempts.reduce((a, x) => a + x.reservedHttp, 0),
        reservations: attempts.length,
      };
      const wanted = current.sources as PassiveSource[];
      const cost = {
        dns: wanted.includes("DNS") ? 4 : 0,
        tls: wanted.includes("TLS_HANDSHAKE") ? 1 : 0,
        http: wanted.includes("HTTPS_HEADERS") ? 1 : 0,
      };
      const policy = defaultPassiveAdmissionPolicy(
        organizationId, current.domain);
      const quotasFit = usage.dns + cost.dns <= policy.maxDnsQueries &&
        usage.tls + cost.tls <= policy.maxTlsConnections &&
        usage.http + cost.http <= policy.maxHttpHeadRequests;
      const verified = current.legalConsentVerified &&
        current.state === "READY" &&
        current.nextEligibleAt !== null &&
        current.nextEligibleAt <= new Date();
      const decision = {
        eligibleForNetwork: false,
        reservationPermitted: false,
        proposedCalls: cost.dns + cost.tls + cost.http,
        quotasFit, usage, cost,
        scheduleEnabled: current.state === "READY",
        independentlyVerifiedLegalConsent: verified,
        requiresTrustedCollector: true,
        noNetworkRequests: true,
        reasons: [...new Set([
          ...!quotasFit ? ["QUOTA_EXCEEDED"] : [],
          ...!verified ? ["LEGAL_CONSENT_NOT_INDEPENDENTLY_VERIFIED"] : [],
          "TRUSTED_COLLECTOR_NOT_ENABLED",
        ])],
      };
      if (command.operation === "QUOTA" ||
          command.operation === "SIMULATE")
        return { decision, policy, schedule: view(current) };
      const requestId = command.requestId!;
      const prior = await db.exposurePassiveReservation.findUnique({
        where: { organizationId_requestId: {
          organizationId, requestId,
        } },
      });
      if (prior)
        return {
          idempotent: true, requestId,
          state: prior.status,
          eligibleForNetwork: false,
          rejectionCode: prior.rejectionCode,
        };
      // Even if counters fit, do not allocate an executable lease
      // until a separate legal consent authority exists.
      return db.$transaction(async tx => {
        const previous = await tx.exposurePassiveSchedule.findFirst({
          where: { id: current.id, organizationId },
        });
        if (!previous) fail("Schedule vanished.");
        const now = new Date();
        const created = await tx.exposurePassiveReservation.create({
          data: {
            organizationId, scheduleId: current.id,
            requestId, authorizationRevision: 1,
            status: "DENIED",
            requestedSources: wanted as Prisma.InputJsonValue,
            reservedDns: 0, reservedTls: 0, reservedHttp: 0,
            periodStart: dayStart(now),
            leaseExpiresAt: now, finishedAt: now,
            rejectionCode: "CONSENT_OR_COLLECTOR_NOT_READY",
            initiatedById: actor.userId,
          },
        });
        await tx.auditEvent.create({
          data: {
            organizationId, actorType: "USER",
            actorUserId: actor.userId,
            action: "EXPOSURE_PASSIVE_DENIED_RESERVATION",
            resourceType: "EXPOSURE_PASSIVE_RESERVATION",
            resourceId: created.id,
            metadata: {
              requestId, domain: current.domain,
              networkRequests: 0,
              consentIndependentlyValidated: false,
            },
          },
        });
        return {
          requestId, reservationId: created.id,
          state: created.status, eligibleForNetwork: false,
          networkCallsStarted: 0,
          rejectionCode: created.rejectionCode,
          quota: decision,
        };
      }, { isolationLevel: "Serializable" });
    }
    if (["UPDATE", "PAUSE", "REVOKE"].includes(command.operation)) {
      if (current.revision !== command.expectedRevision)
        throw new PassiveScheduleConflict();
      const state = command.operation === "REVOKE" ?
        "REVOKED" : command.operation === "PAUSE" ?
          "PAUSED" : "DISABLED";
      if (current.state === "REVOKED" &&
          command.operation !== "REVOKE")
        fail("A revoked schedule cannot be silently reactivated.");
      const nextSources = command.sources ??
        current.sources as PassiveSource[];
      planPassiveDomainTargets(current.domain, nextSources);
      return db.$transaction(async tx => {
        const saved = await tx.exposurePassiveSchedule.update({
          where: { id: current.id, revision: current.revision },
          data: {
            revision: current.revision + 1,
            state, sources: nextSources as Prisma.InputJsonValue,
            legalConsentVerified: false,
            updatedById: actor.userId,
            nextEligibleAt: null,
          },
        });
        await auditEvent(tx, actor, saved,
          current.state, command.operation);
        return {
          schedule: view(saved), auditWritten: true,
          networkConfigurationActivated: false,
          previousState: current.state,
        };
      }, { isolationLevel: "Serializable" });
    }
    throw Error("Unsupported Exposure scheduling operation.");
  }
}
