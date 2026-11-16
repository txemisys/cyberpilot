import { db } from "@cyberpilot/database";
import {
  buildExposureOperationalCloseout,
  verifyExposureOperationalCloseout,
  type ExposureCloseoutInput,
  type ExposureCloseoutReport,
} from "./exposure-operational-closeout";

export type ExposureCloseoutActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export class ExposureCloseoutAccessError extends Error {
  constructor(message: string) { super(message); }
}
const caps = {
  authorizations: 100,
  authorizationEvents: 500,
  schedules: 100,
  scheduleEvents: 500,
  reservations: 1000,
} as const;
function id(value: string) {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function date(value: Date | null) {
  return value?.toISOString() ?? null;
}
function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 3 ||
      value.some(item => typeof item !== "string"))
    return [];
  return value as string[];
}
export async function collectExposureOperationalCloseout(
  actor: ExposureCloseoutActor,
  generatedAt = new Date().toISOString(),
): Promise<ExposureCloseoutReport> {
  if (!id(actor.organizationId) || !id(actor.userId))
    throw new ExposureCloseoutAccessError("Invalid actor identity.");
  if (!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    throw new ExposureCloseoutAccessError(
      "Only organization reviewers may reconcile operation evidence.",
    );
  const member = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId,
      userId: actor.userId,
      role: actor.role,
    },
    select: { role: true },
  });
  if (!member)
    throw new ExposureCloseoutAccessError(
      "Verified organization membership required.",
    );
  const organizationId = actor.organizationId;
  const [authorizations, authorizationEvents,
    schedules, scheduleEvents, reservations] = await Promise.all([
    db.exposureDomainAuthorization.findMany({
      where: { organizationId },
      orderBy: { domain: "asc" },
      take: caps.authorizations + 1,
    }),
    db.exposureAuthorizationEvent.findMany({
      where: { organizationId },
      orderBy: { createdAt: "asc" },
      take: caps.authorizationEvents + 1,
    }),
    db.exposurePassiveSchedule.findMany({
      where: { organizationId },
      orderBy: { domain: "asc" },
      take: caps.schedules + 1,
    }),
    db.exposurePassiveEvent.findMany({
      where: { organizationId },
      orderBy: { createdAt: "asc" },
      take: caps.scheduleEvents + 1,
    }),
    db.exposurePassiveReservation.findMany({
      where: { organizationId },
      orderBy: { createdAt: "asc" },
      take: caps.reservations + 1,
    }),
  ]);
  const source: ExposureCloseoutInput = {
    organizationId, generatedAt,
    collectionCaps: caps,
    collectionCounts: {
      authorizations: authorizations.length,
      authorizationEvents: authorizationEvents.length,
      schedules: schedules.length,
      scheduleEvents: scheduleEvents.length,
      reservations: reservations.length,
    },
    authorizations: authorizations.slice(0, caps.authorizations)
      .map(row => ({
        id: row.id,
        organizationId: row.organizationId,
        domain: row.domain,
        revision: row.revision,
        state: row.state,
        method: row.method,
        challengeExpiresAt: row.challengeExpiresAt.toISOString(),
        verifiedAt: date(row.verifiedAt),
        revokedAt: date(row.revokedAt),
        evidenceDigest: row.evidenceDigest,
        updatedAt: row.updatedAt.toISOString(),
      })),
    authorizationEvents: authorizationEvents.slice(0,
      caps.authorizationEvents).map(row => ({
        id: row.id,
        organizationId: row.organizationId,
        authorizationId: row.authorizationId,
        revision: row.revision,
        action: row.action,
        priorState: row.priorState,
        newState: row.newState,
        actorUserId: row.actorUserId,
        createdAt: row.createdAt.toISOString(),
      })),
    schedules: schedules.slice(0, caps.schedules).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      authorizationId: row.authorizationId,
      domain: row.domain,
      revision: row.revision,
      state: row.state,
      sources: stringArray(row.sources),
      policyDigest: row.policyDigest,
      legalConsentVerified: row.legalConsentVerified,
      dailyDnsLimit: row.dailyDnsLimit,
      dailyTlsLimit: row.dailyTlsLimit,
      dailyHttpLimit: row.dailyHttpLimit,
      minimumIntervalMs: row.minimumIntervalMs,
      lastAttemptAt: date(row.lastAttemptAt),
      nextEligibleAt: date(row.nextEligibleAt),
      updatedAt: row.updatedAt.toISOString(),
    })),
    scheduleEvents: scheduleEvents.slice(0, caps.scheduleEvents)
      .map(row => ({
        id: row.id,
        organizationId: row.organizationId,
        scheduleId: row.scheduleId,
        revision: row.revision,
        action: row.action,
        priorState: row.priorState,
        currentState: row.currentState,
        actorUserId: row.actorUserId,
        createdAt: row.createdAt.toISOString(),
      })),
    reservations: reservations.slice(0, caps.reservations)
      .map(row => ({
        id: row.id,
        organizationId: row.organizationId,
        scheduleId: row.scheduleId,
        requestId: row.requestId,
        authorizationRevision: row.authorizationRevision,
        status: row.status,
        requestedSources: stringArray(row.requestedSources),
        reservedDns: row.reservedDns,
        reservedTls: row.reservedTls,
        reservedHttp: row.reservedHttp,
        actualDns: row.actualDns,
        actualTls: row.actualTls,
        actualHttp: row.actualHttp,
        periodStart: row.periodStart.toISOString(),
        leaseExpiresAt: row.leaseExpiresAt.toISOString(),
        finishedAt: date(row.finishedAt),
        rejectionCode: row.rejectionCode,
        evidenceDigest: row.evidenceDigest,
        createdAt: row.createdAt.toISOString(),
      })),
  };
  const report = buildExposureOperationalCloseout(source);
  if (!verifyExposureOperationalCloseout(report, organizationId).valid)
    throw Error("Exposure closeout report integrity invalid.");
  return report;
}
