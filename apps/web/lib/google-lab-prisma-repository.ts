import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
  GoogleLabError, verifyGoogleLabConnection,
  type GoogleLabConnection, type GoogleLabEvent,
  type GoogleLabScope, type GoogleLabTransition,
  type GoogleLabRepository,
} from "@cyberpilot/integrations/google-workspace";

/**
 * Production PostgreSQL repository for offline-only simulated onboarding.
 * Every state change and its versioned CAS audit event share one transaction.
 * All lookups and mutations are bound to the caller's organization.
 */
export type GoogleLabStoredRow = {
  id: string;
  organizationId: string;
  revision: number;
  state: string;
  stateDigest: string;
  payload: unknown;
  createdAt: Date;
  updatedAt: Date;
};
export type GoogleLabStoredEvent = {
  id: string;
  organizationId: string;
  connectionId: string;
  revision: number;
  action: string;
  eventDigest: string;
  connectionDigest: string;
  payload: unknown;
  occurredAt: Date;
};
const states = new Set([
  "NOT_CONFIGURED", "CHALLENGE_ISSUED", "CONSENT_DENIED",
  "CONNECTED_LAB", "SUSPENDED", "REVOKED", "EXPIRED",
]);
const commands = new Set([
  "ISSUE_CHALLENGE", "DENY_CONSENT", "ACCEPT_LAB",
  "SUSPEND", "RESUME", "REVOKE", "EXPIRE",
  "ROTATE_CHALLENGE", "CHANGE_CAPABILITIES",
]);
function conflict(message: string): never {
  throw new GoogleLabError("CONFLICT", message);
}
function missing(): never {
  throw new GoogleLabError("MISSING",
    "Google LAB connection absent for this organization.");
}
function validateId(raw: string) {
  if (typeof raw !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(raw))
    throw new GoogleLabError("INVALID",
      "Malformed Google LAB identifier.");
  return raw;
}
function validateScope(scope: GoogleLabScope) {
  validateId(scope.organizationId);
  validateId(scope.actorUserId);
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role))
    throw new GoogleLabError("FORBIDDEN",
      "Unsupported LAB membership role.");
}
function json(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}
function connectionFrom(row: GoogleLabStoredRow): GoogleLabConnection {
  const raw = row.payload;
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    conflict("Invalid persisted LAB connection JSON.");
  const connection = raw as GoogleLabConnection;
  if (connection.organizationId !== row.organizationId ||
      connection.id !== row.id ||
      connection.revision !== row.revision ||
      connection.state !== row.state ||
      connection.stateDigest !== row.stateDigest ||
      !states.has(connection.state) ||
      !verifyGoogleLabConnection(connection).valid)
    conflict("Persisted Google LAB connection violated CAS integrity.");
  const updatedAt = new Date(connection.updatedAt);
  if (!Number.isFinite(updatedAt.getTime()) ||
      updatedAt.getTime() !== row.updatedAt.getTime())
    conflict("Persisted connection update timestamp drift.");
  return connection;
}
function eventFrom(row: GoogleLabStoredEvent): GoogleLabEvent {
  const raw = row.payload;
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    conflict("Invalid persisted LAB event JSON.");
  const value = raw as GoogleLabEvent;
  if (value.organizationId !== row.organizationId ||
      value.connectionId !== row.connectionId ||
      value.revision !== row.revision ||
      value.type !== row.action ||
      value.digest !== row.eventDigest ||
      value.connectionDigest !== row.connectionDigest ||
      !commands.has(value.type))
    conflict("Persisted LAB event does not agree with indexed columns.");
  if (new Date(value.at).getTime() !== row.occurredAt.getTime())
    conflict("Persisted LAB event occurrence timestamp drift.");
  return value;
}
export function validateStoredLabPair(
  connection: GoogleLabConnection, event: GoogleLabEvent,
) {
  const issues: string[] = [];
  if (connection.organizationId !== event.organizationId ||
      connection.id !== event.connectionId)
    issues.push("TENANT_OR_CONNECTION_MISMATCH");
  if (connection.revision !== event.revision)
    issues.push("REVISION_MISMATCH");
  if (connection.stateDigest !== event.connectionDigest)
    issues.push("CAS_DIGEST_MISMATCH");
  if (connection.updatedAt !== event.at)
    issues.push("UPDATE_TIME_MISMATCH");
  if (connection.state !== event.to)
    issues.push("TRANSITION_STATE_MISMATCH");
  if (!verifyGoogleLabConnection(connection).valid)
    issues.push("INVALID_CONNECTION");
  if (event.realProviderContacted ||
      event.privilegedActionPerformed)
    issues.push("LIVE_OR_PRIVILEGED_ACTION_UNSUPPORTED");
  return { valid: issues.length === 0, issues };
}
export function storedLabSummary(row: GoogleLabStoredRow) {
  const connection = connectionFrom(row);
  return {
    id: connection.id, organizationId: connection.organizationId,
    revision: connection.revision, state: connection.state,
    stateDigest: connection.stateDigest,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
    expiresAt: connection.expiresAt,
    grantedForLab: [...connection.permittedCapabilities],
    credentialStored: false as const,
    googleLiveValidated: false as const,
  };
}
export class PrismaGoogleLabRepository implements GoogleLabRepository {
  async createInitial(scope: GoogleLabScope,
    connection: GoogleLabConnection) {
    validateScope(scope);
    if (!["OWNER", "ADMIN"].includes(scope.role))
      throw new GoogleLabError("FORBIDDEN", "LAB creation requires admin.");
    if (connection.organizationId !== scope.organizationId ||
        connection.createdByUserId !== scope.actorUserId ||
        connection.revision !== 0 ||
        connection.state !== "NOT_CONFIGURED" ||
        !verifyGoogleLabConnection(connection).valid)
      throw new GoogleLabError("INVALID",
        "Invalid initial Google LAB state.");
    const organization = await db.organization.findUnique({
      where: { id: scope.organizationId }, select: { id: true },
    });
    if (!organization) missing();
    const member = await db.membership.findFirst({
      where: {
        organizationId: scope.organizationId,
        userId: scope.actorUserId,
        role: { in: ["ADMIN", "OWNER"] },
      }, select: { id: true },
    });
    if (!member)
      throw new GoogleLabError("FORBIDDEN",
        "Google LAB creation requires a current administrator.");
    try {
      return await db.$transaction(async tx => {
      const row = await tx.googleLabConnection.create({
        data: {
          id: connection.id,
          organizationId: connection.organizationId,
          createdById: connection.createdByUserId,
          revision: connection.revision,
          state: connection.state,
          stateDigest: connection.stateDigest,
          payload: json(connection),
          createdAt: new Date(connection.createdAt),
          updatedAt: new Date(connection.updatedAt),
        },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER",
          actorUserId: scope.actorUserId,
          action: "GOOGLE_LAB_CONNECTION_CREATED",
          resourceType: "GOOGLE_LAB_CONNECTION",
          resourceId: connection.id,
          metadata: {
            schema: "cyberpilot.google.lab.audit.event.v1",
            state: "NOT_CONFIGURED",
            revision: 0, stateDigest: connection.stateDigest,
            externalConsentVerified: false,
            providerRequests: 0,
          },
          occurredAt: new Date(connection.createdAt),
        },
      });
      return connectionFrom(row);
      }, { isolationLevel: "Serializable" });
    } catch (error) {
      if (isPrismaUnique(error))
        conflict("Google LAB connection already exists.");
      throw error;
    }
  }
  async getByOrganization(organizationId: string, connectionId: string) {
    validateId(organizationId);
    validateId(connectionId);
    const row = await db.googleLabConnection.findFirst({
      where: { organizationId, id: connectionId },
    });
    return row ? connectionFrom(row) : null;
  }
  async getEventHead(organizationId: string, connectionId: string) {
    validateId(organizationId);
    validateId(connectionId);
    const event = await db.googleLabEvent.findFirst({
      where: { organizationId, connectionId },
      orderBy: { revision: "desc" },
    });
    return event ? eventFrom(event) : null;
  }
  async compareAndSwap(old: GoogleLabConnection,
    transition: GoogleLabTransition) {
    const check = validateStoredLabPair(
      transition.connection, transition.event);
    if (!check.valid)
      conflict("Invalid Google LAB CAS command: " +
        check.issues.join(","));
    if (old.organizationId !== transition.connection.organizationId ||
        old.id !== transition.connection.id ||
        old.revision + 1 !== transition.connection.revision ||
        !verifyGoogleLabConnection(old).valid)
      conflict("LAB revision or organization changed.");
    try {
      return await db.$transaction(async tx => {
        const priorEvent = old.revision === 0 ? null :
          await tx.googleLabEvent.findFirst({
            where: {
              organizationId: old.organizationId,
              connectionId: old.id,
            }, orderBy: { revision: "desc" },
          });
        if (old.revision > 0 &&
            (!priorEvent ||
             priorEvent.revision !== old.revision ||
             priorEvent.eventDigest !==
               transition.event.previousEventDigest))
          conflict("Previous LAB event CAS head changed.");
        if (old.revision === 0 &&
            transition.event.previousEventDigest !== null)
          conflict("Initial LAB event has unexpected parent.");
        const result = await tx.googleLabConnection.updateMany({
          where: {
            id: old.id, organizationId: old.organizationId,
            revision: old.revision,
            stateDigest: old.stateDigest, state: old.state,
          },
          data: {
            revision: transition.connection.revision,
            state: transition.connection.state,
            stateDigest: transition.connection.stateDigest,
            payload: json(transition.connection),
            updatedAt: new Date(transition.connection.updatedAt),
          },
        });
        if (result.count !== 1)
          conflict("Stale Google LAB revision or tenant scope.");
        await tx.googleLabEvent.create({
          data: {
            organizationId: transition.event.organizationId,
            connectionId: transition.event.connectionId,
            revision: transition.event.revision,
            action: transition.event.type,
            eventDigest: transition.event.digest,
            connectionDigest: transition.event.connectionDigest,
            payload: json(transition.event),
            occurredAt: new Date(transition.event.at),
          },
        });
        await tx.auditEvent.create({
          data: {
            organizationId: transition.event.organizationId,
            actorType: "USER",
            actorUserId: transition.event.actorUserId,
            action: "GOOGLE_LAB_" + transition.event.type,
            resourceType: "GOOGLE_LAB_CONNECTION",
            resourceId: transition.event.connectionId,
            metadata: {
              schema: "cyberpilot.google.lab.audit.event.v1",
              revision: transition.event.revision,
              eventDigest: transition.event.digest,
              connectionDigest: transition.connection.stateDigest,
              priorDigest: transition.event.previousEventDigest,
              fromState: transition.event.from,
              toState: transition.event.to,
              oauthTokensCreated: 0,
              realAdministratorConsent: false,
              providerRequests: 0,
            },
            occurredAt: new Date(transition.event.at),
          },
        });
        const row = await tx.googleLabConnection.findFirst({
          where: {
            id: old.id, organizationId: old.organizationId,
            revision: transition.connection.revision,
          },
        });
        if (!row) conflict("LAB CAS write vanished.");
        return connectionFrom(row);
      }, { isolationLevel: "Serializable" });
    } catch (error) {
      if (isPrismaUnique(error) || isPrismaSerialization(error))
        conflict("Concurrent Google LAB state or audit conflict.");
      throw error;
    }
  }
  async getEvents(organizationId: string, connectionId: string,
    offset: number, limit: number) {
    validateId(organizationId);
    validateId(connectionId);
    if (!Number.isSafeInteger(offset) || offset < 0 ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 10000)
      throw new GoogleLabError("INVALID",
        "Invalid LAB audit pagination.");
    const rows = await db.googleLabEvent.findMany({
      where: { organizationId, connectionId },
      orderBy: { revision: "asc" }, skip: offset, take: limit,
    });
    return rows.map(eventFrom);
  }
  async list(organizationId: string, offset: number, limit: number) {
    validateId(organizationId);
    if (!Number.isSafeInteger(offset) || offset < 0 ||
        offset > 100000 || !Number.isSafeInteger(limit) ||
        limit < 1 || limit > 101)
      throw new GoogleLabError("INVALID",
        "Invalid LAB connection pagination.");
    const rows = await db.googleLabConnection.findMany({
      where: { organizationId },
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: offset, take: limit,
    });
    return rows.map(connectionFrom);
  }
}
function isPrismaUnique(error: unknown) {
  return !!error && typeof error === "object" &&
    "code" in error && error.code === "P2002";
}
function isPrismaSerialization(error: unknown) {
  return !!error && typeof error === "object" &&
    "code" in error && (error.code === "P2034" ||
      error.code === "P2028");
}
export function validateGoogleLabStorageEnvelope(
  value: unknown,
): GoogleLabConnection {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new GoogleLabError("INVALID",
      "Expected stored Google LAB object.");
  const record = value as GoogleLabConnection;
  if (!verifyGoogleLabConnection(record).valid)
    throw new GoogleLabError("CONFLICT",
      "LAB storage envelope digest invalid.");
  return record;
}
export async function countGoogleLabOrganizationRecords(
  scope: GoogleLabScope,
) {
  validateScope(scope);
  const [connections, events] = await Promise.all([
    db.googleLabConnection.count({
      where: { organizationId: scope.organizationId },
    }),
    db.googleLabEvent.count({
      where: { organizationId: scope.organizationId },
    }),
  ]);
  return {
    organizationId: scope.organizationId,
    connectionCount: connections, eventCount: events,
    providerTokenCount: 0 as const,
    liveProviderRequests: 0 as const,
    accountWrites: 0 as const,
    dataScope: "ORGANIZATION_ONLY" as const,
  };
}
export async function assertLabAuditCoherence(
  scope: GoogleLabScope, connectionId: string,
) {
  validateScope(scope);
  const repository = new PrismaGoogleLabRepository();
  const connection = await repository.getByOrganization(
    scope.organizationId, connectionId);
  if (!connection) missing();
  if (connection.revision > 10000)
    conflict("LAB audit exceeds bounded replay.");
  const events = connection.revision ?
    await repository.getEvents(
      scope.organizationId, connectionId, 0, connection.revision) : [];
  const issues: string[] = [];
  if (events.length !== connection.revision)
    issues.push("AUDIT_REVISION_GAP");
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    if (event.revision !== i + 1)
      issues.push("OUT_OF_ORDER_EVENT_" + (i + 1));
    if (event.organizationId !== scope.organizationId)
      issues.push("TENANT_LEAK");
    if (i > 0 && event.previousEventDigest !== events[i - 1]!.digest)
      issues.push("DIGEST_CHAIN_BROKEN");
  }
  if (events.length > 0 &&
      events[events.length - 1]!.connectionDigest !==
        connection.stateDigest)
    issues.push("FINAL_CAS_DIGEST_MISMATCH");
  return {
    organizationId: scope.organizationId,
    connectionId,
    revision: connection.revision,
    events: events.length,
    valid: issues.length === 0,
    issues, readOnly: true as const,
    realGoogleProviderValidated: false as const,
  };
}
