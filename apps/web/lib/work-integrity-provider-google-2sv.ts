import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { observationSnapshot } from "./work-integrity-evidence-assessment";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Google Workspace Admin Directory users.get is an external provider read.
 * The caller must supply an OAuth token with sufficient read permissions.
 * Tokens and raw provider payloads are NEVER persisted or audited.
 *
 * A successful remote read alone does not establish ownership of the
 * organization. We require the returned Google customerId to match the
 * customerId already bound to the evidence record.
 */
export type ProviderCheckOutcome =
  | "PASS" | "FAIL" | "INCONCLUSIVE" | "PROVIDER_ERROR";
export type ProviderCheckInput = {
  taskId: string;
  evidenceId: string;
  subject: string;
  expectedCustomerId: string;
  requestKey: string;
  accessToken: string;
};
export type ProviderCheckQuery = {
  taskId: string;
  offset: number;
  limit: number;
};
export type Google2SvObservation = {
  id: string;
  customerId: string;
  primaryEmail: string;
  isEnrolledIn2Sv: boolean | null;
  isEnforcedIn2Sv: boolean | null;
  suspended: boolean | null;
  archived: boolean | null;
  etag: string | null;
};
export type ProviderCheckResult = {
  outcome: ProviderCheckOutcome;
  observedAt: Date | null;
  reason: string;
  metadata: Record<string, string | boolean | null>;
};
const provider = "GOOGLE_WORKSPACE";
const control = "google_workspace.user_2sv";
const userKey = /^[a-zA-Z0-9._%+@-]{3,254}$/;
const customerKey = /^C[a-zA-Z0-9]{5,40}$/;
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Provider check must be an object.");
  return value as Record<string, unknown>;
}
function strict(raw: Record<string, unknown>, allowed: string[]) {
  const unknown = Object.keys(raw).find(key => !allowed.includes(key));
  if (unknown)
    throw new WorkInputError("INVALID", "Unknown provider check field.");
}
function text(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "string" || value.trim().length < min ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseProviderCheckInput(value: unknown): ProviderCheckInput {
  const raw = object(value);
  strict(raw, [
    "taskId", "evidenceId", "subject", "expectedCustomerId",
    "requestKey", "accessToken",
  ]);
  const subject = text(raw.subject, "subject", 3, 254);
  const expectedCustomerId = text(raw.expectedCustomerId, "customer ID", 6, 41);
  if (!userKey.test(subject) || !customerKey.test(expectedCustomerId))
    throw new WorkInputError("INVALID", "Invalid Google Workspace identity.");
  const accessToken = text(raw.accessToken, "OAuth access token", 20, 8192);
  if (!/^[a-zA-Z0-9._~+\/-]+$/.test(accessToken))
    throw new WorkInputError("INVALID", "Invalid OAuth token format.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    evidenceId: parseWorkId(raw.evidenceId, "evidence ID"),
    subject,
    expectedCustomerId,
    requestKey: text(raw.requestKey, "idempotency key", 8, 160),
    accessToken,
  };
}
export function parseProviderCheckQuery(value: unknown): ProviderCheckQuery {
  const raw = object(value);
  strict(raw, ["taskId", "offset", "limit"]);
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
function booleanOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}
export function parseGoogle2SvObservation(value: unknown): Google2SvObservation {
  const raw = object(value);
  const id = text(raw.id, "Google user ID", 3, 128);
  const customerId = text(raw.customerId, "Google customer ID", 6, 41);
  const primaryEmail = text(raw.primaryEmail, "primary email", 3, 254);
  if (!customerKey.test(customerId) || !primaryEmail.includes("@"))
    throw new WorkInputError("INVALID", "Invalid Google user identity.");
  return {
    id, customerId, primaryEmail,
    isEnrolledIn2Sv: booleanOrNull(raw.isEnrolledIn2Sv),
    isEnforcedIn2Sv: booleanOrNull(raw.isEnforcedIn2Sv),
    suspended: booleanOrNull(raw.suspended),
    archived: booleanOrNull(raw.archived),
    etag: typeof raw.etag === "string" ? raw.etag.slice(0, 300) : null,
  };
}
export function evaluateGoogle2Sv(
  observation: Google2SvObservation,
  expectedCustomerId: string,
  subject: string,
): ProviderCheckResult {
  const metadata = {
    providerUserId: observation.id,
    customerId: observation.customerId,
    primaryEmail: observation.primaryEmail,
    isEnrolledIn2Sv: observation.isEnrolledIn2Sv,
    isEnforcedIn2Sv: observation.isEnforcedIn2Sv,
    suspended: observation.suspended,
    archived: observation.archived,
    etag: observation.etag,
  };
  if (observation.customerId !== expectedCustomerId)
    return {
      outcome: "INCONCLUSIVE", observedAt: null,
      reason: "Google customer identity does not match the bound evidence.",
      metadata,
    };
  if (subject.includes("@") &&
      observation.primaryEmail.toLowerCase() !== subject.toLowerCase())
    return {
      outcome: "INCONCLUSIVE", observedAt: null,
      reason: "Google returned a different user than requested.",
      metadata,
    };
  if (observation.suspended === true || observation.archived === true)
    return {
      outcome: "INCONCLUSIVE", observedAt: null,
      reason: "The account is suspended or archived; active account policy is not proven.",
      metadata,
    };
  if (observation.isEnrolledIn2Sv === null ||
      observation.isEnforcedIn2Sv === null)
    return {
      outcome: "INCONCLUSIVE", observedAt: null,
      reason: "Google did not return complete 2-step verification attributes.",
      metadata,
    };
  if (!observation.isEnrolledIn2Sv || !observation.isEnforcedIn2Sv)
    return {
      outcome: "FAIL", observedAt: null,
      reason: "Google reports 2-step verification enrollment or enforcement absent.",
      metadata,
    };
  return {
    outcome: "PASS", observedAt: null,
    reason: "Google reports enrollment and enforcement for this user.",
    metadata,
  };
}
export type ProviderRead = {
  status: number;
  response: unknown;
  receivedAt: Date;
};
export async function readGoogleWorkspaceUser(
  subject: string, accessToken: string,
  options?: { signal?: AbortSignal; fetcher?: typeof fetch },
): Promise<ProviderRead> {
  if (!userKey.test(subject))
    throw new WorkInputError("INVALID", "Invalid Google user identifier.");
  const url = "https://admin.googleapis.com/admin/directory/v1/users/" +
    encodeURIComponent(subject) +
    "?projection=basic&fields=id,customerId,primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,suspended,archived,etag";
  const fetcher = options?.fetcher ?? fetch;
  const response = await fetcher(url, {
    method: "GET",
    headers: {
      Authorization: "Bearer " + accessToken,
      Accept: "application/json",
    },
    redirect: "error",
    cache: "no-store",
    ...(options?.signal ? { signal: options.signal } : {}),
  });
  const receivedAt = new Date();
  const raw = await response.text();
  if (raw.length > 128000)
    throw new WorkInputError("INVALID", "Provider response too large.");
  let parsed: unknown = null;
  try { parsed = JSON.parse(raw); } catch {
    if (response.ok)
      throw new WorkInputError("INVALID", "Provider returned invalid JSON.");
  }
  return { status: response.status, response: parsed, receivedAt };
}
function providerFailure(status: number) {
  if (status === 401 || status === 403)
    return { code: "AUTHORIZATION_FAILED",
      message: "Google rejected the OAuth token or its permissions." };
  if (status === 404)
    return { code: "SUBJECT_NOT_FOUND",
      message: "Google did not find the requested user." };
  if (status === 429)
    return { code: "RATE_LIMITED",
      message: "Google rate-limited the verification request." };
  if (status >= 500)
    return { code: "PROVIDER_UNAVAILABLE",
      message: "Google service returned an error." };
  return { code: "PROVIDER_REJECTED",
    message: "Google could not complete the verification request." };
}
export function checkGoogle2SvResponse(
  read: ProviderRead, customerId: string, subject: string,
) {
  if (read.status !== 200) {
    const failure = providerFailure(read.status);
    return {
      outcome: "PROVIDER_ERROR" as const,
      observedAt: null,
      reason: failure.message,
      metadata: {
        providerStatus: read.status,
        receivedAt: read.receivedAt.toISOString(),
      },
      failureCode: failure.code,
      responseDigest: hash({ status: read.status, response: read.response }),
    };
  }
  try {
    const observation = parseGoogle2SvObservation(read.response);
    const evaluated = evaluateGoogle2Sv(observation, customerId, subject);
    return {
      ...evaluated, observedAt: read.receivedAt,
      failureCode: null,
      responseDigest: hash({ status: read.status, response: read.response }),
    };
  } catch {
    return {
      outcome: "INCONCLUSIVE" as const,
      observedAt: read.receivedAt,
      reason: "Google returned an incomplete or unexpected user response.",
      metadata: { providerStatus: read.status },
      failureCode: "INVALID_PROVIDER_RESPONSE",
      responseDigest: hash({ status: read.status, response: read.response }),
    };
  }
}
function assertWrite(scope: ReviewScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Provider checks require OWNER or ADMIN.");
}
function assertRead(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Provider checks are unavailable.");
}
function isConflict(error: unknown) {
  return typeof error === "object" && error !== null &&
    "code" in error && (error.code === "P2002" || error.code === "P2034");
}
export async function runGoogle2SvCheck(
  scope: ReviewScope, value: unknown,
  options?: { fetcher?: typeof fetch },
) {
  assertWrite(scope);
  const input = parseProviderCheckInput(value);
  // Tokens must never enter a request digest, database, audit event or log.
  const safeRequest = {
    provider, controlId: control,
    taskId: input.taskId, evidenceId: input.evidenceId,
    subject: input.subject,
    expectedCustomerId: input.expectedCustomerId,
  };
  const requestDigest = hash(safeRequest);
  const existing = await db.integrityProviderCheck.findFirst({
    where: {
      organizationId: scope.organizationId,
      requestedByUserId: scope.userId,
      requestKey: input.requestKey,
    },
  });
  if (existing) {
    if (existing.requestDigest !== requestDigest)
      throw new WorkInputError("CONFLICT", "Idempotency key already used.");
    return { check: existing, replayed: true };
  }
  const [task, evidence] = await Promise.all([
    db.integrityReviewTask.findFirst({
      where: { id: input.taskId, organizationId: scope.organizationId },
      select: { id: true, disposition: true },
    }),
    db.securityEvidence.findFirst({
      where: { id: input.evidenceId, organizationId: scope.organizationId },
    }),
  ]);
  if (!task || !evidence)
    throw new WorkInputError("MISSING", "Review or evidence not found.");
  if (task.disposition === "WAIVED")
    throw new WorkInputError("CONFLICT", "Waived reviews cannot be verified.");
  if (evidence.source !== provider || evidence.controlId !== control)
    throw new WorkInputError("INVALID", "Evidence is not a Google 2SV control.");
  const details = object(evidence.details);
  if (details.customerId !== input.expectedCustomerId ||
      details.subject !== input.subject)
    throw new WorkInputError("CONFLICT",
      "Requested Google identity does not match the bound evidence.");
  const snapshot = observationSnapshot(evidence);
  let read: ProviderRead;
  try {
    read = await readGoogleWorkspaceUser(
      input.subject, input.accessToken, {
        ...(options?.fetcher ? { fetcher: options.fetcher } : {}),
        signal: AbortSignal.timeout(15000),
      });
  } catch (error) {
    // Do not log the exception: a transport error could include token-bearing
    // request details from a custom fetch implementation.
    read = {
      status: 503, response: {
        transportFailure: error instanceof Error ? error.name : "UNKNOWN",
      }, receivedAt: new Date(),
    };
  }
  const checked = checkGoogle2SvResponse(
    read, input.expectedCustomerId, input.subject);
  try {
    return await db.$transaction(async tx => {
      const replay = await tx.integrityProviderCheck.findFirst({
        where: {
          organizationId: scope.organizationId,
          requestedByUserId: scope.userId,
          requestKey: input.requestKey,
        },
      });
      if (replay) {
        if (replay.requestDigest !== requestDigest)
          throw new WorkInputError("CONFLICT", "Idempotency key already used.");
        return { check: replay, replayed: true };
      }
      const current = await tx.securityEvidence.findFirst({
        where: { id: evidence.id, organizationId: scope.organizationId },
      });
      if (!current ||
          observationSnapshot(current).digest !== snapshot.digest)
        throw new WorkInputError("CONFLICT",
          "Evidence changed during remote verification; retry.");
      const check = await tx.integrityProviderCheck.create({
        data: {
          organizationId: scope.organizationId,
          taskId: input.taskId, evidenceId: input.evidenceId,
          provider, subject: input.subject, controlId: control,
          outcome: checked.outcome,
          providerObservedAt: checked.observedAt,
          requestedByUserId: scope.userId,
          requestKey: input.requestKey, requestDigest,
          observationDigest: snapshot.digest,
          responseDigest: checked.responseDigest,
          responseMetadata: checked.metadata as Prisma.InputJsonValue,
          failureCode: checked.failureCode,
          failureMessage: checked.outcome === "PROVIDER_ERROR" ?
            checked.reason : null,
        },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "integrity.provider.google_2sv.check",
          resourceType: "IntegrityProviderCheck",
          resourceId: check.id,
          metadata: {
            taskId: input.taskId, evidenceId: input.evidenceId,
            provider, subject: input.subject, controlId: control,
            outcome: checked.outcome,
            requestDigest, observationDigest: snapshot.digest,
            responseDigest: checked.responseDigest,
            failureCode: checked.failureCode,
          },
        },
      });
      return {
        check, replayed: false,
        limitations: [
          "Google returned a live user record; tenant identity is checked against the bound customer ID.",
          "A PASS is a point-in-time provider observation, not proof of durable security.",
          "This operation does not resolve a finding or modify remediation or CyberScore.",
        ],
      };
    }, { isolationLevel: "Serializable" });
  } catch (error) {
    if (isConflict(error)) {
      const replay = await db.integrityProviderCheck.findFirst({
        where: {
          organizationId: scope.organizationId,
          requestedByUserId: scope.userId,
          requestKey: input.requestKey,
        },
      });
      if (replay && replay.requestDigest === requestDigest)
        return { check: replay, replayed: true };
      throw new WorkInputError("CONFLICT", "Concurrent provider verification.");
    }
    throw error;
  }
}
export async function listProviderChecks(
  scope: ReviewScope, value: unknown,
) {
  assertRead(scope);
  const query = parseProviderCheckQuery(value);
  const task = await db.integrityReviewTask.findFirst({
    where: { id: query.taskId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const where = {
    organizationId: scope.organizationId, taskId: query.taskId,
  };
  const [total, checks] = await db.$transaction([
    db.integrityProviderCheck.count({ where }),
    db.integrityProviderCheck.findMany({
      where,
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, taskId: true, evidenceId: true,
        provider: true, subject: true, controlId: true,
        outcome: true, providerObservedAt: true,
        checkedAt: true, requestedByUserId: true,
        observationDigest: true, responseDigest: true,
        responseMetadata: true, failureCode: true,
      },
    }),
  ]);
  return {
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + checks.length < total,
    checks,
    limitations: [
      "Results reflect provider observations at their checked timestamps.",
      "Provider checks are separate from human assessments and remediation states.",
    ],
  };
}
