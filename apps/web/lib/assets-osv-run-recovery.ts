import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, WorkInputError } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";

/**
 * Incident recovery for one claimed OSV slot.
 * Marking UNKNOWN is a forensic classification, NEVER a release of a slot,
 * refund of provider capacity, or authorization to retry its network calls.
 */
export type OsvRunRecoveryPolicy = {
  minimumExpiredMinutes: number;
  maximumListed: number;
  includeRecentlyClaimed: boolean;
};
export type OsvRunRecoveryCandidate = {
  runId: string;
  scheduleId: string;
  slotAt: string;
  claimedAt: string;
  claimExpiresAt: string;
  expiredMinutes: number;
  eligible: boolean;
  state: string;
  commandDigest: string;
  sourceRequestKey: string;
  associatedInspectionId: string | null;
  associatedQuotaState: string | null;
  associatedQuotaRequests: number | null;
  reason: string;
};
export type OsvRunRecoveryPreview = {
  schema: "cyberpilot.assets.osv.run.recovery.preview.v1";
  organizationId: string;
  checkedAt: string;
  totalClaimed: number;
  displayed: number;
  eligible: number;
  truncated: boolean;
  policy: OsvRunRecoveryPolicy;
  candidates: OsvRunRecoveryCandidate[];
  digest: string;
  warnings: string[];
};
export type OsvRunRecoveryCommand = {
  runId: string;
  confirmRunId: string;
  expectedCommandDigest: string;
  minimumExpiredMinutes: number;
  reason: string;
  acknowledgeUnknownNetwork: true;
};
export type OsvRunRecoveryResult = {
  schema: "cyberpilot.assets.osv.run.recovery.result.v1";
  organizationId: string;
  scheduleId: string;
  runId: string;
  previousState: "CLAIMED" | "UNKNOWN";
  state: "UNKNOWN";
  changed: boolean;
  auditRecorded: boolean;
  quotaRefunded: false;
  slotReleased: false;
  providerRetried: false;
  associatedInspectionId: string | null;
  recoveredAt: string;
  digest: string;
  warnings: string[];
};
function reject(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return reject("OSV run recovery requires a JSON object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, field: string, low: number, high: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < low || value > high)
    return reject("Invalid run recovery " + field + ".");
  return value;
}
function id(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length < 8 ||
      value.length > 150 || !/^[a-zA-Z0-9_-]+$/.test(value))
    return reject("Invalid run recovery " + field + ".");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validTime(now: Date) {
  if (!Number.isFinite(now.getTime()))
    reject("Invalid incident evaluation time.");
}
export function parseOsvRunRecoveryPolicy(
  input: unknown = {},
): OsvRunRecoveryPolicy {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "minimumExpiredMinutes", "maximumListed", "includeRecentlyClaimed",
  ].includes(key))) reject("Unexpected run recovery policy field.");
  if (raw.includeRecentlyClaimed !== undefined &&
      typeof raw.includeRecentlyClaimed !== "boolean")
    reject("Invalid recently-claimed display option.");
  return {
    minimumExpiredMinutes: integer(raw.minimumExpiredMinutes ?? 30,
      "minimum expiry", 15, 10080),
    maximumListed: integer(raw.maximumListed ?? 50,
      "list limit", 1, 100),
    includeRecentlyClaimed: raw.includeRecentlyClaimed === true,
  };
}
export function parseOsvRunRecoveryCommand(input: unknown): OsvRunRecoveryCommand {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "runId", "confirmRunId", "expectedCommandDigest",
    "minimumExpiredMinutes", "reason", "acknowledgeUnknownNetwork",
  ].includes(key))) reject("Unknown run recovery command field.");
  const runId = id(raw.runId, "ID");
  if (raw.confirmRunId !== runId)
    reject("Operator must re-enter the exact schedule run ID.");
  const digest = raw.expectedCommandDigest;
  if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest))
    reject("Expected command digest must be SHA-256 hex.");
  const reason = raw.reason;
  if (typeof reason !== "string" || reason.trim().length < 20 ||
      reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason))
    reject("An investigation reason of 20-500 printable characters is required.");
  if (raw.acknowledgeUnknownNetwork !== true)
    reject("Unknown provider network outcome requires explicit acknowledgment.");
  return {
    runId, confirmRunId: runId, expectedCommandDigest: digest,
    minimumExpiredMinutes: integer(raw.minimumExpiredMinutes ?? 30,
      "minimum expiry", 15, 10080),
    reason: reason.trim(), acknowledgeUnknownNetwork: true,
  };
}
export type ClaimedRun = {
  id: string; organizationId: string; scheduleId: string;
  slotAt: Date; state: string; commandDigest: string;
  claimedAt: Date; claimExpiresAt: Date; inspectionId: string | null;
};
export function classifyRunClaim(
  row: ClaimedRun, now: Date, minExpiredMinutes: number,
): {
  eligible: boolean;
  expiredMinutes: number;
  reason: string;
} {
  validTime(now);
  const age = (now.getTime() - row.claimExpiresAt.getTime()) / 60000;
  const finite = Number.isFinite(age);
  const eligible = row.state === "CLAIMED" && finite &&
    age >= minExpiredMinutes;
  return {
    eligible,
    expiredMinutes: finite ? Math.floor(age) : -1,
    reason: row.state !== "CLAIMED" ?
      "Run already has a terminal state." :
      !finite || age < 0 ?
      "The claim has not expired or the timestamp is invalid." :
      !eligible ? "Investigation delay after claim expiry has not elapsed." :
      "The claim is stale and its upstream outcome must be considered unknown.",
  };
}
export function toOsvRunRecoveryCandidate(
  run: ClaimedRun,
  now: Date, minimumExpiredMinutes: number,
  quota?: { state: string; reservedRequests: number } | null,
  inspectionId?: string | null,
): OsvRunRecoveryCandidate {
  const status = classifyRunClaim(run, now, minimumExpiredMinutes);
  return {
    runId: run.id, scheduleId: run.scheduleId,
    slotAt: run.slotAt.toISOString(),
    claimedAt: run.claimedAt.toISOString(),
    claimExpiresAt: run.claimExpiresAt.toISOString(),
    expiredMinutes: status.expiredMinutes,
    eligible: status.eligible,
    state: run.state, commandDigest: run.commandDigest,
    sourceRequestKey: scheduledRequestKey(run.scheduleId, run.slotAt),
    associatedInspectionId: inspectionId ?? run.inspectionId,
    associatedQuotaState: quota?.state ?? null,
    associatedQuotaRequests: quota?.reservedRequests ?? null,
    reason: status.reason,
  };
}
function scheduledRequestKey(scheduleId: string, slotAt: Date) {
  return "scheduled-" + sha([
    "cyberpilot.osv.schedule.run.v1",
    scheduleId, slotAt.toISOString(),
  ]).slice(0, 48);
}
function reservationKey(scheduleId: string, slotAt: Date) {
  return "osv-ledger-" + scheduledRequestKey(scheduleId, slotAt);
}
export async function previewStalledOsvRuns(
  scope: AssetScope, input: unknown = {}, now = new Date(),
): Promise<OsvRunRecoveryPreview> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Administrator permission required for incident review.");
  validTime(now);
  const policy = parseOsvRunRecoveryPolicy(input);
  const where = {
    organizationId: scope.organizationId, state: "CLAIMED",
  };
  const [totalClaimed, rows] = await db.$transaction([
    db.assetOsvRenewalRun.count({ where }),
    db.assetOsvRenewalRun.findMany({
      where, orderBy: [{ claimExpiresAt: "asc" }, { id: "asc" }],
      take: policy.maximumListed + 1,
    }),
  ]);
  const candidates: OsvRunRecoveryCandidate[] = [];
  for (const row of rows.slice(0, policy.maximumListed)) {
    const key = scheduledRequestKey(row.scheduleId, row.slotAt);
    const [quota, inspection] = await Promise.all([
      db.assetOsvQuotaReservation.findFirst({
        where: {
          organizationId: scope.organizationId,
          requestKey: "osv-ledger-" + key,
        },
        select: { state: true, reservedRequests: true },
      }),
      db.assetOsvInspection.findFirst({
        where: { organizationId: scope.organizationId, requestKey: key },
        select: { id: true },
      }),
    ]);
    const candidate = toOsvRunRecoveryCandidate(
      row, now, policy.minimumExpiredMinutes, quota, inspection?.id);
    if (policy.includeRecentlyClaimed || candidate.eligible)
      candidates.push(candidate);
  }
  const canonical = {
    schema: "cyberpilot.assets.osv.run.recovery.preview.v1" as const,
    organizationId: scope.organizationId,
    checkedAt: now.toISOString(), totalClaimed,
    displayed: candidates.length,
    eligible: candidates.filter(row => row.eligible).length,
    truncated: totalClaimed > policy.maximumListed,
    policy, candidates,
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "An expired claim is not evidence that the provider did not receive requests.",
      "Associated quota reservations remain charged even if a run is marked UNKNOWN.",
      "Preview is read-only and neither repeats nor cancels any provider request.",
      "An already persisted inspection may exist even when the scheduling claim was never settled.",
      "At most the configured bounded number of claims is inspected; review truncation before operational changes.",
    ],
  };
}
function unchangedResult(
  scope: AssetScope,
  row: ClaimedRun,
  now: Date,
): OsvRunRecoveryResult {
  const canonical = {
    schema: "cyberpilot.assets.osv.run.recovery.result.v1" as const,
    organizationId: scope.organizationId,
    scheduleId: row.scheduleId, runId: row.id,
    previousState: "UNKNOWN" as const, state: "UNKNOWN" as const,
    changed: false, auditRecorded: false,
    quotaRefunded: false as const, slotReleased: false as const,
    providerRetried: false as const,
    associatedInspectionId: row.inspectionId,
    recoveredAt: now.toISOString(),
  };
  return { ...canonical, digest: sha(canonical), warnings: [
    "The run had already been marked UNKNOWN. No additional audit event was recorded.",
    "Reserved capacity and the unique due slot remain unchanged.",
  ] };
}
export async function markStalledOsvRunUnknown(
  scope: AssetScope, input: unknown,
  now = new Date(),
): Promise<OsvRunRecoveryResult> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Only administrators can classify unknown OSV runs.");
  validTime(now);
  const command = parseOsvRunRecoveryCommand(input);
  const row = await db.assetOsvRenewalRun.findFirst({
    where: { id: command.runId, organizationId: scope.organizationId },
  });
  if (!row) throw new WorkInputError("MISSING", "Schedule run not found.");
  if (row.commandDigest !== command.expectedCommandDigest)
    throw new WorkInputError("CONFLICT", "Run fingerprint differs from approved incident.");
  if (row.state === "UNKNOWN")
    return unchangedResult(scope, row, now);
  const assessment = classifyRunClaim(
    row, now, command.minimumExpiredMinutes);
  if (!assessment.eligible)
    throw new WorkInputError("CONFLICT", assessment.reason);
  // Both the claim and incident audit change atomically. The predicate
  // prevents settlement from racing with the running worker.
  const updated = await db.$transaction(async tx => {
    const changed = await tx.assetOsvRenewalRun.updateMany({
      where: {
        id: row.id, organizationId: scope.organizationId,
        scheduleId: row.scheduleId, commandDigest: row.commandDigest,
        state: "CLAIMED",
        claimExpiresAt: {
          lte: new Date(now.getTime() -
            command.minimumExpiredMinutes * 60000),
        },
      },
      data: {
        state: "UNKNOWN", errorCode: "WORKER_OUTCOME_UNKNOWN",
        completedAt: now,
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT",
        "Run state changed while incident recovery was being committed.");
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.schedule.run.unknown",
      resourceType: "AssetOsvRenewalRun", resourceId: row.id,
      metadata: {
        schema: "cyberpilot.assets.osv.run.recovery.audit.v1",
        scheduleId: row.scheduleId, commandDigest: row.commandDigest,
        slotAt: row.slotAt.toISOString(), reason: command.reason,
        claimedAt: row.claimedAt.toISOString(),
        claimExpiresAt: row.claimExpiresAt.toISOString(),
        expiryMinutes: command.minimumExpiredMinutes,
        mayHaveContactedProvider: true,
        refunded: false, retried: false, releasedSlot: false,
      },
    } });
    return changed.count;
  });
  const canonical = {
    schema: "cyberpilot.assets.osv.run.recovery.result.v1" as const,
    organizationId: scope.organizationId,
    scheduleId: row.scheduleId, runId: row.id,
    previousState: "CLAIMED" as const, state: "UNKNOWN" as const,
    changed: updated === 1, auditRecorded: updated === 1,
    quotaRefunded: false as const, slotReleased: false as const,
    providerRetried: false as const,
    associatedInspectionId: row.inspectionId,
    recoveredAt: now.toISOString(),
  };
  return { ...canonical, digest: sha(canonical), warnings: [
    "The provider network result remains unknown.",
    "No quota refund, remote retry or slot re-claim occurred.",
    "The incident classification and immutable audit event were committed transactionally.",
    "The scheduled time slot is still permanently consumed and cannot be re-dispatched.",
  ] };
}
