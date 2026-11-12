import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";

export type AssetPurgeCandidate = {
  importId: string;
  state: "COMMITTED" | "RETIRED";
  sourceLabel: string;
  createdAt: Date;
  retiredAt: Date | null;
  importedCount: number;
  payloadDigest: string;
};
export type AssetRetentionPolicy = {
  minimumRetiredDays: number;
  maximumCandidateAgeDays: number;
  limit: number;
  offset: number;
};
export type AssetRetentionRow = {
  importId: string;
  state: string;
  sourceLabel: string;
  importedCount: number;
  ageDays: number;
  daysSinceRetirement: number | null;
  eligible: boolean;
  reason: string;
  fingerprint: string;
};
export type AssetRetentionReport = {
  schema: "cyberpilot.assets.retention.v1";
  organizationId: string;
  generatedAt: string;
  policy: AssetRetentionPolicy;
  total: number;
  hasMore: boolean;
  candidates: AssetRetentionRow[];
  eligibleOnPage: number;
  blockedOnPage: number;
  digest: string;
  warnings: string[];
};
export type AssetPurgeCommand = {
  importId: string;
  expectedDigest: string;
  confirmImportId: string;
  confirmPurge: true;
  minimumRetiredDays: number;
  reason: string;
  dryRun: boolean;
  idempotencyKey: string;
};
export type AssetPurgePreview = {
  schema: "cyberpilot.assets.purge.v1";
  importId: string;
  organizationId: string;
  dryRun: boolean;
  replayed: boolean;
  status: "PREVIEW" | "PURGED" | "REPLAYED";
  devicesAffected: number;
  stateBefore: string;
  confirmationDigest: string;
  provenanceDigest: string;
  auditAction: string;
  warnings: string[];
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected asset lifecycle object.");
  return value as Record<string, unknown>;
}
function strict(value: Record<string, unknown>, keys: readonly string[]) {
  const unexpected = Object.keys(value).find(key => !keys.includes(key));
  if (unexpected)
    throw new WorkInputError("INVALID", "Unknown lifecycle field: " + unexpected);
}
function int(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid lifecycle " + label + ".");
  return value;
}
function string(value: unknown, label: string, minimum: number, maximum: number) {
  if (typeof value !== "string" || value.trim().length < minimum ||
      value.length > maximum || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid lifecycle " + label + ".");
  return value.trim();
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseAssetRetentionPolicy(value: unknown): AssetRetentionPolicy {
  const raw = object(value);
  strict(raw, ["minimumRetiredDays", "maximumCandidateAgeDays", "limit", "offset"]);
  const minimumRetiredDays = int(raw.minimumRetiredDays ?? 30,
    "minimum retired days", 1, 3650);
  const maximumCandidateAgeDays = int(raw.maximumCandidateAgeDays ?? 365,
    "maximum candidate age days", 1, 3650);
  return {
    minimumRetiredDays, maximumCandidateAgeDays,
    offset: int(raw.offset ?? 0, "offset", 0, 1000000),
    limit: int(raw.limit ?? 50, "limit", 1, 100),
  };
}
export function parseAssetPurgeCommand(value: unknown): AssetPurgeCommand {
  const raw = object(value);
  strict(raw, [
    "importId", "expectedDigest", "confirmImportId", "confirmPurge",
    "minimumRetiredDays", "reason", "dryRun", "idempotencyKey",
  ]);
  const importId = parseWorkId(raw.importId, "import ID");
  if (raw.confirmPurge !== true)
    throw new WorkInputError("INVALID", "Explicit purge confirmation is required.");
  if (raw.confirmImportId !== importId)
    throw new WorkInputError("INVALID", "Purge confirmation ID does not match.");
  const expectedDigest = string(raw.expectedDigest,
    "expected snapshot digest", 64, 64);
  if (!/^[a-f0-9]{64}$/.test(expectedDigest))
    throw new WorkInputError("INVALID", "Invalid expected snapshot digest.");
  const reason = string(raw.reason, "purge reason", 20, 1000);
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid purge dryRun flag.");
  return {
    importId, expectedDigest,
    confirmImportId: importId, confirmPurge: true,
    minimumRetiredDays: int(raw.minimumRetiredDays ?? 30,
      "minimum retired days", 1, 3650),
    reason,
    dryRun: raw.dryRun !== false,
    idempotencyKey: string(raw.idempotencyKey, "purge key", 12, 150),
  };
}
export function purgeFingerprint(
  scope: Pick<AssetScope, "organizationId">,
  command: AssetPurgeCommand,
) {
  return hash({
    schema: "cyberpilot.assets.purge.command.v1",
    organizationId: scope.organizationId,
    importId: command.importId, expectedDigest: command.expectedDigest,
    minimumRetiredDays: command.minimumRetiredDays,
    reason: command.reason, idempotencyKey: command.idempotencyKey,
  });
}
export function retentionCandidate(
  row: AssetPurgeCandidate, now: Date,
  policy: Pick<AssetRetentionPolicy, "minimumRetiredDays" | "maximumCandidateAgeDays">,
): AssetRetentionRow {
  const ageDays = Math.max(0, Math.floor(
    (now.getTime() - row.createdAt.getTime()) / 86400000));
  const retired = row.retiredAt ?
    Math.max(0, Math.floor((now.getTime() - row.retiredAt.getTime()) / 86400000)) :
    null;
  let reason = "Eligible for an explicit independent purge request.";
  if (row.state !== "RETIRED")
    reason = "Only retired snapshots can be permanently purged.";
  else if (!row.retiredAt)
    reason = "The retirement timestamp is missing.";
  else if (row.retiredAt.getTime() > now.getTime())
    reason = "Retirement timestamp is in the future.";
  else if (retired !== null && retired < policy.minimumRetiredDays)
    reason = "The minimum retirement holding period has not elapsed.";
  else if (ageDays < policy.maximumCandidateAgeDays)
    reason = "Snapshot has not reached the age threshold for automatic consideration.";
  const eligible = reason === "Eligible for an explicit independent purge request.";
  const canonical = {
    importId: row.importId, state: row.state, sourceLabel: row.sourceLabel,
    importedCount: row.importedCount, ageDays,
    daysSinceRetirement: retired, eligible, reason,
  };
  return { ...canonical, fingerprint: hash(canonical) };
}
export function buildAssetRetentionReport(
  organizationId: string,
  policy: AssetRetentionPolicy,
  records: AssetPurgeCandidate[],
  total: number, now: Date,
): AssetRetentionReport {
  const candidates = records.map(record =>
    retentionCandidate(record, now, policy));
  const canonical = {
    schema: "cyberpilot.assets.retention.v1" as const,
    organizationId, generatedAt: now.toISOString(),
    policy, total, hasMore: policy.offset + candidates.length < total,
    candidates,
    eligibleOnPage: candidates.filter(x => x.eligible).length,
    blockedOnPage: candidates.filter(x => !x.eligible).length,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      "Retention candidate listing is read-only and scoped to the selected page.",
      "Retention thresholds are operational policies, not proof of legal compliance.",
      "No snapshot is deleted by the candidate report.",
      "Audit events are intentionally retained following a confirmed purge.",
      "Purge eligibility is revalidated inside the deletion transaction.",
      "Actual deletion requires a separate explicit authorized command.",
    ],
  };
}
export async function inspectAssetRetention(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<AssetRetentionReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Retention inspection requires administrator.");
  const policy = parseAssetRetentionPolicy(input);
  const where = { organizationId: scope.organizationId };
  const [total, imports] = await db.$transaction([
    db.assetInventoryImport.count({ where }),
    db.assetInventoryImport.findMany({
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: policy.offset, take: policy.limit,
      select: {
        id: true, state: true, sourceLabel: true,
        createdAt: true, retiredAt: true,
        importedCount: true, payloadDigest: true,
      },
    }),
  ]);
  return buildAssetRetentionReport(scope.organizationId, policy,
    imports.map(x => ({ ...x, importId: x.id })), total, now);
}
export function purgePreview(
  scope: AssetScope,
  command: AssetPurgeCommand,
  record: AssetPurgeCandidate,
  now: Date,
): AssetPurgePreview {
  if (record.state !== "RETIRED" || !record.retiredAt)
    throw new WorkInputError("CONFLICT", "Import must be retired before purging.");
  if (record.payloadDigest !== command.expectedDigest)
    throw new WorkInputError("CONFLICT", "Snapshot digest has changed.");
  const since = now.getTime() - record.retiredAt.getTime();
  if (since < command.minimumRetiredDays * 86400000 || since < 0)
    throw new WorkInputError("CONFLICT",
      "Mandatory post-retirement waiting period has not elapsed.");
  return {
    schema: "cyberpilot.assets.purge.v1",
    importId: record.importId, organizationId: scope.organizationId,
    dryRun: command.dryRun,
    replayed: false,
    status: "PREVIEW",
    devicesAffected: record.importedCount,
    stateBefore: record.state,
    confirmationDigest: purgeFingerprint(scope, command),
    provenanceDigest: record.payloadDigest,
    auditAction: "assets.csv.import.purged",
    warnings: [
      "Permanent purge deletes the snapshot and its device observation rows.",
      "The recorded audit trail retains import ID, digests and deletion metadata.",
      "Purge cannot be undone through the application.",
      "This is not proof of deletion from backups or downstream exports.",
      "No change to CyberScore or security findings is performed.",
    ],
  };
}
type PreviousPurge = {
  id: string; action: string; resourceId: string | null;
  metadata: unknown;
};
export function replayedPurge(
  scope: AssetScope, command: AssetPurgeCommand,
  audit: PreviousPurge | null,
): AssetPurgePreview | null {
  if (!audit) return null;
  const metadata = audit.metadata && typeof audit.metadata === "object" &&
    !Array.isArray(audit.metadata) ?
      audit.metadata as Record<string, unknown> : {};
  const digest = purgeFingerprint(scope, command);
  if (audit.resourceId !== command.importId ||
      metadata.fingerprint !== digest)
    throw new WorkInputError("CONFLICT",
      "Purge idempotency key reused for different command data.");
  const affected = metadata.deletedRows;
  const observed = metadata.snapshotDigest;
  if (typeof affected !== "number" || !Number.isSafeInteger(affected) ||
      typeof observed !== "string")
    throw new WorkInputError("CONFLICT", "Prior purge audit metadata is incomplete.");
  return {
    schema: "cyberpilot.assets.purge.v1",
    importId: command.importId, organizationId: scope.organizationId,
    dryRun: false, replayed: true, status: "REPLAYED",
    devicesAffected: affected, stateBefore: "RETIRED",
    confirmationDigest: digest, provenanceDigest: observed,
    auditAction: "assets.csv.import.purged",
    warnings: [
      "Existing audited purge was replayed; no new deletion occurred.",
      "The original device rows are no longer present in the active database.",
      "Backup retention is separate from the active database.",
    ],
  };
}
export async function purgeAssetInventory(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<AssetPurgePreview> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Permanent purge requires administrator.");
  const command = parseAssetPurgeCommand(input);
  const fingerprint = purgeFingerprint(scope, command);
  return db.$transaction(async tx => {
    const prior = await tx.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId,
        resourceType: "AssetInventoryImport",
        action: "assets.csv.import.purged",
        metadata: { path: ["purgeKey"], equals: command.idempotencyKey },
      },
      select: { id: true, action: true, resourceId: true, metadata: true },
    });
    const replay = replayedPurge(scope, command, prior);
    if (replay) return replay;
    const current = await tx.assetInventoryImport.findFirst({
      where: { id: command.importId, organizationId: scope.organizationId },
      select: {
        id: true, state: true, createdAt: true,
        retiredAt: true, sourceLabel: true,
        importedCount: true, payloadDigest: true,
      },
    });
    if (!current)
      throw new WorkInputError("MISSING", "Retired inventory snapshot not found.");
    const candidate = { ...current, importId: current.id };
    const preview = purgePreview(scope, command, candidate, now);
    const actual = await tx.assetInventoryDevice.count({
      where: { organizationId: scope.organizationId, importId: command.importId },
    });
    if (actual !== current.importedCount)
      throw new WorkInputError("CONFLICT",
        "Stored observation count differs from snapshot metadata.");
    if (command.dryRun) return preview;
    const deleted = await tx.assetInventoryImport.deleteMany({
      where: {
        id: command.importId, organizationId: scope.organizationId,
        state: "RETIRED", payloadDigest: command.expectedDigest,
        retiredAt: current.retiredAt,
      },
    });
    if (deleted.count !== 1)
      throw new WorkInputError("CONFLICT", "Snapshot changed during purge.");
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assets.csv.import.purged",
        resourceType: "AssetInventoryImport",
        resourceId: command.importId,
        metadata: {
          fingerprint, purgeKey: command.idempotencyKey,
          sourceLabel: current.sourceLabel,
          snapshotDigest: current.payloadDigest,
          deletedRows: actual,
          retainedDays: Math.floor(
            (now.getTime() - current.retiredAt!.getTime()) / 86400000),
          reason: command.reason, deletedAt: now.toISOString(),
          backupCaveat: true,
        },
      },
    });
    return {
      ...preview, dryRun: false, status: "PURGED" as const,
      devicesAffected: actual,
    };
  });
}
