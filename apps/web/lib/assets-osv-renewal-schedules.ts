import { createHash, randomUUID } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { parseOfficialOsvInspection } from "./assets-osv-official-service";
import { parseRefreshPolicy } from "./assets-osv-refresh-policy";
import { previewOsvRenewal, executeOsvRenewal } from "./assets-osv-renewal";
import type { OsvRenewalOutcome, OsvRenewalPlan } from "./assets-osv-renewal";
import type { AssetScope } from "./assets-inventory-service";

const SCHEMA = "cyberpilot.assets.osv.schedule.v1" as const;
const RUN_SCHEMA = "cyberpilot.assets.osv.schedule.run.v1" as const;
const MAX_DUE_LAG_MS = 30 * 86400000;
const MAX_CLAIM_MS = 30 * 60000;
export type OsvScheduleConfig = {
  name: string;
  inventoryImportId: string;
  sourceInspectionId: string;
  cadenceMinutes: number;
  inspection: ReturnType<typeof parseOfficialOsvInspection>;
  policy: ReturnType<typeof parseRefreshPolicy>;
  allowNewPackages: boolean;
  allowIncompleteInventory: boolean;
};
export type OsvScheduleCommand = {
  scheduleId: string;
  expectedRevision: number;
  operation: "ENABLE" | "DISABLE" | "RECONFIGURE";
  confirmOutbound: boolean;
  consentDigest: string | null;
  config?: OsvScheduleConfig;
};
export type OsvScheduleSummary = {
  id: string;
  organizationId: string;
  name: string;
  inventoryImportId: string;
  sourceInspectionId: string;
  cadenceMinutes: number;
  enabled: boolean;
  outboundConsent: boolean;
  revision: number;
  consentDigest: string;
  nextDueAt: string;
  lastAttemptAt: string | null;
  lastSucceededAt: string | null;
  lastRunId: string | null;
  runCount: number;
  createdAt: string;
  updatedAt: string;
};
export type OsvScheduleList = {
  schema: "cyberpilot.assets.osv.schedule.list.v1";
  total: number;
  schedules: OsvScheduleSummary[];
  warnings: string[];
};
export type OsvSchedulePreview = {
  schema: "cyberpilot.assets.osv.schedule.preview.v1";
  scheduleId: string;
  organizationId: string;
  revision: number;
  enabled: boolean;
  due: boolean;
  checkedAt: string;
  dueAt: string;
  nextDueIfClaimed: string;
  claimable: boolean;
  checks: string[];
  renewal: OsvRenewalPlan | null;
  warnings: string[];
};
export type OsvScheduledRunResult = {
  schema: "cyberpilot.assets.osv.schedule.run.v1";
  scheduleId: string;
  runId: string;
  slotAt: string;
  nextDueAt: string;
  state: "COMPLETE" | "BLOCKED" | "FAILED";
  inspectionId: string | null;
  outcome: OsvRenewalOutcome | null;
  errorCode: string | null;
  warnings: string[];
};
export type OsvScheduleHistory = {
  schema: "cyberpilot.assets.osv.schedule.history.v1";
  scheduleId: string;
  total: number;
  runs: Array<{
    id: string; slotAt: string; state: string;
    commandDigest: string; claimedAt: string;
    completedAt: string | null; inspectionId: string | null;
    errorCode: string | null; result: unknown;
  }>;
};
function error(message: string, code: "INVALID" | "CONFLICT" = "INVALID"): never {
  throw new WorkInputError(code, message);
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return error("Expected schedule object.");
  return value as Record<string, unknown>;
}
function onlyFields(raw: Record<string, unknown>, fields: string[]) {
  for (const key of Object.keys(raw))
    if (!fields.includes(key))
      error("Unsupported schedule property: " + key);
}
function integer(value: unknown, name: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    error("Invalid schedule " + name + ".");
  return value;
}
function identity(value: unknown, label: string) {
  if (typeof value !== "string" || value.length < 8 ||
      value.length > 150 || !/^[a-zA-Z0-9_-]+$/.test(value))
    error("Invalid schedule " + label + ".");
  return value;
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validNow(now: Date) {
  if (!Number.isFinite(now.getTime()))
    error("Invalid current scheduling time.");
}
export function parseOsvScheduleConfig(input: unknown): OsvScheduleConfig {
  const raw = object(input);
  onlyFields(raw, [
    "name", "inventoryImportId", "sourceInspectionId", "cadenceMinutes",
    "inspection", "policy", "allowNewPackages", "allowIncompleteInventory",
  ]);
  const name = raw.name;
  if (typeof name !== "string" || name.trim().length < 3 ||
      name.length > 120 || /[\u0000-\u001f\u007f]/.test(name))
    error("Schedule name requires 3-120 printable characters.");
  const inventoryImportId = identity(raw.inventoryImportId, "inventory ID");
  const sourceInspectionId = identity(raw.sourceInspectionId, "source inspection ID");
  const cadenceMinutes = integer(raw.cadenceMinutes, "cadence", 60, 43200);
  const inspection = parseOfficialOsvInspection(raw.inspection);
  if (!inspection.dryRun || inspection.importId !== inventoryImportId)
    error("Scheduled inspection must be a preview of its own inventory.");
  const policy = parseRefreshPolicy(raw.policy ?? {});
  if (policy.freshnessMinutes > cadenceMinutes * 5)
    error("Schedule freshness cannot exceed five cadence intervals.");
  if (raw.allowNewPackages !== undefined &&
      typeof raw.allowNewPackages !== "boolean")
    error("Invalid new-package authorization.");
  if (raw.allowIncompleteInventory !== undefined &&
      typeof raw.allowIncompleteInventory !== "boolean")
    error("Invalid partial-inventory authorization.");
  return {
    name: name.trim(), inventoryImportId, sourceInspectionId, cadenceMinutes,
    inspection, policy,
    allowNewPackages: raw.allowNewPackages === true,
    allowIncompleteInventory: raw.allowIncompleteInventory === true,
  };
}
export function parseOsvScheduleCommand(input: unknown): OsvScheduleCommand {
  const raw = object(input);
  onlyFields(raw, [
    "scheduleId", "expectedRevision", "operation", "confirmOutbound",
    "consentDigest", "config",
  ]);
  const operation = raw.operation;
  if (operation !== "ENABLE" && operation !== "DISABLE" &&
      operation !== "RECONFIGURE")
    error("Unknown OSV schedule action.");
  const consentDigest = raw.consentDigest;
  if (consentDigest !== undefined && consentDigest !== null &&
      (typeof consentDigest !== "string" ||
       !/^[a-f0-9]{64}$/.test(consentDigest)))
    error("Invalid schedule consent digest.");
  if (raw.confirmOutbound !== undefined &&
      typeof raw.confirmOutbound !== "boolean")
    error("Invalid schedule outbound confirmation.");
  if (operation === "ENABLE" &&
      (raw.confirmOutbound !== true || !consentDigest))
    error("Enabling a schedule requires explicit outbound authorization.");
  if (operation === "RECONFIGURE" && !raw.config)
    error("A new schedule configuration is required.");
  if (operation !== "RECONFIGURE" && raw.config !== undefined)
    error("Configuration may be changed only while reconfiguring.");
  return {
    scheduleId: identity(raw.scheduleId, "ID"),
    expectedRevision: integer(raw.expectedRevision, "revision", 1, 10000000),
    operation,
    confirmOutbound: raw.confirmOutbound === true,
    consentDigest: typeof consentDigest === "string" ? consentDigest : null,
    ...(raw.config ? { config: parseOsvScheduleConfig(raw.config) } : {}),
  };
}
export function scheduleConsentDigest(
  organizationId: string, config: OsvScheduleConfig,
) {
  const canonical = {
    schema: SCHEMA, organizationId,
    inventoryImportId: config.inventoryImportId,
    sourceInspectionId: config.sourceInspectionId,
    name: config.name,
    cadenceMinutes: config.cadenceMinutes,
    inspection: { ...config.inspection,
      packageBindings: [...config.inspection.packageBindings].sort((a, b) =>
        a.inventoryProduct.localeCompare(b.inventoryProduct) ||
        a.packageName.localeCompare(b.packageName)),
    },
    policy: config.policy,
    allowNewPackages: config.allowNewPackages,
    allowIncompleteInventory: config.allowIncompleteInventory,
  };
  return digest(canonical);
}
export function nextOsvDueAt(previousDue: Date, cadenceMinutes: number,
  now: Date): Date {
  validNow(now);
  validNow(previousDue);
  integer(cadenceMinutes, "cadence", 60, 43200);
  if (previousDue.getTime() > now.getTime())
    return new Date(previousDue.getTime());
  const period = cadenceMinutes * 60000;
  const elapsed = now.getTime() - previousDue.getTime();
  return new Date(previousDue.getTime() +
    (Math.floor(elapsed / period) + 1) * period);
}
export function scheduleRunIdempotencyKey(scheduleId: string, slotAt: Date) {
  return "scheduled-" + digest([
    "cyberpilot.osv.schedule.run.v1", scheduleId, slotAt.toISOString(),
  ]).slice(0, 48);
}
function configFromStored(item: {
  name: string; inventoryImportId: string; sourceInspectionId: string;
  cadenceMinutes: number; inspection: unknown; policy: unknown;
  allowNewPackages: boolean; allowIncompleteInventory: boolean;
}): OsvScheduleConfig {
  return parseOsvScheduleConfig({
    name: item.name, inventoryImportId: item.inventoryImportId,
    sourceInspectionId: item.sourceInspectionId,
    cadenceMinutes: item.cadenceMinutes,
    inspection: item.inspection, policy: item.policy,
    allowNewPackages: item.allowNewPackages,
    allowIncompleteInventory: item.allowIncompleteInventory,
  });
}
function summary(value: {
  id: string; organizationId: string; name: string;
  inventoryImportId: string; sourceInspectionId: string;
  cadenceMinutes: number; enabled: boolean; outboundConsent: boolean;
  revision: number; consentDigest: string; nextDueAt: Date;
  lastAttemptAt: Date | null; lastSucceededAt: Date | null;
  lastRunId: string | null; createdAt: Date; updatedAt: Date;
  _count?: { runs: number };
}): OsvScheduleSummary {
  return {
    id: value.id, organizationId: value.organizationId,
    name: value.name, inventoryImportId: value.inventoryImportId,
    sourceInspectionId: value.sourceInspectionId,
    cadenceMinutes: value.cadenceMinutes, enabled: value.enabled,
    outboundConsent: value.outboundConsent, revision: value.revision,
    consentDigest: value.consentDigest,
    nextDueAt: value.nextDueAt.toISOString(),
    lastAttemptAt: value.lastAttemptAt?.toISOString() ?? null,
    lastSucceededAt: value.lastSucceededAt?.toISOString() ?? null,
    lastRunId: value.lastRunId,
    runCount: value._count?.runs ?? 0,
    createdAt: value.createdAt.toISOString(),
    updatedAt: value.updatedAt.toISOString(),
  };
}
export function scheduleEligibility(
  enabled: boolean, outboundConsent: boolean,
  dueAt: Date, now: Date,
): string[] {
  validNow(now);
  const problems: string[] = [];
  if (!enabled) problems.push("This schedule is disabled.");
  if (!outboundConsent)
    problems.push("The schedule has no active outbound authorization.");
  if (dueAt.getTime() > now.getTime())
    problems.push("The next scheduled interval is not yet due.");
  if (dueAt.getTime() < now.getTime() - MAX_DUE_LAG_MS)
    problems.push("The scheduled interval is too old; investigate the skipped period.");
  return problems;
}
export async function createOsvSchedule(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvScheduleSummary> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Only admins can create OSV schedules.");
  validNow(now);
  const config = parseOsvScheduleConfig(input);
  const prior = await db.assetOsvInspection.findFirst({
    where: {
      id: config.sourceInspectionId,
      organizationId: scope.organizationId,
      inventoryImportId: config.inventoryImportId,
    },
    select: { id: true },
  });
  if (!prior) throw new WorkInputError("MISSING",
    "The schedule source inspection is not accessible.");
  const inventory = await db.assetInventoryImport.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: config.inventoryImportId, state: "COMMITTED",
    }, select: { id: true },
  });
  if (!inventory) throw new WorkInputError("CONFLICT",
    "Schedules require an active inventory.");
  const count = await db.assetOsvRenewalSchedule.count({
    where: { organizationId: scope.organizationId },
  });
  if (count >= 50)
    throw new WorkInputError("CONFLICT", "Maximum schedules per organization reached.");
  const created = await db.$transaction(async tx => {
    const schedule = await tx.assetOsvRenewalSchedule.create({
      data: {
        organizationId: scope.organizationId,
        inventoryImportId: config.inventoryImportId,
        sourceInspectionId: config.sourceInspectionId,
        createdByUserId: scope.userId,
        name: config.name, cadenceMinutes: config.cadenceMinutes,
        nextDueAt: new Date(now.getTime() + config.cadenceMinutes * 60000),
        inspection: JSON.parse(JSON.stringify(config.inspection)),
        policy: JSON.parse(JSON.stringify(config.policy)),
        allowNewPackages: config.allowNewPackages,
        allowIncompleteInventory: config.allowIncompleteInventory,
        consentDigest: scheduleConsentDigest(scope.organizationId, config),
        enabled: false, outboundConsent: false,
      },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.schedule.created",
      resourceType: "AssetOsvRenewalSchedule", resourceId: schedule.id,
      metadata: {
        schema: SCHEMA, revision: schedule.revision,
        consentDigest: schedule.consentDigest,
        enabled: false, outboundConsent: false,
        sourceInspectionId: config.sourceInspectionId,
      },
    } });
    return schedule;
  });
  return summary(created);
}
export async function listOsvSchedules(
  scope: AssetScope,
): Promise<OsvScheduleList> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV schedule access denied.");
  const schedules = await db.assetOsvRenewalSchedule.findMany({
    where: { organizationId: scope.organizationId },
    include: { _count: { select: { runs: true } } },
    orderBy: [{ enabled: "desc" }, { nextDueAt: "asc" }],
    take: 50,
  });
  return {
    schema: "cyberpilot.assets.osv.schedule.list.v1",
    total: schedules.length, schedules: schedules.map(summary),
    warnings: [
      "Definitions are stored but there is no installed autonomous cron trigger.",
      "Only an authorized administrator can enable or execute a due schedule.",
      "A schedule never changes endpoint security claims or CyberScore.",
    ],
  };
}
export async function changeOsvSchedule(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvScheduleSummary> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV schedule changes require administrator permission.");
  validNow(now);
  const command = parseOsvScheduleCommand(input);
  const item = await db.assetOsvRenewalSchedule.findFirst({
    where: { organizationId: scope.organizationId, id: command.scheduleId },
  });
  if (!item) throw new WorkInputError("MISSING", "Schedule not found.");
  if (item.revision !== command.expectedRevision)
    throw new WorkInputError("CONFLICT", "Schedule revision has changed.");
  if (command.operation === "ENABLE") {
    const config = configFromStored(item);
    if (command.consentDigest !== item.consentDigest ||
        item.consentDigest !== scheduleConsentDigest(scope.organizationId, config))
      throw new WorkInputError("CONFLICT", "Authorization does not match stored schedule.");
    const current = await db.assetInventoryImport.findFirst({
      where: {
        organizationId: scope.organizationId,
        id: config.inventoryImportId, state: "COMMITTED",
      }, select: { id: true },
    });
    if (!current) throw new WorkInputError("CONFLICT",
      "Cannot enable renewals for a retired inventory.");
  }
  const config = command.config;
  if (command.operation === "RECONFIGURE" && config) {
    if (item.enabled)
      throw new WorkInputError("CONFLICT", "Disable schedule before reconfiguring.");
    if (config.inventoryImportId !== item.inventoryImportId)
      throw new WorkInputError("INVALID",
        "Changing the inventory requires a new schedule.");
    const source = await db.assetOsvInspection.findFirst({
      where: {
        organizationId: scope.organizationId,
        inventoryImportId: item.inventoryImportId,
        id: config.sourceInspectionId,
      }, select: { id: true },
    });
    if (!source) throw new WorkInputError("MISSING",
      "New historical inspection source is unavailable.");
  }
  const updated = await db.$transaction(async tx => {
    const current = await tx.assetOsvRenewalSchedule.updateMany({
      where: {
        id: item.id, organizationId: scope.organizationId,
        revision: command.expectedRevision,
      },
      data: {
        revision: { increment: 1 },
        ...(command.operation === "ENABLE" ? {
          enabled: true, outboundConsent: true, consentedAt: now,
        } : {}),
        ...(command.operation === "DISABLE" ? {
          enabled: false, outboundConsent: false, consentedAt: null,
        } : {}),
        ...(command.operation === "RECONFIGURE" && config ? {
          enabled: false, outboundConsent: false, consentedAt: null,
          name: config.name, sourceInspectionId: config.sourceInspectionId,
          cadenceMinutes: config.cadenceMinutes,
          nextDueAt: new Date(now.getTime() + config.cadenceMinutes * 60000),
          policy: JSON.parse(JSON.stringify(config.policy)),
          inspection: JSON.parse(JSON.stringify(config.inspection)),
          allowNewPackages: config.allowNewPackages,
          allowIncompleteInventory: config.allowIncompleteInventory,
          consentDigest: scheduleConsentDigest(scope.organizationId, config),
        } : {}),
      },
    });
    if (current.count !== 1)
      throw new WorkInputError("CONFLICT", "Concurrent schedule update detected.");
    const result = await tx.assetOsvRenewalSchedule.findUniqueOrThrow({
      where: { id: item.id },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.schedule." + command.operation.toLowerCase(),
      resourceType: "AssetOsvRenewalSchedule", resourceId: result.id,
      metadata: {
        schema: SCHEMA, revisionBefore: command.expectedRevision,
        revisionAfter: result.revision,
        consentDigest: result.consentDigest,
        enabled: result.enabled, outboundConsent: result.outboundConsent,
      },
    } });
    return result;
  });
  return summary(updated);
}
export async function previewDueOsvSchedule(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvSchedulePreview> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Schedule planning requires administrator access.");
  validNow(now);
  const raw = object(input);
  onlyFields(raw, ["scheduleId"]);
  const scheduleId = identity(raw.scheduleId, "ID");
  const item = await db.assetOsvRenewalSchedule.findFirst({
    where: { id: scheduleId, organizationId: scope.organizationId },
  });
  if (!item) throw new WorkInputError("MISSING", "Schedule not found.");
  const checks = scheduleEligibility(
    item.enabled, item.outboundConsent, item.nextDueAt, now);
  const config = configFromStored(item);
  if (scheduleConsentDigest(scope.organizationId, config) !== item.consentDigest)
    checks.push("Schedule configuration no longer matches the original authorization.");
  const requestKey = scheduleRunIdempotencyKey(item.id, item.nextDueAt);
  const renewalInput = {
    sourceInspectionId: config.sourceInspectionId,
    requestKey,
    inspection: { ...config.inspection, dryRun: true },
    policy: config.policy, dryRun: true, confirmOutbound: false,
    expectedPlanDigest: null,
    allowNewPackages: config.allowNewPackages,
    allowIncompleteInventory: config.allowIncompleteInventory,
  };
  let renewal: OsvRenewalPlan | null = null;
  try {
    renewal = await previewOsvRenewal(scope, renewalInput, now);
    if (!renewal.validForExecution)
      checks.push(...renewal.blockingReasons);
  } catch (cause) {
    if (cause instanceof WorkInputError)
      checks.push("Renewal cannot be planned: " + cause.message);
    else throw cause;
  }
  const next = nextOsvDueAt(item.nextDueAt, item.cadenceMinutes, now);
  return {
    schema: "cyberpilot.assets.osv.schedule.preview.v1",
    scheduleId: item.id, organizationId: scope.organizationId,
    revision: item.revision, enabled: item.enabled,
    due: item.nextDueAt <= now,
    checkedAt: now.toISOString(), dueAt: item.nextDueAt.toISOString(),
    nextDueIfClaimed: next.toISOString(),
    claimable: checks.length === 0,
    checks, renewal,
    warnings: [
      "Preview has no remote requests, quota reservations or database writes.",
      "A due schedule is not evidence that a renewal succeeded.",
      "This endpoint does not install or invoke a background timer.",
    ],
  };
}
export async function listOsvScheduleRuns(
  scope: AssetScope, scheduleIdInput: unknown,
): Promise<OsvScheduleHistory> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Schedule run history access denied.");
  const scheduleId = identity(scheduleIdInput, "ID");
  const found = await db.assetOsvRenewalSchedule.findFirst({
    where: { id: scheduleId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!found) throw new WorkInputError("MISSING", "Schedule not found.");
  const where = { organizationId: scope.organizationId, scheduleId };
  const [total, rows] = await db.$transaction([
    db.assetOsvRenewalRun.count({ where }),
    db.assetOsvRenewalRun.findMany({
      where, take: 50,
      orderBy: [{ slotAt: "desc" }, { id: "desc" }],
    }),
  ]);
  return {
    schema: "cyberpilot.assets.osv.schedule.history.v1",
    scheduleId, total,
    runs: rows.map(row => ({
      id: row.id, slotAt: row.slotAt.toISOString(),
      state: row.state, commandDigest: row.commandDigest,
      claimedAt: row.claimedAt.toISOString(),
      completedAt: row.completedAt?.toISOString() ?? null,
      inspectionId: row.inspectionId, errorCode: row.errorCode,
      result: row.result,
    })),
  };
}
export type ScheduleRunDependencies = {
  now?: () => Date;
  preview?: typeof previewOsvRenewal;
  execute?: typeof executeOsvRenewal;
};
export async function executeDueOsvSchedule(
  scope: AssetScope, input: unknown,
  dependencies: ScheduleRunDependencies = {},
): Promise<OsvScheduledRunResult> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Schedule dispatch requires administrator permission.");
  const raw = object(input);
  onlyFields(raw, ["scheduleId", "expectedRevision", "confirmDispatch"]);
  const scheduleId = identity(raw.scheduleId, "ID");
  const expectedRevision = integer(raw.expectedRevision, "revision", 1, 10000000);
  if (raw.confirmDispatch !== true)
    error("A due schedule needs explicit dispatch authorization.");
  const now = dependencies.now?.() ?? new Date();
  validNow(now);
  const item = await db.assetOsvRenewalSchedule.findFirst({
    where: { id: scheduleId, organizationId: scope.organizationId },
  });
  if (!item) throw new WorkInputError("MISSING", "Schedule not found.");
  if (item.revision !== expectedRevision)
    throw new WorkInputError("CONFLICT", "Schedule revision changed.");
  const checks = scheduleEligibility(
    item.enabled, item.outboundConsent, item.nextDueAt, now);
  const config = configFromStored(item);
  if (scheduleConsentDigest(scope.organizationId, config) !== item.consentDigest)
    checks.push("Stored consent no longer matches the schedule.");
  if (checks.length)
    throw new WorkInputError("CONFLICT", checks.join(" "));
  const slotAt = item.nextDueAt;
  const nextDueAt = nextOsvDueAt(slotAt, item.cadenceMinutes, now);
  const requestKey = scheduleRunIdempotencyKey(scheduleId, slotAt);
  const fingerprint = digest({
    scheduleId, revision: expectedRevision,
    slotAt: slotAt.toISOString(), consentDigest: item.consentDigest,
    requestKey,
  });
  const claimToken = randomUUID().replaceAll("-", "").padEnd(64, "0");
  const run = await db.$transaction(async tx => {
    const changed = await tx.assetOsvRenewalSchedule.updateMany({
      where: {
        id: item.id, organizationId: scope.organizationId,
        revision: expectedRevision,
        enabled: true, outboundConsent: true,
        nextDueAt: slotAt,
      },
      data: {
        nextDueAt, lastAttemptAt: now,
        revision: { increment: 1 },
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT",
        "A worker already claimed this schedule slot.");
    const created = await tx.assetOsvRenewalRun.create({
      data: {
        organizationId: scope.organizationId,
        scheduleId: item.id, slotAt, state: "CLAIMED",
        commandDigest: fingerprint, claimToken,
        claimExpiresAt: new Date(now.getTime() + MAX_CLAIM_MS),
        requestedByUserId: scope.userId,
      },
    });
    await tx.assetOsvRenewalSchedule.update({
      where: { id: item.id }, data: { lastRunId: created.id },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.schedule.run.claimed",
      resourceType: "AssetOsvRenewalRun", resourceId: created.id,
      metadata: { schema: RUN_SCHEMA, scheduleId, slotAt,
        commandDigest: fingerprint, consentDigest: item.consentDigest,
        nextDueAt },
    } });
    return created;
  });
  let outcome: OsvRenewalOutcome | null = null;
  let state: "COMPLETE" | "BLOCKED" | "FAILED" = "FAILED";
  let errorCode: string | null = null;
  try {
    const request = {
      sourceInspectionId: config.sourceInspectionId,
      requestKey,
      inspection: { ...config.inspection, dryRun: true },
      policy: config.policy,
      dryRun: true, confirmOutbound: false, expectedPlanDigest: null,
      allowNewPackages: config.allowNewPackages,
      allowIncompleteInventory: config.allowIncompleteInventory,
    };
    const plan = await (dependencies.preview ?? previewOsvRenewal)(
      scope, request, dependencies.now?.() ?? new Date());
    if (!plan.validForExecution) {
      state = "BLOCKED";
      errorCode = "PLAN_NOT_ELIGIBLE";
    } else {
      outcome = await (dependencies.execute ?? executeOsvRenewal)(
        scope, {
          ...request,
          inspection: { ...request.inspection, dryRun: false },
          dryRun: false, confirmOutbound: true,
          expectedPlanDigest: plan.planDigest,
        }, dependencies.now ? { now: dependencies.now } : {},
      );
      state = "COMPLETE";
    }
  } catch (cause) {
    state = "FAILED";
    errorCode = cause instanceof WorkInputError ?
      cause.code : "PROVIDER_OR_DATABASE_FAILURE";
  }
  const completed = dependencies.now?.() ?? new Date();
  const result: OsvScheduledRunResult = {
    schema: RUN_SCHEMA, scheduleId,
    runId: run.id, slotAt: slotAt.toISOString(),
    nextDueAt: nextDueAt.toISOString(), state,
    inspectionId: outcome?.currentInspectionId ?? null,
    outcome, errorCode,
    warnings: [
      "A claimed time slot is never re-run automatically after failure.",
      "The provider may have received a request even when the outcome is FAILED.",
      "The next renewal needs a new authorized due slot and atomic provider quota.",
      "The claim and audit records are tenant-scoped and durable.",
    ],
  };
  await db.$transaction(async tx => {
    const changed = await tx.assetOsvRenewalRun.updateMany({
      where: {
        id: run.id, organizationId: scope.organizationId,
        state: "CLAIMED", claimToken,
      },
      data: {
        state, errorCode, inspectionId: result.inspectionId,
        result: JSON.parse(JSON.stringify(result)),
        completedAt: completed,
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT",
        "Schedule run was already settled or recovered.");
    if (state === "COMPLETE") {
      await tx.assetOsvRenewalSchedule.updateMany({
        where: { id: item.id, organizationId: scope.organizationId },
        data: { lastSucceededAt: completed },
      });
    }
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.schedule.run." + state.toLowerCase(),
      resourceType: "AssetOsvRenewalRun", resourceId: run.id,
      metadata: {
        schema: RUN_SCHEMA, scheduleId,
        commandDigest: fingerprint,
        errorCode, inspectionId: result.inspectionId,
        slotAt: slotAt.toISOString(),
      },
    } });
  });
  return result;
}
