import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, WorkInputError } from "./remediation-work-input";
import { parseOfficialOsvInspection, planOfficialOsvInspection } from "./assets-osv-official-service";
import type { OfficialOsvInspectionInput, OfficialOsvFetchDependencies } from "./assets-osv-official-service";
import { parseRefreshPolicy, classifyPackageRefresh, refreshPackageKey } from "./assets-osv-refresh-policy";
import type { RefreshPolicy, RefreshPackageState, RefreshPackageDecision } from "./assets-osv-refresh-policy";
import { persistOsvInspection } from "./assets-osv-inspection-ledger";
import type { OsvLedgerCommit } from "./assets-osv-inspection-ledger";
import { inspectOfficialOsvQuota, computeReservedRequestPages } from "./assets-osv-atomic-quota";
import { inspectOsvHistoryDelta } from "./assets-osv-refresh-service";
import type { OsvChangeReport } from "./assets-osv-refresh-policy";
import type { AssetScope } from "./assets-inventory-service";

export type OsvRenewalCommand = {
  sourceInspectionId: string;
  requestKey: string;
  inspection: OfficialOsvInspectionInput;
  policy: RefreshPolicy;
  dryRun: boolean;
  confirmOutbound: boolean;
  allowNewPackages: boolean;
  allowIncompleteInventory: boolean;
  expectedPlanDigest: string | null;
};
export type OsvRenewalDecision = {
  packageKey: string;
  ecosystem: string;
  packageName: string;
  version: string;
  classification: string;
  eligible: boolean;
  lastCheckedAt: string | null;
  lastProviderStatus: string | null;
  reason: string;
};
export type OsvRenewalPlan = {
  schema: "cyberpilot.assets.osv.renewal.plan.v1";
  organizationId: string;
  importId: string;
  sourceInspectionId: string;
  generatedAt: string;
  sourceCompletedAt: string;
  sourceStatus: string;
  selectedPackages: number;
  eligiblePackages: number;
  deferredPackages: number;
  missingPreviousPackages: number;
  unreviewedPackages: number;
  inventoryRows: number;
  unboundRows: number;
  invalidVersionRows: number;
  maximumHttpPages: number;
  capacityAvailable: boolean;
  quotaInspectionsRemaining: number;
  quotaRequestsRemaining: number;
  decisions: OsvRenewalDecision[];
  validForExecution: boolean;
  blockingReasons: string[];
  newPackagesApproved: boolean;
  partialInventoryApproved: boolean;
  planDigest: string;
  warnings: string[];
};
export type OsvRenewalOutcome = {
  schema: "cyberpilot.assets.osv.renewal.outcome.v1";
  organizationId: string;
  importId: string;
  previousInspectionId: string;
  currentInspectionId: string;
  replayed: boolean;
  status: string;
  newReportDigest: string;
  previousReportDigest: string;
  comparison: OsvChangeReport | null;
  completeComparison: boolean;
  warnings: string[];
};
type PreviousQuery = {
  inspectionId: string;
  ecosystem: string;
  packageName: string;
  version: string;
  queryKey: string;
  checkedAt: Date | null;
  providerStatus: string;
  observationCount: number;
  possibleIds: unknown;
  providerOnlyIds: unknown;
  withdrawnIds: unknown;
  unresolvedIds: unknown;
};
type PreviousInspection = {
  id: string;
  organizationId: string;
  inventoryImportId: string;
  status: string;
  completedAt: Date;
  reportDigest: string;
  queryCount: number;
  queries: PreviousQuery[];
};
type SnapshotRow = {
  externalId: string;
  softwareName: string;
  softwareVersion: string | null;
  versionStatus: string;
  normalizedProductKey: string;
};
function fail(message: string, code: "INVALID" | "CONFLICT" = "INVALID"): never {
  throw new WorkInputError(code, message);
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("OSV renewal request must be a JSON object.");
  return value as Record<string, unknown>;
}
function string(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "string" || value.length < min || value.length > max ||
      !/^[A-Za-z0-9_-]+$/.test(value))
    fail("Invalid OSV renewal " + label + ".");
  return value;
}
function advisoryIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string =>
    typeof item === "string" && /^[a-zA-Z0-9][a-zA-Z0-9._:+-]{1,119}$/.test(item)))].sort();
}
function previousToPackage(value: PreviousQuery): RefreshPackageState {
  return {
    inspectionId: value.inspectionId, queryKey: value.queryKey,
    ecosystem: value.ecosystem, packageName: value.packageName,
    version: value.version, checkedAt: value.checkedAt,
    providerStatus: value.providerStatus,
    observationCount: value.observationCount,
    possibleIds: advisoryIds(value.possibleIds),
    providerOnlyIds: advisoryIds(value.providerOnlyIds),
    withdrawnIds: advisoryIds(value.withdrawnIds),
    unresolvedIds: advisoryIds(value.unresolvedIds),
  };
}
export function parseOsvRenewalCommand(input: unknown): OsvRenewalCommand {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "sourceInspectionId", "requestKey", "inspection", "policy",
    "dryRun", "confirmOutbound", "expectedPlanDigest",
    "allowNewPackages", "allowIncompleteInventory",
  ].includes(key))) fail("Unexpected OSV renewal field.");
  const inspection = parseOfficialOsvInspection(raw.inspection);
  const dryRun = raw.dryRun !== false;
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    fail("Invalid renewal preview flag.");
  if (raw.allowNewPackages !== undefined && typeof raw.allowNewPackages !== "boolean")
    fail("Invalid new-package approval flag.");
  if (raw.allowIncompleteInventory !== undefined && typeof raw.allowIncompleteInventory !== "boolean")
    fail("Invalid partial-inventory approval flag.");
  if (raw.confirmOutbound !== undefined &&
      typeof raw.confirmOutbound !== "boolean")
    fail("Invalid outbound authorization flag.");
  const expectedPlanDigest = raw.expectedPlanDigest;
  if (expectedPlanDigest !== undefined && expectedPlanDigest !== null &&
      (typeof expectedPlanDigest !== "string" ||
       !/^[a-f0-9]{64}$/.test(expectedPlanDigest)))
    fail("Invalid renewal plan digest.");
  if (!dryRun && (!raw.confirmOutbound || !expectedPlanDigest))
    fail("Live renewal requires explicit authorization and a validated preview digest.");
  if (!dryRun && inspection.dryRun)
    fail("Live renewal requires inspection.dryRun=false.");
  if (dryRun && !inspection.dryRun)
    fail("Renewal preview requires inspection.dryRun=true.");
  return {
    sourceInspectionId: string(raw.sourceInspectionId, "source ID", 8, 150),
    requestKey: string(raw.requestKey, "idempotency key", 12, 150),
    inspection, policy: parseRefreshPolicy(raw.policy ?? {}),
    dryRun, confirmOutbound: raw.confirmOutbound === true,
    allowNewPackages: raw.allowNewPackages === true,
    allowIncompleteInventory: raw.allowIncompleteInventory === true,
    expectedPlanDigest: typeof expectedPlanDigest === "string" ?
      expectedPlanDigest : null,
  };
}
export function assertRenewalPrevious(
  scope: AssetScope, command: OsvRenewalCommand,
  previous: PreviousInspection,
): void {
  if (previous.organizationId !== scope.organizationId ||
      previous.inventoryImportId !== command.inspection.importId)
    fail("Renewal source must belong to the same organization and inventory.", "CONFLICT");
  if (previous.queries.length !== previous.queryCount ||
      previous.queryCount < 1 || previous.queryCount > 100)
    fail("Previous inspection does not have complete recorded query coverage.", "CONFLICT");
  if (!Number.isFinite(previous.completedAt.getTime()))
    fail("Invalid previous inspection completion date.", "CONFLICT");
}
export function evaluateRenewalPlan(
  scope: AssetScope, command: OsvRenewalCommand,
  previous: PreviousInspection, rows: SnapshotRow[],
  quota: {
    inspectionsRemaining: number; requestsRemaining: number;
  }, now: Date,
  recentQueries: PreviousQuery[] = previous.queries,
): OsvRenewalPlan {
  assertRenewalPrevious(scope, command, previous);
  if (!Number.isFinite(now.getTime())) fail("Invalid renewal time.");
  const coverage = planOfficialOsvInspection(
    command.inspection.importId, rows,
    command.inspection.packageBindings, command.inspection.limitPackages);
  if (!coverage.allRowsAccountedFor) fail("Inconsistent inventory mappings.", "CONFLICT");
  // A selected historical source is an audit reference, not permission to
  // bypass newer complete checks of the same package/version. Consult all
  // recorded queries of the active inventory, then use the latest timestamp.
  const prior = new Map<string, RefreshPackageState>();
  for (const value of recentQueries) {
    const item = previousToPackage(value);
    const key = refreshPackageKey(item);
    const current = prior.get(key);
    if (!current || (item.checkedAt?.getTime() ?? -Infinity) >
        (current.checkedAt?.getTime() ?? -Infinity))
      prior.set(key, item);
  }
  const decisions: OsvRenewalDecision[] = [];
  for (const entry of coverage.work) {
    const key = JSON.stringify([entry.ecosystem, entry.name, entry.version]);
    const old = prior.get(key);
    const status: RefreshPackageDecision | null = old ?
      classifyPackageRefresh(old, command.policy, now) : null;
    decisions.push({
      packageKey: key, ecosystem: entry.ecosystem,
      packageName: entry.name, version: entry.version,
      classification: status?.state ?? "NEW_PACKAGE",
      eligible: status?.shouldRefresh ?? true,
      lastCheckedAt: status?.lastCheckedAt ?? null,
      lastProviderStatus: status?.lastProviderStatus ?? null,
      reason: !old ?
        "This package/version was absent from the chosen historical inspection." :
        status!.reasons.join(" "),
    });
  }
  const allEligible = decisions.every(x => x.eligible);
  const maximumHttpPages = computeReservedRequestPages(
    coverage.selectedPackages, command.inspection.maxPagesPerPackage);
  const capacityAvailable = quota.inspectionsRemaining >= 1 &&
    quota.requestsRemaining >= maximumHttpPages;
  const blockingReasons: string[] = [];
  if (coverage.selectedPackages === 0)
    blockingReasons.push("No eligible package-version queries were selected.");
  if (!allEligible)
    blockingReasons.push(
      "At least one package is fresh, still cooling down, or has inconsistent provider timestamps.");
  if (coverage.skippedPackages > 0)
    blockingReasons.push(
      "The query limit omitted known package versions from the inventory.");
  if (!capacityAvailable)
    blockingReasons.push(
      "Atomic quota has insufficient inspections or reserved HTTP pages remaining.");
  if (decisions.some(item => item.classification === "NEW_PACKAGE") &&
      !command.allowNewPackages)
    blockingReasons.push(
      "New package-version identities require explicit operator approval.");
  if ((coverage.unmappedRows + coverage.invalidVersionRows) > 0 &&
      !command.allowIncompleteInventory)
    blockingReasons.push(
      "Incomplete inventory coverage requires explicit acknowledgement.");
  if (previous.completedAt.getTime() > now.getTime() + 300000)
    blockingReasons.push(
      "The historical inspection has a future completion timestamp.");
  if (!coverage.allRowsAccountedFor)
    blockingReasons.push(
      "Inventory record accounting is inconsistent.");
  const canonical = {
    schema: "cyberpilot.assets.osv.renewal.plan.v1" as const,
    organizationId: scope.organizationId,
    importId: command.inspection.importId,
    sourceInspectionId: previous.id,
    generatedAt: now.toISOString(),
    sourceCompletedAt: previous.completedAt.toISOString(),
    sourceStatus: previous.status,
    selectedPackages: coverage.selectedPackages,
    eligiblePackages: decisions.filter(x => x.eligible).length,
    deferredPackages: decisions.filter(x => !x.eligible).length,
    missingPreviousPackages: decisions.filter(x =>
      x.classification === "NEW_PACKAGE").length,
    unreviewedPackages: coverage.skippedPackages,
    inventoryRows: coverage.inventoryRows,
    unboundRows: coverage.unmappedRows,
    invalidVersionRows: coverage.invalidVersionRows,
    maximumHttpPages, capacityAvailable,
    quotaInspectionsRemaining: quota.inspectionsRemaining,
    quotaRequestsRemaining: quota.requestsRemaining,
    decisions,
    validForExecution: blockingReasons.length === 0,
    blockingReasons,
    newPackagesApproved: command.allowNewPackages,
    partialInventoryApproved: command.allowIncompleteInventory,
  };
  // Date and quota counters must NOT be part of the approval digest:
  // they legitimately change between preview and execution.
  const planDigest = sha({
    schema: canonical.schema,
    organizationId: scope.organizationId,
    importId: command.inspection.importId,
    sourceInspectionId: previous.id,
    sourceDigest: previous.reportDigest,
    requestKey: command.requestKey,
    inspection: {
      ...command.inspection, dryRun: false,
      packageBindings: [...command.inspection.packageBindings].sort(
        (a, b) => a.inventoryProduct.localeCompare(b.inventoryProduct)),
    },
    policy: command.policy,
    allowNewPackages: command.allowNewPackages,
    allowIncompleteInventory: command.allowIncompleteInventory,
    packageKeys: decisions.map(x => x.packageKey).sort(),
  });
  return {
    ...canonical, planDigest,
    warnings: [
      "Approval is valid only for the explicitly mapped packages and source inventory.",
      "The renewal never infers vulnerability remediation from disappeared OSV IDs.",
      "A fresh completed query is not repeated before its freshness threshold.",
      "Incomplete provider observations are subject to the minimum retry cooldown.",
      "OSV HTTPS requests are executed only after the operator confirms this preview.",
      ...(canonical.missingPreviousPackages && !command.allowNewPackages ?
        ["New package identities require separate explicit operator approval."] : []),
      ...((coverage.unmappedRows + coverage.invalidVersionRows > 0) &&
        !command.allowIncompleteInventory ?
        ["Incomplete inventory mappings require an explicit partial-coverage acknowledgement."] : []),
      ...blockingReasons.map(reason => "Renewal blocked: " + reason),
    ],
  };
}
export function assertRenewalExecution(
  command: OsvRenewalCommand, plan: OsvRenewalPlan,
): void {
  if (command.dryRun || !command.confirmOutbound ||
      !command.expectedPlanDigest || command.expectedPlanDigest !== plan.planDigest)
    fail("Renewal authorization does not match the current inventory plan.", "CONFLICT");
  if (!plan.validForExecution)
    fail("Renewal plan is not eligible under freshness and quota rules.", "CONFLICT");
}
export async function loadOsvRenewalSource(
  scope: AssetScope, command: OsvRenewalCommand,
): Promise<{ previous: PreviousInspection; rows: SnapshotRow[] }> {
  const previous = await db.assetOsvInspection.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: command.sourceInspectionId,
      inventoryImportId: command.inspection.importId,
    },
    include: {
      queries: {
        take: 101, orderBy: { queryKey: "asc" },
      },
    },
  });
  if (!previous) throw new WorkInputError("MISSING",
    "Previous OSV inspection not found in this inventory.");
  const inventory = await db.assetInventoryImport.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: command.inspection.importId, state: "COMMITTED",
    },
    select: { id: true, importedCount: true },
  });
  if (!inventory) throw new WorkInputError("CONFLICT",
    "An OSV renewal requires an active inventory snapshot.");
  if (inventory.importedCount < 1 || inventory.importedCount > 10000)
    fail("Invalid inventory observation count.", "CONFLICT");
  const rows = await db.assetInventoryDevice.findMany({
    where: {
      organizationId: scope.organizationId,
      importId: inventory.id,
    },
    take: 10001,
    select: {
      externalId: true, softwareName: true, softwareVersion: true,
      versionStatus: true, normalizedProductKey: true,
    },
  });
  if (rows.length !== inventory.importedCount)
    fail("Current inventory snapshot coverage has changed.", "CONFLICT");
  assertRenewalPrevious(scope, command, previous);
  return { previous, rows };
}
/**
 * Read the entire bounded query history for this inventory, not merely the
 * chosen source report. Otherwise selecting an arbitrarily old report would
 * bypass the freshness gate and generate duplicate provider traffic.
 *
 * The limit is intentionally fail-closed: if the number of persisted query
 * records exceeds the bounded search, the server rejects live renewals
 * rather than trusting an incomplete recency analysis.
 */
export async function loadLatestOsvRenewalQueries(
  scope: AssetScope, command: OsvRenewalCommand,
): Promise<PreviousQuery[]> {
  const rows = await db.assetOsvQueryRecord.findMany({
    where: {
      organizationId: scope.organizationId,
      inspection: {
        organizationId: scope.organizationId,
        inventoryImportId: command.inspection.importId,
      },
    },
    select: {
      inspectionId: true, ecosystem: true, packageName: true,
      version: true, queryKey: true, checkedAt: true,
      providerStatus: true, observationCount: true,
      possibleIds: true, providerOnlyIds: true,
      withdrawnIds: true, unresolvedIds: true,
    },
    orderBy: [
      { checkedAt: "desc" }, { inspectionId: "desc" },
      { queryKey: "desc" },
    ],
    take: 10001,
  });
  if (rows.length > 10000)
    fail("OSV renewal history exceeds bounded freshness capacity.", "CONFLICT");
  return rows;
}
export async function previewOsvRenewal(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvRenewalPlan> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Renewal planning requires organization administrator permission.");
  const command = parseOsvRenewalCommand(input);
  const { previous, rows } = await loadOsvRenewalSource(scope, command);
  const quota = await inspectOfficialOsvQuota(scope, now, 1);
  const recent = await loadLatestOsvRenewalQueries(scope, command);
  return evaluateRenewalPlan(scope, command, previous, rows, quota, now, recent);
}
export type RenewalExecutionDeps = {
  now?: () => Date;
  official?: OfficialOsvFetchDependencies;
};
export async function executeOsvRenewal(
  scope: AssetScope, input: unknown,
  deps: RenewalExecutionDeps = {},
): Promise<OsvRenewalOutcome> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV renewal requires administrator permission.");
  const command = parseOsvRenewalCommand(input);
  if (command.dryRun)
    fail("Execution requires a live renewal command.");
  const now = deps.now?.() ?? new Date();
  const { previous, rows } = await loadOsvRenewalSource(scope, command);
  const quota = await inspectOfficialOsvQuota(scope, now, 1);
  const recent = await loadLatestOsvRenewalQueries(scope, command);
  const plan = evaluateRenewalPlan(scope, command, previous, rows, quota, now, recent);
  assertRenewalExecution(command, plan);
  // The persisted inspection ledger and atomic quota share the same
  // human-authorized idempotency key. The quota enforces concurrent spend.
  const ledger: OsvLedgerCommit = await persistOsvInspection(scope, {
    requestKey: command.requestKey,
    inspection: { ...command.inspection, dryRun: false },
  }, deps.official);
  let comparison: OsvChangeReport | null = null;
  try {
    comparison = await inspectOsvHistoryDelta(scope, {
      previousInspectionId: previous.id,
      currentInspectionId: ledger.inspectionId,
      offset: 0, limit: 100,
    });
  } catch (cause) {
    // Ledger persistence is complete even if optional history comparison
    // cannot run. Never retry the upstream query merely for a delta report.
    if (cause instanceof WorkInputError &&
        (cause.code === "INVALID" || cause.code === "CONFLICT"))
      comparison = null;
    else throw cause;
  }
  return {
    schema: "cyberpilot.assets.osv.renewal.outcome.v1",
    organizationId: scope.organizationId,
    importId: command.inspection.importId,
    previousInspectionId: previous.id,
    currentInspectionId: ledger.inspectionId,
    replayed: ledger.replayed,
    status: ledger.status,
    newReportDigest: ledger.reportDigest,
    previousReportDigest: previous.reportDigest,
    comparison, completeComparison: comparison?.completeComparison ?? false,
    warnings: [
      "Both inspections are historical OSV API reports, not proof of endpoint vulnerability.",
      "A disappeared advisory is not evidence of patching or risk reduction.",
      "Daily quota was charged atomically before the remote provider query.",
      ...(comparison ? comparison.warnings :
        ["Automatic comparison was unavailable; the new report remains in the ledger."]),
    ],
  };
}
