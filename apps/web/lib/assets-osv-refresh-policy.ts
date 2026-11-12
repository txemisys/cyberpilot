import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";

export type RefreshPolicy = {
  freshnessMinutes: number;
  minimumRetryMinutes: number;
  maximumQueriesPerDay: number;
  maximumInspectionsPerDay: number;
  maximumPackagesPerRun: number;
  historyWindowDays: number;
  includeIncomplete: boolean;
};
export type RefreshHistory = {
  inspectionId: string;
  completedAt: Date;
  status: string;
  queryCount: number;
  completedCount: number;
};
export type RefreshPackageState = {
  ecosystem: string;
  packageName: string;
  version: string;
  providerStatus: string;
  checkedAt: Date | null;
  observationCount: number;
  inspectionId: string;
  queryKey: string;
  possibleIds: string[];
  providerOnlyIds: string[];
  unresolvedIds: string[];
  withdrawnIds: string[];
};
export type RefreshPackageStatus =
  "NEVER_CHECKED" | "FRESH_COMPLETE" | "STALE" |
  "RETRY_DEFERRED" | "INCOMPLETE" | "CLOCK_INVALID";
export type RefreshPackageDecision = {
  key: string;
  ecosystem: string;
  packageName: string;
  version: string;
  state: RefreshPackageStatus;
  shouldRefresh: boolean;
  dueAt: string | null;
  lastCheckedAt: string | null;
  lastInspectionId: string | null;
  lastProviderStatus: string | null;
  ageMinutes: number | null;
  reasons: string[];
  possibleIds: string[];
  providerOnlyIds: string[];
  unresolvedIds: string[];
  withdrawnIds: string[];
};
export type RefreshBudget = {
  inspectionCountToday: number;
  queryCountToday: number;
  inspectionBudgetRemaining: number;
  queryBudgetRemaining: number;
  maximumPackagesPerRun: number;
  allowedPackageQueries: number;
  blockedByInspectionBudget: boolean;
};
export type RefreshPlan = {
  schema: "cyberpilot.assets.osv.refresh.plan.v1";
  organizationId: string;
  generatedAt: string;
  policy: RefreshPolicy;
  totalHistoricalPackages: number;
  dueCount: number;
  freshCount: number;
  incompleteCount: number;
  deferredCount: number;
  selectedCount: number;
  excludedDueToBudget: number;
  hasMore: boolean;
  offset: number;
  limit: number;
  budget: RefreshBudget;
  selected: RefreshPackageDecision[];
  candidates: RefreshPackageDecision[];
  digest: string;
  warnings: string[];
};
const safeTime = 86400000;
function fail(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return fail("Expected a refresh policy object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, minimum: number, maximum: number,
  name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    return fail("Invalid OSV refresh " + name + ".");
  return value;
}
function sha(data: unknown) {
  return createHash("sha256").update(JSON.stringify(data)).digest("hex");
}
export function parseRefreshPolicy(value: unknown): RefreshPolicy {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "freshnessMinutes", "minimumRetryMinutes", "maximumQueriesPerDay",
    "maximumInspectionsPerDay", "maximumPackagesPerRun",
    "historyWindowDays", "includeIncomplete",
  ].includes(key)))
    fail("Unexpected refresh policy field.");
  if (raw.includeIncomplete !== undefined &&
      typeof raw.includeIncomplete !== "boolean")
    fail("Invalid includeIncomplete flag.");
  const policy: RefreshPolicy = {
    freshnessMinutes: integer(raw.freshnessMinutes ?? 1440,
      15, 43200, "freshness"),
    minimumRetryMinutes: integer(raw.minimumRetryMinutes ?? 60,
      5, 10080, "minimum retry"),
    maximumQueriesPerDay: integer(raw.maximumQueriesPerDay ?? 200,
      1, 10000, "daily query limit"),
    maximumInspectionsPerDay: integer(raw.maximumInspectionsPerDay ?? 20,
      1, 500, "daily inspection limit"),
    maximumPackagesPerRun: integer(raw.maximumPackagesPerRun ?? 10,
      1, 20, "per-run packages"),
    historyWindowDays: integer(raw.historyWindowDays ?? 90,
      1, 3650, "history window"),
    includeIncomplete: raw.includeIncomplete !== false,
  };
  return policy;
}
export function refreshPackageKey(
  row: Pick<RefreshPackageState, "ecosystem" | "packageName" | "version">,
) {
  return JSON.stringify([row.ecosystem, row.packageName, row.version]);
}
export function latestPackageResults(
  history: RefreshPackageState[],
): RefreshPackageState[] {
  const latest = new Map<string, RefreshPackageState>();
  for (const entry of history) {
    const key = refreshPackageKey(entry);
    const previous = latest.get(key);
    const t = entry.checkedAt?.getTime() ?? -Infinity;
    const old = previous?.checkedAt?.getTime() ?? -Infinity;
    if (!previous || t > old ||
        (t === old && entry.inspectionId > previous.inspectionId))
      latest.set(key, entry);
  }
  return [...latest.values()].sort((a, b) =>
    a.ecosystem.localeCompare(b.ecosystem) ||
    a.packageName.localeCompare(b.packageName) ||
    a.version.localeCompare(b.version));
}
export function classifyPackageRefresh(
  row: RefreshPackageState, policy: RefreshPolicy, now: Date,
): RefreshPackageDecision {
  const key = refreshPackageKey(row);
  const age = row.checkedAt ?
    (now.getTime() - row.checkedAt.getTime()) / 60000 : NaN;
  const status = row.providerStatus;
  const incomplete = status !== "COMPLETE";
  let state: RefreshPackageStatus;
  let dueAt: string | null = null;
  let shouldRefresh = false;
  const reasons: string[] = [];
  if (!row.checkedAt) {
    state = "NEVER_CHECKED"; shouldRefresh = true;
    reasons.push("Provider never returned a usable checkedAt timestamp.");
  } else if (!Number.isFinite(age) || age < -5) {
    state = "CLOCK_INVALID"; shouldRefresh = false;
    reasons.push("Provider timestamp is inconsistent with current time.");
  } else if (incomplete && age < policy.minimumRetryMinutes) {
    state = "RETRY_DEFERRED";
    dueAt = new Date(row.checkedAt.getTime() +
      policy.minimumRetryMinutes * 60000).toISOString();
    reasons.push("Incomplete provider query remains within its retry cooldown.");
  } else if (incomplete) {
    state = "INCOMPLETE";
    shouldRefresh = policy.includeIncomplete;
    reasons.push("Historical query was incomplete; absence of listed CVEs is inconclusive.");
  } else if (age >= policy.freshnessMinutes) {
    state = "STALE"; shouldRefresh = true;
    reasons.push("The provider observation is older than the configured freshness window.");
  } else {
    state = "FRESH_COMPLETE";
    dueAt = new Date(row.checkedAt.getTime() +
      policy.freshnessMinutes * 60000).toISOString();
    reasons.push("Last provider query was complete within the configured freshness window.");
  }
  if (!shouldRefresh && !dueAt && state === "INCOMPLETE" && row.checkedAt)
    dueAt = new Date(row.checkedAt.getTime() +
      policy.freshnessMinutes * 60000).toISOString();
  return {
    key, ecosystem: row.ecosystem, packageName: row.packageName,
    version: row.version, state, shouldRefresh,
    dueAt, lastCheckedAt: row.checkedAt?.toISOString() ?? null,
    lastInspectionId: row.inspectionId,
    lastProviderStatus: status,
    ageMinutes: Number.isFinite(age) ? Math.floor(age) : null,
    reasons, possibleIds: [...row.possibleIds].sort(),
    providerOnlyIds: [...row.providerOnlyIds].sort(),
    unresolvedIds: [...row.unresolvedIds].sort(),
    withdrawnIds: [...row.withdrawnIds].sort(),
  };
}
export function computeRefreshBudget(
  history: RefreshHistory[], policy: RefreshPolicy,
  now: Date,
): RefreshBudget {
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(),
    now.getUTCDate());
  const today = history.filter(row =>
    row.completedAt.getTime() >= start &&
    row.completedAt.getTime() < start + safeTime);
  const inspectionCountToday = today.length;
  const queryCountToday = today.reduce((sum, row) =>
    sum + row.queryCount, 0);
  const inspectionBudgetRemaining =
    Math.max(0, policy.maximumInspectionsPerDay - inspectionCountToday);
  const queryBudgetRemaining =
    Math.max(0, policy.maximumQueriesPerDay - queryCountToday);
  const blockedByInspectionBudget = inspectionBudgetRemaining === 0;
  return {
    inspectionCountToday, queryCountToday,
    inspectionBudgetRemaining, queryBudgetRemaining,
    maximumPackagesPerRun: policy.maximumPackagesPerRun,
    allowedPackageQueries: blockedByInspectionBudget ? 0 :
      Math.min(policy.maximumPackagesPerRun, queryBudgetRemaining),
    blockedByInspectionBudget,
  };
}
export function planOsvRefresh(
  organizationId: string,
  input: {
    policy: RefreshPolicy;
    history: RefreshHistory[];
    packages: RefreshPackageState[];
    now: Date;
    offset: number;
    limit: number;
  },
): RefreshPlan {
  const { policy, now, offset, limit } = input;
  if (!Number.isFinite(now.getTime()))
    fail("Invalid refresh evaluation time.");
  integer(offset, 0, 1000000, "offset");
  integer(limit, 1, 100, "limit");
  const latest = latestPackageResults(input.packages);
  const decisions = latest.map(row =>
    classifyPackageRefresh(row, policy, now));
  const due = decisions.filter(row => row.shouldRefresh).sort((a, b) =>
    (b.ageMinutes ?? Number.MAX_SAFE_INTEGER) -
      (a.ageMinutes ?? Number.MAX_SAFE_INTEGER) ||
    a.key.localeCompare(b.key));
  const budget = computeRefreshBudget(input.history, policy, now);
  const selected = due.slice(0, budget.allowedPackageQueries);
  const ordered = [...decisions].sort((a, b) =>
    Number(b.shouldRefresh) - Number(a.shouldRefresh) ||
    a.key.localeCompare(b.key));
  const candidates = ordered.slice(offset, offset + limit);
  const canonical = {
    schema: "cyberpilot.assets.osv.refresh.plan.v1" as const,
    organizationId, generatedAt: now.toISOString(), policy,
    totalHistoricalPackages: latest.length,
    dueCount: due.length,
    freshCount: decisions.filter(x => x.state === "FRESH_COMPLETE").length,
    incompleteCount: decisions.filter(x =>
      x.state === "INCOMPLETE" || x.state === "RETRY_DEFERRED").length,
    deferredCount: decisions.filter(x =>
      x.state === "RETRY_DEFERRED").length,
    selectedCount: selected.length,
    excludedDueToBudget: Math.max(0, due.length - selected.length),
    hasMore: offset + candidates.length < ordered.length,
    offset, limit, budget, selected, candidates,
  };
  return {
    ...canonical,
    digest: sha(canonical),
    warnings: [
      "Budget is a retrospective advisory calculation, not an atomic upstream quota reservation.",
      "Historical results may be missing packages never previously queried.",
      "A complete OSV query does not verify customer inventory coverage or endpoint security.",
      "Provider-reported CVEs may change without a device patch or removal.",
      "No automatic OSV network requests or database writes are performed by this report.",
    ],
  };
}
export type OsvChangeKind =
  "POSSIBLE_ID_ADDED" | "POSSIBLE_ID_NOT_LISTED" |
  "PROVIDER_ONLY_ADDED" | "PROVIDER_ONLY_NOT_LISTED" |
  "WITHDRAWN_ADDED" | "WITHDRAWN_NOT_LISTED" |
  "UNRESOLVED_ADDED" | "UNRESOLVED_NOT_LISTED" |
  "PROVIDER_STATUS_CHANGED" | "UNCHANGED";
export type OsvChange = {
  key: string;
  ecosystem: string;
  packageName: string;
  version: string;
  kind: OsvChangeKind;
  advisoryId: string | null;
  previous: string | null;
  current: string | null;
  confidence: "PROVIDER_HISTORY_ONLY";
  explanation: string;
  fingerprint: string;
};
export type OsvChangeSummary = {
  total: number;
  changed: number;
  unchanged: number;
  possibleAdded: number;
  possibleNoLongerListed: number;
  providerOnlyAdded: number;
  withdrawnAdded: number;
  statusChanged: number;
  comparedPackages: number;
  excludedPackages: number;
};
export type OsvChangeReport = {
  schema: "cyberpilot.assets.osv.history.delta.v1";
  organizationId: string;
  previousInspectionId: string;
  currentInspectionId: string;
  completeComparison: boolean;
  summary: OsvChangeSummary;
  totalChanges: number;
  rows: OsvChange[];
  offset: number;
  limit: number;
  hasMore: boolean;
  digest: string;
  warnings: string[];
};
function uniqueIds(input: string[]) {
  return [...new Set(input)].sort();
}
function changeExplanation(kind: OsvChangeKind): string {
  if (kind === "POSSIBLE_ID_ADDED")
    return "The OSV provider lists a new literal version association; endpoint exposure is unverified.";
  if (kind === "POSSIBLE_ID_NOT_LISTED")
    return "A previous literal association is not listed now; this is not proof of remediation.";
  if (kind.includes("WITHDRAWN"))
    return "Withdrawn advisory identifiers changed; do not infer current exploitability.";
  if (kind.includes("UNRESOLVED"))
    return "Unresolved provider ranges changed; no automatic version interpretation is made.";
  if (kind.includes("PROVIDER_ONLY"))
    return "Provider-reported nonliteral associations changed and require manual assessment.";
  if (kind === "PROVIDER_STATUS_CHANGED")
    return "Provider completion status changed and can invalidate comparison coverage.";
  return "No change in recorded advisory IDs or provider status for this package/version.";
}
function changeRow(
  previous: RefreshPackageState, current: RefreshPackageState,
  kind: OsvChangeKind, advisoryId: string | null,
  before: string | null, after: string | null,
): OsvChange {
  const canonical = {
    key: refreshPackageKey(current), ecosystem: current.ecosystem,
    packageName: current.packageName, version: current.version,
    kind, advisoryId, previous: before, current: after,
    confidence: "PROVIDER_HISTORY_ONLY" as const,
    explanation: changeExplanation(kind),
  };
  return { ...canonical, fingerprint: sha(canonical) };
}
function diffIds(
  previous: RefreshPackageState, current: RefreshPackageState,
  older: string[], newer: string[],
  added: OsvChangeKind, removed: OsvChangeKind,
): OsvChange[] {
  const before = new Set(uniqueIds(older));
  const after = new Set(uniqueIds(newer));
  return [
    ...[...after].filter(id => !before.has(id))
      .map(id => changeRow(previous, current, added, id, null, id)),
    ...[...before].filter(id => !after.has(id))
      .map(id => changeRow(previous, current, removed, id, id, null)),
  ];
}
export function compareOsvPackageHistory(
  previous: RefreshPackageState[],
  current: RefreshPackageState[],
): {
  rows: OsvChange[];
  compared: number;
  excluded: number;
} {
  const a = new Map(previous.map(row =>
    [refreshPackageKey(row), row]));
  const b = new Map(current.map(row =>
    [refreshPackageKey(row), row]));
  const shared = [...a.keys()].filter(key => b.has(key)).sort();
  const output: OsvChange[] = [];
  for (const key of shared) {
    const older = a.get(key)!;
    const newer = b.get(key)!;
    const changes = [
      ...diffIds(older, newer, older.possibleIds, newer.possibleIds,
        "POSSIBLE_ID_ADDED", "POSSIBLE_ID_NOT_LISTED"),
      ...diffIds(older, newer, older.providerOnlyIds, newer.providerOnlyIds,
        "PROVIDER_ONLY_ADDED", "PROVIDER_ONLY_NOT_LISTED"),
      ...diffIds(older, newer, older.withdrawnIds, newer.withdrawnIds,
        "WITHDRAWN_ADDED", "WITHDRAWN_NOT_LISTED"),
      ...diffIds(older, newer, older.unresolvedIds, newer.unresolvedIds,
        "UNRESOLVED_ADDED", "UNRESOLVED_NOT_LISTED"),
    ];
    if (older.providerStatus !== newer.providerStatus)
      changes.push(changeRow(older, newer, "PROVIDER_STATUS_CHANGED",
        null, older.providerStatus, newer.providerStatus));
    if (!changes.length)
      changes.push(changeRow(older, newer, "UNCHANGED", null, null, null));
    output.push(...changes);
  }
  return {
    rows: output.sort((x, y) =>
      x.key.localeCompare(y.key) || x.kind.localeCompare(y.kind) ||
      (x.advisoryId ?? "").localeCompare(y.advisoryId ?? "")),
    compared: shared.length,
    excluded: new Set([...a.keys(), ...b.keys()]).size - shared.length,
  };
}
export function buildOsvHistoryDelta(
  organizationId: string,
  previousInspectionId: string, currentInspectionId: string,
  previous: RefreshPackageState[],
  current: RefreshPackageState[],
  previousComplete: boolean, currentComplete: boolean,
  offset: number, limit: number,
): OsvChangeReport {
  integer(offset, 0, 1000000, "offset");
  integer(limit, 1, 100, "limit");
  if (previousInspectionId === currentInspectionId)
    fail("Two different inspection IDs are required.");
  const compared = compareOsvPackageHistory(previous, current);
  const all = compared.rows;
  const completeComparison = previousComplete && currentComplete &&
    compared.excluded === 0;
  const summary: OsvChangeSummary = {
    total: all.length,
    changed: all.filter(x => x.kind !== "UNCHANGED").length,
    unchanged: all.filter(x => x.kind === "UNCHANGED").length,
    possibleAdded: all.filter(x => x.kind === "POSSIBLE_ID_ADDED").length,
    possibleNoLongerListed: all.filter(x =>
      x.kind === "POSSIBLE_ID_NOT_LISTED").length,
    providerOnlyAdded: all.filter(x =>
      x.kind === "PROVIDER_ONLY_ADDED").length,
    withdrawnAdded: all.filter(x => x.kind === "WITHDRAWN_ADDED").length,
    statusChanged: all.filter(x =>
      x.kind === "PROVIDER_STATUS_CHANGED").length,
    comparedPackages: compared.compared,
    excludedPackages: compared.excluded,
  };
  const rows = all.slice(offset, offset + limit);
  const canonical = {
    schema: "cyberpilot.assets.osv.history.delta.v1" as const,
    organizationId, previousInspectionId, currentInspectionId,
    completeComparison, summary,
    totalChanges: all.length, rows, offset, limit,
    hasMore: offset + rows.length < all.length,
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "Only identical ecosystem, package and version identities are compared.",
      "A missing advisory ID is not proof of remediation, patching, or reduced risk.",
      "Historical provider data cannot certify current endpoint security.",
      ...(completeComparison ? [] :
        ["One or both inspections or package sets are incomplete; comparison is partial."]),
    ],
  };
}
