import type { CaseRow, CaseSeverity, CaseState } from "./work-integrity-cases";
import type { CaseSnapshot, CaseDelta, SnapshotComparison } from "./work-integrity-snapshots";

/** Deterministic case-queue analytics. All counts refer to the supplied bounded snapshot. */
export type CaseDimensions = {
  total: number;
  byState: Record<CaseState, number>;
  bySeverity: Record<CaseSeverity | "none", number>;
  byWorkItem: Record<string, number>;
  byCode: Record<string, number>;
  reviewed: number;
  unreviewed: number;
  stale: number;
  historical: number;
  incompleteCoverage: number;
  criticalUnreviewed: number;
  attentionUnreviewed: number;
};
export type CaseGroup = {
  key: string;
  count: number;
  critical: number;
  attention: number;
  info: number;
  noSeverity: number;
  unreviewed: number;
  stale: number;
  reviewed: number;
  historical: number;
  incompleteCoverage: number;
  workItemIds: string[];
  caseKeys: string[];
};
export type CaseTrend = {
  before: CaseDimensions;
  after: CaseDimensions;
  change: {
    total: number;
    reviewed: number;
    unreviewed: number;
    stale: number;
    criticalUnreviewed: number;
    incompleteCoverage: number;
  };
  caseChangeCounts: SnapshotComparison["counts"];
  comparisonComplete: boolean;
  warnings: string[];
};
export type CaseSliceOptions = {
  states?: readonly CaseState[];
  severities?: readonly (CaseSeverity | null)[];
  codes?: readonly string[];
  workItemIds?: readonly string[];
  reviewed?: boolean;
  historical?: boolean;
  completeCoverage?: boolean;
  text?: string;
};
export type CaseFacet = {
  dimension: "state" | "severity" | "code" | "workItemId";
  values: Array<{ value: string; count: number }>;
};
export type CaseCohort = {
  cohort: string;
  before: number;
  after: number;
  entered: number;
  exited: number;
  persisted: number;
  uncertain: boolean;
};
const stateNames: CaseState[] = [
  "UNREVIEWED", "INVESTIGATING", "ACKNOWLEDGED", "DISMISSED",
  "REOPENED", "STALE", "NO_LONGER_DETECTED",
];
const severityNames = ["critical", "attention", "info", "none"] as const;
function countOf<K extends string>(keys: readonly K[]): Record<K, number> {
  return Object.fromEntries(keys.map(key => [key, 0])) as Record<K, number>;
}
function increment(record: Record<string, number>, key: string): void {
  record[key] = (record[key] ?? 0) + 1;
}
export function caseDimensions(rows: readonly CaseRow[]): CaseDimensions {
  const byState = countOf(stateNames);
  const bySeverity = countOf(severityNames);
  const byWorkItem: Record<string, number> = {};
  const byCode: Record<string, number> = {};
  let reviewed = 0;
  let historical = 0;
  let incompleteCoverage = 0;
  let criticalUnreviewed = 0;
  let attentionUnreviewed = 0;
  for (const row of rows) {
    increment(byState, row.state);
    increment(bySeverity, row.severity ?? "none");
    increment(byWorkItem, row.workItemId);
    increment(byCode, row.code);
    if (row.reviewEventId) reviewed++;
    if (row.historicalOnly) historical++;
    if (!row.completeCoverage) incompleteCoverage++;
    if (row.state === "UNREVIEWED" && row.severity === "critical") criticalUnreviewed++;
    if (row.state === "UNREVIEWED" && row.severity === "attention") attentionUnreviewed++;
  }
  return {
    total: rows.length, byState, bySeverity, byWorkItem, byCode,
    reviewed, unreviewed: byState.UNREVIEWED, stale: byState.STALE,
    historical, incompleteCoverage, criticalUnreviewed, attentionUnreviewed,
  };
}
export function sliceCases(rows: readonly CaseRow[], options: CaseSliceOptions): CaseRow[] {
  const states = options.states ? new Set(options.states) : null;
  const severities = options.severities ? new Set(options.severities) : null;
  const codes = options.codes ? new Set(options.codes) : null;
  const workItemIds = options.workItemIds ? new Set(options.workItemIds) : null;
  const text = options.text?.trim().toLocaleLowerCase() ?? "";
  return rows.filter(row => {
    if (states && !states.has(row.state)) return false;
    if (severities && !severities.has(row.severity)) return false;
    if (codes && !codes.has(row.code)) return false;
    if (workItemIds && !workItemIds.has(row.workItemId)) return false;
    if (options.reviewed !== undefined && Boolean(row.reviewEventId) !== options.reviewed) return false;
    if (options.historical !== undefined && row.historicalOnly !== options.historical) return false;
    if (options.completeCoverage !== undefined && row.completeCoverage !== options.completeCoverage)
      return false;
    if (text) {
      const haystack = [
        row.workItemId, row.resourceId, row.code, row.diagnostic,
        row.recommendation, row.reviewRationale, row.reviewReference,
      ].filter((value): value is string => typeof value === "string").join(" ").toLocaleLowerCase();
      if (!haystack.includes(text)) return false;
    }
    return true;
  });
}
export function groupCases(rows: readonly CaseRow[], by: "code" | "state" | "severity" | "workItemId"): CaseGroup[] {
  const groups = new Map<string, CaseRow[]>();
  for (const row of rows) {
    const key = by === "severity" ? row.severity ?? "none" : String(row[by]);
    const existing = groups.get(key);
    if (existing) existing.push(row);
    else groups.set(key, [row]);
  }
  return [...groups.entries()].map(([key, items]) => ({
    key,
    count: items.length,
    critical: items.filter(x => x.severity === "critical").length,
    attention: items.filter(x => x.severity === "attention").length,
    info: items.filter(x => x.severity === "info").length,
    noSeverity: items.filter(x => x.severity === null).length,
    unreviewed: items.filter(x => x.state === "UNREVIEWED").length,
    stale: items.filter(x => x.state === "STALE").length,
    reviewed: items.filter(x => x.reviewEventId !== null).length,
    historical: items.filter(x => x.historicalOnly).length,
    incompleteCoverage: items.filter(x => !x.completeCoverage).length,
    workItemIds: [...new Set(items.map(x => x.workItemId))].sort(),
    caseKeys: items.map(x => x.key).sort(),
  })).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}
export function facetCases(rows: readonly CaseRow[]): CaseFacet[] {
  return (["state", "severity", "code", "workItemId"] as const).map(dimension => ({
    dimension,
    values: groupCases(rows, dimension).map(group => ({ value: group.key, count: group.count })),
  }));
}
export function trendCases(
  before: CaseSnapshot, after: CaseSnapshot, comparison: SnapshotComparison,
): CaseTrend {
  if (before.organizationId !== after.organizationId ||
      comparison.organizationId !== before.organizationId)
    throw new Error("Cannot analyze different organizations.");
  const old = caseDimensions(before.cases);
  const current = caseDimensions(after.cases);
  return {
    before: old, after: current,
    change: {
      total: current.total - old.total,
      reviewed: current.reviewed - old.reviewed,
      unreviewed: current.unreviewed - old.unreviewed,
      stale: current.stale - old.stale,
      criticalUnreviewed: current.criticalUnreviewed - old.criticalUnreviewed,
      incompleteCoverage: current.incompleteCoverage - old.incompleteCoverage,
    },
    caseChangeCounts: comparison.counts,
    comparisonComplete: comparison.complete,
    warnings: [
      "Differences in bounded pages are not organization-wide trends.",
      "Review status and diagnostic severity are not verified control effectiveness.",
      ...(!comparison.complete ? ["Missing cases may reflect incomplete collection, not resolution."] : []),
    ],
  };
}
export function caseCohorts(
  comparison: SnapshotComparison,
  dimension: "code" | "state" | "severity" | "workItemId",
): CaseCohort[] {
  const before = new Map<string, Set<string>>();
  const after = new Map<string, Set<string>>();
  const dimensionValue = (row: CaseRow) =>
    dimension === "severity" ? row.severity ?? "none" : String(row[dimension]);
  for (const delta of comparison.deltas) {
    if (delta.before) {
      const key = dimensionValue(delta.before);
      const set = before.get(key) ?? new Set<string>();
      set.add(delta.key);
      before.set(key, set);
    }
    if (delta.after) {
      const key = dimensionValue(delta.after);
      const set = after.get(key) ?? new Set<string>();
      set.add(delta.key);
      after.set(key, set);
    }
  }
  return [...new Set([...before.keys(), ...after.keys()])].sort().map(cohort => {
    const old = before.get(cohort) ?? new Set<string>();
    const current = after.get(cohort) ?? new Set<string>();
    let persisted = 0;
    for (const key of old) if (current.has(key)) persisted++;
    return {
      cohort, before: old.size, after: current.size,
      entered: current.size - persisted,
      exited: old.size - persisted,
      persisted,
      uncertain: !comparison.complete,
    };
  });
}
export function changedCaseRows(comparison: SnapshotComparison): CaseDelta[] {
  return comparison.deltas.filter(delta => delta.kind !== "UNCHANGED");
}
export function highPriorityCases(rows: readonly CaseRow[], limit = 25): CaseRow[] {
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > 10000)
    throw new Error("Invalid high-priority case limit.");
  const rank = (row: CaseRow) => {
    if (row.state === "STALE") return 0;
    if (row.state === "UNREVIEWED" && row.severity === "critical") return 1;
    if (row.state === "REOPENED" && row.severity === "critical") return 2;
    if (row.state === "UNREVIEWED" && row.severity === "attention") return 3;
    if (row.state === "REOPENED") return 4;
    if (row.state === "INVESTIGATING") return 5;
    return 6;
  };
  return [...rows].sort((a, b) => rank(a) - rank(b) || a.key.localeCompare(b.key)).slice(0, limit);
}
