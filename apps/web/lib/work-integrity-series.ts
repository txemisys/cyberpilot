import type { CaseRow, CaseState, CaseSeverity } from "./work-integrity-cases";
import type { CaseSnapshot, CaseDeltaKind } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { caseDimensions } from "./work-integrity-analytics";

/** Multi-capture operational history. Never interprets absent partial data as clearance. */
export type SnapshotSeries = {
  organizationId: string;
  snapshots: CaseSnapshot[];
};
export type CaseObservation = {
  capturedAt: string;
  present: boolean | null;
  row: CaseRow | null;
  coverageComplete: boolean;
};
export type CaseHistory = {
  key: string;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  observations: CaseObservation[];
  transitions: Array<{
    from: string;
    to: string;
    fromTime: string;
    toTime: string;
    certain: boolean;
  }>;
  longestObservedStreak: number;
  latestState: CaseState | null;
  latestSeverity: CaseSeverity | null;
  unresolved: boolean;
  uncertainty: string[];
};
export type SeriesInterval = {
  before: string;
  after: string;
  complete: boolean;
  counts: Record<CaseDeltaKind, number>;
  totalBefore: number;
  totalAfter: number;
  criticalBefore: number;
  criticalAfter: number;
  reviewedBefore: number;
  reviewedAfter: number;
};
export type SeriesSummary = {
  organizationId: string;
  snapshots: number;
  intervals: SeriesInterval[];
  histories: CaseHistory[];
  latest: ReturnType<typeof caseDimensions> | null;
  warnings: string[];
};
export function normalizeSnapshotSeries(snapshots: readonly CaseSnapshot[], max = 100): SnapshotSeries {
  if (!Number.isSafeInteger(max) || max < 1 || max > 1000)
    throw new Error("Invalid series size limit.");
  if (snapshots.length > max) throw new Error("Too many snapshots.");
  const organizationId = snapshots[0]?.organizationId ?? "";
  for (const snapshot of snapshots) {
    if (snapshot.organizationId !== organizationId)
      throw new Error("Snapshot series must be tenant-scoped.");
    if (!Number.isFinite(Date.parse(snapshot.capturedAt)))
      throw new Error("Invalid capture timestamp.");
    const keys = snapshot.cases.map(row => row.key);
    if (new Set(keys).size !== keys.length)
      throw new Error("Duplicate case key within a snapshot.");
  }
  const sorted = [...snapshots].sort((a, b) =>
    Date.parse(a.capturedAt) - Date.parse(b.capturedAt) ||
    a.source.localeCompare(b.source));
  for (let index = 1; index < sorted.length; index++) {
    if (sorted[index]!.capturedAt === sorted[index - 1]!.capturedAt)
      throw new Error("Snapshot timestamps must be unique.");
  }
  return { organizationId, snapshots: sorted };
}
export function caseHistory(series: SnapshotSeries, key: string): CaseHistory {
  if (!key) throw new Error("Case key required.");
  const observations: CaseObservation[] = series.snapshots.map(snapshot => {
    const row = snapshot.cases.find(item => item.key === key) ?? null;
    return {
      capturedAt: snapshot.capturedAt,
      present: row ? true : snapshot.complete ? false : null,
      row, coverageComplete: snapshot.complete,
    };
  });
  const observed = observations.filter(o => o.row !== null);
  const transitions: CaseHistory["transitions"] = [];
  for (let index = 1; index < observations.length; index++) {
    const previous = observations[index - 1]!;
    const current = observations[index]!;
    const from = previous.row?.state ?? (previous.present === false ? "ABSENT" : "UNKNOWN");
    const to = current.row?.state ?? (current.present === false ? "ABSENT" : "UNKNOWN");
    if (from !== to || previous.row?.severity !== current.row?.severity) {
      transitions.push({
        from, to, fromTime: previous.capturedAt, toTime: current.capturedAt,
        certain: previous.present !== null && current.present !== null,
      });
    }
  }
  let longestObservedStreak = 0;
  let streak = 0;
  for (const observation of observations) {
    if (observation.present === true) {
      streak++;
      longestObservedStreak = Math.max(longestObservedStreak, streak);
    } else streak = 0;
  }
  const latest = observations.at(-1) ?? null;
  return {
    key,
    firstObservedAt: observed[0]?.capturedAt ?? null,
    lastObservedAt: observed.at(-1)?.capturedAt ?? null,
    observations, transitions, longestObservedStreak,
    latestState: latest?.row?.state ?? null,
    latestSeverity: latest?.row?.severity ?? null,
    unresolved: latest?.present === true,
    uncertainty: [
      ...observations.some(o => o.present === null)
        ? ["At least one incomplete snapshot cannot establish absence."] : [],
      ...transitions.some(t => !t.certain)
        ? ["Some transitions cross unknown collection coverage."] : [],
      "Presence and state describe recorded diagnostics, not confirmed security incidents.",
    ],
  };
}
export function summarizeSnapshotSeries(series: SnapshotSeries): SeriesSummary {
  const keys = [...new Set(series.snapshots.flatMap(snapshot => snapshot.cases.map(row => row.key)))].sort();
  const intervals: SeriesInterval[] = [];
  for (let index = 1; index < series.snapshots.length; index++) {
    const before = series.snapshots[index - 1]!;
    const after = series.snapshots[index]!;
    const comparison = compareCaseSnapshots(before, after);
    const old = caseDimensions(before.cases);
    const current = caseDimensions(after.cases);
    intervals.push({
      before: before.capturedAt, after: after.capturedAt,
      complete: comparison.complete, counts: comparison.counts,
      totalBefore: old.total, totalAfter: current.total,
      criticalBefore: old.bySeverity.critical,
      criticalAfter: current.bySeverity.critical,
      reviewedBefore: old.reviewed, reviewedAfter: current.reviewed,
    });
  }
  return {
    organizationId: series.organizationId,
    snapshots: series.snapshots.length,
    intervals,
    histories: keys.map(key => caseHistory(series, key)),
    latest: series.snapshots.length ? caseDimensions(series.snapshots.at(-1)!.cases) : null,
    warnings: [
      "Series reflect sampled bounded snapshots, not continuous monitoring.",
      "No disappearance is considered a clearance when either capture is incomplete.",
      "A change in case state is not evidence that a control has been verified.",
    ],
  };
}
export type TransitionMatrix = {
  states: string[];
  transitions: Record<string, Record<string, number>>;
  uncertain: number;
  observed: number;
};
export function caseTransitionMatrix(summary: SeriesSummary): TransitionMatrix {
  const transitions: Record<string, Record<string, number>> = {};
  const states = new Set<string>();
  let uncertain = 0;
  let observed = 0;
  for (const history of summary.histories) {
    for (const transition of history.transitions) {
      states.add(transition.from);
      states.add(transition.to);
      if (!transition.certain) {
        uncertain++;
        continue;
      }
      transitions[transition.from] ??= {};
      transitions[transition.from]![transition.to] =
        (transitions[transition.from]![transition.to] ?? 0) + 1;
      observed++;
    }
  }
  return { states: [...states].sort(), transitions, uncertain, observed };
}
export type PersistenceBucket = {
  capturesObserved: number;
  cases: number;
  keys: string[];
};
export function casePersistenceDistribution(summary: SeriesSummary): PersistenceBucket[] {
  const groups = new Map<number, string[]>();
  for (const history of summary.histories) {
    const count = history.observations.filter(o => o.present === true).length;
    const keys = groups.get(count) ?? [];
    keys.push(history.key);
    groups.set(count, keys);
  }
  return [...groups.entries()].sort(([a], [b]) => a - b)
    .map(([capturesObserved, keys]) => ({
      capturesObserved, cases: keys.length, keys: keys.sort(),
    }));
}
export type WorkItemHistory = {
  workItemId: string;
  caseKeys: string[];
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  activeAtLatestCapture: number;
  criticalAtLatestCapture: number;
  uncertainCases: number;
};
export function workItemHistories(summary: SeriesSummary): WorkItemHistory[] {
  const groups = new Map<string, CaseHistory[]>();
  for (const history of summary.histories) {
    let workItemId: string;
    try {
      const parsed: unknown = JSON.parse(history.key);
      workItemId = Array.isArray(parsed) && typeof parsed[0] === "string" ? parsed[0] : "";
    } catch { workItemId = ""; }
    if (!workItemId) throw new Error("Invalid case identity in history.");
    const group = groups.get(workItemId) ?? [];
    group.push(history);
    groups.set(workItemId, group);
  }
  return [...groups.entries()].map(([workItemId, histories]) => ({
    workItemId,
    caseKeys: histories.map(h => h.key).sort(),
    firstObservedAt: histories.map(h => h.firstObservedAt).filter((x): x is string => x !== null).sort()[0] ?? null,
    lastObservedAt: histories.map(h => h.lastObservedAt).filter((x): x is string => x !== null).sort().at(-1) ?? null,
    activeAtLatestCapture: histories.filter(h => h.unresolved).length,
    criticalAtLatestCapture: histories.filter(h => h.unresolved && h.latestSeverity === "critical").length,
    uncertainCases: histories.filter(h => h.uncertainty.length > 1).length,
  })).sort((a, b) => b.criticalAtLatestCapture - a.criticalAtLatestCapture ||
    b.activeAtLatestCapture - a.activeAtLatestCapture || a.workItemId.localeCompare(b.workItemId));
}
