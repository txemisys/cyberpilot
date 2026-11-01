import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

export type SnapshotIncidentKind =
  | "COVERAGE_REGRESSION"
  | "QUALITY_REGRESSION"
  | "CRITICAL_CASE_INCREASE"
  | "REVIEW_BACKLOG_INCREASE"
  | "SOURCE_GAP"
  | "CASE_DISAPPEARANCE_UNCERTAIN";
export type SnapshotIncidentSeverity = "BLOCKER" | "WARNING" | "INFORMATION";
export type SnapshotIncident = {
  id: string;
  source: string;
  kind: SnapshotIncidentKind;
  severity: SnapshotIncidentSeverity;
  baselineAt: string;
  currentAt: string;
  affectedCaseKeys: string[];
  baselineValue: number;
  currentValue: number;
  explanation: string;
  nextAction: string;
};
export type SnapshotIncidentPolicy = {
  maxCaptureGapDays: number;
  criticalIncreaseThreshold: number;
  reviewBacklogIncreaseThreshold: number;
  reportDisappearance: boolean;
};
export type SnapshotIncidentReport = {
  organizationId: string;
  incidents: SnapshotIncident[];
  bySeverity: Record<SnapshotIncidentSeverity, number>;
  sourcesCompared: number;
  sourcesWithoutBaseline: string[];
  warnings: string[];
};
const DAY = 86400000;
function bounded(value: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function critical(capture: CaseSnapshot): number {
  return capture.cases.filter(row => row.severity === "critical" && !row.historicalOnly).length;
}
function backlog(capture: CaseSnapshot): number {
  return capture.cases.filter(row => row.reviewEventId === null && !row.historicalOnly).length;
}
export function detectSnapshotIncidents(
  input: readonly unknown[], organizationId: string, policy: SnapshotIncidentPolicy,
): SnapshotIncidentReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (input.length > 10000) throw new Error("Too many incident captures.");
  const maxCaptureGapDays = bounded(policy.maxCaptureGapDays, 3650, "capture gap");
  const criticalIncreaseThreshold = bounded(policy.criticalIncreaseThreshold, 10000, "critical threshold");
  const reviewBacklogIncreaseThreshold = bounded(policy.reviewBacklogIncreaseThreshold, 10000, "review threshold");
  const groups = new Map<string, CaseSnapshot[]>();
  const identities = new Set<string>();
  for (const raw of input) {
    const capture = parseCaseSnapshot(raw);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization incident analysis is forbidden.");
    const key = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (identities.has(key)) throw new Error("Duplicate incident capture identity.");
    identities.add(key);
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const incidents: SnapshotIncident[] = [];
  const sourcesWithoutBaseline: string[] = [];
  let sourcesCompared = 0;
  for (const [source, group] of groups) {
    group.sort((a, b) => Date.parse(b.capturedAt) - Date.parse(a.capturedAt));
    const current = group[0]!;
    const baseline = group[1];
    if (!baseline) {
      sourcesWithoutBaseline.push(source);
      continue;
    }
    sourcesCompared++;
    const delta = compareCaseSnapshots(baseline, current);
    const oldQuality = inspectCaptureQuality(baseline);
    const newQuality = inspectCaptureQuality(current);
    const add = (
      kind: SnapshotIncidentKind, severity: SnapshotIncidentSeverity,
      baselineValue: number, currentValue: number, explanation: string,
      nextAction: string, affectedCaseKeys: string[] = [],
    ) => {
      incidents.push({
        id: JSON.stringify([source, current.capturedAt, kind]), source, kind, severity,
        baselineAt: baseline.capturedAt, currentAt: current.capturedAt,
        affectedCaseKeys: affectedCaseKeys.sort(), baselineValue, currentValue,
        explanation, nextAction,
      });
    };
    const gapDays = (Date.parse(current.capturedAt) - Date.parse(baseline.capturedAt)) / DAY;
    if (gapDays > maxCaptureGapDays)
      add("SOURCE_GAP", "WARNING", 0, gapDays,
        "The interval between the two latest source captures exceeds the configured limit.",
        "Check capture scheduling, connector availability, and collection logs.");
    if (baseline.complete && !current.complete)
      add("COVERAGE_REGRESSION", "BLOCKER", 1, 0,
        "The latest capture no longer claims complete coverage.",
        "Recollect missing records before using this capture as a complete baseline.");
    if (newQuality.blockers > oldQuality.blockers)
      add("QUALITY_REGRESSION", "BLOCKER", oldQuality.blockers, newQuality.blockers,
        "The latest capture contains more structural quality blockers.",
        "Inspect capture quality diagnostics and reconcile the source data.");
    if (critical(current) - critical(baseline) >= criticalIncreaseThreshold)
      add("CRITICAL_CASE_INCREASE", "WARNING", critical(baseline), critical(current),
        "The count of recorded active critical cases has increased.",
        "Review newly recorded diagnostics and prioritize investigation; do not infer a new attack.");
    if (backlog(current) - backlog(baseline) >= reviewBacklogIncreaseThreshold)
      add("REVIEW_BACKLOG_INCREASE", "WARNING", backlog(baseline), backlog(current),
        "The unreviewed active diagnostic backlog has increased.",
        "Assign triage capacity and confirm review ownership.");
    if (policy.reportDisappearance && delta.counts.INDETERMINATE > 0)
      add("CASE_DISAPPEARANCE_UNCERTAIN", "INFORMATION", 0, delta.counts.INDETERMINATE,
        "Incomplete coverage prevents a reliable interpretation of missing diagnostic cases.",
        "Restore complete comparable captures before classifying disappearance.",
        delta.deltas.filter(row => row.kind === "INDETERMINATE").map(row => row.key));
  }
  incidents.sort((a, b) => {
    const priority = { BLOCKER: 0, WARNING: 1, INFORMATION: 2 };
    return priority[a.severity] - priority[b.severity] ||
      a.source.localeCompare(b.source) || a.kind.localeCompare(b.kind);
  });
  return {
    organizationId, incidents, sourcesCompared, sourcesWithoutBaseline: sourcesWithoutBaseline.sort(),
    bySeverity: {
      BLOCKER: incidents.filter(item => item.severity === "BLOCKER").length,
      WARNING: incidents.filter(item => item.severity === "WARNING").length,
      INFORMATION: incidents.filter(item => item.severity === "INFORMATION").length,
    },
    warnings: [
      "Incidents are deterministic operational signals, not security verdicts.",
      "Changes in diagnostics do not prove a security incident or verified remediation.",
      ...(sourcesWithoutBaseline.length ?
        ["Some sources have no historical baseline and could not be compared."] : []),
    ],
  };
}
