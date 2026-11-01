import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

export type BaselineSelectionPolicy = {
  requireComplete: boolean;
  requireQualityClearance: boolean;
  maxAgeDays: number;
  minimumCases: number;
  preferSameSource: boolean;
};
export type BaselineCandidate = {
  capturedAt: string;
  source: string;
  cases: number;
  complete: boolean;
  qualityBlockers: number;
  qualityWarnings: number;
  eligible: boolean;
  reasons: string[];
  ageDays: number;
};
export type BaselineSelection = {
  organizationId: string;
  targetCapturedAt: string;
  selected: BaselineCandidate | null;
  candidates: BaselineCandidate[];
  warnings: string[];
};
const DAY = 86400000;
export function selectSnapshotBaseline(
  input: readonly unknown[], targetInput: unknown,
  organizationId: string, policy: BaselineSelectionPolicy,
): BaselineSelection {
  if (input.length > 10000) throw new Error("Too many baseline candidates.");
  if (!Number.isSafeInteger(policy.maxAgeDays) || policy.maxAgeDays < 1 ||
    policy.maxAgeDays > 3650) throw new Error("Invalid baseline age limit.");
  if (!Number.isSafeInteger(policy.minimumCases) || policy.minimumCases < 0 ||
    policy.minimumCases > 10000) throw new Error("Invalid baseline case threshold.");
  const target = parseCaseSnapshot(targetInput);
  if (target.organizationId !== organizationId)
    throw new Error("Cross-organization target is forbidden.");
  const targetTime = Date.parse(target.capturedAt);
  const seen = new Set<string>();
  const candidates = input.map(value => {
    const capture = parseCaseSnapshot(value);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization baseline is forbidden.");
    const key = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (seen.has(key)) throw new Error("Duplicate baseline capture identity.");
    seen.add(key);
    const quality = inspectCaptureQuality(capture);
    const ageDays = (targetTime - Date.parse(capture.capturedAt)) / DAY;
    const reasons: string[] = [];
    if (ageDays <= 0) reasons.push("not-earlier-than-target");
    if (ageDays > policy.maxAgeDays) reasons.push("outside-age-window");
    if (policy.preferSameSource && capture.source !== target.source)
      reasons.push("different-source");
    if (policy.requireComplete && !capture.complete) reasons.push("incomplete-capture");
    if (policy.requireQualityClearance && !quality.safeToTreatAsComplete)
      reasons.push("quality-not-cleared");
    if (capture.cases.length < policy.minimumCases) reasons.push("below-case-threshold");
    return {
      capturedAt: capture.capturedAt, source: capture.source,
      cases: capture.cases.length, complete: capture.complete,
      qualityBlockers: quality.blockers, qualityWarnings: quality.warnings,
      eligible: reasons.length === 0, reasons, ageDays,
    };
  }).sort((a, b) => {
    if (a.eligible !== b.eligible) return a.eligible ? -1 : 1;
    if (a.source === target.source && b.source !== target.source) return -1;
    if (b.source === target.source && a.source !== target.source) return 1;
    return Date.parse(b.capturedAt) - Date.parse(a.capturedAt);
  });
  const selected = candidates.find(candidate => candidate.eligible) ?? null;
  return {
    organizationId, targetCapturedAt: target.capturedAt, selected, candidates,
    warnings: [
      ...(!selected ? ["No eligible historical baseline meets the configured constraints."] : []),
      ...(selected && selected.source !== target.source ?
        ["Selected baseline belongs to a different source; direct comparison is not valid."] : []),
      "Baseline selection cannot establish evidence authenticity or remediation success.",
    ],
  };
}
export type ComparisonBatchItem = {
  source: string;
  baselineAt: string | null;
  targetAt: string;
  comparable: boolean;
  newCases: number;
  clearedCases: number;
  changedCases: number;
  indeterminateCases: number;
  warnings: string[];
};
export type ComparisonBatch = {
  organizationId: string;
  items: ComparisonBatchItem[];
  compared: number;
  skipped: number;
  warnings: string[];
};
export function compareLatestCapturesBySource(
  input: readonly unknown[], organizationId: string,
): ComparisonBatch {
  if (input.length > 10000) throw new Error("Too many comparison captures.");
  const grouped = new Map<string, CaseSnapshot[]>();
  const seen = new Set<string>();
  for (const value of input) {
    const capture = parseCaseSnapshot(value);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization batch comparison is forbidden.");
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (seen.has(identity)) throw new Error("Duplicate capture identity.");
    seen.add(identity);
    const group = grouped.get(capture.source) ?? [];
    group.push(capture);
    grouped.set(capture.source, group);
  }
  const items: ComparisonBatchItem[] = [];
  for (const [source, captures] of grouped) {
    captures.sort((a, b) => Date.parse(b.capturedAt) - Date.parse(a.capturedAt));
    const latest = captures[0]!;
    const previous = captures[1];
    if (!previous) {
      items.push({
        source, baselineAt: null, targetAt: latest.capturedAt, comparable: false,
        newCases: 0, clearedCases: 0, changedCases: 0, indeterminateCases: 0,
        warnings: ["At least two captures are required to compare this source."],
      });
      continue;
    }
    const result = compareCaseSnapshots(previous, latest);
    items.push({
      source, baselineAt: previous.capturedAt, targetAt: latest.capturedAt,
      comparable: result.complete, newCases: result.counts.NEW,
      clearedCases: result.counts.CLEARED, changedCases: result.counts.CHANGED,
      indeterminateCases: result.counts.INDETERMINATE, warnings: result.warnings,
    });
  }
  items.sort((a, b) => a.source.localeCompare(b.source));
  return {
    organizationId, items,
    compared: items.filter(item => item.baselineAt !== null).length,
    skipped: items.filter(item => item.baselineAt === null).length,
    warnings: ["Changes in recorded diagnostics do not demonstrate security-control effectiveness."],
  };
}
