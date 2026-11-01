import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";

/**
 * Cross-capture case continuity analysis.
 * Each case is tracked by its stable diagnostic identity inside one source.
 * Missing cases in partial captures are treated as unknown, never cleared.
 */
export type ContinuityState =
  | "FIRST_SEEN" | "PRESENT" | "CHANGED" | "MISSING"
  | "INDETERMINATE" | "RETURNED";
export type ContinuityEvent = {
  source: string;
  caseKey: string;
  capturedAt: string;
  state: ContinuityState;
  previousCapturedAt: string | null;
  changedFields: string[];
  evidenceComplete: boolean;
};
export type ContinuityCase = {
  source: string;
  caseKey: string;
  firstSeenAt: string;
  lastSeenAt: string;
  latestState: ContinuityState;
  observedCaptures: number;
  missingCaptures: number;
  uncertainCaptures: number;
  returnCount: number;
  changeCount: number;
  events: ContinuityEvent[];
};
export type ContinuitySource = {
  source: string;
  captures: number;
  firstCapturedAt: string;
  latestCapturedAt: string;
  cases: ContinuityCase[];
  firstSeen: number;
  present: number;
  changed: number;
  missing: number;
  indeterminate: number;
  returned: number;
};
export type ContinuityReport = {
  organizationId: string;
  sources: ContinuitySource[];
  totalTrackedCases: number;
  totalEvents: number;
  warnings: string[];
};
export type ContinuityPolicy = {
  maxCapturesPerSource: number;
  maxEvents: number;
  includeUnchangedEvents: boolean;
};
function positive(value: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
export function buildCaseContinuityReport(
  input: readonly unknown[], organizationId: string, policy: ContinuityPolicy,
): ContinuityReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (input.length > 10000) throw new Error("Continuity capture limit exceeded.");
  const maxCapturesPerSource = positive(policy.maxCapturesPerSource, 1000, "capture limit");
  const maxEvents = positive(policy.maxEvents, 100000, "event limit");
  const groups = new Map<string, CaseSnapshot[]>();
  const identities = new Set<string>();
  for (const raw of input) {
    const capture = parseCaseSnapshot(raw);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization continuity capture is forbidden.");
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (identities.has(identity)) throw new Error("Duplicate continuity capture identity.");
    identities.add(identity);
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const sources: ContinuitySource[] = [];
  let totalEvents = 0;
  for (const [source, group] of groups) {
    if (group.length > maxCapturesPerSource)
      throw new Error("Source exceeds continuity capture limit.");
    group.sort((a, b) => Date.parse(a.capturedAt) - Date.parse(b.capturedAt));
    const tracked = new Map<string, ContinuityCase>();
    for (let index = 0; index < group.length; index++) {
      const current = group[index]!;
      const previous = index > 0 ? group[index - 1]! : null;
      const comparison = previous ? compareCaseSnapshots(previous, current) : null;
      const changed = new Map(comparison?.deltas.map(delta => [delta.key, delta]) ?? []);
      const currentKeys = new Set(current.cases.map(row => row.key));
      const previousKeys = new Set(previous?.cases.map(row => row.key) ?? []);
      for (const row of current.cases) {
        let item = tracked.get(row.key);
        const priorState = item?.latestState;
        const delta = changed.get(row.key);
        const state: ContinuityState = !item ? "FIRST_SEEN" :
          priorState === "MISSING" || priorState === "INDETERMINATE" ? "RETURNED" :
          delta?.kind === "CHANGED" ? "CHANGED" : "PRESENT";
        if (!item) {
          item = {
            source, caseKey: row.key, firstSeenAt: current.capturedAt,
            lastSeenAt: current.capturedAt, latestState: state,
            observedCaptures: 0, missingCaptures: 0, uncertainCaptures: 0,
            returnCount: 0, changeCount: 0, events: [],
          };
          tracked.set(row.key, item);
        }
        item.observedCaptures++;
        item.lastSeenAt = current.capturedAt;
        item.latestState = state;
        if (state === "RETURNED") item.returnCount++;
        if (state === "CHANGED") item.changeCount++;
        if (policy.includeUnchangedEvents || state !== "PRESENT") {
          item.events.push({
            source, caseKey: row.key, capturedAt: current.capturedAt,
            state, previousCapturedAt: previous?.capturedAt ?? null,
            changedFields: delta?.changes ?? [],
            evidenceComplete: current.complete && (previous?.complete ?? true),
          });
          totalEvents++;
        }
      }
      if (!previous) continue;
      for (const [key, item] of tracked) {
        if (currentKeys.has(key)) continue;
        // Only cases previously seen can be missing from this capture.
        // A partial capture never establishes a confirmed disappearance.
        const state: ContinuityState = current.complete ? "MISSING" : "INDETERMINATE";
        item.latestState = state;
        if (state === "MISSING") item.missingCaptures++;
        else item.uncertainCaptures++;
        if (policy.includeUnchangedEvents || previousKeys.has(key) ||
            item.events.at(-1)?.state !== state) {
          item.events.push({
            source, caseKey: key, capturedAt: current.capturedAt,
            state, previousCapturedAt: previous.capturedAt,
            changedFields: [], evidenceComplete: current.complete && previous.complete,
          });
          totalEvents++;
        }
      }
      if (totalEvents > maxEvents) throw new Error("Continuity event limit exceeded.");
    }
    if (totalEvents > maxEvents) throw new Error("Continuity event limit exceeded.");
    const cases = [...tracked.values()].sort((a, b) => a.caseKey.localeCompare(b.caseKey));
    const count = (state: ContinuityState) =>
      cases.filter(item => item.latestState === state).length;
    sources.push({
      source, captures: group.length,
      firstCapturedAt: group[0]!.capturedAt,
      latestCapturedAt: group.at(-1)!.capturedAt,
      cases, firstSeen: count("FIRST_SEEN"), present: count("PRESENT"),
      changed: count("CHANGED"), missing: count("MISSING"),
      indeterminate: count("INDETERMINATE"), returned: count("RETURNED"),
    });
  }
  sources.sort((a, b) => a.source.localeCompare(b.source));
  return {
    organizationId, sources,
    totalTrackedCases: sources.reduce((sum, source) => sum + source.cases.length, 0),
    totalEvents,
    warnings: [
      "Case continuity is derived from supplied snapshots and cannot verify their authenticity.",
      "Missing diagnostics do not prove remediation or security-control effectiveness.",
      "Incomplete captures cannot establish that a diagnostic case has disappeared.",
    ],
  };
}
