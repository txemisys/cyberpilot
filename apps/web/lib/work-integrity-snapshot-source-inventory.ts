import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest, verifySnapshotManifest, type SnapshotManifest } from "./work-integrity-snapshot-integrity";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

/**
 * Reconcile offline capture inventories against an explicit expected-source
 * schedule. Missing or stale sources remain unknown; they are never counted
 * as healthy, verified, or remediated.
 */
export type SourceSchedule = {
  source: string;
  required: boolean;
  expectedIntervalMinutes: number;
  maximumLagMinutes: number;
  minimumCases: number;
  requireComplete: boolean;
  requireQualityClearance: boolean;
};
export type SourceHealth =
  | "CURRENT" | "LATE" | "MISSING" | "INCOMPLETE"
  | "QUALITY_BLOCKED" | "BELOW_MINIMUM" | "OPTIONAL_MISSING";
export type SourceInventoryRow = {
  source: string;
  required: boolean;
  health: SourceHealth;
  latestCapturedAt: string | null;
  previousCapturedAt: string | null;
  observedCaptures: number;
  completeCaptures: number;
  latestCaseCount: number | null;
  latestQualityBlockers: number | null;
  lagMinutes: number | null;
  observedIntervalMinutes: number | null;
  expectedIntervalMinutes: number;
  maximumLagMinutes: number;
  nextExpectedAt: string | null;
  reasons: string[];
  recommendedAction: string;
};
export type SourceInventoryReport = {
  organizationId: string;
  evaluatedAt: string;
  scheduledSources: number;
  requiredSources: number;
  currentRequiredSources: number;
  missingRequiredSources: number;
  lateRequiredSources: number;
  otherBlockedRequiredSources: number;
  unscheduledSources: string[];
  rows: SourceInventoryRow[];
  coverageRatio: number | null;
  warnings: string[];
};
export type SourceInventoryPolicy = {
  rejectUnscheduledSources: boolean;
  maxSnapshots: number;
  maxSources: number;
};
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function validatedSchedule(input: SourceSchedule): SourceSchedule {
  if (!input || typeof input.source !== "string" ||
      !input.source.trim() || input.source.length > 1000)
    throw new Error("Invalid scheduled source.");
  if (typeof input.required !== "boolean" ||
      typeof input.requireComplete !== "boolean" ||
      typeof input.requireQualityClearance !== "boolean")
    throw new Error("Invalid source schedule flags.");
  return {
    source: input.source, required: input.required,
    expectedIntervalMinutes: integer(input.expectedIntervalMinutes, 1, 525600,
      "expected interval"),
    maximumLagMinutes: integer(input.maximumLagMinutes, 1, 525600,
      "maximum lag"),
    minimumCases: integer(input.minimumCases, 0, 10000, "minimum case count"),
    requireComplete: input.requireComplete,
    requireQualityClearance: input.requireQualityClearance,
  };
}
export function reconcileSnapshotSourceInventory(
  input: readonly unknown[], organizationId: string, evaluatedAt: string,
  scheduleInput: readonly SourceSchedule[], policy: SourceInventoryPolicy,
): SourceInventoryReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  const maxSnapshots = integer(policy.maxSnapshots, 1, 10000, "inventory snapshot limit");
  const maxSources = integer(policy.maxSources, 1, 1000, "inventory source limit");
  if (input.length > maxSnapshots || scheduleInput.length > maxSources)
    throw new Error("Inventory cardinality limit exceeded.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid inventory evaluation time.");
  const schedule = scheduleInput.map(validatedSchedule);
  const scheduled = new Map<string, SourceSchedule>();
  for (const item of schedule) {
    if (scheduled.has(item.source)) throw new Error("Duplicate scheduled source.");
    scheduled.set(item.source, item);
  }
  const groups = new Map<string, CaseSnapshot[]>();
  const identities = new Set<string>();
  for (const raw of input) {
    const capture = parseCaseSnapshot(raw);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization inventory capture is forbidden.");
    const timestamp = Date.parse(capture.capturedAt);
    if (timestamp > now) throw new Error("Future capture in source inventory.");
    const key = JSON.stringify([capture.source, timestamp]);
    if (identities.has(key)) throw new Error("Duplicate inventory capture identity.");
    identities.add(key);
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const unscheduledSources = [...groups.keys()].filter(source =>
    !scheduled.has(source)).sort();
  if (policy.rejectUnscheduledSources && unscheduledSources.length)
    throw new Error("Unscheduled capture sources are forbidden.");
  const rows: SourceInventoryRow[] = [];
  for (const item of schedule) {
    const captures = (groups.get(item.source) ?? []).sort((a, b) =>
      Date.parse(b.capturedAt) - Date.parse(a.capturedAt));
    const latest = captures[0];
    const previous = captures[1];
    const lagMinutes = latest ?
      (now - Date.parse(latest.capturedAt)) / 60000 : null;
    const observedIntervalMinutes = latest && previous ?
      (Date.parse(latest.capturedAt) - Date.parse(previous.capturedAt)) / 60000 : null;
    const quality = latest ? inspectCaptureQuality(latest) : null;
    const reasons: string[] = [];
    let health: SourceHealth;
    if (!latest) {
      health = item.required ? "MISSING" : "OPTIONAL_MISSING";
      reasons.push("No capture has been supplied for this scheduled source.");
    } else if (lagMinutes! > item.maximumLagMinutes) {
      health = "LATE";
      reasons.push("Latest capture exceeds the allowed source lag.");
    } else if (item.requireComplete && !latest.complete) {
      health = "INCOMPLETE";
      reasons.push("Latest capture does not claim complete coverage.");
    } else if (item.requireQualityClearance && quality && !quality.safeToTreatAsComplete) {
      health = "QUALITY_BLOCKED";
      reasons.push("Latest capture has unresolved structural quality issues.");
    } else if (latest.cases.length < item.minimumCases) {
      health = "BELOW_MINIMUM";
      reasons.push("Latest capture is below the configured case count floor.");
    } else {
      health = "CURRENT";
    }
    const recommendedAction = health === "CURRENT" ?
      "Continue scheduled collection and preserve source history." :
      health === "LATE" || health === "MISSING" || health === "OPTIONAL_MISSING" ?
        "Investigate connector collection and obtain a current capture." :
      health === "INCOMPLETE" ?
        "Recollect complete source coverage before treating absence as resolved." :
      health === "QUALITY_BLOCKED" ?
        "Inspect structural quality diagnostics and recollect inconsistent records." :
        "Validate expected source scope and the configured minimum case count.";
    rows.push({
      source: item.source, required: item.required, health,
      latestCapturedAt: latest?.capturedAt ?? null,
      previousCapturedAt: previous?.capturedAt ?? null,
      observedCaptures: captures.length,
      completeCaptures: captures.filter(capture => capture.complete).length,
      latestCaseCount: latest?.cases.length ?? null,
      latestQualityBlockers: quality?.blockers ?? null,
      lagMinutes, observedIntervalMinutes,
      expectedIntervalMinutes: item.expectedIntervalMinutes,
      maximumLagMinutes: item.maximumLagMinutes,
      nextExpectedAt: latest ?
        new Date(Date.parse(latest.capturedAt) +
          item.expectedIntervalMinutes * 60000).toISOString() : null,
      reasons, recommendedAction,
    });
  }
  rows.sort((a, b) => a.source.localeCompare(b.source));
  const required = rows.filter(row => row.required);
  const current = required.filter(row => row.health === "CURRENT").length;
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    scheduledSources: rows.length, requiredSources: required.length,
    currentRequiredSources: current,
    missingRequiredSources: required.filter(row => row.health === "MISSING").length,
    lateRequiredSources: required.filter(row => row.health === "LATE").length,
    otherBlockedRequiredSources: required.filter(row =>
      !["CURRENT", "MISSING", "LATE"].includes(row.health)).length,
    unscheduledSources,
    coverageRatio: required.length ? Math.round(current / required.length * 10000) / 100 : null,
    rows,
    warnings: [
      "Source inventory evaluates supplied captures against a declared collection schedule.",
      "CURRENT means operationally timely and structurally acceptable, not security-compliant.",
      "Missing sources and incomplete captures cannot prove absence of findings.",
      ...(unscheduledSources.length ?
        ["Some captured sources are not present in the expected source schedule."] : []),
    ],
  };
}
export type InventoryManifestAudit = {
  organizationId: string;
  generatedAt: string;
  expectedRoot: string;
  actualRoot: string;
  verified: boolean;
  sourceCoverage: number | null;
  sourceIssues: Array<{ source: string; health: SourceHealth }>;
  warnings: string[];
};
export function auditInventoryAgainstManifest(
  report: SourceInventoryReport, captures: readonly unknown[],
  manifest: SnapshotManifest,
): InventoryManifestAudit {
  if (manifest.organizationId !== report.organizationId)
    throw new Error("Cross-organization inventory manifest forbidden.");
  const actual = buildSnapshotManifest(captures, report.organizationId,
    manifest.generatedAt);
  const verification = verifySnapshotManifest(manifest, captures);
  return {
    organizationId: report.organizationId, generatedAt: manifest.generatedAt,
    expectedRoot: manifest.rootSha256, actualRoot: actual.rootSha256,
    verified: verification.verified,
    sourceCoverage: report.coverageRatio,
    sourceIssues: report.rows.filter(row => row.health !== "CURRENT")
      .map(row => ({ source: row.source, health: row.health })),
    warnings: [
      "A matching manifest confirms relative integrity only when the original manifest is trusted.",
      "Source schedule coverage and manifest integrity are separate operational properties.",
    ],
  };
}
