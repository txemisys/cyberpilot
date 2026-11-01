import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest, type SnapshotManifest } from "./work-integrity-snapshot-integrity";
import { auditSnapshotCustody, type CustodyPolicy, type CustodyReport } from "./work-integrity-snapshot-custody";
import { reconcileSnapshotSourceInventory, type SourceSchedule, type SourceInventoryPolicy, type SourceInventoryReport } from "./work-integrity-snapshot-source-inventory";
import { detectSnapshotIncidents, type SnapshotIncidentPolicy, type SnapshotIncidentReport } from "./work-integrity-snapshot-incidents";
import { planSnapshotIngestion, type IngestionPolicy, type IngestionPlan } from "./work-integrity-snapshot-ingestion";
import { type SnapshotJournal, verifySnapshotJournal } from "./work-integrity-snapshot-journal";

/**
 * An operational evidence gate combining independently calculated integrity,
 * custody, source schedule, change incidents, and ingestion preflight.
 *
 * This is intentionally fail-closed. An unknown or missing source cannot be
 * represented as healthy; an unsigned caller-supplied journal is not trusted
 * as independent evidence of custody. The output is a decision aid, not a
 * compliance certification or a persistent evidence store.
 */
export type ReadinessDecision = "BLOCK" | "REVIEW" | "READY";
export type ReadinessCheckId =
  | "JOURNAL_INTEGRITY" | "CUSTODY_RECONCILIATION" | "SOURCE_COVERAGE"
  | "SOURCE_FRESHNESS" | "SOURCE_QUALITY" | "UNSCHEDULED_SOURCES"
  | "CAPTURE_COMPLETENESS" | "CAPTURE_FRESHNESS"
  | "INCIDENT_BLOCKERS" | "INCIDENT_WARNINGS"
  | "INGESTION_REJECTIONS" | "INGESTION_SKIPS"
  | "MANIFEST_CONSISTENCY" | "MINIMUM_HISTORY";
export type ReadinessCheck = {
  id: ReadinessCheckId;
  decision: ReadinessDecision;
  measured: number;
  expected: number | null;
  unit: "captures" | "sources" | "incidents" | "issues" | "ratio";
  explanation: string;
  nextAction: string;
  affectedSources: string[];
};
export type ReadinessPolicy = {
  custody: CustodyPolicy;
  inventory: SourceInventoryPolicy;
  incidents: SnapshotIncidentPolicy;
  ingestion: IngestionPolicy;
  minimumHistoryPerRequiredSource: number;
  minimumRequiredCoverageRatio: number;
  maximumWarningIncidents: number;
  maximumUnscheduledSources: number;
  maximumIngestionRejections: number;
  blockOnIncompleteCaptures: boolean;
  blockOnUnverifiedJournal: boolean;
  blockOnCustodyWarnings: boolean;
  requireAtLeastOneRequiredSource: boolean;
};
export type ReadinessSource = {
  source: string;
  required: boolean;
  health: string;
  captureCount: number;
  activeJournalCount: number;
  custodyBlockers: number;
  custodyWarnings: number;
  incidentBlockers: number;
  incidentWarnings: number;
  ingestionRejected: number;
  latestCapturedAt: string | null;
  decision: ReadinessDecision;
  reasons: string[];
  nextActions: string[];
};
export type ReadinessSummary = {
  decision: ReadinessDecision;
  blockers: number;
  reviews: number;
  passed: number;
  requiredSources: number;
  readyRequiredSources: number;
  reviewedRequiredSources: number;
  blockedRequiredSources: number;
  sourceCoverageRatio: number | null;
  sourceReadinessRatio: number | null;
  activeJournalCaptures: number;
  observedCaptures: number;
  acceptedIncomingCaptures: number;
  rejectedIncomingCaptures: number;
  unresolvedIncidents: number;
};
export type SnapshotReadinessReport = {
  version: 1;
  organizationId: string;
  evaluatedAt: string;
  summary: ReadinessSummary;
  checks: ReadinessCheck[];
  sources: ReadinessSource[];
  manifest: SnapshotManifest;
  custody: CustodyReport;
  inventory: SourceInventoryReport;
  incidents: SnapshotIncidentReport;
  ingestion: IngestionPlan;
  nextActions: Array<{
    priority: "IMMEDIATE" | "HIGH" | "NORMAL";
    source: string | null;
    action: string;
    relatedChecks: ReadinessCheckId[];
  }>;
  limitations: string[];
};
function bounded(value: number, min: number, max: number, label: string): number {
  if (!Number.isFinite(value) || value < min || value > max)
    throw new Error(`Invalid readiness ${label}.`);
  return value;
}
function boundedInt(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value)) throw new Error(`Invalid readiness ${label}.`);
  return bounded(value, min, max, label);
}
function severity(decision: ReadinessDecision): number {
  return decision === "BLOCK" ? 2 : decision === "REVIEW" ? 1 : 0;
}
function strongest(decisions: readonly ReadinessDecision[]): ReadinessDecision {
  return decisions.some(decision => decision === "BLOCK") ? "BLOCK" :
    decisions.some(decision => decision === "REVIEW") ? "REVIEW" : "READY";
}
function identity(source: string, at: string): string {
  return JSON.stringify([source, Date.parse(at)]);
}
function uniqueCaptures(raw: readonly unknown[], organizationId: string): CaseSnapshot[] {
  if (raw.length > 10000) throw new Error("Readiness capture limit exceeded.");
  const captures = raw.map(value => parseCaseSnapshot(value));
  const seen = new Set<string>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization readiness capture forbidden.");
    const key = identity(capture.source, capture.capturedAt);
    if (seen.has(key)) throw new Error("Duplicate readiness capture identity.");
    seen.add(key);
  }
  return captures.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
}
function check(
  id: ReadinessCheckId, decision: ReadinessDecision, measured: number,
  expected: number | null, unit: ReadinessCheck["unit"],
  explanation: string, nextAction: string,
  affectedSources: string[] = [],
): ReadinessCheck {
  return {
    id, decision, measured, expected, unit,
    explanation, nextAction, affectedSources: [...new Set(affectedSources)].sort(),
  };
}
function collectNextActions(checks: ReadinessCheck[]): SnapshotReadinessReport["nextActions"] {
  const result = new Map<string, SnapshotReadinessReport["nextActions"][number]>();
  for (const item of checks) {
    if (item.decision === "READY") continue;
    const sources: Array<string | null> = item.affectedSources.length ?
      item.affectedSources : [null];
    for (const source of sources) {
      const key = JSON.stringify([source, item.nextAction]);
      const priority = item.decision === "BLOCK" ? "IMMEDIATE" : "HIGH";
      const previous = result.get(key);
      if (previous) {
        if (!previous.relatedChecks.includes(item.id))
          previous.relatedChecks.push(item.id);
        if (priority === "IMMEDIATE") previous.priority = priority;
      } else result.set(key, {
        priority, source, action: item.nextAction, relatedChecks: [item.id],
      });
    }
  }
  return [...result.values()].sort((a, b) => {
    const rank = (priority: string) => priority === "IMMEDIATE" ? 0 : 1;
    return rank(a.priority) - rank(b.priority) ||
      (a.source ?? "").localeCompare(b.source ?? "") ||
      a.action.localeCompare(b.action);
  });
}
export function assessSnapshotOperationalReadiness(
  rawCaptures: readonly unknown[], incomingCaptures: readonly unknown[],
  journal: SnapshotJournal, organizationId: string, evaluatedAt: string,
  schedule: readonly SourceSchedule[], policy: ReadinessPolicy,
): SnapshotReadinessReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid readiness evaluation time.");
  boundedInt(policy.minimumHistoryPerRequiredSource, 0, 1000, "history floor");
  bounded(policy.minimumRequiredCoverageRatio, 0, 1, "coverage ratio");
  boundedInt(policy.maximumWarningIncidents, 0, 10000, "incident warning cap");
  boundedInt(policy.maximumUnscheduledSources, 0, 1000, "unscheduled source cap");
  boundedInt(policy.maximumIngestionRejections, 0, 10000, "ingestion rejection cap");
  if (typeof policy.blockOnIncompleteCaptures !== "boolean" ||
      typeof policy.blockOnUnverifiedJournal !== "boolean" ||
      typeof policy.blockOnCustodyWarnings !== "boolean" ||
      typeof policy.requireAtLeastOneRequiredSource !== "boolean")
    throw new Error("Invalid readiness policy flags.");
  const captures = uniqueCaptures(rawCaptures, organizationId);
  const incoming = uniqueCaptures(incomingCaptures, organizationId);
  if (captures.length + incoming.length > 10000)
    throw new Error("Combined readiness capture limit exceeded.");
  // A capture cannot be both historical and pending ingestion. Reject this
  // ambiguous provenance before custody, source coverage or incident analysis.
  // The two collections are individually unique, but must also be disjoint.
  const historicalKeys = new Set(captures.map(capture =>
    identity(capture.source, capture.capturedAt)));
  for (const candidate of incoming) {
    if (historicalKeys.has(identity(candidate.source, candidate.capturedAt)))
      throw new Error("Incoming readiness capture already exists in historical captures.");
  }
  const manifest = buildSnapshotManifest(captures, organizationId, evaluatedAt);
  const journalCheck = verifySnapshotJournal(journal, organizationId);
  const custody = auditSnapshotCustody(captures, journal, organizationId,
    evaluatedAt, policy.custody);
  const inventory = reconcileSnapshotSourceInventory(captures, organizationId,
    evaluatedAt, schedule, policy.inventory);
  const incidents = detectSnapshotIncidents(captures, organizationId, policy.incidents);
  const ingestion = planSnapshotIngestion(incoming, captures, organizationId,
    evaluatedAt, policy.ingestion);
  const checks: ReadinessCheck[] = [];
  const add = (...args: Parameters<typeof check>) => checks.push(check(...args));
  add("JOURNAL_INTEGRITY",
    journalCheck.valid ? "READY" :
      policy.blockOnUnverifiedJournal ? "BLOCK" : "REVIEW",
    journalCheck.errors.length, 0, "issues",
    journalCheck.valid ? "Journal replay matches the supplied chain and state." :
      "Journal replay found structural or digest inconsistencies.",
    "Restore and independently verify the journal checkpoint before relying on custody.");
  add("CUSTODY_RECONCILIATION",
    custody.blockers ? "BLOCK" :
      custody.warnings && policy.blockOnCustodyWarnings ? "BLOCK" :
      custody.warnings ? "REVIEW" : "READY",
    custody.blockers + custody.warnings, 0, "issues",
    "Active journal entries must match the supplied capture inventory and digests.",
    "Investigate missing, unregistered, changed or quarantined evidence.",
    custody.issues.filter(issue => issue.severity !== "INFO")
      .map(issue => issue.source).filter(source => source !== "*"));
  const required = inventory.rows.filter(row => row.required);
  const current = required.filter(row => row.health === "CURRENT");
  const unhealthy = required.filter(row => row.health !== "CURRENT");
  const coverage = inventory.coverageRatio ?? 0;
  add("SOURCE_COVERAGE",
    policy.requireAtLeastOneRequiredSource && !required.length ? "BLOCK" :
      coverage < policy.minimumRequiredCoverageRatio ? "BLOCK" : "READY",
    coverage, policy.minimumRequiredCoverageRatio, "ratio",
    "Required sources must be represented by current, usable captures.",
    "Collect required missing sources and verify the expected connector schedule.",
    unhealthy.map(row => row.source));
  const late = required.filter(row => row.health === "LATE" ||
    row.health === "MISSING");
  add("SOURCE_FRESHNESS", late.length ? "BLOCK" : "READY",
    late.length, 0, "sources",
    "Required sources must not be absent or beyond their maximum lag.",
    "Re-run source collection and investigate connector freshness.",
    late.map(row => row.source));
  const qualityBlocked = required.filter(row =>
    !["CURRENT", "LATE", "MISSING"].includes(row.health));
  add("SOURCE_QUALITY", qualityBlocked.length ? "BLOCK" : "READY",
    qualityBlocked.length, 0, "sources",
    "Required sources must meet configured quality, completeness and case floors.",
    "Investigate capture quality and recollect incomplete evidence.",
    qualityBlocked.map(row => row.source));
  add("UNSCHEDULED_SOURCES",
    inventory.unscheduledSources.length > policy.maximumUnscheduledSources ?
      "BLOCK" : inventory.unscheduledSources.length ? "REVIEW" : "READY",
    inventory.unscheduledSources.length, policy.maximumUnscheduledSources,
    "sources", "Unscheduled sources may indicate unexpected or untrusted data.",
    "Review the source inventory and explicitly authorize expected collectors.",
    inventory.unscheduledSources);
  const incomplete = captures.filter(capture => !capture.complete);
  add("CAPTURE_COMPLETENESS",
    incomplete.length && policy.blockOnIncompleteCaptures ? "BLOCK" :
      incomplete.length ? "REVIEW" : "READY",
    incomplete.length, 0, "captures",
    "Incomplete captures cannot establish that absent findings were remediated.",
    "Recollect incomplete sources before interpreting missing findings.",
    incomplete.map(capture => capture.source));
  const old = captures.filter(capture =>
    now - Date.parse(capture.capturedAt) > policy.custody.maxAgeDays * 86400000);
  add("CAPTURE_FRESHNESS", old.length ? "REVIEW" : "READY",
    old.length, 0, "captures",
    "Old captures are historical observations, not current assurance.",
    "Collect a current capture before making present-tense security claims.",
    old.map(capture => capture.source));
  const blockingIncidents = incidents.incidents.filter(incident =>
    incident.severity === "BLOCKER");
  const warningIncidents = incidents.incidents.filter(incident =>
    incident.severity === "WARNING");
  add("INCIDENT_BLOCKERS", blockingIncidents.length ? "BLOCK" : "READY",
    blockingIncidents.length, 0, "incidents",
    "Blocking regressions require investigation before accepting new evidence.",
    "Investigate regression and retain the prior trusted baseline.",
    blockingIncidents.map(incident => incident.source));
  add("INCIDENT_WARNINGS",
    warningIncidents.length > policy.maximumWarningIncidents ? "BLOCK" :
      warningIncidents.length ? "REVIEW" : "READY",
    warningIncidents.length, policy.maximumWarningIncidents, "incidents",
    "Warning regressions may invalidate confidence in source continuity.",
    "Review warning regressions and document their disposition.",
    warningIncidents.map(incident => incident.source));
  add("INGESTION_REJECTIONS",
    ingestion.rejected > policy.maximumIngestionRejections ? "BLOCK" :
      ingestion.rejected ? "REVIEW" : "READY",
    ingestion.rejected, policy.maximumIngestionRejections, "captures",
    "Rejected incoming captures must not enter trusted evidence inventories.",
    "Inspect ingestion rejection reasons and recollect invalid source data.",
    ingestion.candidates.filter(candidate => candidate.disposition === "REJECT")
      .map(candidate => candidate.source));
  add("INGESTION_SKIPS", ingestion.skippedIdentical ? "REVIEW" : "READY",
    ingestion.skippedIdentical, 0, "captures",
    "Identical captures already present in the inventory are skipped.",
    "Confirm duplicate collection scheduling and avoid redundant imports.",
    ingestion.candidates.filter(candidate =>
      candidate.disposition === "SKIP_IDENTICAL").map(candidate => candidate.source));
  const manifestCount = manifest.entries.length;
  add("MANIFEST_CONSISTENCY", manifestCount === captures.length ? "READY" : "BLOCK",
    manifestCount, captures.length, "captures",
    "Every unique capture must have one canonical manifest digest.",
    "Rebuild the manifest from the original validated captures.");
  const insufficient = required.filter(row =>
    row.observedCaptures < policy.minimumHistoryPerRequiredSource);
  add("MINIMUM_HISTORY", insufficient.length ? "REVIEW" : "READY",
    insufficient.length, 0, "sources",
    "Historical comparisons require enough observations per required source.",
    "Collect additional scheduled snapshots before interpreting trends.",
    insufficient.map(row => row.source));
  const sources: ReadinessSource[] = inventory.rows.map(row => {
    const custodyRow = custody.sources.find(item => item.source === row.source);
    const sourceIncidents = incidents.incidents.filter(item => item.source === row.source);
    const rejected = ingestion.candidates.filter(item =>
      item.source === row.source && item.disposition === "REJECT");
    const relevant = checks.filter(item => item.affectedSources.includes(row.source));
    const reasons = relevant.filter(item => item.decision !== "READY")
      .map(item => item.explanation);
    const nextActions = relevant.filter(item => item.decision !== "READY")
      .map(item => item.nextAction);
    const decision = strongest([
      row.required && row.health !== "CURRENT" ? "BLOCK" : "READY",
      ...relevant.map(item => item.decision),
    ]);
    return {
      source: row.source, required: row.required, health: row.health,
      captureCount: row.observedCaptures,
      activeJournalCount: custodyRow?.activeJournalCaptures ?? 0,
      custodyBlockers: custodyRow?.blockers ?? 0,
      custodyWarnings: custodyRow?.warnings ?? 0,
      incidentBlockers: sourceIncidents.filter(item => item.severity === "BLOCKER").length,
      incidentWarnings: sourceIncidents.filter(item => item.severity === "WARNING").length,
      ingestionRejected: rejected.length,
      latestCapturedAt: row.latestCapturedAt, decision,
      reasons: [...new Set(reasons)],
      nextActions: [...new Set(nextActions)],
    };
  }).sort((a, b) => severity(b.decision) - severity(a.decision) ||
    Number(b.required) - Number(a.required) || a.source.localeCompare(b.source));
  const requiredSources = sources.filter(source => source.required);
  const blockedRequiredSources = requiredSources.filter(source =>
    source.decision === "BLOCK").length;
  const reviewedRequiredSources = requiredSources.filter(source =>
    source.decision === "REVIEW").length;
  const readyRequiredSources = requiredSources.filter(source =>
    source.decision === "READY").length;
  const summary: ReadinessSummary = {
    decision: strongest(checks.map(item => item.decision)),
    blockers: checks.filter(item => item.decision === "BLOCK").length,
    reviews: checks.filter(item => item.decision === "REVIEW").length,
    passed: checks.filter(item => item.decision === "READY").length,
    requiredSources: requiredSources.length, readyRequiredSources,
    reviewedRequiredSources, blockedRequiredSources,
    sourceCoverageRatio: inventory.coverageRatio,
    sourceReadinessRatio: requiredSources.length ?
      readyRequiredSources / requiredSources.length : null,
    activeJournalCaptures: journalCheck.valid ?
      journal.captures.filter(item => item.status === "ACTIVE").length : 0,
    observedCaptures: captures.length,
    acceptedIncomingCaptures: ingestion.accepted,
    rejectedIncomingCaptures: ingestion.rejected,
    unresolvedIncidents: incidents.incidents.length,
  };
  return {
    version: 1, organizationId,
    evaluatedAt: new Date(now).toISOString(),
    summary, checks, sources, manifest, custody, inventory,
    incidents, ingestion, nextActions: collectNextActions(checks),
    limitations: [
      "This report is calculated from caller-supplied data, not directly from durable evidence storage.",
      "Journal hashes do not independently authenticate authors or establish custody.",
      "A READY decision means only that configured operational preflight checks passed.",
      "READY does not certify regulatory compliance, finding closure or security effectiveness.",
      "Missing source observations must remain unknown rather than being reported as healthy.",
    ],
  };
}
