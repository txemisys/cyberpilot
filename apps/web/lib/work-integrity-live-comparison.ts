import type { CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots, parseCaseSnapshot } from "./work-integrity-snapshots";
import { compareReviewWorklists } from "./work-integrity-worklist";
import { caseDimensions, trendCases, caseCohorts } from "./work-integrity-analytics";
import { buildEvidenceReadiness, compareEvidenceReadiness } from "./work-integrity-evidence-readiness";
import { LIVE_EVIDENCE_REQUIREMENTS } from "./work-integrity-live-queue";
import { inspectCaptureQuality, type CaptureQualityReport } from "./work-integrity-capture-quality";

/**
 * Explicitly offline comparison of two user-provided operational case captures.
 * The server must authenticate the caller and supply its trusted organization ID.
 * A submitted organizationId never grants access to another tenant.
 */
export type IntegrityComparisonInput = {
  before: unknown;
  after: unknown;
};
export type IntegrityComparisonSummary = {
  organizationId: string;
  beforeCapturedAt: string;
  afterCapturedAt: string;
  complete: boolean;
  quality: { before: CaptureQualityReport; after: CaptureQualityReport };
  counts: ReturnType<typeof compareCaseSnapshots>["counts"];
  priority: {
    escalations: number;
    deescalations: number;
    indeterminate: number;
  };
  evidence: {
    beforeReady: number;
    afterReady: number;
    beforeBlocked: number;
    afterBlocked: number;
    newlyBlocked: number;
    newlyReady: number;
    uncertain: number;
  };
  changes: Array<{
    key: string;
    kind: string;
    fields: string[];
    priorityBefore: string | null;
    priorityAfter: string | null;
    priorityEscalated: boolean;
    priorityDeescalated: boolean;
    beforeReady: boolean | null;
    afterReady: boolean | null;
    addedEvidenceGaps: string[];
    removedEvidenceGaps: string[];
    uncertain: boolean;
  }>;
  cohorts: {
    code: ReturnType<typeof caseCohorts>;
    severity: ReturnType<typeof caseCohorts>;
    state: ReturnType<typeof caseCohorts>;
  };
  metrics: {
    before: ReturnType<typeof caseDimensions>;
    after: ReturnType<typeof caseDimensions>;
    change: ReturnType<typeof trendCases>["change"];
  };
  warnings: string[];
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Comparison body must be an object.");
  return value as Record<string, unknown>;
}
export function validateComparisonInput(
  value: unknown, trustedOrganizationId: string, maxCases = 5000,
): { before: CaseSnapshot; after: CaseSnapshot } {
  if (!trustedOrganizationId || trustedOrganizationId.length > 256)
    throw new Error("Trusted organization ID is invalid.");
  if (!Number.isSafeInteger(maxCases) || maxCases < 1 || maxCases > 10000)
    throw new Error("Comparison case limit is invalid.");
  const raw = object(value);
  const before = parseCaseSnapshot(raw.before, maxCases);
  const after = parseCaseSnapshot(raw.after, maxCases);
  if (before.organizationId !== trustedOrganizationId ||
      after.organizationId !== trustedOrganizationId)
    throw new Error("Snapshot organization does not match authenticated membership.");
  if (before.source !== after.source)
    throw new Error("Capture source or bounded page scope differs; compare matching capture scopes.");
  if (Date.parse(before.capturedAt) > Date.parse(after.capturedAt))
    throw new Error("Before snapshot must not be newer than after snapshot.");
  return { before, after };
}
export function compareIntegrityCaptures(
  input: unknown, trustedOrganizationId: string, maxCases = 5000,
): IntegrityComparisonSummary {
  const { before, after } = validateComparisonInput(
    input, trustedOrganizationId, maxCases,
  );
  const quality = {
    before: inspectCaptureQuality(before),
    after: inspectCaptureQuality(after),
  };
  const comparison = compareCaseSnapshots(before, after);
  const priorities = compareReviewWorklists(before, after);
  const previousEvidence = buildEvidenceReadiness(before, LIVE_EVIDENCE_REQUIREMENTS);
  const currentEvidence = buildEvidenceReadiness(after, LIVE_EVIDENCE_REQUIREMENTS);
  const evidenceChanges = compareEvidenceReadiness(
    before, after, LIVE_EVIDENCE_REQUIREMENTS,
  );
  const priorityByKey = new Map(priorities.changes.map(change => [change.key, change]));
  const evidenceByKey = new Map(evidenceChanges.map(change => [change.caseKey, change]));
  const trends = trendCases(before, after, comparison);
  const verifiedCoverage = comparison.complete &&
    quality.before.safeToTreatAsComplete && quality.after.safeToTreatAsComplete;
  const changes = comparison.deltas
    .filter(delta => delta.kind !== "UNCHANGED")
    .map(delta => {
      const priority = priorityByKey.get(delta.key);
      const evidence = evidenceByKey.get(delta.key);
      const uncertain = !verifiedCoverage ||
        delta.kind === "INDETERMINATE" || Boolean(evidence?.uncertain);
      return {
        key: delta.key, kind: delta.kind, fields: delta.changes,
        priorityBefore: priority?.beforePriority ?? null,
        priorityAfter: priority?.afterPriority ?? null,
        priorityEscalated: priority?.escalated ?? false,
        priorityDeescalated: priority?.deescalated ?? false,
        beforeReady: evidence?.beforeReady ?? null,
        afterReady: evidence?.afterReady ?? null,
        addedEvidenceGaps: evidence?.addedGaps ?? [],
        removedEvidenceGaps: evidence?.removedGaps ?? [],
        uncertain,
      };
    });
  return {
    organizationId: trustedOrganizationId,
    beforeCapturedAt: before.capturedAt,
    afterCapturedAt: after.capturedAt,
    complete: verifiedCoverage,
    quality,
    counts: comparison.counts,
    priority: {
      escalations: priorities.escalations,
      deescalations: priorities.deescalations,
      indeterminate: priorities.indeterminate,
    },
    evidence: {
      beforeReady: previousEvidence.ready,
      afterReady: currentEvidence.ready,
      beforeBlocked: previousEvidence.blocked,
      afterBlocked: currentEvidence.blocked,
      newlyBlocked: changes.filter(x =>
        x.beforeReady === true && x.afterReady === false && !x.uncertain).length,
      newlyReady: changes.filter(x =>
        x.beforeReady === false && x.afterReady === true && !x.uncertain).length,
      uncertain: changes.filter(x => x.uncertain).length,
    },
    changes,
    cohorts: {
      code: caseCohorts(comparison, "code"),
      severity: caseCohorts(comparison, "severity"),
      state: caseCohorts(comparison, "state"),
    },
    metrics: {
      before: trends.before, after: trends.after, change: trends.change,
    },
    warnings: [
      ...comparison.warnings,
      ...trends.warnings,
      ...(!verifiedCoverage && comparison.complete ? [
        "One or both supplied captures contain quality warnings; coverage-dependent conclusions are not certified.",
      ] : []),
      "Snapshots are supplied by the caller and are not authenticated source records.",
      "Differences in diagnostic data do not establish remediation or security control effectiveness.",
      "Only captures with identical authenticated organization IDs can be compared.",
      "Results reflect only cases included in the supplied bounded captures.",
    ],
  };
}
export function integrityComparisonCsv(report: IntegrityComparisonSummary): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const columns = [
    "caseKey", "change", "fields", "priorityBefore", "priorityAfter",
    "escalated", "deescalated", "evidenceBeforeReady", "evidenceAfterReady",
    "addedEvidenceGaps", "removedEvidenceGaps", "uncertain",
  ];
  const rows = [columns.map(safe).join(",")];
  for (const change of report.changes) {
    rows.push([
      change.key, change.kind, change.fields.join(";"),
      change.priorityBefore, change.priorityAfter,
      change.priorityEscalated, change.priorityDeescalated,
      change.beforeReady, change.afterReady,
      change.addedEvidenceGaps.join(";"),
      change.removedEvidenceGaps.join(";"), change.uncertain,
    ].map(safe).join(","));
  }
  return rows.join("\r\n") + "\r\n";
}
