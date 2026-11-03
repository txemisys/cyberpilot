import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { reviewIntegrityLinks } from "./work-integrity-link-review";
import {
  evaluateIntegrityEvents, type IntegrityReviewPolicy,
  type IntegrityPolicyEvaluation,
} from "./work-integrity-review-policy";
import {
  snapshotIntegrityReview, compareIntegritySnapshots,
} from "./work-integrity-link-timeline";

export type IntegrityReviewWatchpoint = {
  id: string;
  label: string;
  policy: IntegrityReviewPolicy;
  baselineAt: string;
  currentAt: string;
};
export type IntegrityReviewWatchStatus =
  | "HEALTHY" | "WARNINGS" | "ERRORS" | "INCOMPLETE";
export type IntegrityReviewWatchResult = {
  id: string;
  label: string;
  captureId: string;
  baselineAt: string;
  currentAt: string;
  status: IntegrityReviewWatchStatus;
  baseline: IntegrityPolicyEvaluation;
  current: IntegrityPolicyEvaluation;
  changes: {
    linksCreated: number;
    linksWithdrawn: number;
    netActiveChange: number;
    introducedViolations: number;
    resolvedViolations: number;
  };
  introducedRules: string[];
  resolvedRules: string[];
};
export type IntegrityReviewWatchSummary = {
  captureId: string;
  total: number;
  healthy: number;
  warnings: number;
  errors: number;
  incomplete: number;
  watches: IntegrityReviewWatchResult[];
};
export function parseIntegrityWatchpoints(value: unknown): IntegrityReviewWatchpoint[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100)
    throw new WorkInputError("INVALID", "Watchpoints must contain 1–100 items.");
  const ids = new Set<string>();
  return value.map(raw => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new WorkInputError("INVALID", "Invalid watchpoint.");
    const item = raw as Record<string, unknown>;
    if (Object.keys(item).some(key =>
      !["id", "label", "policy", "baselineAt", "currentAt"].includes(key)))
      throw new WorkInputError("INVALID", "Unknown watchpoint field.");
    if (typeof item.id !== "string" || !/^[a-zA-Z0-9_-]{5,100}$/.test(item.id) ||
        ids.has(item.id))
      throw new WorkInputError("INVALID", "Invalid or duplicate watchpoint identifier.");
    ids.add(item.id);
    if (typeof item.label !== "string" || !item.label.trim() ||
        item.label.length > 160 || /[\u0000-\u001f]/.test(item.label))
      throw new WorkInputError("INVALID", "Invalid watchpoint label.");
    if (typeof item.baselineAt !== "string" ||
        typeof item.currentAt !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T/.test(item.baselineAt) ||
        !/^\d{4}-\d{2}-\d{2}T/.test(item.currentAt) ||
        item.baselineAt > item.currentAt)
      throw new WorkInputError("INVALID", "Invalid watchpoint interval.");
    const policy = item.policy as IntegrityReviewPolicy;
    if (!policy || typeof policy !== "object" || Array.isArray(policy))
      throw new WorkInputError("INVALID", "Invalid watchpoint policy.");
    return {
      id: item.id, label: item.label.trim(),
      policy, baselineAt: item.baselineAt, currentAt: item.currentAt,
    };
  });
}
function violationKey(item: IntegrityPolicyEvaluation["violations"][number]) {
  return JSON.stringify([
    item.ruleId, item.auditId, item.caseKey, item.workItemId,
  ]);
}
export function evaluateIntegrityWatchpoint(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  watch: IntegrityReviewWatchpoint,
): IntegrityReviewWatchResult {
  const before = snapshotIntegrityReview(captureId, events, watch.baselineAt);
  const after = snapshotIntegrityReview(captureId, events, watch.currentAt);
  const interval = compareIntegritySnapshots(before, after);
  const baseline = evaluateIntegrityEvents(captureId, events, {
    ...watch.policy, asOf: watch.baselineAt,
  });
  const current = evaluateIntegrityEvents(captureId, events, {
    ...watch.policy, asOf: watch.currentAt,
  });
  const old = new Map(baseline.violations.map(x => [violationKey(x), x]));
  const next = new Map(current.violations.map(x => [violationKey(x), x]));
  const introduced = [...next].filter(([key]) => !old.has(key)).map(([, x]) => x);
  const resolved = [...old].filter(([key]) => !next.has(key)).map(([, x]) => x);
  const status: IntegrityReviewWatchStatus =
    current.bySeverity.errors > 0 ? "ERRORS" :
    current.bySeverity.warnings > 0 ? "WARNINGS" : "HEALTHY";
  return {
    id: watch.id, label: watch.label, captureId,
    baselineAt: watch.baselineAt, currentAt: watch.currentAt,
    status, baseline, current,
    changes: {
      linksCreated: interval.linksCreated,
      linksWithdrawn: interval.linksWithdrawn,
      netActiveChange: interval.netChange,
      introducedViolations: introduced.length,
      resolvedViolations: resolved.length,
    },
    introducedRules: [...new Set(introduced.map(x => x.ruleId))].sort(),
    resolvedRules: [...new Set(resolved.map(x => x.ruleId))].sort(),
  };
}
export function evaluateIntegrityWatchpoints(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  watchpoints: readonly IntegrityReviewWatchpoint[],
): IntegrityReviewWatchSummary {
  const watches = watchpoints.map(watch =>
    evaluateIntegrityWatchpoint(captureId, events, watch));
  return {
    captureId, total: watches.length,
    healthy: watches.filter(x => x.status === "HEALTHY").length,
    warnings: watches.filter(x => x.status === "WARNINGS").length,
    errors: watches.filter(x => x.status === "ERRORS").length,
    incomplete: watches.filter(x => x.status === "INCOMPLETE").length,
    watches,
  };
}
export type IntegrityReviewWatchHistory = {
  captureId: string;
  evaluatedAt: string;
  totalEvents: number;
  watchpoints: IntegrityReviewWatchSummary;
  auditIntegrity: {
    errors: number;
    warnings: number;
    active: number;
    withdrawn: number;
  };
};
export function buildIntegrityReviewWatchHistory(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  watchpoints: readonly IntegrityReviewWatchpoint[],
  evaluatedAt: string,
): IntegrityReviewWatchHistory {
  const report = reviewIntegrityLinks(captureId, events.filter(x => x.occurredAt <= evaluatedAt));
  return {
    captureId, evaluatedAt, totalEvents: report.totalEvents,
    watchpoints: evaluateIntegrityWatchpoints(captureId, events, watchpoints),
    auditIntegrity: {
      errors: report.counts.errors, warnings: report.counts.warnings,
      active: report.counts.active, withdrawn: report.counts.withdrawn,
    },
  };
}

export type IntegrityWatchSeverityDistribution = {
  healthy: string[];
  warning: string[];
  error: string[];
  incomplete: string[];
};
export function distributeIntegrityWatchStatuses(
  summary: IntegrityReviewWatchSummary,
): IntegrityWatchSeverityDistribution {
  const distribution: IntegrityWatchSeverityDistribution = {
    healthy: [], warning: [], error: [], incomplete: [],
  };
  for (const watch of summary.watches) {
    if (watch.status === "HEALTHY") distribution.healthy.push(watch.id);
    else if (watch.status === "WARNINGS") distribution.warning.push(watch.id);
    else if (watch.status === "ERRORS") distribution.error.push(watch.id);
    else distribution.incomplete.push(watch.id);
  }
  for (const ids of Object.values(distribution)) ids.sort();
  return distribution;
}
export function findRegressedIntegrityWatchpoints(
  before: IntegrityReviewWatchSummary,
  after: IntegrityReviewWatchSummary,
): string[] {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Watch summaries belong to different captures.");
  const previous = new Map(before.watches.map(watch => [watch.id, watch]));
  return after.watches.filter(watch => {
    const old = previous.get(watch.id);
    if (!old) return false;
    const severity = { HEALTHY: 0, WARNINGS: 1, ERRORS: 2, INCOMPLETE: 3 };
    return severity[watch.status] > severity[old.status];
  }).map(watch => watch.id).sort();
}
