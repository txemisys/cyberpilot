import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/**
 * Offline review SLA engine. The policy is explicitly advisory: it does not
 * mutate work items, create audit events, or send notifications.
 */
export type SlaPriority = "P0" | "P1" | "P2" | "P3" | "P4";
export type SlaRule = {
  priority: SlaPriority;
  acknowledgeWithinMinutes: number;
  resolveWithinMinutes: number;
  warningBeforeMinutes: number;
  escalationAfterMinutes: number;
};
export type SlaPolicy = {
  rules: SlaRule[];
  excludeHistorical: boolean;
  pauseReviewed: boolean;
  requireCompleteCoverage: boolean;
  maximumCases: number;
};
export type SlaCheckpoint = {
  caseKey: string;
  workItemId: string;
  code: string;
  priority: SlaPriority;
  anchorAt: string;
  acknowledgeBy: string;
  resolveBy: string;
  warningAt: string;
  escalateAt: string;
  reviewed: boolean;
  staleReview: boolean;
  completeCoverage: boolean;
  historicalOnly: boolean;
};
export type SlaPlan = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  checkpoints: SlaCheckpoint[];
  excluded: number;
  warnings: string[];
};
export type SlaPhase = "UNKNOWN" | "PAUSED" | "ON_TRACK" |
  "ACK_WARNING" | "ACK_OVERDUE" | "RESOLUTION_WARNING" |
  "RESOLUTION_OVERDUE" | "ESCALATED";
export type SlaEvaluation = {
  caseKey: string;
  workItemId: string;
  priority: SlaPriority;
  phase: SlaPhase;
  minutesUntilAcknowledgement: number | null;
  minutesUntilResolution: number | null;
  minutesUntilEscalation: number | null;
  evaluatedAt: string;
  explanation: string;
};
export type SlaDashboard = {
  organizationId: string;
  evaluatedAt: string;
  complete: boolean;
  total: number;
  counts: Record<SlaPhase, number>;
  evaluations: SlaEvaluation[];
  urgent: SlaEvaluation[];
  warnings: string[];
};
export const DEFAULT_SLA_POLICY: SlaPolicy = {
  rules: [
    { priority: "P0", acknowledgeWithinMinutes: 30, resolveWithinMinutes: 240, warningBeforeMinutes: 15, escalationAfterMinutes: 60 },
    { priority: "P1", acknowledgeWithinMinutes: 120, resolveWithinMinutes: 1440, warningBeforeMinutes: 30, escalationAfterMinutes: 180 },
    { priority: "P2", acknowledgeWithinMinutes: 480, resolveWithinMinutes: 4320, warningBeforeMinutes: 60, escalationAfterMinutes: 720 },
    { priority: "P3", acknowledgeWithinMinutes: 1440, resolveWithinMinutes: 10080, warningBeforeMinutes: 120, escalationAfterMinutes: 2880 },
    { priority: "P4", acknowledgeWithinMinutes: 4320, resolveWithinMinutes: 20160, warningBeforeMinutes: 240, escalationAfterMinutes: 5760 },
  ],
  excludeHistorical: true,
  pauseReviewed: false,
  requireCompleteCoverage: true,
  maximumCases: 100000,
};
const priorities: SlaPriority[] = ["P0", "P1", "P2", "P3", "P4"];
const phases: SlaPhase[] = ["UNKNOWN", "PAUSED", "ON_TRACK", "ACK_WARNING",
  "ACK_OVERDUE", "RESOLUTION_WARNING", "RESOLUTION_OVERDUE", "ESCALATED"];
function utc(value: string, label: string): number {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw new Error(`Invalid ${label} timestamp.`);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value)
    throw new Error(`Noncanonical ${label} timestamp.`);
  return time;
}
function plusMinutes(anchor: number, minutes: number): string {
  const result = anchor + minutes * 60000;
  if (!Number.isFinite(result) || Math.abs(result) > 8_640_000_000_000_000)
    throw new Error("SLA timestamp outside supported range.");
  return new Date(result).toISOString();
}
function deltaMinutes(target: string, now: number): number {
  return Math.ceil((utc(target, "deadline") - now) / 60000);
}
export function validateSlaPolicy(input: SlaPolicy): SlaPolicy {
  if (!input || !Array.isArray(input.rules) || input.rules.length !== 5)
    throw new Error("Exactly five SLA priority rules are required.");
  const seen = new Set<string>();
  const rules = input.rules.map(rule => {
    if (!priorities.includes(rule.priority) || seen.has(rule.priority))
      throw new Error("Duplicate or invalid SLA priority.");
    seen.add(rule.priority);
    const values = [rule.acknowledgeWithinMinutes, rule.resolveWithinMinutes,
      rule.warningBeforeMinutes, rule.escalationAfterMinutes];
    if (values.some(value => !Number.isSafeInteger(value) || value < 0 || value > 5 * 365 * 1440))
      throw new Error("Invalid SLA time bound.");
    if (rule.acknowledgeWithinMinutes < 1 ||
        rule.resolveWithinMinutes < rule.acknowledgeWithinMinutes ||
        rule.warningBeforeMinutes > rule.acknowledgeWithinMinutes ||
        rule.escalationAfterMinutes < rule.acknowledgeWithinMinutes)
      throw new Error("Inconsistent SLA time bounds.");
    return { ...rule };
  }).sort((a, b) => a.priority.localeCompare(b.priority));
  if (!Number.isSafeInteger(input.maximumCases) ||
      input.maximumCases < 1 || input.maximumCases > 100000)
    throw new Error("Invalid SLA maximum case count.");
  if (typeof input.excludeHistorical !== "boolean" ||
      typeof input.pauseReviewed !== "boolean" ||
      typeof input.requireCompleteCoverage !== "boolean")
    throw new Error("Invalid SLA policy flags.");
  return { ...input, rules };
}
export function createSlaPlan(
  snapshot: CaseSnapshot, input: SlaPolicy = DEFAULT_SLA_POLICY,
): SlaPlan {
  const policy = validateSlaPolicy(input);
  const anchor = utc(snapshot.capturedAt, "snapshot");
  const entries = buildReviewWorklist(snapshot).entries.filter(entry =>
    !policy.excludeHistorical || !entry.historicalOnly);
  if (entries.length > policy.maximumCases)
    throw new Error("SLA plan exceeds configured maximum cases.");
  const rules = new Map(policy.rules.map(rule => [rule.priority, rule]));
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, complete: snapshot.complete,
    checkpoints: entries.map(entry => {
      const rule = rules.get(entry.priority)!;
      return {
        caseKey: entry.caseKey, workItemId: entry.workItemId, code: entry.code,
        priority: entry.priority, anchorAt: snapshot.capturedAt,
        acknowledgeBy: plusMinutes(anchor, rule.acknowledgeWithinMinutes),
        resolveBy: plusMinutes(anchor, rule.resolveWithinMinutes),
        warningAt: plusMinutes(anchor, rule.acknowledgeWithinMinutes - rule.warningBeforeMinutes),
        escalateAt: plusMinutes(anchor, rule.escalationAfterMinutes),
        reviewed: !!entry.reviewEventId,
        staleReview: entry.state === "STALE",
        completeCoverage: entry.completeCoverage,
        historicalOnly: entry.historicalOnly,
      };
    }),
    excluded: snapshot.cases.length - entries.length,
    warnings: [
      "SLA times are advisory and anchored to capture time, not original incident discovery.",
      "No external notifications, escalations, or remediation actions are performed.",
      ...(!snapshot.complete ? ["Partial collection prevents definitive SLA conclusions."] : []),
    ],
  };
}
export function evaluateSlaCheckpoint(
  checkpoint: SlaCheckpoint, assessedAt: string,
  options: { pauseReviewed?: boolean; requireCompleteCoverage?: boolean; snapshotComplete?: boolean } = {},
): SlaEvaluation {
  const now = utc(assessedAt, "assessment");
  const unknown = options.snapshotComplete === false ||
    (options.requireCompleteCoverage !== false && !checkpoint.completeCoverage);
  const acknowledged = checkpoint.reviewed && !checkpoint.staleReview;
  const ackRemaining = deltaMinutes(checkpoint.acknowledgeBy, now);
  const resolutionRemaining = deltaMinutes(checkpoint.resolveBy, now);
  const escalationRemaining = deltaMinutes(checkpoint.escalateAt, now);
  let phase: SlaPhase;
  let explanation: string;
  if (unknown) {
    phase = "UNKNOWN";
    explanation = "Coverage is incomplete; SLA state cannot be established.";
  } else if (options.pauseReviewed && acknowledged) {
    phase = "PAUSED";
    explanation = "Policy pauses reviewed cases; no resolution is implied.";
  } else if (!acknowledged && escalationRemaining <= 0) {
    phase = "ESCALATED";
    explanation = "Acknowledgement escalation threshold has elapsed.";
  } else if (resolutionRemaining <= 0) {
    phase = "RESOLUTION_OVERDUE";
    explanation = "Resolution planning deadline has elapsed.";
  } else if (!acknowledged && ackRemaining <= 0) {
    phase = "ACK_OVERDUE";
    explanation = "Acknowledgement planning deadline has elapsed.";
  } else if (!acknowledged && utc(checkpoint.warningAt, "warning") <= now) {
    phase = "ACK_WARNING";
    explanation = "Acknowledgement deadline is approaching.";
  } else if (resolutionRemaining <= Math.max(60, (utc(checkpoint.resolveBy, "resolution") -
    utc(checkpoint.acknowledgeBy, "acknowledgement")) / 60000 / 10)) {
    phase = "RESOLUTION_WARNING";
    explanation = "Resolution planning deadline is approaching.";
  } else {
    phase = "ON_TRACK";
    explanation = "No configured SLA planning threshold has elapsed.";
  }
  return {
    caseKey: checkpoint.caseKey, workItemId: checkpoint.workItemId,
    priority: checkpoint.priority, phase,
    minutesUntilAcknowledgement: unknown ? null : ackRemaining,
    minutesUntilResolution: unknown ? null : resolutionRemaining,
    minutesUntilEscalation: unknown ? null : escalationRemaining,
    evaluatedAt: assessedAt, explanation,
  };
}
export function evaluateSlaPlan(
  plan: SlaPlan, assessedAt: string,
  policy: SlaPolicy = DEFAULT_SLA_POLICY,
): SlaDashboard {
  const validated = validateSlaPolicy(policy);
  utc(assessedAt, "assessment");
  const evaluations = plan.checkpoints.map(item => evaluateSlaCheckpoint(item, assessedAt, {
    pauseReviewed: validated.pauseReviewed,
    requireCompleteCoverage: validated.requireCompleteCoverage,
    snapshotComplete: plan.complete,
  }));
  const counts = Object.fromEntries(phases.map(phase => [phase, 0])) as Record<SlaPhase, number>;
  for (const item of evaluations) counts[item.phase]++;
  const urgent = evaluations.filter(item =>
    ["ESCALATED", "RESOLUTION_OVERDUE", "ACK_OVERDUE", "ACK_WARNING"].includes(item.phase))
    .sort((a, b) => priorities.indexOf(a.priority) - priorities.indexOf(b.priority) ||
      a.caseKey.localeCompare(b.caseKey));
  return {
    organizationId: plan.organizationId, evaluatedAt: assessedAt,
    complete: plan.complete, total: evaluations.length, counts, evaluations, urgent,
    warnings: [...plan.warnings, "Assessment is based on the immutable capture; refresh before acting."],
  };
}
export type SlaDelta = {
  caseKey: string;
  previous: SlaPhase | null;
  current: SlaPhase | null;
  direction: "NEW" | "REMOVED" | "DEGRADED" | "IMPROVED" | "UNCHANGED" | "UNCERTAIN";
};
export function compareSlaDashboards(
  before: SlaDashboard, after: SlaDashboard,
): SlaDelta[] {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare SLA dashboards across organizations.");
  const old = new Map(before.evaluations.map(item => [item.caseKey, item]));
  const current = new Map(after.evaluations.map(item => [item.caseKey, item]));
  const rank: Record<SlaPhase, number> = {
    UNKNOWN: -1, PAUSED: 0, ON_TRACK: 0, ACK_WARNING: 1,
    RESOLUTION_WARNING: 1, ACK_OVERDUE: 2, RESOLUTION_OVERDUE: 3, ESCALATED: 4,
  };
  return [...new Set([...old.keys(), ...current.keys()])].sort().map(key => {
    const a = old.get(key)?.phase ?? null;
    const b = current.get(key)?.phase ?? null;
    const direction: SlaDelta["direction"] =
      !before.complete || !after.complete || a === "UNKNOWN" || b === "UNKNOWN"
        ? "UNCERTAIN"
        : a === null ? "NEW" : b === null ? "REMOVED"
        : rank[b] > rank[a] ? "DEGRADED"
        : rank[b] < rank[a] ? "IMPROVED" : "UNCHANGED";
    return { caseKey: key, previous: a, current: b, direction };
  });
}
export function slaDashboardCsv(dashboard: SlaDashboard): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const escaped = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + escaped.replace(/"/g, '""') + '"';
  };
  const lines = [[
    "caseKey", "workItemId", "priority", "phase", "evaluatedAt",
    "minutesUntilAcknowledgement", "minutesUntilResolution",
    "minutesUntilEscalation", "explanation",
  ].map(safe).join(",")];
  for (const item of dashboard.evaluations) lines.push([
    item.caseKey, item.workItemId, item.priority, item.phase, item.evaluatedAt,
    item.minutesUntilAcknowledgement, item.minutesUntilResolution,
    item.minutesUntilEscalation, item.explanation,
  ].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function slaDashboardJson(dashboard: SlaDashboard): string {
  return JSON.stringify(dashboard, null, 2) + "\n";
}
