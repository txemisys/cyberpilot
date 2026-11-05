import { createHash } from "node:crypto";
import type {
  AcceptanceCode, AcceptanceFinding, AcceptanceReport,
  AcceptanceTaskReport,
} from "./work-integrity-phase3c-acceptance";

export type AcceptanceWorkstream =
  | "REVIEW_LEDGER"
  | "INBOX_INTEGRITY"
  | "ESCALATION_LIFECYCLE"
  | "PROVIDER_OBSERVATION"
  | "WORK_LINKAGE"
  | "AUDIT_PROVENANCE";
export type AcceptanceNextStep =
  | "INVESTIGATE_LEDGER"
  | "INSPECT_NOTIFICATION"
  | "REVIEW_RECIPIENT_MEMBERSHIP"
  | "INSPECT_ESCALATION"
  | "RECHECK_PROVIDER"
  | "RECONCILE_REVIEW_PROVIDER"
  | "INSPECT_WORK_LINK"
  | "INSPECT_TRIAGE_AUDIT"
  | "MANUAL_INSPECTION";
export type AcceptanceAction = {
  key: string;
  taskId: string;
  workstream: AcceptanceWorkstream;
  nextStep: AcceptanceNextStep;
  priority: "P0" | "P1" | "P2";
  message: string;
  codes: AcceptanceCode[];
  blockerCount: number;
  reviewCount: number;
  entityIds: string[];
  fingerprint: string;
};
export type AcceptanceExecutionPlan = {
  schema: "cyberpilot.integrity.phase3c.acceptance.plan.v1";
  organizationId: string;
  captureId: string;
  generatedAt: string;
  sourceDigest: string;
  partial: boolean;
  requiresManualSignoff: true;
  actions: AcceptanceAction[];
  byPriority: { P0: number; P1: number; P2: number };
  byWorkstream: Partial<Record<AcceptanceWorkstream, number>>;
  digest: string;
  warnings: string[];
};
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function acceptanceWorkstream(
  code: AcceptanceCode,
): AcceptanceWorkstream {
  if (code.startsWith("REVIEW_") || [
    "INVALID_REVIEW_REVISION", "CLOSED_WITHOUT_COMPLETION",
    "OPEN_WITH_COMPLETION", "COMPLETION_BEFORE_CREATION",
    "NO_REVIEW_EVENTS",
  ].includes(code)) return "REVIEW_LEDGER";
  if (code.startsWith("NOTIFICATION_")) return "INBOX_INTEGRITY";
  if (code.startsWith("ESCALATION_")) return "ESCALATION_LIFECYCLE";
  if (code.startsWith("PROVIDER_")) return "PROVIDER_OBSERVATION";
  if (code === "WORK_LINK_AFTER_UNLINK") return "WORK_LINKAGE";
  return "AUDIT_PROVENANCE";
}
export function acceptanceNextStep(
  code: AcceptanceCode,
): AcceptanceNextStep {
  if (code.includes("REVISION") || code.startsWith("REVIEW_") ||
      code.includes("COMPLETION") || code === "OPEN_WITH_COMPLETION" ||
      code === "CLOSED_WITHOUT_COMPLETION")
    return "INVESTIGATE_LEDGER";
  if (code === "NOTIFICATION_RECIPIENT_NOT_MEMBER")
    return "REVIEW_RECIPIENT_MEMBERSHIP";
  if (code.startsWith("NOTIFICATION_"))
    return "INSPECT_NOTIFICATION";
  if (code.startsWith("ESCALATION_"))
    return "INSPECT_ESCALATION";
  if (code === "PROVIDER_FAILURE_WITH_HUMAN_CLOSURE")
    return "RECONCILE_REVIEW_PROVIDER";
  if (code.startsWith("PROVIDER_"))
    return "RECHECK_PROVIDER";
  if (code === "WORK_LINK_AFTER_UNLINK")
    return "INSPECT_WORK_LINK";
  if (code === "AUDIT_MISSING_TRIAGE_ACTION")
    return "INSPECT_TRIAGE_AUDIT";
  return "MANUAL_INSPECTION";
}
export function acceptanceActionPriority(findings: AcceptanceFinding[]):
  AcceptanceAction["priority"] {
  return findings.some(x => x.level === "BLOCKER") ? "P0" :
    findings.some(x => x.level === "REVIEW") ? "P1" : "P2";
}
function groupTaskFindings(task: AcceptanceTaskReport) {
  const groups = new Map<string, AcceptanceFinding[]>();
  for (const finding of task.findings) {
    const stream = acceptanceWorkstream(finding.code);
    const step = acceptanceNextStep(finding.code);
    const key = stream + ":" + step;
    const array = groups.get(key) ?? [];
    array.push(finding);
    groups.set(key, array);
  }
  return groups;
}
export function acceptanceTaskActions(
  task: AcceptanceTaskReport,
): AcceptanceAction[] {
  const results: AcceptanceAction[] = [];
  for (const [key, findings] of groupTaskFindings(task)) {
    if (!findings.length) continue;
    const [stream, next] = key.split(":");
    const workstream = stream as AcceptanceWorkstream;
    const nextStep = next as AcceptanceNextStep;
    const codes = [...new Set(findings.map(x => x.code))].sort();
    const entityIds = [...new Set(findings.map(x => x.entityId))].sort();
    const priority = acceptanceActionPriority(findings);
    const blockerCount = findings.filter(x => x.level === "BLOCKER").length;
    const reviewCount = findings.filter(x => x.level === "REVIEW").length;
    const canonical = {
      key: task.taskId + ":" + key, taskId: task.taskId,
      workstream, nextStep, priority,
      message: acceptanceActionMessage(nextStep, entityIds.length),
      codes, blockerCount, reviewCount, entityIds,
    };
    results.push({ ...canonical, fingerprint: hash(canonical) });
  }
  const rank = { P0: 0, P1: 1, P2: 2 };
  return results.sort((a, b) =>
    rank[a.priority] - rank[b.priority] ||
    a.workstream.localeCompare(b.workstream) ||
    a.nextStep.localeCompare(b.nextStep));
}
export function acceptanceActionMessage(
  step: AcceptanceNextStep, affected: number,
): string {
  const n = affected === 1 ? "record" : "records";
  const messages: Record<AcceptanceNextStep, string> = {
    INVESTIGATE_LEDGER: "Investigate persisted review revisions and transition history.",
    INSPECT_NOTIFICATION: "Inspect notification creation and transition timestamps.",
    REVIEW_RECIPIENT_MEMBERSHIP: "Review recipient membership and authorization history.",
    INSPECT_ESCALATION: "Reconcile escalation lifecycle timestamps and states.",
    RECHECK_PROVIDER: "Inspect evidence provenance and consider an authorized provider recheck.",
    RECONCILE_REVIEW_PROVIDER: "Reconcile human review disposition against independent provider evidence.",
    INSPECT_WORK_LINK: "Inspect the linked remediation work history.",
    INSPECT_TRIAGE_AUDIT: "Review triage audit coverage for operational records.",
    MANUAL_INSPECTION: "Inspect the affected records manually.",
  };
  return messages[step] + " (" + affected + " " + n + ")";
}
export function buildAcceptanceExecutionPlan(
  report: AcceptanceReport,
): AcceptanceExecutionPlan {
  const rank = { P0: 0, P1: 1, P2: 2 };
  const actions = report.tasks.flatMap(acceptanceTaskActions).sort((a, b) =>
    rank[a.priority] - rank[b.priority] ||
    a.taskId.localeCompare(b.taskId) ||
    a.key.localeCompare(b.key));
  const byPriority = { P0: 0, P1: 0, P2: 0 };
  const byWorkstream: Partial<Record<AcceptanceWorkstream, number>> = {};
  for (const action of actions) {
    byPriority[action.priority]++;
    byWorkstream[action.workstream] =
      (byWorkstream[action.workstream] ?? 0) + 1;
  }
  const canonical = {
    schema: "cyberpilot.integrity.phase3c.acceptance.plan.v1" as const,
    organizationId: report.organizationId,
    captureId: report.captureId,
    generatedAt: report.generatedAt,
    sourceDigest: report.digest,
    partial: !report.complete,
    requiresManualSignoff: true as const,
    actions, byPriority, byWorkstream,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      "Recommendations are read-only; no corrective action is executed.",
      "Priorities describe workflow consistency, not measured cyber risk.",
      "The plan can be incomplete if the source report is page-scoped.",
      "A finding-free plan never substitutes for user acceptance or release approval.",
    ],
  };
}
