import { getPriorityNavigation, type PriorityRemediation, type PrioritySource } from "./priority-navigation";

export type SmeActionPriority = {
  id: string;
  title: string;
  severity: string;
  href: string;
  status: "IN_PROGRESS" | "READY" | "NEEDS_REVIEW";
  statusLabel: string;
  nextStep: string;
  lastObservedAt: Date | null;
};

/** A three-item, evidence-backed decision view; no write operations or risk-score inference. */
export function buildSmeActionPriorities(
  hasCompletedScan: boolean,
  topActions: readonly { id: string; title: string; severity: string }[],
  findings: PrioritySource[],
  remediations: PriorityRemediation[],
): SmeActionPriority[] {
  if (!hasCompletedScan) return [];
  const seen = new Set<string>();
  const result: SmeActionPriority[] = [];
  for (const action of topActions) {
    if (!action.id || seen.has(action.id)) continue;
    const nav = getPriorityNavigation(action.id, findings, remediations);
    if (!nav.source) continue;
    seen.add(action.id);
    const status = nav.playbook?.status === "EXECUTING"
      ? "IN_PROGRESS" as const
      : nav.playbook ? "READY" as const : "NEEDS_REVIEW" as const;
    result.push({
      id: action.id,
      title: action.title,
      severity: action.severity,
      href: nav.href,
      status,
      statusLabel: status === "IN_PROGRESS" ? "In progress" : status === "READY" ? "Action available" : "Review required",
      nextStep: status === "IN_PROGRESS" ? "Review progress and verify the result using fresh evidence."
        : status === "READY" ? "Review the remediation steps before applying changes."
        : "Review the finding and its supporting evidence.",
      lastObservedAt: nav.source.lastSeenAt,
    });
    if (result.length === 3) break;
  }
  return result;
}
