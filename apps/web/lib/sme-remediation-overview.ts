export type SmeRemediationItem = {
  id: string;
  title: string;
  mode: "GUIDED" | "AUTOMATED";
  status: string;
  steps: unknown;
  finding: { status: string };
};

export type SmeRemediationProgress = {
  id: string;
  title: string;
  label: string;
  completedSteps: number;
  totalSteps: number;
  percentComplete: number | null;
  href: string;
  needsVerification: boolean;
};

export type SmeRemediationOverview = {
  visibleCount: number;
  inProgress: number;
  waitingForAction: number;
  awaitingVerification: number;
  verified: number;
  items: SmeRemediationProgress[];
};

/**
 * Read-only progress from persisted remediation statuses and acknowledged guided steps.
 * Acknowledged steps must never be treated as verified security improvements.
 */
export function buildSmeRemediationOverview(
  remediations: readonly SmeRemediationItem[],
  guidedProgress: ReadonlyMap<string, ReadonlySet<number>>,
): SmeRemediationOverview {
  let inProgress = 0;
  let waitingForAction = 0;
  let awaitingVerification = 0;
  let verified = 0;
  const items: SmeRemediationProgress[] = [];
  for (const remediation of remediations) {
    if (remediation.status === "VERIFIED") verified++;
    else if (remediation.status === "EXECUTING") inProgress++;
    else if (remediation.status === "SUCCEEDED") awaitingVerification++;
    else if (remediation.status === "PROPOSED" || remediation.status === "APPROVED" || remediation.status === "FAILED") waitingForAction++;

    const steps = remediation.mode === "GUIDED" && Array.isArray(remediation.steps)
      ? remediation.steps.filter((step): step is string => typeof step === "string")
      : [];
    const acknowledgements = guidedProgress.get(remediation.id) ?? new Set<number>();
    const completedSteps = steps.reduce((count, _step, index) =>
      count + (acknowledgements.has(index) ? 1 : 0), 0);
    const totalSteps = steps.length;
    const percentComplete = totalSteps > 0 ? Math.round(completedSteps * 100 / totalSteps) : null;
    const needsVerification = remediation.status !== "VERIFIED" &&
      (remediation.status === "SUCCEEDED" || (totalSteps > 0 && completedSteps === totalSteps));
    const label = remediation.status === "VERIFIED"
      ? "Verified with evidence"
      : remediation.status === "EXECUTING" ? "Being worked on"
      : needsVerification ? "Needs fresh evidence to verify"
      : remediation.status === "FAILED" ? "Needs attention"
      : remediation.status === "APPROVED" ? "Ready to work on"
      : remediation.status === "PROPOSED" ? "Proposed action"
      : "Review status";
    items.push({
      id: remediation.id, title: remediation.title, label, completedSteps, totalSteps,
      percentComplete, href: `#remediation-${remediation.id}`, needsVerification,
    });
  }
  const rank = (item: SmeRemediationProgress) =>
    item.needsVerification ? 0 :
    item.label === "Being worked on" ? 1 :
    item.label === "Needs attention" ? 2 :
    item.label === "Ready to work on" ? 3 :
    item.label === "Proposed action" ? 4 : 5;
  items.sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id));
  return {visibleCount:remediations.length,inProgress,waitingForAction,awaitingVerification,verified,items};
}
