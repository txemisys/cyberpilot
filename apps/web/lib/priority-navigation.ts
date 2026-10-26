export type PrioritySource = { id: string; lastSeenAt: Date };
export type PriorityRemediation = {
  id: string;
  finding: { id: string; status: string };
  status: string;
  createdAt: Date;
};

const STATUS_ORDER: Record<string, number> = {
  EXECUTING: 0,
  APPROVED: 1,
  PROPOSED: 2,
};

/** Choose one active playbook per open finding, independently of input order. */
export function getPriorityNavigation(
  findingId: string,
  findings: PrioritySource[],
  remediations: PriorityRemediation[],
) {
  const source = findings.find((finding) => finding.id === findingId);
  const playbook = source
    ? remediations
        .filter(
          (remediation) =>
            remediation.finding.id === findingId &&
            remediation.finding.status === "OPEN" &&
            remediation.status in STATUS_ORDER,
        )
        .sort(
          (a, b) =>
            (STATUS_ORDER[a.status] ?? 99) - (STATUS_ORDER[b.status] ?? 99) ||
            b.createdAt.getTime() - a.createdAt.getTime() ||
            a.id.localeCompare(b.id),
        )[0]
    : undefined;

  return {
    source,
    playbook,
    href: playbook ? `#remediation-${playbook.id}` : `#finding-${findingId}`,
  };
}
