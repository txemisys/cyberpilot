export type PrioritySource = { id: string; lastSeenAt: Date };
export type PriorityRemediation = {
  id: string;
  finding: { id: string; status: string };
  status: string;
};

/** Only link a priority to an open finding's active remediation. */
export function getPriorityNavigation(
  findingId: string,
  findings: PrioritySource[],
  remediations: PriorityRemediation[],
) {
  const source = findings.find((finding) => finding.id === findingId);
  const playbook = source
    ? remediations.find(
        (remediation) =>
          remediation.finding.id === findingId &&
          remediation.finding.status === "OPEN" &&
          !["VERIFIED", "FAILED"].includes(remediation.status),
      )
    : undefined;
  return {
    source,
    playbook,
    href: playbook ? `#remediation-${playbook.id}` : `#finding-${findingId}`,
  };
}
