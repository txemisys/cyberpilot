import type {
  BranchIssue, BranchIssueCode, BranchReport,
} from "./work-integrity-audit-branch-explorer";

/** Source-backed follow-up recommendations, never persisted assignments. */
export type BranchActionType =
  | "RECONCILE_CONCURRENT_REVIEWS"
  | "INVESTIGATE_SOURCE_LINK"
  | "VERIFY_WORK_REVISION_SEQUENCE"
  | "INSPECT_REVIEW_CLOCKS"
  | "RECAPTURE_AUDIT_HISTORY"
  | "REVIEW_EVENT_METADATA";
export type BranchAction = {
  id: string; workItemId: string; caseKey: string | null;
  type: BranchActionType; priority: "P0" | "P1" | "P2" | "P3";
  eventIds: string[]; issueKinds: BranchIssueCode[];
  occurrences: number; explanation: string; nextStep: string;
  sourceAccessRequired: boolean; humanDecisionRequired: boolean;
  canCloseAutomatically: false;
};
export type BranchActionPlan = {
  organizationId: string; workItemId: string; generatedAt: string;
  sourceTruncated: boolean; total: number; displayed: number;
  omitted: number; uniqueAffectedCases: number;
  priorities: { P0: number; P1: number; P2: number; P3: number };
  actions: BranchAction[]; limitations: string[];
};
type Rule = {
  type: BranchActionType; priority: BranchAction["priority"];
  explanation: string; nextStep: string;
  sourceAccessRequired: boolean; humanDecisionRequired: boolean;
};
const rules: Record<BranchIssueCode, Rule> = {
  MULTIPLE_SUCCESSORS: {
    type: "RECONCILE_CONCURRENT_REVIEWS", priority: "P0",
    explanation: "Multiple reviews reference the same predecessor.",
    nextStep: "Inspect concurrent human decisions and server optimistic-lock enforcement.",
    sourceAccessRequired: true, humanDecisionRequired: true,
  },
  MISSING_PREDECESSOR: {
    type: "INVESTIGATE_SOURCE_LINK", priority: "P1",
    explanation: "A recorded review references an unavailable source predecessor.",
    nextStep: "Retrieve original audit events before treating the history as complete.",
    sourceAccessRequired: true, humanDecisionRequired: false,
  },
  CROSS_CASE_LINK: {
    type: "INVESTIGATE_SOURCE_LINK", priority: "P0",
    explanation: "A predecessor reference crosses diagnostic case identities.",
    nextStep: "Reconcile audit metadata and case ownership without combining unrelated cases.",
    sourceAccessRequired: true, humanDecisionRequired: true,
  },
  PREDECESSOR_CYCLE: {
    type: "INVESTIGATE_SOURCE_LINK", priority: "P0",
    explanation: "A recorded review chain contains a cyclic reference.",
    nextStep: "Inspect source event references and retain original audit records.",
    sourceAccessRequired: true, humanDecisionRequired: true,
  },
  DISCONNECTED_ROOTS: {
    type: "INVESTIGATE_SOURCE_LINK", priority: "P1",
    explanation: "More than one review begins a separate root in the same diagnostic.",
    nextStep: "Verify review history, event retention and diagnostic source identity.",
    sourceAccessRequired: true, humanDecisionRequired: true,
  },
  NO_ROOT: {
    type: "INVESTIGATE_SOURCE_LINK", priority: "P1",
    explanation: "No initial root review is available in the selected source.",
    nextStep: "Inspect original event retention and predecessor cycles.",
    sourceAccessRequired: true, humanDecisionRequired: false,
  },
  REVERSED_REVIEW_TIME: {
    type: "INSPECT_REVIEW_CLOCKS", priority: "P1",
    explanation: "Linked event timestamps are reversed.",
    nextStep: "Compare audit event source clock and transaction ordering.",
    sourceAccessRequired: true, humanDecisionRequired: false,
  },
  REVIEW_REVISION_DECREASED: {
    type: "VERIFY_WORK_REVISION_SEQUENCE", priority: "P0",
    explanation: "A subsequent review references an earlier task revision.",
    nextStep: "Reconcile task revision concurrency and human audit decisions.",
    sourceAccessRequired: true, humanDecisionRequired: true,
  },
  UNPARSEABLE_SOURCE: {
    type: "REVIEW_EVENT_METADATA", priority: "P1",
    explanation: "Stored human review metadata could not be decoded.",
    nextStep: "Inspect original organization-scoped source audit row metadata.",
    sourceAccessRequired: true, humanDecisionRequired: false,
  },
  HISTORY_LIMIT_REACHED: {
    type: "RECAPTURE_AUDIT_HISTORY", priority: "P2",
    explanation: "The selected work audit source exceeded its bounded query cap.",
    nextStep: "Increase the audit event cap or query a narrower reviewed work period.",
    sourceAccessRequired: true, humanDecisionRequired: false,
  },
};
const rank = { P0: 0, P1: 1, P2: 2, P3: 3 };
function identity(issue: BranchIssue, type: BranchActionType): string {
  return JSON.stringify([issue.caseKey, type]);
}
export function planBranchActions(
  report: BranchReport, limit = 100,
): BranchActionPlan {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500)
    throw new Error("Branch action limit must be between 1 and 500.");
  const grouped = new Map<string, BranchIssue[]>();
  for (const issue of report.issues) {
    const rule = rules[issue.code];
    if (!rule) throw new Error("Unmapped source branch issue.");
    const key = identity(issue, rule.type);
    const existing = grouped.get(key) ?? [];
    existing.push(issue);
    grouped.set(key, existing);
  }
  const actions: BranchAction[] = [];
  for (const [id, issues] of grouped) {
    const ordered = [...issues].sort((a, b) =>
      rank[rules[a.code].priority] - rank[rules[b.code].priority] ||
      a.code.localeCompare(b.code));
    const selected = ordered[0]!;
    const rule = rules[selected.code];
    actions.push({
      id, workItemId: report.workItemId,
      caseKey: selected.caseKey, type: rule.type,
      priority: rule.priority,
      eventIds: [...new Set(issues.flatMap(item =>
        [item.eventId, item.relatedEventId]
          .filter((value): value is string => value !== null)))].sort(),
      issueKinds: [...new Set(issues.map(item => item.code))].sort(),
      occurrences: issues.length, explanation: rule.explanation,
      nextStep: rule.nextStep,
      sourceAccessRequired: issues.some(item => rules[item.code].sourceAccessRequired),
      humanDecisionRequired: issues.some(item => rules[item.code].humanDecisionRequired),
      canCloseAutomatically: false,
    });
  }
  actions.sort((a, b) =>
    rank[a.priority] - rank[b.priority] ||
    b.occurrences - a.occurrences || a.id.localeCompare(b.id));
  const priorities = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const action of actions) priorities[action.priority]++;
  return {
    organizationId: report.organizationId,
    workItemId: report.workItemId,
    generatedAt: report.generatedAt, sourceTruncated: report.sourceTruncated,
    total: actions.length, displayed: Math.min(limit, actions.length),
    omitted: Math.max(0, actions.length - limit),
    uniqueAffectedCases: new Set(actions.map(action => action.caseKey)
      .filter((value): value is string => value !== null)).size,
    priorities, actions: actions.slice(0, limit),
    limitations: [
      "These follow-ups are recommendations, not persisted human assignments.",
      "Authorized human reviewers must use the audited triage workflow.",
      "Source coverage limits prevent definitive missing-event conclusions.",
      "No suggested action attests security-control or remediation effectiveness.",
    ],
  };
}
export function branchActionsCsv(report: BranchActionPlan): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const columns = ["priority", "type", "workItemId", "caseKey", "eventIds",
    "issueKinds", "occurrences", "explanation", "nextStep",
    "sourceAccessRequired", "humanDecisionRequired", "canCloseAutomatically"];
  const lines = [columns.map(quote).join(",")];
  for (const action of report.actions) lines.push([
    action.priority, action.type, action.workItemId, action.caseKey,
    action.eventIds.join(";"), action.issueKinds.join(";"),
    action.occurrences, action.explanation, action.nextStep,
    action.sourceAccessRequired, action.humanDecisionRequired,
    action.canCloseAutomatically,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
