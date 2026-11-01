import type {
  LineageIssue, LineageIssueKind, LineageReport,
} from "./work-integrity-audit-lineage";

/** Actionable human investigation queues derived from actual audit lineage. */
export type LineageActionType =
  | "CHECK_AUDIT_EVENT_INTEGRITY"
  | "RECONCILE_CASE_LINK"
  | "INVESTIGATE_REVIEW_CONCURRENCY"
  | "VERIFY_EVENT_TIME"
  | "REVIEW_SOURCE_RETENTION"
  | "REVIEW_ACTOR_ATTRIBUTION"
  | "DOCUMENT_REVIEW_RATIONALE"
  | "VERIFY_WORK_REVISION";
export type LineageAction = {
  key: string;
  type: LineageActionType;
  priority: "P0" | "P1" | "P2" | "P3";
  workItemId: string;
  eventIds: string[];
  sourceCodes: LineageIssueKind[];
  firstDepth: number;
  nextStep: string;
  occurrenceCount: number;
  requiresSourceAccess: boolean;
  requiresHumanDecision: boolean;
  automaticClosurePermitted: false;
};
export type LineageActionPlan = {
  organizationId: string;
  workItemId: string;
  requestedEventId: string;
  sourceTerminatedAt: LineageReport["terminal"];
  completedSourceChain: boolean;
  itemCount: number;
  selectedCount: number;
  omitted: number;
  actions: LineageAction[];
  byPriority: { P0: number; P1: number; P2: number; P3: number };
  limitations: string[];
};
type Rule = {
  type: LineageActionType;
  priority: LineageAction["priority"];
  requiresSourceAccess: boolean;
  requiresHumanDecision: boolean;
  nextStep: string;
};
const rules: Record<LineageIssueKind, Rule> = {
  MISSING_PREDECESSOR: {
    type: "REVIEW_SOURCE_RETENTION", priority: "P1",
    requiresSourceAccess: true, requiresHumanDecision: false,
    nextStep: "Locate the referenced source event and investigate audit retention.",
  },
  CROSS_CASE_REFERENCE: {
    type: "RECONCILE_CASE_LINK", priority: "P0",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Inspect original source event identities and prevent cross-case conclusions.",
  },
  PREDECESSOR_CYCLE: {
    type: "CHECK_AUDIT_EVENT_INTEGRITY", priority: "P0",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Investigate cyclical source event links without rewriting audit history.",
  },
  TIME_INVERSION: {
    type: "VERIFY_EVENT_TIME", priority: "P1",
    requiresSourceAccess: true, requiresHumanDecision: false,
    nextStep: "Compare source transaction order and audit-event timestamps.",
  },
  REVISION_DECREASE: {
    type: "INVESTIGATE_REVIEW_CONCURRENCY", priority: "P0",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Reconcile work revisions and review optimistic locking.",
  },
  MISSING_ACTOR: {
    type: "REVIEW_ACTOR_ATTRIBUTION", priority: "P2",
    requiresSourceAccess: true, requiresHumanDecision: false,
    nextStep: "Inspect source user and account retention references.",
  },
  MISSING_RATIONALE: {
    type: "DOCUMENT_REVIEW_RATIONALE", priority: "P2",
    requiresSourceAccess: false, requiresHumanDecision: true,
    nextStep: "Record a new human explanation through the authorized audit workflow.",
  },
  INVALID_PREDECESSOR_METADATA: {
    type: "CHECK_AUDIT_EVENT_INTEGRITY", priority: "P0",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Review the unreadable audit event metadata directly in the source.",
  },
  WORK_ITEM_MISSING: {
    type: "REVIEW_SOURCE_RETENTION", priority: "P1",
    requiresSourceAccess: true, requiresHumanDecision: false,
    nextStep: "Investigate archive and work record retention.",
  },
  WORK_REVISION_DRIFT: {
    type: "VERIFY_WORK_REVISION", priority: "P1",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Request a human review of the latest revision using stored evidence.",
  },
  DEPTH_LIMIT_REACHED: {
    type: "REVIEW_SOURCE_RETENTION", priority: "P2",
    requiresSourceAccess: true, requiresHumanDecision: false,
    nextStep: "Increase the bounded source lineage depth before claiming continuity.",
  },
  EVENT_IDENTITY_MISMATCH: {
    type: "CHECK_AUDIT_EVENT_INTEGRITY", priority: "P0",
    requiresSourceAccess: true, requiresHumanDecision: true,
    nextStep: "Re-read the referenced source audit event and check identifier consistency.",
  },
};
const rank = { P0: 0, P1: 1, P2: 2, P3: 3 };
function issueGroupKey(issue: LineageIssue, type: LineageActionType): string {
  return JSON.stringify([type, issue.eventId ?? issue.referencedEventId]);
}
export function planLineageActions(report: LineageReport, limit = 100): LineageActionPlan {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500)
    throw new Error("Audit investigation queue limit must be 1–500.");
  const depths = new Map(report.nodes.map(node => [node.eventId, node.depth]));
  const groups = new Map<string, LineageIssue[]>();
  for (const issue of report.issues) {
    const rule = rules[issue.kind];
    const key = issueGroupKey(issue, rule.type);
    const group = groups.get(key) ?? [];
    group.push(issue);
    groups.set(key, group);
  }
  const actions: LineageAction[] = [];
  for (const [key, group] of groups) {
    const selected = group.map(issue => ({ issue, rule: rules[issue.kind] }))
      .sort((a, b) => rank[a.rule.priority] - rank[b.rule.priority]);
    const primary = selected[0]!;
    actions.push({
      key, type: primary.rule.type, priority: primary.rule.priority,
      workItemId: report.workItemId,
      eventIds: [...new Set(group.flatMap(issue =>
        [issue.eventId, issue.referencedEventId].filter((id): id is string => id !== null)))],
      sourceCodes: [...new Set(group.map(issue => issue.kind))].sort(),
      firstDepth: Math.min(...group.map(issue =>
        depths.get(issue.eventId ?? "") ?? report.nodes.length)),
      nextStep: primary.rule.nextStep, occurrenceCount: group.length,
      requiresSourceAccess: selected.some(x => x.rule.requiresSourceAccess),
      requiresHumanDecision: selected.some(x => x.rule.requiresHumanDecision),
      automaticClosurePermitted: false,
    });
  }
  actions.sort((a, b) =>
    rank[a.priority] - rank[b.priority] ||
    a.firstDepth - b.firstDepth || a.key.localeCompare(b.key));
  const byPriority = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const action of actions) byPriority[action.priority]++;
  return {
    organizationId: report.organizationId, workItemId: report.workItemId,
    requestedEventId: report.requestedEventId,
    sourceTerminatedAt: report.terminal,
    completedSourceChain: report.sourceChainComplete,
    itemCount: actions.length,
    selectedCount: Math.min(actions.length, limit),
    omitted: Math.max(0, actions.length - limit),
    actions: actions.slice(0, limit),
    byPriority,
    limitations: [
      "Human follow-ups are suggestions; no task or review is persisted.",
      "Cases with missing audit history require original source access.",
      "A complete predecessor chain cannot establish security-control effectiveness.",
      "Only an authorized reviewer can record a new audited human decision.",
    ],
  };
}
export function lineageActionsCsv(result: LineageActionPlan): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const header = [
    "priority", "type", "workItemId", "eventIds", "sourceCodes",
    "occurrenceCount", "firstDepth", "nextStep", "requiresSourceAccess",
    "requiresHumanDecision", "automaticClosurePermitted",
  ];
  const lines = [header.map(quote).join(",")];
  for (const action of result.actions) lines.push([
    action.priority, action.type, action.workItemId,
    action.eventIds.join(";"), action.sourceCodes.join(";"),
    action.occurrenceCount, action.firstDepth, action.nextStep,
    action.requiresSourceAccess, action.requiresHumanDecision,
    action.automaticClosurePermitted,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
