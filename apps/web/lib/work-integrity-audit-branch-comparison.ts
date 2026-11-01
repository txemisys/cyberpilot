import type { BranchNode, BranchReport } from "./work-integrity-audit-branch-explorer";

/**
 * Compare two bounded captures of the same authoritative work audit graph.
 * Differences are observations, never claims of cryptographic tampering.
 */
export type BranchDifferenceKind =
  | "EVENT_APPEARED" | "EVENT_DISAPPEARED"
  | "PREDECESSOR_CHANGED" | "REVIEW_DECISION_CHANGED"
  | "REVIEW_REVISION_CHANGED" | "CASE_IDENTITY_CHANGED"
  | "REVIEW_TIME_CHANGED" | "REVIEW_ACTOR_CHANGED"
  | "SUCCESSOR_SET_CHANGED" | "ROOT_STATUS_CHANGED"
  | "SOURCE_COVERAGE_CHANGED" | "WORK_REVISION_CHANGED"
  | "MALFORMED_COUNT_CHANGED" | "FORK_COUNT_CHANGED";
export type BranchDifference = {
  kind: BranchDifferenceKind;
  severity: "REVIEW" | "UNKNOWN" | "CONTEXT";
  eventId: string | null;
  before: string | null;
  after: string | null;
  explanation: string;
  suggestedAction: string;
};
export type BranchComparison = {
  organizationId: string; workItemId: string;
  baselineCapturedAt: string; subsequentCapturedAt: string;
  baselineSourceCount: number; subsequentSourceCount: number;
  bothSourcesUntruncated: boolean;
  eventsPresentInBoth: number;
  eventsOnlyInBaseline: number; eventsOnlyInSubsequent: number;
  differences: BranchDifference[];
  severity: { REVIEW: number; UNKNOWN: number; CONTEXT: number };
  limitations: string[];
};
function normalized(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return typeof value === "string" ? value : JSON.stringify(value);
}
function fields(node: BranchNode): Record<string, unknown> {
  return {
    caseKey: node.caseKey,
    previousEventId: node.previousEventId,
    decision: node.decision, revision: node.revision,
    occurredAt: node.occurredAt, actorUserId: node.actorUserId,
    successorIds: [...node.successorIds].sort(),
    isRoot: node.isRoot,
  };
}
export function compareAuditBranches(
  before: BranchReport, after: BranchReport,
): BranchComparison {
  if (!before.organizationId || before.organizationId !== after.organizationId ||
      before.workItemId !== after.workItemId)
    throw new Error("Audit branch comparison requires identical trusted tenant and work.");
  const left = new Map(before.nodes.map(node => [node.id, node]));
  const right = new Map(after.nodes.map(node => [node.id, node]));
  if (left.size !== before.nodes.length || right.size !== after.nodes.length)
    throw new Error("Repeated source event identities in compared audit graph.");
  const complete = !before.sourceTruncated && !after.sourceTruncated &&
    before.malformedRows === 0 && after.malformedRows === 0;
  const differences: BranchDifference[] = [];
  const add = (
    kind: BranchDifferenceKind, severity: BranchDifference["severity"],
    eventId: string | null, a: unknown, b: unknown,
    explanation: string, suggestedAction: string,
  ) => differences.push({
    kind, severity, eventId,
    before: normalized(a), after: normalized(b),
    explanation, suggestedAction,
  });
  for (const [id, old] of left) {
    const newer = right.get(id);
    if (!newer) {
      add("EVENT_DISAPPEARED", complete ? "REVIEW" : "UNKNOWN", id, id, null,
        "An event previously captured is absent from the subsequent bounded source graph.",
        "Re-read the original audit event by ID; check retention and the source cap.");
      continue;
    }
    const oldFields = fields(old);
    const newFields = fields(newer);
    const mappings: {
      key: string; kind: BranchDifferenceKind;
      description: string;
    }[] = [
      {
        key: "caseKey", kind: "CASE_IDENTITY_CHANGED",
        description: "An existing event appears under a different diagnostic identity.",
      },
      {
        key: "previousEventId", kind: "PREDECESSOR_CHANGED",
        description: "An existing source event has a different predecessor reference.",
      },
      {
        key: "decision", kind: "REVIEW_DECISION_CHANGED",
        description: "An existing source event has a different human decision.",
      },
      {
        key: "revision", kind: "REVIEW_REVISION_CHANGED",
        description: "An existing source event has a different reviewed work revision.",
      },
      {
        key: "occurredAt", kind: "REVIEW_TIME_CHANGED",
        description: "An existing source event has a different recorded timestamp.",
      },
      {
        key: "actorUserId", kind: "REVIEW_ACTOR_CHANGED",
        description: "An existing source event has a different reviewer attribution.",
      },
      {
        key: "successorIds", kind: "SUCCESSOR_SET_CHANGED",
        description: "The observed successor event set changed for an existing audit decision.",
      },
      {
        key: "isRoot", kind: "ROOT_STATUS_CHANGED",
        description: "An existing source event changed its apparent review-root status.",
      },
    ];
    for (const mapping of mappings) {
      const prior = normalized(oldFields[mapping.key]);
      const later = normalized(newFields[mapping.key]);
      if (prior !== later)
        add(mapping.kind,
          mapping.kind === "SUCCESSOR_SET_CHANGED" && !complete ? "UNKNOWN" : "REVIEW",
          id, prior, later, mapping.description,
          "Inspect original tenant audit records and verify capture coverage.");
    }
  }
  for (const [id] of right)
    if (!left.has(id))
      add("EVENT_APPEARED", complete ? "REVIEW" : "UNKNOWN", id, null, id,
        "An event is visible in the subsequent source graph but not in the baseline.",
        "Review the original audit event and both capture boundaries.");
  if (before.sourceTruncated !== after.sourceTruncated) add(
    "SOURCE_COVERAGE_CHANGED", "UNKNOWN", null,
    before.sourceTruncated, after.sourceTruncated,
    "The source query limit was reached in only one of the two reports.",
    "Compare equally bounded source history before inferring missing events.");
  if (before.workRevision !== after.workRevision) add(
    "WORK_REVISION_CHANGED", "CONTEXT", null,
    before.workRevision, after.workRevision,
    "The current work item revision changed between source reads.",
    "Determine whether an authorized new review is required.");
  if (before.malformedRows !== after.malformedRows) add(
    "MALFORMED_COUNT_CHANGED", "UNKNOWN", null,
    before.malformedRows, after.malformedRows,
    "The number of undecodable audit records changed.",
    "Inspect source event metadata in both captures.");
  if (before.totals.forks !== after.totals.forks) add(
    "FORK_COUNT_CHANGED", complete ? "REVIEW" : "UNKNOWN", null,
    before.totals.forks, after.totals.forks,
    "The number of competing audit review successors changed.",
    "Review source event links and concurrency history.");
  const rank = { REVIEW: 0, UNKNOWN: 1, CONTEXT: 2 };
  differences.sort((a, b) =>
    rank[a.severity] - rank[b.severity] ||
    a.kind.localeCompare(b.kind) ||
    (a.eventId ?? "").localeCompare(b.eventId ?? ""));
  return {
    organizationId: before.organizationId, workItemId: before.workItemId,
    baselineCapturedAt: before.generatedAt,
    subsequentCapturedAt: after.generatedAt,
    baselineSourceCount: before.sourceRows,
    subsequentSourceCount: after.sourceRows,
    bothSourcesUntruncated: complete,
    eventsPresentInBoth: [...left.keys()].filter(id => right.has(id)).length,
    eventsOnlyInBaseline: [...left.keys()].filter(id => !right.has(id)).length,
    eventsOnlyInSubsequent: [...right.keys()].filter(id => !left.has(id)).length,
    differences,
    severity: {
      REVIEW: differences.filter(item => item.severity === "REVIEW").length,
      UNKNOWN: differences.filter(item => item.severity === "UNKNOWN").length,
      CONTEXT: differences.filter(item => item.severity === "CONTEXT").length,
    },
    limitations: [
      "Both reports must refer to the same tenant-scoped work item.",
      "Missing entries in truncated or malformed source captures are inconclusive.",
      "This comparison cannot independently authenticate database audit immutability.",
      "An operational audit difference does not prove a vulnerability or resolved control.",
    ],
  };
}
export function auditBranchComparisonCsv(result: BranchComparison): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const columns = ["kind", "severity", "eventId", "before",
    "after", "explanation", "suggestedAction"];
  const lines = [columns.map(quote).join(",")];
  for (const item of result.differences) lines.push([
    item.kind, item.severity, item.eventId, item.before,
    item.after, item.explanation, item.suggestedAction,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
