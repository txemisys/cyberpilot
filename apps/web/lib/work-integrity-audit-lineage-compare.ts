import type { LineageNode, LineageReport } from "./work-integrity-audit-lineage";

/**
 * Compare two source-derived predecessor walks for the same diagnostic.
 * This does not compare unverifiable external snapshots and never treats a
 * missing bounded record as evidence of tampering.
 */
export type LineageChangeKind =
  | "REVIEW_EVENT_NEW"
  | "REVIEW_EVENT_ABSENT"
  | "EVENT_METADATA_CHANGED"
  | "CASE_IDENTITY_CHANGED"
  | "CHAIN_PREDECESSOR_CHANGED"
  | "DECISION_CHANGED"
  | "REVIEW_REVISION_CHANGED"
  | "ACTOR_REFERENCE_CHANGED"
  | "REVIEW_TIME_CHANGED"
  | "WORK_REVISION_CHANGED"
  | "SOURCE_TERMINAL_CHANGED"
  | "HISTORY_COVERAGE_CHANGED";
export type LineageChange = {
  kind: LineageChangeKind;
  severity: "REVIEW" | "UNKNOWN" | "CONTEXT";
  eventId: string | null;
  explanation: string;
  sourceA: string | null;
  sourceB: string | null;
  requiresOriginalEventReview: boolean;
};
export type LineageComparison = {
  organizationId: string;
  requestedEventId: string;
  workItemId: string;
  baselineDepth: number;
  subsequentDepth: number;
  commonEventCount: number;
  onlyInBaseline: number;
  onlyInSubsequent: number;
  coverageIsComparable: boolean;
  differences: LineageChange[];
  counts: { review: number; unknown: number; context: number };
  limitations: string[];
};
function nodeData(node: LineageNode): Record<string, string | number | null> {
  return {
    caseKey: node.caseKey, actorUserId: node.actorUserId,
    decision: node.decision, reviewedRevision: node.reviewedRevision,
    previousEventId: node.previousEventId, occurredAt: node.occurredAt,
  };
}
export function compareAuditLineages(
  baseline: LineageReport,
  subsequent: LineageReport,
): LineageComparison {
  if (baseline.organizationId !== subsequent.organizationId ||
      baseline.requestedEventId !== subsequent.requestedEventId ||
      baseline.workItemId !== subsequent.workItemId)
    throw new Error("Cannot compare audit lineage from different trusted scopes.");
  const left = new Map(baseline.nodes.map(node => [node.eventId, node]));
  const right = new Map(subsequent.nodes.map(node => [node.eventId, node]));
  const differences: LineageChange[] = [];
  const add = (
    kind: LineageChangeKind,
    severity: LineageChange["severity"],
    eventId: string | null,
    sourceA: string | number | null,
    sourceB: string | number | null,
    explanation: string,
    requiresOriginalEventReview: boolean,
  ) => differences.push({
    kind, severity, eventId,
    sourceA: sourceA === null ? null : String(sourceA),
    sourceB: sourceB === null ? null : String(sourceB),
    explanation, requiresOriginalEventReview,
  });
  const coverageIsComparable = baseline.terminal === "ROOT" &&
    subsequent.terminal === "ROOT" &&
    baseline.sourceChainComplete && subsequent.sourceChainComplete;
  for (const [id, before] of left) {
    const after = right.get(id);
    if (!after) {
      add("REVIEW_EVENT_ABSENT",
        coverageIsComparable ? "REVIEW" : "UNKNOWN",
        id, id, null,
        "A previously observed audit event is absent from the subsequent source walk.",
        coverageIsComparable);
      continue;
    }
    const fields: {
      key: keyof ReturnType<typeof nodeData>; kind: LineageChangeKind;
      explanation: string;
    }[] = [
      {
        key: "caseKey", kind: "CASE_IDENTITY_CHANGED",
        explanation: "A recorded audit event now belongs to a different diagnostic identity.",
      },
      {
        key: "actorUserId", kind: "ACTOR_REFERENCE_CHANGED",
        explanation: "The linked reviewer identity changed for an existing audit event.",
      },
      {
        key: "decision", kind: "DECISION_CHANGED",
        explanation: "A stored event identity now describes a different human decision.",
      },
      {
        key: "reviewedRevision", kind: "REVIEW_REVISION_CHANGED",
        explanation: "The reviewed work revision changed for the same audit event.",
      },
      {
        key: "previousEventId", kind: "CHAIN_PREDECESSOR_CHANGED",
        explanation: "An event's recorded predecessor reference has changed.",
      },
      {
        key: "occurredAt", kind: "REVIEW_TIME_CHANGED",
        explanation: "An event timestamp changed between two source reads.",
      },
    ];
    const beforeData = nodeData(before);
    const afterData = nodeData(after);
    for (const field of fields)
      if (beforeData[field.key] !== afterData[field.key]) add(
        field.kind, "REVIEW", id,
        beforeData[field.key], afterData[field.key],
        field.explanation, true,
      );
  }
  for (const [id] of right)
    if (!left.has(id)) add(
      "REVIEW_EVENT_NEW",
      coverageIsComparable ? "REVIEW" : "UNKNOWN",
      id, null, id,
      "An event exists in the subsequent predecessor walk but not in the baseline.",
      coverageIsComparable,
    );
  if (baseline.currentRevision !== subsequent.currentRevision) add(
    "WORK_REVISION_CHANGED", "CONTEXT", null,
    baseline.currentRevision, subsequent.currentRevision,
    "The current work revision changed between source lineage reads.",
    false,
  );
  if (baseline.terminal !== subsequent.terminal) add(
    "SOURCE_TERMINAL_CHANGED", "UNKNOWN", null,
    baseline.terminal, subsequent.terminal,
    "Predecessor traversal ended at a different source boundary.",
    false,
  );
  if (baseline.sourceChainComplete !== subsequent.sourceChainComplete) add(
    "HISTORY_COVERAGE_CHANGED", "UNKNOWN", null,
    String(baseline.sourceChainComplete), String(subsequent.sourceChainComplete),
    "The level of recorded lineage coverage changed between source reads.",
    false,
  );
  const rank = { REVIEW: 0, UNKNOWN: 1, CONTEXT: 2 };
  differences.sort((a, b) =>
    rank[a.severity] - rank[b.severity] ||
    a.kind.localeCompare(b.kind) ||
    (a.eventId ?? "").localeCompare(b.eventId ?? ""));
  return {
    organizationId: baseline.organizationId,
    requestedEventId: baseline.requestedEventId,
    workItemId: baseline.workItemId,
    baselineDepth: baseline.nodes.length,
    subsequentDepth: subsequent.nodes.length,
    commonEventCount: [...left.keys()].filter(id => right.has(id)).length,
    onlyInBaseline: [...left.keys()].filter(id => !right.has(id)).length,
    onlyInSubsequent: [...right.keys()].filter(id => !left.has(id)).length,
    coverageIsComparable, differences,
    counts: {
      review: differences.filter(d => d.severity === "REVIEW").length,
      unknown: differences.filter(d => d.severity === "UNKNOWN").length,
      context: differences.filter(d => d.severity === "CONTEXT").length,
    },
    limitations: [
      "Both reports must derive from the same trusted organization, work item and selected audit event.",
      "Missing events in depth-limited predecessor walks are unknown, not confirmed deletion.",
      "Only available metadata is compared; excluded rationales are not evaluated.",
      "This is not cryptographic verification of source audit immutability.",
      "Work revision changes are contextual and do not prove a resolved security control.",
    ],
  };
}
export function lineageComparisonCsv(report: LineageComparison): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const header = [
    "kind", "severity", "eventId", "sourceA", "sourceB",
    "explanation", "requiresOriginalEventReview",
  ];
  const lines = [header.map(quote).join(",")];
  for (const change of report.differences) lines.push([
    change.kind, change.severity, change.eventId, change.sourceA,
    change.sourceB, change.explanation, change.requiresOriginalEventReview,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
