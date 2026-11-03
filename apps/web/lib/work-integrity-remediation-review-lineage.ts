import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityReviewEvent, IntegrityReviewReplay } from "./work-integrity-remediation-review-event-replay";
import type { IntegrityReviewEvidenceReport } from "./work-integrity-remediation-review-evidence";
import type { IntegrityReviewBatchDecision } from "./work-integrity-remediation-review-batch";

export type IntegrityReviewLineageNode = {
  nodeId: string;
  kind: "TASK" | "EVENT" | "EVIDENCE" | "ASSOCIATION";
  taskId: string | null;
  eventId: string | null;
  reference: string | null;
  associationId: string | null;
  accepted: boolean;
  verified: false;
  label: string;
};
export type IntegrityReviewLineageEdge = {
  edgeId: string;
  from: string;
  to: string;
  kind: "TASK_EVENT" | "EVENT_EVIDENCE" |
    "EVIDENCE_ASSOCIATION" | "EVENT_FOLLOWS";
  valid: boolean;
};
export type IntegrityReviewLineageFinding = {
  code: "ORPHAN_EVENT" | "ORPHAN_EVIDENCE" |
    "MISSING_ASSOCIATION" | "REJECTED_EVENT" |
    "MISSING_PREDECESSOR" | "DUPLICATE_NODE" |
    "INVALID_BATCH_EVENT" | "CROSS_TASK_ASSOCIATION" |
    "WITHDRAWN_ASSOCIATION";
  severity: "ERROR" | "WARNING";
  nodeId: string | null;
  detail: string;
};
export type IntegrityReviewLineagePolicy = {
  maximumNodes: number;
  maximumEdges: number;
  includeRejectedEvents: boolean;
  includeUnusedTasks: boolean;
  includeUnmatchedEvidence: boolean;
  includeEventSequenceEdges: boolean;
};
export type IntegrityReviewLineageReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewLineagePolicy;
  nodes: IntegrityReviewLineageNode[];
  edges: IntegrityReviewLineageEdge[];
  findings: IntegrityReviewLineageFinding[];
  totals: {
    nodes: number;
    edges: number;
    tasks: number;
    events: number;
    evidence: number;
    associations: number;
    rejectedEvents: number;
    unmatchedReferences: number;
    errors: number;
    warnings: number;
    truncated: boolean;
    omittedNodes: number;
    omittedEdges: number;
  };
  limitation: string;
};
export type IntegrityReviewLineageQuery = {
  kinds?: IntegrityReviewLineageNode["kind"][];
  taskIds?: string[];
  onlyInvalid?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityReviewLineagePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  nodes: IntegrityReviewLineageNode[];
};
const defaults: IntegrityReviewLineagePolicy = {
  maximumNodes: 5000, maximumEdges: 10000,
  includeRejectedEvents: true, includeUnusedTasks: true,
  includeUnmatchedEvidence: true,
  includeEventSequenceEdges: true,
};
const kinds: IntegrityReviewLineageNode["kind"][] = [
  "TASK", "EVENT", "EVIDENCE", "ASSOCIATION",
];
function record(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityReviewLineagePolicy(
  value: unknown,
): IntegrityReviewLineagePolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "review lineage policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown lineage policy field.");
  const policy = { ...defaults };
  for (const key of [
    "includeRejectedEvents", "includeUnusedTasks",
    "includeUnmatchedEvidence", "includeEventSequenceEdges",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid lineage policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumNodes !== undefined)
    policy.maximumNodes = integer(raw.maximumNodes,
      "maximum lineage nodes", 1, 10000);
  if (raw.maximumEdges !== undefined)
    policy.maximumEdges = integer(raw.maximumEdges,
      "maximum lineage edges", 1, 20000);
  return policy;
}
export function buildIntegrityReviewLineage(
  queue: IntegrityCapacityReviewQueue,
  events: readonly IntegrityReviewEvent[],
  replay: IntegrityReviewReplay,
  evidence: IntegrityReviewEvidenceReport | null,
  batch: IntegrityReviewBatchDecision | null,
  policy: IntegrityReviewLineagePolicy = defaults,
): IntegrityReviewLineageReport {
  if (queue.captureId !== replay.captureId ||
      (evidence && evidence.captureId !== queue.captureId) ||
      (batch && batch.captureId !== queue.captureId))
    throw new WorkInputError("INVALID", "Review lineage capture mismatch.");
  const allNodes: IntegrityReviewLineageNode[] = [];
  const allEdges: IntegrityReviewLineageEdge[] = [];
  const findings: IntegrityReviewLineageFinding[] = [];
  const nodeIds = new Set<string>();
  const accepted = new Set(replay.results.filter(x =>
    x.accepted).map(x => x.eventId));
  const validBatch = new Set(batch?.events.filter(x =>
    x.acceptedForAnalysis).map(x => x.eventId) ?? []);
  const queueTasks = new Set(queue.tasks.map(x => x.taskId));
  const node = (item: IntegrityReviewLineageNode) => {
    if (nodeIds.has(item.nodeId)) {
      findings.push({
        code: "DUPLICATE_NODE", severity: "ERROR",
        nodeId: item.nodeId,
        detail: "Multiple inputs resolve to the same lineage node.",
      });
      return;
    }
    nodeIds.add(item.nodeId);
    allNodes.push(item);
  };
  const edge = (
    from: string, to: string, kind: IntegrityReviewLineageEdge["kind"],
    valid: boolean,
  ) => {
    allEdges.push({
      edgeId: kind + ":" + from + "->" + to,
      from, to, kind, valid,
    });
  };
  const eventIds = new Set(events.map(x => x.eventId));
  for (const task of queue.tasks) {
    if (!policy.includeUnusedTasks &&
        !events.some(x => x.taskId === task.taskId)) continue;
    node({
      nodeId: "task:" + task.taskId,
      kind: "TASK", taskId: task.taskId,
      eventId: null, reference: null, associationId: null,
      accepted: true, verified: false,
      label: task.action,
    });
  }
  const previousByTask = new Map<string, string>();
  for (const event of events) {
    if (!accepted.has(event.eventId) &&
        !policy.includeRejectedEvents) continue;
    const eventNodeId = "event:" + event.eventId;
    node({
      nodeId: eventNodeId, kind: "EVENT",
      taskId: event.taskId, eventId: event.eventId,
      reference: null, associationId: null,
      accepted: accepted.has(event.eventId),
      verified: false, label: event.kind,
    });
    if (queueTasks.has(event.taskId)) {
      if (nodeIds.has("task:" + event.taskId))
        edge("task:" + event.taskId, eventNodeId,
          "TASK_EVENT", accepted.has(event.eventId));
    } else {
      findings.push({
        code: "ORPHAN_EVENT", severity: "ERROR",
        nodeId: eventNodeId,
        detail: "The event references a task outside the queue.",
      });
    }
    if (!accepted.has(event.eventId))
      findings.push({
        code: "REJECTED_EVENT", severity: "WARNING",
        nodeId: eventNodeId,
        detail: "The event was rejected by optimistic replay.",
      });
    if (batch && !validBatch.has(event.eventId))
      findings.push({
        code: "INVALID_BATCH_EVENT", severity: "ERROR",
        nodeId: eventNodeId,
        detail: "The event failed analytical batch validation.",
      });
    const previous = previousByTask.get(event.taskId);
    if (policy.includeEventSequenceEdges && previous &&
        nodeIds.has(previous))
      edge(previous, eventNodeId, "EVENT_FOLLOWS",
        accepted.has(event.eventId));
    previousByTask.set(event.taskId, eventNodeId);
  }
  if (evidence) {
    for (const reference of evidence.references) {
      if (!policy.includeUnmatchedEvidence &&
          reference.status !== "ACTIVE") continue;
      const evidenceNodeId = "evidence:" + reference.eventId +
        ":" + reference.reference;
      node({
        nodeId: evidenceNodeId, kind: "EVIDENCE",
        taskId: reference.taskId, eventId: reference.eventId,
        reference: reference.reference,
        associationId: reference.associationId,
        accepted: reference.status === "ACTIVE",
        verified: false, label: reference.status,
      });
      if (eventIds.has(reference.eventId) &&
          nodeIds.has("event:" + reference.eventId))
        edge("event:" + reference.eventId, evidenceNodeId,
          "EVENT_EVIDENCE", reference.status === "ACTIVE");
      else
        findings.push({
          code: "ORPHAN_EVIDENCE", severity: "ERROR",
          nodeId: evidenceNodeId,
          detail: "Evidence references an absent or omitted event.",
        });
      if (reference.associationId !== null) {
        const associationNodeId = "association:" + reference.associationId;
        if (!nodeIds.has(associationNodeId))
          node({
            nodeId: associationNodeId, kind: "ASSOCIATION",
            taskId: reference.taskId, eventId: null,
            reference: reference.reference,
            associationId: reference.associationId,
            accepted: reference.status === "ACTIVE",
            verified: false, label: reference.status,
          });
        edge(evidenceNodeId, associationNodeId,
          "EVIDENCE_ASSOCIATION", reference.status === "ACTIVE");
      } else {
        findings.push({
          code: "MISSING_ASSOCIATION", severity: "ERROR",
          nodeId: evidenceNodeId,
          detail: "No scoped association was matched to the reference.",
        });
      }
      if (reference.status === "WITHDRAWN")
        findings.push({
          code: "WITHDRAWN_ASSOCIATION", severity: "ERROR",
          nodeId: evidenceNodeId,
          detail: "The evidence association was withdrawn at review time.",
        });
      if (reference.status === "CROSS_TASK" ||
          reference.status === "CROSS_CAPTURE")
        findings.push({
          code: "CROSS_TASK_ASSOCIATION", severity: "ERROR",
          nodeId: evidenceNodeId,
          detail: "Evidence belongs to another task or capture.",
        });
    }
  }
  const nodes = allNodes.slice(0, policy.maximumNodes);
  const included = new Set(nodes.map(x => x.nodeId));
  const possibleEdges = allEdges.filter(x =>
    included.has(x.from) && included.has(x.to));
  const edges = possibleEdges.slice(0, policy.maximumEdges);
  const truncated = nodes.length !== allNodes.length ||
    edges.length !== allEdges.length;
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: replay.evaluatedAt, policy,
    nodes, edges, findings,
    totals: {
      nodes: nodes.length, edges: edges.length,
      tasks: nodes.filter(x => x.kind === "TASK").length,
      events: nodes.filter(x => x.kind === "EVENT").length,
      evidence: nodes.filter(x => x.kind === "EVIDENCE").length,
      associations: nodes.filter(x =>
        x.kind === "ASSOCIATION").length,
      rejectedEvents: nodes.filter(x =>
        x.kind === "EVENT" && !x.accepted).length,
      unmatchedReferences: nodes.filter(x =>
        x.kind === "EVIDENCE" && !x.accepted).length,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
      truncated,
      omittedNodes: allNodes.length - nodes.length,
      omittedEdges: allEdges.length - edges.length,
    },
    limitation: "Lineage is reconstructed from caller-provided events and evidence associations. Graph edges do not prove independent evidence integrity, authenticated identity or persisted audit provenance.",
  };
}
export function parseIntegrityReviewLineageQuery(
  value: unknown,
): IntegrityReviewLineageQuery {
  const raw = record(value, "review lineage query");
  if (Object.keys(raw).some(x => ![
    "kinds", "taskIds", "onlyInvalid", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown lineage query field.");
  const selectedKinds = raw.kinds === undefined ? undefined :
    identifiers(raw.kinds, "lineage kinds", kinds.length);
  if (selectedKinds?.some(x => !kinds.includes(
    x as IntegrityReviewLineageNode["kind"])))
    throw new WorkInputError("INVALID", "Unknown lineage kind.");
  if (raw.onlyInvalid !== undefined &&
      typeof raw.onlyInvalid !== "boolean")
    throw new WorkInputError("INVALID", "Invalid lineage filter.");
  return {
    ...(selectedKinds === undefined ? {} : {
      kinds: selectedKinds as IntegrityReviewLineageNode["kind"][],
    }),
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "lineage task IDs", 500),
    }),
    onlyInvalid: raw.onlyInvalid === true,
    offset: integer(raw.offset ?? 0, "lineage offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "lineage limit", 1, 500),
  };
}
export function queryIntegrityReviewLineage(
  report: IntegrityReviewLineageReport,
  query: IntegrityReviewLineageQuery,
): IntegrityReviewLineagePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.nodes.filter(x =>
    (!query.kinds || query.kinds.includes(x.kind)) &&
    (!query.taskIds || (x.taskId !== null &&
      query.taskIds.includes(x.taskId))) &&
    (!query.onlyInvalid || !x.accepted));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    nodes: selected.slice(offset, offset + limit),
  };
}
