import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";

/**
 * Read-only local reconciliation across signed dispatch authentication,
 * schedule claims, provider reservations, inspections and audit events.
 * Time-proximity is diagnostic, never proof of request causality.
 */
export type OsvForensicInput = {
  scheduleId: string | null;
  lookbackHours: number;
  maximumRecords: number;
  includeAudit: boolean;
  includeInspections: boolean;
  includeQuota: boolean;
  strictCompleteness: boolean;
};
export type OsvForensicNode = {
  id: string;
  type: "SIGNATURE" | "SCHEDULE_RUN" | "QUOTA" |
    "INSPECTION" | "AUDIT";
  referenceId: string;
  scheduleId: string | null;
  eventAt: string;
  state: string;
  digest: string;
  attributes: Record<string, string | number | boolean | null>;
};
export type OsvForensicEdge = {
  from: string;
  to: string;
  relation: "EXACT_SCHEDULE" | "EXACT_INSPECTION" |
    "EXACT_REQUEST_KEY" | "EXACT_AUDIT_RESOURCE" |
    "TIME_ADJACENT_ONLY";
  confidence: "EXACT_REFERENCE" | "HEURISTIC";
  evidence: string;
};
export type OsvForensicAnomaly = {
  id: string;
  code: string;
  severity: "WARNING" | "CRITICAL";
  nodeId: string | null;
  description: string;
  remediation: string;
  supportedBy: string[];
};
export type OsvForensicReport = {
  schema: "cyberpilot.assets.osv.dispatch.forensic.v1";
  organizationId: string;
  evaluatedAt: string;
  windowStart: string;
  windowEnd: string;
  input: OsvForensicInput;
  complete: boolean;
  truncatedCollections: string[];
  collectionCounts: {
    signatures: number;
    runs: number;
    quotas: number;
    inspections: number;
    audits: number;
  };
  nodes: OsvForensicNode[];
  edges: OsvForensicEdge[];
  anomalies: OsvForensicAnomaly[];
  summary: {
    nodes: number; edges: number;
    exactReferences: number; heuristicLinks: number;
    criticalAnomalies: number;
    warningAnomalies: number;
    unfinishedClaims: number;
    unknownProviderResults: number;
    unresolvedQuotas: number;
  };
  reportDigest: string;
  liveProviderVerified: false;
  changesCommitted: false;
  networkRequestsMade: 0;
  findingsModified: false;
  warnings: string[];
};
export type OsvForensicDataset = {
  signatures: Array<{
    id: string; scheduleId: string; acceptedAt: Date;
    expiresAt: Date; requestDigest: string; nonceDigest: string;
    keyId: string;
  }>;
  runs: Array<{
    id: string; scheduleId: string; slotAt: Date;
    claimedAt: Date; claimExpiresAt: Date;
    completedAt: Date | null; state: string;
    commandDigest: string; inspectionId: string | null;
    errorCode: string | null;
  }>;
  quotas: Array<{
    id: string; requestKey: string; startedAt: Date;
    finishedAt: Date | null; state: string;
    reservedRequests: number; actualRequests: number;
    errorCode: string | null; requestDigest: string;
  }>;
  inspections: Array<{
    id: string; requestKey: string; completedAt: Date;
    status: string; reportDigest: string;
    queryCount: number; completedCount: number;
  }>;
  audits: Array<{
    id: string; occurredAt: Date; actorType: string;
    action: string; resourceType: string;
    resourceId: string | null;
  }>;
};
const SCHEMA = "cyberpilot.assets.osv.dispatch.forensic.v1" as const;
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function record(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    invalid("Forensic dispatch input must be an object.");
  return value as Record<string, unknown>;
}
function numeric(value: unknown, label: string,
  low: number, high: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < low || value > high)
    invalid("Invalid forensic " + label + ".");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validDate(value: Date) {
  if (!Number.isFinite(value.getTime()))
    invalid("Invalid forensic evaluation timestamp.");
  return value.toISOString();
}
export function parseOsvForensicInput(
  value: unknown = {},
): OsvForensicInput {
  const input = record(value);
  const allowed = [
    "scheduleId", "lookbackHours", "maximumRecords",
    "includeAudit", "includeInspections", "includeQuota",
    "strictCompleteness",
  ];
  if (Object.keys(input).some(key => !allowed.includes(key)))
    invalid("Unexpected forensic dispatch query property.");
  const scheduleId = input.scheduleId ?? null;
  if (scheduleId !== null && (typeof scheduleId !== "string" ||
      !/^[A-Za-z0-9_-]{8,150}$/.test(scheduleId)))
    invalid("Invalid forensic schedule ID.");
  const booleans = [
    "includeAudit", "includeInspections",
    "includeQuota", "strictCompleteness",
  ] as const;
  for (const key of booleans)
    if (input[key] !== undefined && typeof input[key] !== "boolean")
      invalid("Invalid forensic " + key + " toggle.");
  return {
    scheduleId,
    lookbackHours: numeric(input.lookbackHours ?? 72,
      "lookback", 1, 720),
    maximumRecords: numeric(input.maximumRecords ?? 100,
      "record cap", 1, 500),
    includeAudit: input.includeAudit !== false,
    includeInspections: input.includeInspections !== false,
    includeQuota: input.includeQuota !== false,
    strictCompleteness: input.strictCompleteness !== false,
  };
}
export function canonicalForensicNode(
  type: OsvForensicNode["type"], id: string,
  scheduleId: string | null, at: Date, state: string,
  attributes: OsvForensicNode["attributes"],
): OsvForensicNode {
  validDate(at);
  const ref = type.toLowerCase() + ":" + id;
  const canonical = {
    id: ref, type, referenceId: id, scheduleId,
    eventAt: at.toISOString(), state, attributes,
  };
  return { ...canonical, digest: sha(canonical) };
}
function edge(from: OsvForensicNode, to: OsvForensicNode,
  relation: OsvForensicEdge["relation"],
  evidence: string): OsvForensicEdge {
  return {
    from: from.id, to: to.id, relation,
    confidence: relation === "TIME_ADJACENT_ONLY" ?
      "HEURISTIC" : "EXACT_REFERENCE",
    evidence,
  };
}
function anomaly(code: string, nodeId: string | null,
  severity: OsvForensicAnomaly["severity"], description: string,
  remediation: string,
  supportedBy: string[]): OsvForensicAnomaly {
  const id = code + ":" + sha([nodeId, supportedBy]).slice(0, 24);
  return { id, code, nodeId, severity,
    description, remediation, supportedBy };
}
function proximity(a: Date, b: Date) {
  const gap = b.getTime() - a.getTime();
  return gap >= -10000 && gap <= 60000;
}
export function composeOsvForensicReport(
  organizationId: string,
  input: OsvForensicInput, data: OsvForensicDataset,
  now: Date, totals?: Partial<Record<keyof OsvForensicDataset, number>>,
): OsvForensicReport {
  validDate(now);
  const windowStart = new Date(now.getTime() -
    input.lookbackHours * 3600000);
  const collectionCounts = {
    signatures: totals?.signatures ?? data.signatures.length,
    runs: totals?.runs ?? data.runs.length,
    quotas: totals?.quotas ?? data.quotas.length,
    inspections: totals?.inspections ?? data.inspections.length,
    audits: totals?.audits ?? data.audits.length,
  };
  const truncatedCollections = (Object.keys(collectionCounts) as
    Array<keyof typeof collectionCounts>).filter(key =>
    collectionCounts[key] > data[key].length);
  const nodes: OsvForensicNode[] = [];
  const edges: OsvForensicEdge[] = [];
  const anomalies: OsvForensicAnomaly[] = [];
  const nodeMap = new Map<string, OsvForensicNode>();
  const add = (node: OsvForensicNode) => {
    if (nodeMap.has(node.id))
      invalid("Duplicate forensic record identifier.");
    nodeMap.set(node.id, node); nodes.push(node);
  };
  for (const item of data.signatures) add(canonicalForensicNode(
    "SIGNATURE", item.id, item.scheduleId, item.acceptedAt,
    "ACCEPTED", {
      keyId: item.keyId,
      requestDigest: item.requestDigest,
      nonceDigest: item.nonceDigest,
      expiresAt: item.expiresAt.toISOString(),
    }));
  for (const item of data.runs) add(canonicalForensicNode(
    "SCHEDULE_RUN", item.id, item.scheduleId,
    item.claimedAt, item.state, {
      slotAt: item.slotAt.toISOString(),
      claimExpiresAt: item.claimExpiresAt.toISOString(),
      completedAt: item.completedAt?.toISOString() ?? null,
      commandDigest: item.commandDigest,
      inspectionId: item.inspectionId,
      errorCode: item.errorCode,
    }));
  for (const item of data.quotas) add(canonicalForensicNode(
    "QUOTA", item.id, null, item.startedAt, item.state, {
      requestKey: item.requestKey,
      requestDigest: item.requestDigest,
      reservedRequests: item.reservedRequests,
      actualRequests: item.actualRequests,
      errorCode: item.errorCode,
      finishedAt: item.finishedAt?.toISOString() ?? null,
    }));
  for (const item of data.inspections) add(canonicalForensicNode(
    "INSPECTION", item.id, null,
    item.completedAt, item.status, {
      requestKey: item.requestKey,
      reportDigest: item.reportDigest,
      queryCount: item.queryCount,
      completedCount: item.completedCount,
    }));
  for (const item of data.audits) add(canonicalForensicNode(
    "AUDIT", item.id, null, item.occurredAt,
    item.action, {
      actorType: item.actorType, resourceType: item.resourceType,
      resourceId: item.resourceId,
    }));
  const runsBySchedule = new Map<string,
    Array<(typeof data.runs)[number]>>();
  for (const run of data.runs) {
    const rows = runsBySchedule.get(run.scheduleId) ?? [];
    rows.push(run); runsBySchedule.set(run.scheduleId, rows);
  }
  for (const signed of data.signatures) {
    const source = nodeMap.get("signature:" + signed.id)!;
    const possible = (runsBySchedule.get(signed.scheduleId) ?? [])
      .filter(run => proximity(signed.acceptedAt, run.claimedAt));
    if (possible.length === 1) {
      const target = nodeMap.get("schedule_run:" + possible[0]!.id)!;
      edges.push(edge(source, target, "TIME_ADJACENT_ONLY",
        "Same schedule and acceptance timestamp within a 70-second window; not proven causation."));
    } else if (possible.length === 0) {
      if (now.getTime() - signed.acceptedAt.getTime() >= 45 * 60000)
        anomalies.push(anomaly("SIGNATURE_WITHOUT_VISIBLE_CLAIM",
          source.id, "WARNING",
          "A signing nonce was consumed but no nearby schedule claim was found.",
          "Review logs and audit history. Do not retry a spent nonce.",
          [source.digest]));
    } else anomalies.push(anomaly("AMBIGUOUS_SIGNED_CLAIM",
      source.id, "WARNING",
      "Multiple schedule claims are adjacent to the same accepted signature.",
      "Investigate exact audit metadata rather than assuming a causal link.",
      [source.digest, ...possible.map(run =>
        nodeMap.get("schedule_run:" + run.id)!.digest)]));
  }
  const inspectionsById = new Map(data.inspections.map(row =>
    [row.id, row]));
  const quotaByKey = new Map<string, (typeof data.quotas)[number][]>();
  for (const quota of data.quotas) {
    const items = quotaByKey.get(quota.requestKey) ?? [];
    items.push(quota); quotaByKey.set(quota.requestKey, items);
  }
  for (const run of data.runs) {
    const source = nodeMap.get("schedule_run:" + run.id)!;
    if (run.inspectionId) {
      const target = inspectionsById.get(run.inspectionId);
      if (target) edges.push(edge(source,
        nodeMap.get("inspection:" + target.id)!,
        "EXACT_INSPECTION", "Run inspectionId is an exact persisted reference."));
      else anomalies.push(anomaly("INSPECTION_NOT_IN_WINDOW",
        source.id, "WARNING",
        "An inspection referenced by the scheduler is absent from the selected evidence window.",
        "Expand the window or inspect the original source before interpreting the record.",
        [source.digest]));
    }
    if (run.state === "CLAIMED" &&
        run.claimExpiresAt.getTime() + 30 * 60000 <= now.getTime())
      anomalies.push(anomaly("STALE_UNSETTLED_CLAIM",
        source.id, "CRITICAL",
        "A claimed schedule slot has outlived its expiry and investigation delay.",
        "Classify UNKNOWN using audited incident recovery; do not reissue HTTP requests.",
        [source.digest]));
    if (run.state === "UNKNOWN")
      anomalies.push(anomaly("UNKNOWN_PROVIDER_OUTCOME",
        source.id, "WARNING",
        "The provider may have received the request, but the outcome is unknown.",
        "Keep quota and slot consumed and investigate the provider-side evidence.",
        [source.digest]));
    if (run.state === "COMPLETE" && !run.inspectionId)
      anomalies.push(anomaly("COMPLETE_WITHOUT_INSPECTION_REFERENCE",
        source.id, "WARNING",
        "Run is marked complete without an inspection ID.",
        "Verify the persisted execution outcome and audit before acceptance.",
        [source.digest]));
  }
  for (const inspection of data.inspections) {
    const target = nodeMap.get("inspection:" + inspection.id)!;
    for (const quota of quotaByKey.get(inspection.requestKey) ?? []) {
      edges.push(edge(nodeMap.get("quota:" + quota.id)!,
        target, "EXACT_REQUEST_KEY",
        "Reservation and inspection share an exact persisted request key."));
    }
    if (inspection.completedCount > inspection.queryCount)
      anomalies.push(anomaly("INVALID_INSPECTION_COUNTER",
        target.id, "CRITICAL",
        "Completed query count exceeds total recorded queries.",
        "Inspect the immutable inspection ledger before interpreting coverage.",
        [target.digest]));
  }
  for (const quota of data.quotas) {
    const node = nodeMap.get("quota:" + quota.id)!;
    if (quota.state === "RESERVED" &&
        now.getTime() - quota.startedAt.getTime() >= 45 * 60000)
      anomalies.push(anomaly("UNSETTLED_PROVIDER_RESERVATION",
        node.id, "CRITICAL",
        "Provider quota remains reserved beyond the operational investigation threshold.",
        "Review quota recovery and do not refund reservations automatically.",
        [node.digest]));
    if (quota.actualRequests > quota.reservedRequests)
      anomalies.push(anomaly("QUOTA_EXCEEDS_RESERVATION",
        node.id, "CRITICAL",
        "Reported actual requests exceed the reserved budget.",
        "Block further dispatch until the provider quota discrepancy is reviewed.",
        [node.digest]));
  }
  const resourceMap = new Map<string, OsvForensicNode>();
  for (const node of nodes)
    if (node.type !== "AUDIT") resourceMap.set(node.referenceId, node);
  for (const audit of data.audits) {
    if (!audit.resourceId) continue;
    const target = resourceMap.get(audit.resourceId);
    if (target) edges.push(edge(
      nodeMap.get("audit:" + audit.id)!, target,
      "EXACT_AUDIT_RESOURCE",
      "AuditEvent.resourceId refers to the exact persisted record identifier."));
  }
  nodes.sort((a, b) =>
    a.eventAt.localeCompare(b.eventAt) || a.id.localeCompare(b.id));
  edges.sort((a, b) =>
    a.from.localeCompare(b.from) || a.to.localeCompare(b.to));
  anomalies.sort((a, b) =>
    a.code.localeCompare(b.code) || a.id.localeCompare(b.id));
  const summary = {
    nodes: nodes.length, edges: edges.length,
    exactReferences: edges.filter(e =>
      e.confidence === "EXACT_REFERENCE").length,
    heuristicLinks: edges.filter(e =>
      e.confidence === "HEURISTIC").length,
    criticalAnomalies: anomalies.filter(e =>
      e.severity === "CRITICAL").length,
    warningAnomalies: anomalies.filter(e =>
      e.severity === "WARNING").length,
    unfinishedClaims: data.runs.filter(e => e.state === "CLAIMED").length,
    unknownProviderResults: data.runs.filter(e => e.state === "UNKNOWN").length,
    unresolvedQuotas: data.quotas.filter(e => e.state === "RESERVED").length,
  };
  const canonical = {
    schema: SCHEMA, organizationId,
    evaluatedAt: now.toISOString(),
    windowStart: windowStart.toISOString(),
    windowEnd: now.toISOString(), input,
    complete: truncatedCollections.length === 0,
    truncatedCollections, collectionCounts,
    nodes, edges, anomalies, summary,
    liveProviderVerified: false as const,
    changesCommitted: false as const,
    networkRequestsMade: 0 as const,
    findingsModified: false as const,
  };
  return { ...canonical, reportDigest: sha(canonical),
    warnings: [
      "This is a local read-only forensic snapshot, not proof of external provider delivery.",
      "Time-adjacent signatures and run claims are heuristic associations only.",
      "Missing records outside the selected window are never treated as proof of absence.",
      "No provider requests, quota refunds or changes to CyberScore or findings are performed.",
      ...(truncatedCollections.length ?
        ["One or more collections were truncated and the report is incomplete."] : []),
    ],
  };
}
export async function inspectOsvForensicTimeline(
  scope: AssetScope, value: unknown = {},
  now = new Date(),
): Promise<OsvForensicReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only tenant administrators may inspect OSV forensic evidence.");
  validDate(now);
  const input = parseOsvForensicInput(value);
  const start = new Date(now.getTime() -
    input.lookbackHours * 3600000);
  if (input.scheduleId) {
    const exists = await db.assetOsvRenewalSchedule.count({
      where: { organizationId: scope.organizationId,
        id: input.scheduleId },
    });
    if (!exists) throw new WorkInputError("MISSING",
      "Selected OSV schedule does not exist in this organization.");
  }
  const scheduleFilter = input.scheduleId ?
    { scheduleId: input.scheduleId } : {};
  const [signatures, runs, quotas, inspections, audits] =
    await Promise.all([
      db.assetOsvDispatchNonce.findMany({
        where: {
          organizationId: scope.organizationId,
          ...scheduleFilter,
          acceptedAt: { gte: start, lte: now },
        },
        orderBy: [{ acceptedAt: "desc" }, { id: "desc" }],
        take: input.maximumRecords + 1,
      }),
      db.assetOsvRenewalRun.findMany({
        where: {
          organizationId: scope.organizationId,
          ...scheduleFilter,
          claimedAt: { gte: start, lte: now },
        },
        orderBy: [{ claimedAt: "desc" }, { id: "desc" }],
        take: input.maximumRecords + 1,
      }),
      input.includeQuota ? db.assetOsvQuotaReservation.findMany({
        where: {
          organizationId: scope.organizationId,
          startedAt: { gte: start, lte: now },
        },
        orderBy: [{ startedAt: "desc" }, { id: "desc" }],
        take: input.maximumRecords + 1,
      }) : Promise.resolve([]),
      input.includeInspections ? db.assetOsvInspection.findMany({
        where: {
          organizationId: scope.organizationId,
          completedAt: { gte: start, lte: now },
        },
        orderBy: [{ completedAt: "desc" }, { id: "desc" }],
        take: input.maximumRecords + 1,
      }) : Promise.resolve([]),
      input.includeAudit ? db.auditEvent.findMany({
        where: {
          organizationId: scope.organizationId,
          occurredAt: { gte: start, lte: now },
          action: { startsWith: "assets.osv." },
        },
        orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
        take: input.maximumRecords + 1,
      }) : Promise.resolve([]),
    ]);
  const cap = input.maximumRecords;
  const dataset: OsvForensicDataset = {
    signatures: signatures.slice(0, cap),
    runs: runs.slice(0, cap),
    quotas: quotas.slice(0, cap),
    inspections: inspections.slice(0, cap),
    audits: audits.slice(0, cap),
  };
  const counts = {
    signatures: signatures.length, runs: runs.length,
    quotas: quotas.length, inspections: inspections.length,
    audits: audits.length,
  };
  const result = composeOsvForensicReport(
    scope.organizationId, input, dataset, now, counts);
  if (input.strictCompleteness && !result.complete)
    throw new WorkInputError("CONFLICT",
      "Forensic result exceeds the bounded evidence window; narrow the period or select a schedule.");
  return result;
}
