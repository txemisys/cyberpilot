import { createHash } from "node:crypto";
import type {
  TimelineEvent, TimelineSource, TimelineIntegrity,
} from "./incident-operational-timeline-domain";
import type { ForensicCaseReport } from "./incident-timeline-forensics-domain";

/** Explicitly selected incidents only. Never a whole-tenant discovery engine. */
export type CorrelationKind =
  "SHARED_ACTOR" | "REPEATED_OPERATION" | "COMMON_SOURCE_KEY" |
  "NEARBY_ACTIVITY" | "REPEATED_FORENSIC_FINDING" |
  "JOINT_COVERAGE_GAP" | "SOURCE_CONFLICT_CLUSTER";
export type CorrelationStrength = "WEAK" | "REQUIRES_REVIEW" | "UNKNOWN";
export type CorrelationPriority = "P0" | "P1" | "P2" | "P3";
export type CorrelationEvidence = {
  incidentId: string;
  source: TimelineSource | null;
  sourceId: string | null;
  eventIds: string[];
  eventCount: number;
  firstAt: string | null;
  lastAt: string | null;
  integrity: TimelineIntegrity;
  provenance: "LOCAL_TIMELINE" | "LOCAL_FORENSIC";
};
export type CorrelationFinding = {
  id: string;
  kind: CorrelationKind;
  strength: CorrelationStrength;
  priority: CorrelationPriority;
  leftIncidentId: string;
  rightIncidentId: string;
  explanation: string;
  evidence: [CorrelationEvidence, CorrelationEvidence];
  sharedValueFingerprint: string | null;
  identityEquivalenceEstablished: false;
  compromiseEstablished: false;
  providerOutcomeVerified: false;
  manualReviewRequired: true;
};
export type CorrelationCaseInput = {
  incidentId: string;
  incidentRevision: number;
  timelineEvents: TimelineEvent[];
  forensic: ForensicCaseReport;
  eventInventoryComplete: boolean;
};
export type CorrelationCaseStatus = {
  incidentId: string;
  incidentRevision: number;
  sourceEvents: number;
  retainedEvents: number;
  duplicateRevisionCount: number;
  foreignEventCount: 0;
  sourceFamilies: TimelineSource[];
  forensicDigest: string;
  forensicIntegrity: TimelineIntegrity;
  inventoryComplete: boolean;
  lastActivityAt: string | null;
  findingsLinked: number;
};
export type CorrelationPolicy = {
  schema: "cyberpilot.incident.correlation.policy.v1";
  maximumCases: number;
  maximumEventsPerCase: number;
  maximumResults: number;
  temporalWindowMinutes: number;
  minRepeatedOperations: number;
  minSharedActorEvents: number;
  includeCommonSourceKeys: boolean;
  includeTemporalProximity: boolean;
  includeForensicClusters: boolean;
  allowExternalIdentityClaims: false;
  requireExplicitCaseSelection: true;
  providerWrites: 0;
};
export type CorrelationReport = {
  schema: "cyberpilot.incident.correlation.report.v1";
  organizationId: string;
  requestedAt: string;
  selectedIncidentIds: string[];
  policyDigest: string;
  selectionDigest: string;
  cases: CorrelationCaseStatus[];
  findings: CorrelationFinding[];
  totalCandidateLinks: number;
  resultsTruncated: boolean;
  completeness: "PARTIAL" | "UNKNOWN";
  weakestEvidenceLevel: CorrelationStrength;
  warnings: string[];
  digest: string;
  externalActions: 0;
  providerIdentityConfirmed: false;
  providerContainmentConfirmed: false;
};
export type CorrelationGraphNode = {
  incidentId: string;
  eventCount: number;
  degree: number;
  connectedComponents: number[];
  importantFindingCount: number;
  hasUnknownCoverage: boolean;
};
export type CorrelationGraphEdge = {
  id: string;
  left: string;
  right: string;
  candidateCount: number;
  kinds: CorrelationKind[];
  strongestPriority: CorrelationPriority;
  directProviderProof: false;
};
export type CorrelationGraph = {
  schema: "cyberpilot.incident.correlation.graph.v1";
  organizationId: string;
  reportDigest: string;
  nodes: CorrelationGraphNode[];
  edges: CorrelationGraphEdge[];
  components: Array<{ index: number; incidentIds: string[]; links: number }>;
  orphanIncidentIds: string[];
  provenSharedCompromises: 0;
};
export type CorrelationReviewRequest = {
  id: string;
  findingId: string;
  organizationId: string;
  incidentIds: [string, string];
  kind: CorrelationKind;
  priority: CorrelationPriority;
  suggestedReviewerRole: "OWNER" | "ADMIN" | "AUDITOR";
  question: string;
  requiredChecks: string[];
  status: "OPEN_INTERNAL";
  externalActionAuthorized: false;
  identityMatchConfirmed: false;
};
const sources: TimelineSource[] = [
  "INCIDENT", "SITUATION_REVIEW", "TABLETOP_SESSION", "ASSURANCE_HANDOFF",
];
const kinds: CorrelationKind[] = [
  "SHARED_ACTOR", "REPEATED_OPERATION", "COMMON_SOURCE_KEY",
  "NEARBY_ACTIVITY", "REPEATED_FORENSIC_FINDING",
  "JOINT_COVERAGE_GAP", "SOURCE_CONFLICT_CLUSTER",
];
const priorities: CorrelationPriority[] = ["P0", "P1", "P2", "P3"];
const id = (x: unknown): x is string =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const sha = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const fail = (code: string): never => { throw Error(code); };
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") {
    const r = v as Record<string, unknown>;
    return Object.fromEntries(Object.keys(r).sort()
      .filter(k => r[k] !== undefined)
      .map(k => [k, canonical(r[k])]));
  }
  return v;
}
export function correlationDigest(value: unknown) {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value))).digest("hex");
}
export function defaultCorrelationPolicy(): CorrelationPolicy {
  return {
    schema: "cyberpilot.incident.correlation.policy.v1",
    maximumCases: 12, maximumEventsPerCase: 3000,
    maximumResults: 400, temporalWindowMinutes: 120,
    minRepeatedOperations: 2, minSharedActorEvents: 2,
    includeCommonSourceKeys: true,
    includeTemporalProximity: true, includeForensicClusters: true,
    allowExternalIdentityClaims: false, requireExplicitCaseSelection: true,
    providerWrites: 0,
  };
}
export function validateCorrelationPolicy(value: CorrelationPolicy) {
  const issues: string[] = [];
  if (!value || value.schema !== "cyberpilot.incident.correlation.policy.v1")
    issues.push("CORRELATION_POLICY_SCHEMA_INVALID");
  const range: Array<[number, number, number]> = [
    [value?.maximumCases, 2, 50],
    [value?.maximumEventsPerCase, 1, 10000],
    [value?.maximumResults, 1, 2000],
    [value?.temporalWindowMinutes, 1, 10080],
    [value?.minRepeatedOperations, 1, 50],
    [value?.minSharedActorEvents, 1, 50],
  ];
  if (range.some(([v, low, high]) =>
    !Number.isSafeInteger(v) || v < low || v > high))
    issues.push("CORRELATION_POLICY_BOUNDS_INVALID");
  if ([
    value?.includeCommonSourceKeys, value?.includeTemporalProximity,
    value?.includeForensicClusters,
  ].some(x => typeof x !== "boolean"))
    issues.push("CORRELATION_POLICY_FILTERS_INVALID");
  if (value?.allowExternalIdentityClaims !== false ||
      value?.requireExplicitCaseSelection !== true ||
      value?.providerWrites !== 0)
    issues.push("CORRELATION_POLICY_UNSAFE");
  return issues;
}
export function validateCorrelationSelection(args: {
  organizationId: string; requestedAt: string;
  cases: CorrelationCaseInput[]; policy: CorrelationPolicy;
}) {
  if (!args || !id(args.organizationId) || !iso(args.requestedAt))
    fail("CORRELATION_REQUEST_SCOPE_INVALID");
  const problems = validateCorrelationPolicy(args.policy);
  if (problems.length) fail(problems.join(","));
  if (!Array.isArray(args.cases) || args.cases.length < 2 ||
      args.cases.length > args.policy.maximumCases)
    fail("CORRELATION_EXPLICIT_SELECTION_REQUIRED");
  const names = new Set<string>();
  for (const row of args.cases) {
    if (!row || !id(row.incidentId) || names.has(row.incidentId) ||
        !Number.isSafeInteger(row.incidentRevision) ||
        row.incidentRevision < 1 ||
        typeof row.eventInventoryComplete !== "boolean")
      fail("CORRELATION_CASE_SELECTION_INVALID");
    names.add(row.incidentId);
    if (!Array.isArray(row.timelineEvents) ||
        row.timelineEvents.length > args.policy.maximumEventsPerCase)
      fail("CORRELATION_SOURCE_EVENT_CAP");
    if (row.timelineEvents.some(e => !e ||
        e.organizationId !== args.organizationId ||
        e.incidentId !== row.incidentId))
      fail("CORRELATION_CROSS_TENANT_OR_INCIDENT");
    const report = row.forensic;
    if (!report || report.organizationId !== args.organizationId ||
        report.incidentId !== row.incidentId ||
        !sha(report.digest) || report.externalActions !== 0 ||
        report.independentProviderProof !== false)
      fail("CORRELATION_FORENSIC_SOURCE_INVALID");
  }
}
function eventTimeRange(events: TimelineEvent[]): {
  firstAt: string | null; lastAt: string | null;
} {
  const times = events.map(e => e.occurredAt).sort();
  return { firstAt: times[0] ?? null, lastAt: times.at(-1) ?? null };
}
function observedIntegrity(
  items: TimelineEvent[], status: TimelineIntegrity,
): TimelineIntegrity {
  if (status === "CONFLICT" ||
      items.some(x => x.sourceIntegrity === "CONFLICT")) return "CONFLICT";
  return "INCOMPLETE";
}
function evidence(
  row: CorrelationCaseInput,
  selected: TimelineEvent[],
  source: TimelineSource | null,
  sourceId: string | null,
  provenance: CorrelationEvidence["provenance"],
): CorrelationEvidence {
  const dates = eventTimeRange(selected);
  return {
    incidentId: row.incidentId, source, sourceId,
    eventIds: selected.map(x => x.eventId).sort().slice(0, 60),
    eventCount: selected.length,
    firstAt: dates.firstAt, lastAt: dates.lastAt,
    integrity: observedIntegrity(selected, row.forensic.integrity),
    provenance,
  };
}
function rank(priority: CorrelationPriority) {
  return priorities.indexOf(priority);
}
function higher(
  a: CorrelationPriority, b: CorrelationPriority,
): CorrelationPriority {
  return rank(a) < rank(b) ? a : b;
}
function emit(args: {
  kind: CorrelationKind; left: CorrelationCaseInput;
  right: CorrelationCaseInput; leftEvents: TimelineEvent[];
  rightEvents: TimelineEvent[]; sharedKey: string | null;
  explanation: string; priority: CorrelationPriority;
  strength?: CorrelationStrength; provenance?: CorrelationEvidence["provenance"];
}) {
  const pair = [args.left.incidentId, args.right.incidentId].sort();
  if (pair[0] !== args.left.incidentId)
    fail("CORRELATION_INPUT_ORDER_INVALID");
  const provenance = args.provenance ?? "LOCAL_TIMELINE";
  const sourceId = args.sharedKey !== null &&
    args.kind === "COMMON_SOURCE_KEY" ? args.sharedKey : null;
  const source = args.leftEvents.length &&
    args.rightEvents.length &&
    args.leftEvents[0]!.source === args.rightEvents[0]!.source ?
      args.leftEvents[0]!.source : null;
  const left = evidence(args.left, args.leftEvents, source,
    sourceId, provenance);
  const right = evidence(args.right, args.rightEvents, source,
    sourceId, provenance);
  const strength: CorrelationStrength = args.strength ?? "REQUIRES_REVIEW";
  return {
    id: "corr:" + correlationDigest({
      pair, kind: args.kind, sharedKey: args.sharedKey,
      left: left.eventIds, right: right.eventIds,
    }).slice(0, 40),
    kind: args.kind, strength, priority: args.priority,
    leftIncidentId: args.left.incidentId,
    rightIncidentId: args.right.incidentId,
    explanation: args.explanation,
    evidence: [left, right] as [CorrelationEvidence, CorrelationEvidence],
    sharedValueFingerprint: args.sharedKey === null ? null :
      correlationDigest(args.sharedKey),
    identityEquivalenceEstablished: false as const,
    compromiseEstablished: false as const,
    providerOutcomeVerified: false as const,
    manualReviewRequired: true as const,
  };
}
function groupEvents<T>(
  events: T[], key: (e: T) => string,
) {
  const groups = new Map<string, T[]>();
  for (const e of events) {
    const k = key(e);
    const bucket = groups.get(k) ?? [];
    bucket.push(e);
    groups.set(k, bucket);
  }
  return groups;
}
function sharedKeys<A, B>(
  a: Map<string, A[]>,
  b: Map<string, B[]>,
) {
  return [...a.keys()].filter(key => b.has(key)).sort();
}
function pairCorrelations(
  left: CorrelationCaseInput, right: CorrelationCaseInput,
  policy: CorrelationPolicy,
): CorrelationFinding[] {
  const out: CorrelationFinding[] = [];
  const leftActors = groupEvents(left.timelineEvents, e => e.actorUserId);
  const rightActors = groupEvents(right.timelineEvents, e => e.actorUserId);
  for (const actor of sharedKeys(leftActors, rightActors)) {
    const a = leftActors.get(actor)!;
    const b = rightActors.get(actor)!;
    if (a.length < policy.minSharedActorEvents ||
        b.length < policy.minSharedActorEvents) continue;
    out.push(emit({
      kind: "SHARED_ACTOR", left, right, leftEvents: a, rightEvents: b,
      sharedKey: actor,
      explanation: "El mismo identificador de operador aparece en " +
        "ambos historiales internos. No demuestra identidad de víctimas " +
        "ni compromiso común.",
      priority: "P2", strength: "WEAK",
    }));
  }
  const leftOps = groupEvents(left.timelineEvents, e =>
    e.source + "/" + e.operation);
  const rightOps = groupEvents(right.timelineEvents, e =>
    e.source + "/" + e.operation);
  for (const operation of sharedKeys(leftOps, rightOps)) {
    const a = leftOps.get(operation)!;
    const b = rightOps.get(operation)!;
    if (a.length < policy.minRepeatedOperations ||
        b.length < policy.minRepeatedOperations) continue;
    out.push(emit({
      kind: "REPEATED_OPERATION", left, right,
      leftEvents: a, rightEvents: b, sharedKey: operation,
      explanation: "Se repite el tipo de actividad operativa en dos " +
        "casos seleccionados; puede obedecer a un flujo habitual.",
      priority: "P3", strength: "WEAK",
    }));
  }
  if (policy.includeCommonSourceKeys) {
    const key = (e: TimelineEvent) => e.source + "/" + e.sourceId;
    const a = groupEvents(left.timelineEvents, key);
    const b = groupEvents(right.timelineEvents, key);
    for (const sourceKey of sharedKeys(a, b)) {
      // Deliberately NOT an entity-resolution claim.
      out.push(emit({
        kind: "COMMON_SOURCE_KEY", left, right,
        leftEvents: a.get(sourceKey)!, rightEvents: b.get(sourceKey)!,
        sharedKey: sourceKey,
        explanation: "Una clave local de fuente coincide. Revisar " +
          "colisiones, ámbitos y procedencia antes de relacionar identidades.",
        priority: "P1", strength: "REQUIRES_REVIEW",
      }));
    }
  }
  if (policy.includeTemporalProximity) {
    const a = left.timelineEvents.filter(x => x.source === "INCIDENT");
    const b = right.timelineEvents.filter(x => x.source === "INCIDENT");
    const windowMs = policy.temporalWindowMinutes * 60000;
    const groupedA: TimelineEvent[] = [];
    const groupedB: TimelineEvent[] = [];
    for (const x of a) {
      const related = b.filter(y =>
        Math.abs(Date.parse(x.occurredAt) -
          Date.parse(y.occurredAt)) <= windowMs);
      if (related.length) {
        groupedA.push(x);
        groupedB.push(...related);
      }
    }
    if (groupedA.length && groupedB.length) {
      out.push(emit({
        kind: "NEARBY_ACTIVITY", left, right,
        leftEvents: groupedA, rightEvents: [...new Map(
          groupedB.map(e => [e.eventId, e])).values()],
        sharedKey: null,
        explanation: "Hay eventos de incidentes cercanos en el tiempo; " +
          "la proximidad no demuestra una campaña común.",
        priority: "P2", strength: "WEAK",
      }));
    }
  }
  if (policy.includeForensicClusters) {
    const a = groupEvents(
      left.forensic.findings.map(f => ({
        eventId: f.eventId ?? "none",
        code: f.code,
      })), x => x.code);
    const b = groupEvents(
      right.forensic.findings.map(f => ({
        eventId: f.eventId ?? "none",
        code: f.code,
      })), x => x.code);
    for (const code of sharedKeys(a, b)) {
      if (code === "MISSING_EVENT_DIGEST" &&
          a.get(code)!.length + b.get(code)!.length > 20)
        continue;
      const negative = ["CHAIN_LINK_MISMATCH", "END_DIGEST_MISMATCH",
        "PROVIDER_ASSERTION_UNSUPPORTED", "EVENT_REUSED"].includes(code);
      out.push(emit({
        kind: "REPEATED_FORENSIC_FINDING", left, right,
        leftEvents: left.timelineEvents.filter(x =>
          a.get(code)!.some(f => f.eventId === x.eventId)).slice(0, 60),
        rightEvents: right.timelineEvents.filter(x =>
          b.get(code)!.some(f => f.eventId === x.eventId)).slice(0, 60),
        sharedKey: code,
        explanation: "Los informes forenses locales contienen la misma " +
          "anomalía " + code + ". Revisar si comparten origen o limitación.",
        priority: negative ? "P1" : "P2",
        strength: negative ? "REQUIRES_REVIEW" : "UNKNOWN",
        provenance: "LOCAL_FORENSIC",
      }));
    }
    if (!left.eventInventoryComplete && !right.eventInventoryComplete) {
      out.push(emit({
        kind: "JOINT_COVERAGE_GAP", left, right,
        leftEvents: [], rightEvents: [], sharedKey: null,
        explanation: "Ambos inventarios son incompletos; no se permite " +
          "concluir que no haya incidentes relacionados.",
        priority: "P1", strength: "UNKNOWN",
        provenance: "LOCAL_FORENSIC",
      }));
    }
    if (left.forensic.integrity === "CONFLICT" &&
        right.forensic.integrity === "CONFLICT") {
      out.push(emit({
        kind: "SOURCE_CONFLICT_CLUSTER", left, right,
        leftEvents: [], rightEvents: [], sharedKey: null,
        explanation: "Los dos informes contienen conflictos internos " +
          "que deben investigarse por separado antes de correlacionar.",
        priority: "P0", strength: "UNKNOWN",
        provenance: "LOCAL_FORENSIC",
      }));
    }
  }
  return out;
}
function statusFor(row: CorrelationCaseInput): CorrelationCaseStatus {
  const revisions = new Set<string>();
  let duplicates = 0;
  for (const event of row.timelineEvents) {
    const key = event.source + "/" + event.sourceId + "/" +
      event.sourceRevision;
    if (revisions.has(key)) duplicates++;
    revisions.add(key);
  }
  return {
    incidentId: row.incidentId, incidentRevision: row.incidentRevision,
    sourceEvents: row.timelineEvents.length,
    retainedEvents: row.timelineEvents.length - duplicates,
    duplicateRevisionCount: duplicates, foreignEventCount: 0,
    sourceFamilies: [...new Set(row.timelineEvents.map(e => e.source))].sort(),
    forensicDigest: row.forensic.digest,
    forensicIntegrity: row.forensic.integrity,
    inventoryComplete: row.eventInventoryComplete,
    lastActivityAt: eventTimeRange(row.timelineEvents).lastAt,
    findingsLinked: 0,
  };
}
export function correlateSelectedIncidents(args: {
  organizationId: string; requestedAt: string;
  cases: CorrelationCaseInput[]; policy?: CorrelationPolicy;
}): CorrelationReport {
  const policy = args.policy ?? defaultCorrelationPolicy();
  validateCorrelationSelection({ ...args, policy });
  const cases = [...args.cases].sort((a, b) =>
    a.incidentId.localeCompare(b.incidentId));
  const all: CorrelationFinding[] = [];
  for (let i = 0; i < cases.length; i++) {
    for (let j = i + 1; j < cases.length; j++) {
      all.push(...pairCorrelations(cases[i]!, cases[j]!, policy));
    }
  }
  all.sort((a, b) => rank(a.priority) - rank(b.priority) ||
    a.leftIncidentId.localeCompare(b.leftIncidentId) ||
    a.rightIncidentId.localeCompare(b.rightIncidentId) ||
    a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id));
  const unique = [...new Map(all.map(f => [f.id, f])).values()];
  const limited = unique.slice(0, policy.maximumResults);
  const statuses = cases.map(statusFor).map(status => ({
    ...status, findingsLinked: limited.filter(x =>
      x.leftIncidentId === status.incidentId ||
      x.rightIncidentId === status.incidentId).length,
  }));
  const warnings = [
    "Los candidatos son correlaciones de datos internos, no compromisos probados",
    "Las coincidencias de actores pueden corresponder al mismo operador",
    "Se requieren revisiones de identidad y evidencia independiente",
    "Nunca se autorizan acciones de proveedor por una correlación",
  ];
  if (statuses.some(x => !x.inventoryComplete))
    warnings.push("Algunos inventarios de origen son incompletos");
  if (limited.length < unique.length)
    warnings.push("Resultados truncados por política de capacidad");
  if (cases.some(x => x.forensic.findingsTruncated))
    warnings.push("Un informe forense de origen truncó sus hallazgos");
  const selectionDigest = correlationDigest(cases.map(x => ({
    incidentId: x.incidentId, incidentRevision: x.incidentRevision,
    forensicDigest: x.forensic.digest,
    events: x.timelineEvents.map(y => [
      y.source, y.sourceId, y.sourceRevision, y.nextDigest,
    ]),
  })));
  const base = {
    schema: "cyberpilot.incident.correlation.report.v1" as const,
    organizationId: args.organizationId, requestedAt: args.requestedAt,
    selectedIncidentIds: cases.map(x => x.incidentId),
    policyDigest: correlationDigest(policy), selectionDigest,
    cases: statuses, findings: limited,
    totalCandidateLinks: unique.length,
    resultsTruncated: limited.length < unique.length,
    completeness: statuses.every(x => x.inventoryComplete) ?
      "PARTIAL" as const : "UNKNOWN" as const,
    weakestEvidenceLevel: limited.some(x => x.strength === "UNKNOWN") ?
      "UNKNOWN" as const : limited.some(x => x.strength === "WEAK") ?
      "WEAK" as const : "REQUIRES_REVIEW" as const,
    warnings, externalActions: 0 as const,
    providerIdentityConfirmed: false as const,
    providerContainmentConfirmed: false as const,
  };
  return { ...base, digest: correlationDigest(base) };
}
export function verifyCorrelationReport(report: CorrelationReport): string[] {
  const errors: string[] = [];
  if (!report ||
      report.schema !== "cyberpilot.incident.correlation.report.v1" ||
      !id(report.organizationId) || !iso(report.requestedAt))
    errors.push("CORRELATION_REPORT_HEADER_INVALID");
  if (!Array.isArray(report?.cases) || !Array.isArray(report?.findings) ||
      !Array.isArray(report?.selectedIncidentIds))
    errors.push("CORRELATION_REPORT_ARRAYS_INVALID");
  else {
    const ids = new Set(report.selectedIncidentIds);
    if (ids.size !== report.selectedIncidentIds.length ||
        report.cases.length !== ids.size ||
        report.cases.some(x => !ids.has(x.incidentId)))
      errors.push("CORRELATION_REPORT_SELECTION_MISMATCH");
    if (report.findings.some(x =>
      !ids.has(x.leftIncidentId) || !ids.has(x.rightIncidentId) ||
      x.leftIncidentId === x.rightIncidentId ||
      x.identityEquivalenceEstablished !== false ||
      x.compromiseEstablished !== false ||
      x.providerOutcomeVerified !== false ||
      x.manualReviewRequired !== true))
      errors.push("CORRELATION_REPORT_FALSE_IDENTITY");
    if (new Set(report.findings.map(x => x.id)).size !==
        report.findings.length)
      errors.push("CORRELATION_REPORT_DUPLICATE_FINDINGS");
  }
  if (report?.externalActions !== 0 ||
      report?.providerIdentityConfirmed !== false ||
      report?.providerContainmentConfirmed !== false)
    errors.push("CORRELATION_REPORT_PROVIDER_FORGERY");
  if (!sha(report?.digest) ||
      report.digest !== correlationDigest({
        ...report, digest: undefined,
      })) errors.push("CORRELATION_REPORT_HASH_INVALID");
  return [...new Set(errors)];
}
export function graphSelectedCorrelations(
  report: CorrelationReport,
): CorrelationGraph {
  if (verifyCorrelationReport(report).length)
    fail("CORRELATION_GRAPH_REPORT_INVALID");
  const linked = new Map<string, CorrelationFinding[]>();
  for (const finding of report.findings) {
    const key = finding.leftIncidentId + "/" + finding.rightIncidentId;
    const bucket = linked.get(key) ?? [];
    bucket.push(finding);
    linked.set(key, bucket);
  }
  const edges: CorrelationGraphEdge[] = [...linked].map(([key, findings]) => {
    const [left, right] = key.split("/");
    return {
      id: "edge:" + correlationDigest(key).slice(0, 32),
      left: left!, right: right!, candidateCount: findings.length,
      kinds: [...new Set(findings.map(x => x.kind))].sort(),
      strongestPriority: findings.reduce(
        (p, x) => higher(p, x.priority), "P3" as CorrelationPriority),
      directProviderProof: false as const,
    };
  }).sort((a, b) => a.left.localeCompare(b.left) ||
    a.right.localeCompare(b.right));
  const adjacency = new Map(report.selectedIncidentIds.map(id =>
    [id, new Set<string>()]));
  for (const edge of edges) {
    adjacency.get(edge.left)!.add(edge.right);
    adjacency.get(edge.right)!.add(edge.left);
  }
  const visited = new Set<string>();
  const components: CorrelationGraph["components"] = [];
  for (const root of report.selectedIncidentIds) {
    if (visited.has(root)) continue;
    const stack = [root];
    const members: string[] = [];
    while (stack.length) {
      const current = stack.pop()!;
      if (visited.has(current)) continue;
      visited.add(current);
      members.push(current);
      for (const neighbor of adjacency.get(current) ?? []) {
        if (!visited.has(neighbor)) stack.push(neighbor);
      }
    }
    members.sort();
    components.push({
      index: components.length, incidentIds: members,
      links: edges.filter(edge =>
        members.includes(edge.left) && members.includes(edge.right)).length,
    });
  }
  const nodes = report.cases.map(c => ({
    incidentId: c.incidentId, eventCount: c.sourceEvents,
    degree: adjacency.get(c.incidentId)!.size,
    connectedComponents: components.filter(x =>
      x.incidentIds.includes(c.incidentId)).map(x => x.index),
    importantFindingCount: report.findings.filter(x =>
      (x.leftIncidentId === c.incidentId ||
       x.rightIncidentId === c.incidentId) &&
      ["P0", "P1"].includes(x.priority)).length,
    hasUnknownCoverage: !c.inventoryComplete,
  }));
  return {
    schema: "cyberpilot.incident.correlation.graph.v1",
    organizationId: report.organizationId,
    reportDigest: report.digest, nodes, edges, components,
    orphanIncidentIds: nodes.filter(n => n.degree === 0)
      .map(n => n.incidentId),
    provenSharedCompromises: 0,
  };
}
export function prepareCorrelationReviews(report: CorrelationReport) {
  if (verifyCorrelationReport(report).length)
    fail("CORRELATION_REVIEW_REPORT_INVALID");
  return report.findings.map((finding): CorrelationReviewRequest => {
    const role: CorrelationReviewRequest["suggestedReviewerRole"] =
      finding.priority === "P0" ? "OWNER" :
      finding.kind === "REPEATED_FORENSIC_FINDING" ? "AUDITOR" : "ADMIN";
    const requiredChecks = [
      "Confirmar explícitamente el ámbito de ambas organizaciones y casos",
      "Contrastar el origen y la integridad de los dos historiales",
      "Documentar explicaciones alternativas de la coincidencia",
      "No declarar compromiso sin telemetría de fuente independiente",
    ];
    if (finding.kind === "SHARED_ACTOR")
      requiredChecks.push(
        "Distinguir la identidad del operador de la identidad de una víctima");
    if (finding.kind === "COMMON_SOURCE_KEY")
      requiredChecks.push(
        "Comprobar unicidad y ámbito de la clave en el proveedor original");
    if (finding.strength === "UNKNOWN")
      requiredChecks.push(
        "Resolver datos ausentes antes de atribuir una campaña común");
    return {
      id: "review:" + correlationDigest(finding.id).slice(0, 36),
      findingId: finding.id, organizationId: report.organizationId,
      incidentIds: [finding.leftIncidentId, finding.rightIncidentId],
      kind: finding.kind, priority: finding.priority,
      suggestedReviewerRole: role,
      question: "¿Qué prueba permite confirmar o descartar " +
        "esta coincidencia entre los casos seleccionados?",
      requiredChecks, status: "OPEN_INTERNAL",
      externalActionAuthorized: false, identityMatchConfirmed: false,
    };
  });
}
function csvEscape(value: string) {
  const safe = /^[\s]*[=+@-]/.test(value) ||
    /^[\s]*[\t\r]/.test(value) ? "'" + value : value;
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function exportCorrelationCSV(report: CorrelationReport): string {
  if (verifyCorrelationReport(report).length)
    fail("CORRELATION_EXPORT_INVALID");
  const head = [
    "findingId", "kind", "priority", "strength", "firstIncident",
    "secondIncident", "firstEventCount", "secondEventCount", "explanation",
    "identityProven", "externalActions",
  ];
  const body = report.findings.map(x => [
    x.id, x.kind, x.priority, x.strength, x.leftIncidentId,
    x.rightIncidentId, String(x.evidence[0].eventCount),
    String(x.evidence[1].eventCount), x.explanation, "false", "0",
  ].map(csvEscape).join(","));
  return [head.join(","), ...body].join("\r\n") + "\r\n";
}
export function exportCorrelationJSON(report: CorrelationReport) {
  if (verifyCorrelationReport(report).length)
    fail("CORRELATION_EXPORT_INVALID");
  return JSON.stringify(report, null, 2);
}
export function compareCorrelationReports(
  previous: CorrelationReport, current: CorrelationReport,
) {
  if (verifyCorrelationReport(previous).length ||
      verifyCorrelationReport(current).length)
    fail("CORRELATION_COMPARE_INVALID");
  if (previous.organizationId !== current.organizationId ||
      previous.selectedIncidentIds.join("\0") !==
      current.selectedIncidentIds.join("\0"))
    fail("CORRELATION_COMPARE_SELECTION_CHANGED");
  const old = new Set(previous.findings.map(x => x.id));
  const now = new Set(current.findings.map(x => x.id));
  return {
    schema: "cyberpilot.incident.correlation.diff.v1" as const,
    organizationId: current.organizationId,
    priorDigest: previous.digest, currentDigest: current.digest,
    newCandidates: current.findings.filter(x => !old.has(x.id)),
    noLongerMatched: previous.findings.filter(x => !now.has(x.id)),
    sourceChanged: previous.selectionDigest !== current.selectionDigest,
    identityVerified: false as const,
    reductionDoesNotProveContainment: true as const,
  };
}
export function summarizeCorrelationByKind(report: CorrelationReport) {
  if (verifyCorrelationReport(report).length)
    fail("CORRELATION_SUMMARY_INVALID");
  return kinds.map(kind => {
    const findings = report.findings.filter(x => x.kind === kind);
    return {
      kind, links: findings.length,
      incidentPairs: new Set(findings.map(x =>
        x.leftIncidentId + "/" + x.rightIncidentId)).size,
      priorities: Object.fromEntries(priorities.map(p => [
        p, findings.filter(f => f.priority === p).length,
      ])) as Record<CorrelationPriority, number>,
      reviewRequired: findings.length,
      independentlyConfirmed: 0,
    };
  });
}
