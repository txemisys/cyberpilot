import {
  type TimelineEvent, type TimelineSource, type TimelineIntegrity,
} from "./incident-operational-timeline-domain";
import {
  type ForensicCaseReport, type ForensicFinding,
  forensicDigest,
} from "./incident-timeline-forensics-domain";

/**
 * Deterministic incident investigation guide assembled solely from local
 * timeline events and forensic findings. It never schedules a live action.
 */
export type InvestigationPriority = "P0" | "P1" | "P2" | "P3";
export type InvestigationWorkstream =
  "LEDGER_INTEGRITY" | "PROVENANCE" | "RESPONSE_COORDINATION" |
  "TABLETOP_VALIDATION" | "ASSURANCE_FOLLOWUP" | "COVERAGE";
export type InvestigationEvidenceKind =
  "AUDIT_EVENT" | "SNAPSHOT" | "SOURCE_CHAIN" | "OPERATOR_CONFIRMATION" |
  "PROVIDER_RECEIPT" | "ACCESS_REVIEW" | "COMPLETENESS_REVIEW";
export type InvestigationStatus =
  "REQUIRES_REVIEW" | "WAITING_FOR_EVIDENCE" | "BLOCKED" |
  "ACKNOWLEDGED_INTERNAL";
export type InvestigationSignal = {
  id: string;
  priority: InvestigationPriority;
  workstream: InvestigationWorkstream;
  source: TimelineSource | null;
  sourceId: string | null;
  eventId: string | null;
  findingCode: string;
  observedAt: string | null;
  summary: string;
  limitations: string[];
};
export type InvestigationEvidenceRequest = {
  id: string;
  signalId: string;
  kind: InvestigationEvidenceKind;
  source: TimelineSource | null;
  sourceId: string | null;
  requiredFromRole: "OWNER" | "ADMIN" | "AUDITOR";
  question: string;
  acceptanceCriteria: string[];
  cannotBeReplacedBy: string[];
  collected: false;
};
export type InvestigationTask = {
  id: string;
  signalIds: string[];
  priority: InvestigationPriority;
  workstream: InvestigationWorkstream;
  status: InvestigationStatus;
  assignedRole: "OWNER" | "ADMIN" | "AUDITOR";
  description: string;
  evidenceRequestIds: string[];
  manualOnly: true;
  ownerUserId: null;
  providerWriteAuthorized: false;
  proofOfContainment: false;
};
export type InvestigationCasebook = {
  schema: "cyberpilot.incident.timeline.investigation.v1";
  organizationId: string;
  incidentId: string;
  generatedAt: string;
  sourceReportDigest: string;
  inventoryComplete: boolean;
  signals: InvestigationSignal[];
  requests: InvestigationEvidenceRequest[];
  tasks: InvestigationTask[];
  priorityCounts: Record<InvestigationPriority, number>;
  workstreamCounts: Record<InvestigationWorkstream, number>;
  limitations: string[];
  completeness: "UNKNOWN" | "PARTIAL";
  externalWrites: 0;
  providerOutcomesVerified: false;
  digest: string;
};
export type InvestigationPolicy = {
  requireSeparateApproval: boolean;
  includeTrainingHistory: boolean;
  includeInternalAssurance: boolean;
  requireProviderReceiptsForExternalClaims: boolean;
  maximumSignals: number;
  maximumTasks: number;
  maximumRequests: number;
  includeLowPriority: boolean;
};
const defaults: InvestigationPolicy = {
  requireSeparateApproval: true, includeTrainingHistory: true,
  includeInternalAssurance: true,
  requireProviderReceiptsForExternalClaims: true,
  maximumSignals: 500, maximumTasks: 250,
  maximumRequests: 750, includeLowPriority: true,
};
const priorities: InvestigationPriority[] = ["P0", "P1", "P2", "P3"];
const workstreams: InvestigationWorkstream[] = [
  "LEDGER_INTEGRITY", "PROVENANCE", "RESPONSE_COORDINATION",
  "TABLETOP_VALIDATION", "ASSURANCE_FOLLOWUP", "COVERAGE",
];
const ident = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const iso = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
function reject(code: string): never { throw Error(code); }
function stableId(type: string, details: unknown) {
  return type + ":" + forensicDigest(details).slice(0, 36);
}
function priorityWeight(p: InvestigationPriority) {
  return priorities.indexOf(p);
}
function choice(
  current: InvestigationPriority, next: InvestigationPriority,
): InvestigationPriority {
  return priorityWeight(current) <= priorityWeight(next) ? current : next;
}
export function validateInvestigationPolicy(
  candidate: Partial<InvestigationPolicy> = {},
): InvestigationPolicy {
  if (!candidate || typeof candidate !== "object" ||
      Array.isArray(candidate))
    reject("INVESTIGATION_POLICY_INVALID");
  if (Object.keys(candidate).some(k => !(k in defaults)))
    reject("INVESTIGATION_POLICY_FIELD_UNKNOWN");
  const policy = { ...defaults, ...candidate };
  const limits = [
    policy.maximumSignals, policy.maximumTasks, policy.maximumRequests,
  ];
  if (limits.some(x => !Number.isSafeInteger(x) || x < 1 || x > 5000))
    reject("INVESTIGATION_POLICY_LIMIT_INVALID");
  const bools = [
    policy.requireSeparateApproval, policy.includeTrainingHistory,
    policy.includeInternalAssurance,
    policy.requireProviderReceiptsForExternalClaims,
    policy.includeLowPriority,
  ];
  if (bools.some(x => typeof x !== "boolean"))
    reject("INVESTIGATION_POLICY_FLAGS_INVALID");
  if (!policy.requireProviderReceiptsForExternalClaims ||
      !policy.requireSeparateApproval)
    reject("INVESTIGATION_POLICY_UNSAFE");
  return policy;
}
function workstreamForFinding(f: ForensicFinding): InvestigationWorkstream {
  if (f.code === "MISSING_SOURCE" ||
      f.code === "LEDGER_INVENTORY_TRUNCATED") return "COVERAGE";
  if (f.code === "PROVIDER_ASSERTION_UNSUPPORTED") return "PROVENANCE";
  if (f.code === "MISSING_EVENT_DIGEST" ||
      f.code === "ROOT_LINK_UNEXPECTED") return "PROVENANCE";
  if (f.source === "TABLETOP_SESSION") return "TABLETOP_VALIDATION";
  if (f.source === "ASSURANCE_HANDOFF") return "ASSURANCE_FOLLOWUP";
  return "LEDGER_INTEGRITY";
}
function priorityForFinding(f: ForensicFinding): InvestigationPriority {
  if (f.code === "SCOPE_MISMATCH" ||
      f.code === "PROVIDER_ASSERTION_UNSUPPORTED" ||
      f.code === "CHAIN_LINK_MISMATCH" ||
      f.code === "END_DIGEST_MISMATCH") return "P0";
  if (f.severity === "CONFLICT" ||
      f.code === "SNAPSHOT_REVISION_MISMATCH") return "P1";
  if (f.code === "MISSING_EVENT_DIGEST" ||
      f.code === "SOURCE_TIMESTAMP_IN_FUTURE") return "P2";
  return f.severity === "UNKNOWN" ? "P2" : "P3";
}
function summarizeFinding(f: ForensicFinding): string {
  const descriptions: Record<string, string> = {
    SCOPE_MISMATCH: "La procedencia del evento no coincide con el incidente",
    ENTRY_INVALID: "Un evento no satisface el contrato estructural",
    EVENT_REUSED: "Un identificador de evento aparece repetido",
    REVISION_DUPLICATE: "Hay dos registros para una misma revisión",
    REVISION_GAP: "Faltan revisiones intermedias de la fuente",
    FIRST_REVISION_MISSING: "No consta el inicio del historial",
    EVENT_TIME_REGRESSION: "El reloj de origen retrocede en el historial",
    CHAIN_LINK_MISMATCH: "Se interrumpe la cadena de digests",
    ROOT_LINK_UNEXPECTED: "El primer evento presenta digest previo",
    MISSING_EVENT_DIGEST: "Falta un digest independiente del evento",
    MISSING_SOURCE: "No se encontró la fuente esperada",
    LEDGER_INVENTORY_TRUNCATED: "La consulta no cubre el inventario completo",
    SNAPSHOT_REVISION_MISMATCH: "El snapshot y los eventos discrepan",
    END_DIGEST_MISMATCH: "El digest de snapshot no coincide con el historial",
    SOURCE_TIMESTAMP_IN_FUTURE: "La fecha del evento supera el reloj de análisis",
    PROVIDER_ASSERTION_UNSUPPORTED: "Una afirmación externa carece de recibo",
  };
  return descriptions[f.code] ?? "Hallazgo pendiente de investigación";
}
function actorRoleForStream(
  stream: InvestigationWorkstream,
): "OWNER" | "ADMIN" | "AUDITOR" {
  if (stream === "LEDGER_INTEGRITY" || stream === "PROVENANCE")
    return "AUDITOR";
  if (stream === "COVERAGE" || stream === "RESPONSE_COORDINATION")
    return "OWNER";
  return "ADMIN";
}
function requestKindForFinding(
  finding: ForensicFinding,
): InvestigationEvidenceKind {
  if (finding.code === "PROVIDER_ASSERTION_UNSUPPORTED")
    return "PROVIDER_RECEIPT";
  if (finding.code === "MISSING_SOURCE" ||
      finding.code === "LEDGER_INVENTORY_TRUNCATED")
    return "COMPLETENESS_REVIEW";
  if (finding.code === "ENTRY_INVALID" ||
      finding.code === "EVENT_REUSED")
    return "AUDIT_EVENT";
  if (finding.code === "END_DIGEST_MISMATCH" ||
      finding.code === "SNAPSHOT_REVISION_MISMATCH")
    return "SNAPSHOT";
  if (finding.code === "SOURCE_TIMESTAMP_IN_FUTURE")
    return "OPERATOR_CONFIRMATION";
  return "SOURCE_CHAIN";
}
function criteriaFor(
  kind: InvestigationEvidenceKind, f: ForensicFinding,
): string[] {
  const base = [
    "La prueba identifica organización, incidente, fuente y revisión",
    "El registro incluye fecha, procedencia y responsable verificable",
    "Las discrepancias permanecen abiertas hasta una nueva reconciliación",
  ];
  if (kind === "PROVIDER_RECEIPT") {
    return [...base,
      "Un recibo independiente identifica el proveedor y la operación",
      "El recibo vincula destino, operación, resultado y momento exacto",
      "La autorización externa se verifica en el sistema ejecutor"];
  }
  if (kind === "SOURCE_CHAIN") {
    return [...base,
      "Las revisiones forman una secuencia completa e inequívoca",
      "Cada digest previo coincide con el snapshot precedente",
      "El origen de los digests está documentado"];
  }
  if (kind === "SNAPSHOT") {
    return [...base,
      "El snapshot presenta revisión y digest correspondiente",
      "La historia persistida reproduce la revisión final"];
  }
  if (kind === "AUDIT_EVENT") {
    return [...base,
      "Los identificadores son únicos por ámbito de la fuente",
      "La operación y el actor se pueden contrastar con la auditoría"];
  }
  if (kind === "COMPLETENESS_REVIEW") {
    return [...base,
      "Los límites y la paginación se han comprobado",
      "Se identifican las fuentes ausentes y las excluidas"];
  }
  return [...base, "La explicación del operador está fechada y auditada",
    "La revisión humana no se transforma en resultado externo",
    "El hallazgo " + f.code + " queda explícitamente referenciado"];
}
function makeSignal(
  finding: ForensicFinding, ordinal: number,
): InvestigationSignal {
  const workstream = workstreamForFinding(finding);
  const priority = priorityForFinding(finding);
  const id = stableId("signal", { finding, ordinal });
  const limitations = [
    "El estado descrito corresponde al historial interno del producto",
    "La ausencia de registros no demuestra ausencia de incidente",
  ];
  if (finding.code === "MISSING_EVENT_DIGEST")
    limitations.push("No se ha reejecutado ni autenticado la fuente original");
  if (finding.code === "PROVIDER_ASSERTION_UNSUPPORTED")
    limitations.push("No autoriza revocar, aislar, borrar ni bloquear");
  return {
    id, priority, workstream, source: finding.source,
    sourceId: finding.sourceId, eventId: finding.eventId,
    findingCode: finding.code, observedAt: null,
    summary: summarizeFinding(finding),
    limitations,
  };
}
function requestFromSignal(
  signal: InvestigationSignal, finding: ForensicFinding,
): InvestigationEvidenceRequest {
  const kind = requestKindForFinding(finding);
  const requiredFromRole = actorRoleForStream(signal.workstream);
  return {
    id: stableId("request", { signal: signal.id, kind }),
    signalId: signal.id, kind, source: signal.source, sourceId: signal.sourceId,
    requiredFromRole, question: signal.summary +
      ". ¿Qué fuente verificable permite resolver esta discrepancia?",
    acceptanceCriteria: criteriaFor(kind, finding),
    cannotBeReplacedBy: [
      "Un estado de UI sin procedencia",
      "Una ejecución simulada de tabletop",
      "La aprobación del mismo solicitante",
      "Una afirmación de éxito sin recibo del proveedor",
    ],
    collected: false,
  };
}
function clusterSignals(signals: InvestigationSignal[]) {
  const clusters = new Map<string, InvestigationSignal[]>();
  for (const signal of signals) {
    const key = [signal.workstream, signal.source,
      signal.sourceId ?? "none"].join("/");
    const members = clusters.get(key) ?? [];
    members.push(signal);
    clusters.set(key, members);
  }
  return clusters;
}
function buildTask(
  key: string, signals: InvestigationSignal[],
  requests: InvestigationEvidenceRequest[],
): InvestigationTask {
  const stream = signals[0]!.workstream;
  const priority = signals.reduce(
    (p, signal) => choice(p, signal.priority), "P3" as InvestigationPriority);
  const assignedRole = actorRoleForStream(stream);
  const evidenceRequestIds = requests.filter(r =>
    signals.some(s => s.id === r.signalId)).map(r => r.id).sort();
  return {
    id: stableId("task", { key, signals: signals.map(x => x.id).sort() }),
    signalIds: signals.map(x => x.id).sort(),
    priority, workstream: stream,
    status: stream === "COVERAGE" ? "BLOCKED" : "WAITING_FOR_EVIDENCE",
    assignedRole,
    description: signals.length + " hallazgo(s) internos requieren " +
      "revisión de " + stream,
    evidenceRequestIds, manualOnly: true, ownerUserId: null,
    providerWriteAuthorized: false, proofOfContainment: false,
  };
}
export function buildInvestigationCasebook(args: {
  organizationId: string; incidentId: string; generatedAt: string;
  report: ForensicCaseReport; events: TimelineEvent[];
  policy?: Partial<InvestigationPolicy>;
}): InvestigationCasebook {
  if (!args || !ident(args.organizationId) ||
      !ident(args.incidentId) || !iso(args.generatedAt))
    reject("INVESTIGATION_CONTEXT_INVALID");
  const policy = validateInvestigationPolicy(args.policy ?? {});
  if (args.report.organizationId !== args.organizationId ||
      args.report.incidentId !== args.incidentId ||
      !Array.isArray(args.events) || args.events.length > 25000 ||
      args.events.some(e => e.organizationId !== args.organizationId ||
        e.incidentId !== args.incidentId))
    reject("INVESTIGATION_SCOPE_MISMATCH");
  if (args.report.externalActions !== 0 ||
      args.report.independentProviderProof !== false)
    reject("INVESTIGATION_FORGED_PROVIDER_RESULT");
  const findings = [...args.report.findings];
  if (args.report.findingsTruncated) {
    findings.push({
      code: "LEDGER_INVENTORY_TRUNCATED", severity: "UNKNOWN",
      source: null, sourceId: null, eventId: null, revision: null,
      explanation: "Forensic findings were limited by display cap",
    });
  }
  if (!policy.includeTrainingHistory) {
    for (let i = findings.length - 1; i >= 0; i--) {
      if (findings[i]?.source === "TABLETOP_SESSION") findings.splice(i, 1);
    }
  }
  if (!policy.includeInternalAssurance) {
    for (let i = findings.length - 1; i >= 0; i--) {
      if (findings[i]?.source === "ASSURANCE_HANDOFF") findings.splice(i, 1);
    }
  }
  const signals = findings.map((f, i) => makeSignal(f, i))
    .filter(x => policy.includeLowPriority || x.priority !== "P3")
    .sort((a, b) => priorityWeight(a.priority) -
      priorityWeight(b.priority) || a.id.localeCompare(b.id));
  if (signals.length > policy.maximumSignals)
    reject("INVESTIGATION_SIGNALS_EXCEED_POLICY");
  const findingMap = new Map(signals.map(s => {
    const idx = findings.findIndex((f, i) => stableId("signal", {
      finding: f, ordinal: i,
    }) === s.id);
    return [s.id, findings[idx]!] as const;
  }));
  const requests = signals.map(s =>
    requestFromSignal(s, findingMap.get(s.id)!));
  if (requests.length > policy.maximumRequests)
    reject("INVESTIGATION_REQUESTS_EXCEED_POLICY");
  const tasks = [...clusterSignals(signals)]
    .map(([key, members]) => buildTask(key, members, requests))
    .sort((a, b) => priorityWeight(a.priority) -
      priorityWeight(b.priority) || a.id.localeCompare(b.id));
  if (tasks.length > policy.maximumTasks)
    reject("INVESTIGATION_TASKS_EXCEED_POLICY");
  const priorityCounts = Object.fromEntries(priorities.map(p => [
    p, signals.filter(x => x.priority === p).length,
  ])) as Record<InvestigationPriority, number>;
  const workstreamCounts = Object.fromEntries(workstreams.map(w => [
    w, signals.filter(x => x.workstream === w).length,
  ])) as Record<InvestigationWorkstream, number>;
  const limitations = [
    "Los hallazgos reflejan únicamente eventos internos persistidos",
    "Una prueba tabletop no acredita contención en un sistema externo",
    "Los responsables son sugerencias de rol, no asignaciones persistidas",
    "La recopilación no autoriza operaciones destructivas ni proveedor LIVE",
  ];
  if (!args.report.inventoryComplete)
    limitations.push("El inventario de eventos sigue siendo incompleto");
  if (args.report.findingsTruncated)
    limitations.push("Los hallazgos de origen están truncados");
  const base = {
    schema: "cyberpilot.incident.timeline.investigation.v1" as const,
    organizationId: args.organizationId, incidentId: args.incidentId,
    generatedAt: args.generatedAt,
    sourceReportDigest: args.report.digest,
    inventoryComplete: args.report.inventoryComplete,
    signals, requests, tasks, priorityCounts, workstreamCounts, limitations,
    completeness: "PARTIAL" as const,
    externalWrites: 0 as const, providerOutcomesVerified: false as const,
  };
  return { ...base, digest: forensicDigest(base) };
}
export function verifyInvestigationCasebook(value: InvestigationCasebook) {
  const errors: string[] = [];
  if (value?.schema !== "cyberpilot.incident.timeline.investigation.v1" ||
      !ident(value.organizationId) || !ident(value.incidentId) ||
      !iso(value.generatedAt)) errors.push("CASEBOOK_HEADER_INVALID");
  if (value?.externalWrites !== 0 ||
      value?.providerOutcomesVerified !== false)
    errors.push("CASEBOOK_PROVIDER_CLAIM_INVALID");
  if (!value || value.digest !== forensicDigest({
    ...value, digest: undefined,
  })) errors.push("CASEBOOK_DIGEST_MISMATCH");
  if (!Array.isArray(value?.signals) ||
      !Array.isArray(value?.requests) ||
      !Array.isArray(value?.tasks)) errors.push("CASEBOOK_ARRAYS_INVALID");
  else {
    const signals = new Set(value.signals.map(x => x.id));
    const requests = new Set(value.requests.map(x => x.id));
    if (signals.size !== value.signals.length ||
        requests.size !== value.requests.length ||
        new Set(value.tasks.map(x => x.id)).size !== value.tasks.length)
      errors.push("CASEBOOK_DUPLICATE_IDENTIFIERS");
    if (value.requests.some(r => !signals.has(r.signalId) ||
        r.collected !== false))
      errors.push("CASEBOOK_REQUEST_ORPHANED");
    if (value.tasks.some(t => t.signalIds.some(id => !signals.has(id)) ||
        t.evidenceRequestIds.some(id => !requests.has(id)) ||
        t.providerWriteAuthorized !== false ||
        t.proofOfContainment !== false || t.manualOnly !== true))
      errors.push("CASEBOOK_TASK_UNSAFE");
  }
  return [...new Set(errors)];
}
export function compareInvestigationCasebooks(
  before: InvestigationCasebook, after: InvestigationCasebook,
) {
  if (verifyInvestigationCasebook(before).length ||
      verifyInvestigationCasebook(after).length)
    reject("CASEBOOK_COMPARE_INVALID");
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId)
    reject("CASEBOOK_COMPARE_SCOPE_MISMATCH");
  const oldSignals = new Set(before.signals.map(s => s.id));
  const newSignals = new Set(after.signals.map(s => s.id));
  const added = after.signals.filter(s => !oldSignals.has(s.id));
  const absent = before.signals.filter(s => !newSignals.has(s.id));
  return {
    schema: "cyberpilot.incident.timeline.investigation-diff.v1" as const,
    organizationId: after.organizationId, incidentId: after.incidentId,
    previousDigest: before.digest, currentDigest: after.digest,
    added, noLongerPresent: absent,
    note: "El hallazgo desaparecido puede deberse a filtros o inventario; " +
      "no acredita que se haya corregido una amenaza",
    independentProviderVerification: false as const,
  };
}
export function investigationTaskQueue(
  value: InvestigationCasebook,
  role?: "OWNER" | "ADMIN" | "AUDITOR",
) {
  const errors = verifyInvestigationCasebook(value);
  if (errors.length) reject("CASEBOOK_QUEUE_INVALID");
  return value.tasks.filter(x => !role || x.assignedRole === role)
    .sort((a, b) => priorityWeight(a.priority) -
      priorityWeight(b.priority) ||
      b.evidenceRequestIds.length - a.evidenceRequestIds.length ||
      a.id.localeCompare(b.id));
}
export function exportInvestigationCasebookJSON(value: InvestigationCasebook) {
  if (verifyInvestigationCasebook(value).length)
    reject("CASEBOOK_EXPORT_INVALID");
  return JSON.stringify(value, null, 2);
}
function csvSafe(input: string): string {
  const safe = /^[\s]*[=+@-]/.test(input) ||
    /^[\s]*[\t\r]/.test(input) ? "'" + input : input;
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function exportInvestigationTaskCSV(value: InvestigationCasebook) {
  if (verifyInvestigationCasebook(value).length)
    reject("CASEBOOK_EXPORT_INVALID");
  const headers = [
    "taskId", "priority", "workstream", "role", "status",
    "description", "signals", "requests", "externalActions",
  ];
  return [headers.join(","), ...value.tasks.map(t => [
    t.id, t.priority, t.workstream, t.assignedRole, t.status,
    t.description, t.signalIds.join(";"), t.evidenceRequestIds.join(";"), "0",
  ].map(csvSafe).join(","))].join("\r\n") + "\r\n";
}
