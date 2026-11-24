import { createHash } from "node:crypto";
import type {
  TimelineEvent, TimelineSource, TimelineIntegrity,
} from "./incident-operational-timeline-domain";
import type { ForensicCaseReport } from "./incident-timeline-forensics-domain";
import type {
  InvestigationCasebook, InvestigationPriority, InvestigationTask,
} from "./incident-timeline-investigation-domain";

/**
 * Read-only incident shift handoff. It explains pending internal work and
 * source uncertainty; it does not acknowledge receipt on anyone's behalf.
 */
export type ShiftUrgency = "IMMEDIATE" | "BEFORE_END" | "NEXT_SHIFT" |
  "MONITOR";
export type ShiftProofClass =
  "LOCAL_LEDGER" | "FORENSIC_FINDING" | "OPERATOR_REVIEW" |
  "PROVIDER_INDEPENDENT";
export type ShiftActionClass =
  "VERIFY_SOURCE_CHAIN" | "REQUEST_MISSING_EVIDENCE" |
  "REVIEW_PRIVILEGED_ACCESS" | "ASSESS_SCOPE" |
  "VERIFY_APPROVAL_SEPARATION" | "DOCUMENT_OPERATOR_HANDOFF" |
  "RECHECK_SLA" | "VALIDATE_PROVIDER_RECEIPT" |
  "RECONCILE_TIMELINE" | "REVIEW_UNKNOWN_COVERAGE";
export type ShiftWorkItem = {
  id: string;
  incidentId: string;
  urgency: ShiftUrgency;
  priority: InvestigationPriority;
  category: ShiftActionClass;
  source: TimelineSource | null;
  sourceId: string | null;
  assignedRole: "OWNER" | "ADMIN" | "AUDITOR";
  assignedUserId: null;
  explanation: string;
  dueAt: string;
  evidenceReferences: string[];
  evidenceNeeded: string[];
  underlyingTaskIds: string[];
  internalStatus: "PROPOSED";
  providerWritePermitted: false;
  externallyVerified: false;
};
export type ShiftActivity = {
  id: string;
  source: TimelineSource;
  sourceId: string;
  revision: number;
  eventId: string;
  operation: string;
  actorUserId: string;
  at: string;
  integrity: TimelineIntegrity;
  belongsToWindow: boolean;
  providerReceiptAvailable: false;
};
export type ShiftSourceInventory = {
  source: TimelineSource;
  ledgerCount: number;
  eventCount: number;
  inWindow: number;
  latestAt: string | null;
  staleMinutes: number | null;
  completeness: "UNKNOWN" | "LOCAL_ONLY";
  independentlyVerified: false;
};
export type ShiftWatchpoint = {
  id: string;
  category: "FRESHNESS" | "INTEGRITY" | "COVERAGE" |
    "UNREVIEWED_WORK" | "UPCOMING_DEADLINE" | "TIMING" |
    "PRIVILEGE_BOUNDARY";
  priority: InvestigationPriority;
  source: TimelineSource | null;
  trigger: string;
  explanation: string;
  recommendedRole: "OWNER" | "ADMIN" | "AUDITOR";
  requiresIndependentConfirmation: boolean;
};
export type ShiftPolicy = {
  schema: "cyberpilot.incident.shift.policy.v1";
  id: string;
  maximumActivities: number;
  maximumWorkItems: number;
  maximumWatchpoints: number;
  maxSourceStalenessMinutes: number;
  highPriorityDueMinutes: number;
  normalPriorityDueMinutes: number;
  monitorDueMinutes: number;
  sourceWindowMinutes: number;
  preserveUnknownCoverage: true;
  allowOfflineHandoffs: true;
  allowExternalActions: false;
  requireIndependentProviderProof: true;
};
export type ShiftWindow = {
  shiftId: string;
  startsAt: string;
  endsAt: string;
  evaluatedAt: string;
  outgoingRole: "OWNER" | "ADMIN" | "AUDITOR";
  incomingRole: "OWNER" | "ADMIN" | "AUDITOR";
  outgoingUserId: string | null;
  incomingUserId: string | null;
  acknowledgedBy: null;
  acceptedAt: null;
};
export type ShiftBriefing = {
  schema: "cyberpilot.incident.shift.briefing.v1";
  organizationId: string;
  incidentId: string;
  incidentRevision: number;
  window: ShiftWindow;
  policyDigest: string;
  forensicDigest: string;
  investigationDigest: string;
  activity: ShiftActivity[];
  sourceInventory: ShiftSourceInventory[];
  workItems: ShiftWorkItem[];
  watchpoints: ShiftWatchpoint[];
  workTruncated: boolean;
  activityTruncated: boolean;
  watchpointsTruncated: boolean;
  sourceEvents: number;
  openEvidenceRequests: number;
  priorityCounts: Record<InvestigationPriority, number>;
  completeness: "UNKNOWN" | "PARTIAL";
  operationalConfidence: "INSUFFICIENT" | "LOCAL_ONLY";
  limitations: string[];
  digest: string;
  receiptIssued: false;
  handoffAcknowledged: false;
  externalActions: 0;
  providerOutcomesIndependentlyVerified: false;
};
export type ShiftAcceptancePreview = {
  schema: "cyberpilot.incident.shift.acceptance-preview.v1";
  organizationId: string;
  incidentId: string;
  shiftId: string;
  expectedBriefingDigest: string;
  actorId: string;
  actorRole: "OWNER" | "ADMIN" | "AUDITOR";
  action: "REVIEW_PREVIEW" | "REQUEST_RECONCILIATION";
  checkedAt: string;
  requiredSourceChecks: string[];
  concerns: string[];
  canAcknowledgeAfterPersistence: boolean;
  locallyRecorded: false;
  providerActionsAuthorized: false;
  digest: string;
};
export type ShiftTransitionDelta = {
  schema: "cyberpilot.incident.shift.delta.v1";
  organizationId: string;
  incidentId: string;
  earlierDigest: string;
  laterDigest: string;
  newEvents: ShiftActivity[];
  disappearedEvents: ShiftActivity[];
  newWorkItems: ShiftWorkItem[];
  missingWorkItems: ShiftWorkItem[];
  sourceRegressions: string[];
  acknowledgementProven: false;
  mitigationProven: false;
};
const sourceNames: TimelineSource[] = [
  "INCIDENT", "SITUATION_REVIEW", "TABLETOP_SESSION", "ASSURANCE_HANDOFF",
];
const priorityNames: InvestigationPriority[] = ["P0", "P1", "P2", "P3"];
const roles = ["OWNER", "ADMIN", "AUDITOR"] as const;
const id = (x: unknown): x is string =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const sha = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const iso = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const fail = (code: string): never => { throw Error(code); };
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const r = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(r).sort()
      .filter(k => r[k] !== undefined)
      .map(k => [k, canonical(r[k])]));
  }
  return value;
}
export function shiftDigest(value: unknown) {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value))).digest("hex");
}
const plus = (at: string, minutes: number) =>
  new Date(Date.parse(at) + minutes * 60000).toISOString();
const minutesBetween = (later: string, earlier: string) =>
  Math.max(0, Math.floor((Date.parse(later) -
    Date.parse(earlier)) / 60000));
const rank = (priority: InvestigationPriority) =>
  priorityNames.indexOf(priority);
const urgent = (priority: InvestigationPriority): ShiftUrgency =>
  priority === "P0" ? "IMMEDIATE" :
  priority === "P1" ? "BEFORE_END" :
  priority === "P2" ? "NEXT_SHIFT" : "MONITOR";
function byPriority<A extends { priority: InvestigationPriority; id: string }>(
  a: A, b: A,
) {
  return rank(a.priority) - rank(b.priority) ||
    a.id.localeCompare(b.id);
}
export function defaultShiftPolicy(): ShiftPolicy {
  return {
    schema: "cyberpilot.incident.shift.policy.v1",
    id: "incident-shift-default-v1",
    maximumActivities: 400, maximumWorkItems: 300,
    maximumWatchpoints: 200,
    maxSourceStalenessMinutes: 1440,
    highPriorityDueMinutes: 60, normalPriorityDueMinutes: 480,
    monitorDueMinutes: 1440,
    sourceWindowMinutes: 10080,
    preserveUnknownCoverage: true, allowOfflineHandoffs: true,
    allowExternalActions: false, requireIndependentProviderProof: true,
  };
}
export function validateShiftPolicy(policy: ShiftPolicy): string[] {
  const problems: string[] = [];
  if (!policy || policy.schema !== "cyberpilot.incident.shift.policy.v1" ||
      !id(policy.id)) problems.push("SHIFT_POLICY_HEADER_INVALID");
  const fields: Array<[number, number, number]> = [
    [policy?.maximumActivities, 1, 2000],
    [policy?.maximumWorkItems, 1, 1500],
    [policy?.maximumWatchpoints, 1, 1500],
    [policy?.maxSourceStalenessMinutes, 1, 525600],
    [policy?.highPriorityDueMinutes, 1, 525600],
    [policy?.normalPriorityDueMinutes, 1, 525600],
    [policy?.monitorDueMinutes, 1, 525600],
    [policy?.sourceWindowMinutes, 1, 525600],
  ];
  if (fields.some(([v, min, max]) =>
      !Number.isSafeInteger(v) || v < min || v > max))
    problems.push("SHIFT_POLICY_BOUNDS_INVALID");
  if (policy?.preserveUnknownCoverage !== true ||
      policy?.allowOfflineHandoffs !== true ||
      policy?.allowExternalActions !== false ||
      policy?.requireIndependentProviderProof !== true)
    problems.push("SHIFT_POLICY_PROVIDER_WRITE_FORBIDDEN");
  return problems;
}
export function validateShiftWindow(window: ShiftWindow): string[] {
  const problems: string[] = [];
  if (!window || !id(window.shiftId) ||
      !iso(window.startsAt) || !iso(window.endsAt) ||
      !iso(window.evaluatedAt))
    problems.push("SHIFT_WINDOW_INVALID");
  if (iso(window?.startsAt) && iso(window?.endsAt) &&
      (window.endsAt <= window.startsAt ||
       minutesBetween(window.endsAt, window.startsAt) > 10080))
    problems.push("SHIFT_WINDOW_RANGE_INVALID");
  if (iso(window?.endsAt) && iso(window?.evaluatedAt) &&
      window.evaluatedAt < window.startsAt)
    problems.push("SHIFT_EVALUATED_BEFORE_START");
  if (!roles.includes(window?.outgoingRole) ||
      !roles.includes(window?.incomingRole))
    problems.push("SHIFT_ROLE_INVALID");
  if (window?.outgoingUserId !== null &&
      !id(window.outgoingUserId) ||
      window?.incomingUserId !== null && !id(window.incomingUserId))
    problems.push("SHIFT_USER_INVALID");
  if (window?.acknowledgedBy !== null ||
      window?.acceptedAt !== null)
    problems.push("SHIFT_FORGED_ACKNOWLEDGEMENT");
  return problems;
}
export function validateShiftInput(args: {
  organizationId: string; incidentId: string; incidentRevision: number;
  window: ShiftWindow; policy: ShiftPolicy;
  events: TimelineEvent[];
  forensics: ForensicCaseReport;
  investigation: InvestigationCasebook;
}) {
  if (!args || !id(args.organizationId) || !id(args.incidentId) ||
      !Number.isSafeInteger(args.incidentRevision) ||
      args.incidentRevision < 1)
    fail("SHIFT_CONTEXT_INVALID");
  const policyErrors = validateShiftPolicy(args.policy);
  if (policyErrors.length) fail(policyErrors.join(","));
  const windowErrors = validateShiftWindow(args.window);
  if (windowErrors.length) fail(windowErrors.join(","));
  if (!Array.isArray(args.events) || args.events.length > 25000 ||
      args.events.some(e => !e ||
        e.organizationId !== args.organizationId ||
        e.incidentId !== args.incidentId))
    fail("SHIFT_CROSS_TENANT_OR_INCIDENT");
  if (!args.forensics ||
      args.forensics.organizationId !== args.organizationId ||
      args.forensics.incidentId !== args.incidentId ||
      !sha(args.forensics.digest) ||
      args.forensics.externalActions !== 0 ||
      args.forensics.independentProviderProof !== false)
    fail("SHIFT_FORENSIC_SOURCE_INVALID");
  if (!args.investigation ||
      args.investigation.organizationId !== args.organizationId ||
      args.investigation.incidentId !== args.incidentId ||
      !sha(args.investigation.digest) ||
      args.investigation.externalWrites !== 0 ||
      args.investigation.providerOutcomesVerified !== false ||
      args.investigation.sourceReportDigest !== args.forensics.digest)
    fail("SHIFT_INVESTIGATION_SOURCE_INVALID");
}
function timelineActivity(
  events: TimelineEvent[], window: ShiftWindow,
): ShiftActivity[] {
  const activity = events.map(e => ({
    id: "activity:" + shiftDigest([
      e.source, e.sourceId, e.sourceRevision, e.eventId,
    ]).slice(0, 36),
    source: e.source, sourceId: e.sourceId,
    revision: e.sourceRevision, eventId: e.eventId,
    operation: e.operation, actorUserId: e.actorUserId,
    at: e.occurredAt, integrity: e.sourceIntegrity,
    belongsToWindow: e.occurredAt >= window.startsAt &&
      e.occurredAt <= window.endsAt,
    providerReceiptAvailable: false as const,
  }));
  activity.sort((a, b) => b.at.localeCompare(a.at) ||
    a.id.localeCompare(b.id));
  return activity;
}
function sourceInventories(
  events: TimelineEvent[], window: ShiftWindow,
  complete: boolean,
): ShiftSourceInventory[] {
  return sourceNames.map(source => {
    const own = events.filter(e => e.source === source);
    const ledgerIds = new Set(own.map(e => e.sourceId));
    const latest = own.map(e => e.occurredAt).sort().at(-1) ?? null;
    return {
      source, ledgerCount: ledgerIds.size, eventCount: own.length,
      inWindow: own.filter(e => e.occurredAt >= window.startsAt &&
        e.occurredAt <= window.endsAt).length,
      latestAt: latest,
      staleMinutes: latest && latest <= window.evaluatedAt ?
        minutesBetween(window.evaluatedAt, latest) : null,
      completeness: complete ? "LOCAL_ONLY" as const :
        "UNKNOWN" as const,
      independentlyVerified: false as const,
    };
  });
}
function categoryFor(task: InvestigationTask): ShiftActionClass {
  if (task.workstream === "LEDGER_INTEGRITY")
    return "VERIFY_SOURCE_CHAIN";
  if (task.workstream === "PROVENANCE")
    return "REQUEST_MISSING_EVIDENCE";
  if (task.workstream === "RESPONSE_COORDINATION")
    return "DOCUMENT_OPERATOR_HANDOFF";
  if (task.workstream === "TABLETOP_VALIDATION")
    return "RECONCILE_TIMELINE";
  if (task.workstream === "ASSURANCE_FOLLOWUP")
    return "VERIFY_APPROVAL_SEPARATION";
  return "REVIEW_UNKNOWN_COVERAGE";
}
function deadlineFor(
  priority: InvestigationPriority, window: ShiftWindow,
  policy: ShiftPolicy,
) {
  const minutes = priority === "P0" ?
    1 : priority === "P1" ? policy.highPriorityDueMinutes :
    priority === "P2" ? policy.normalPriorityDueMinutes :
    policy.monitorDueMinutes;
  return plus(window.evaluatedAt, minutes);
}
function workFromInvestigation(
  investigation: InvestigationCasebook, window: ShiftWindow,
  policy: ShiftPolicy,
): ShiftWorkItem[] {
  const out: ShiftWorkItem[] = [];
  for (const task of investigation.tasks) {
    const references = investigation.requests.filter(r =>
      task.evidenceRequestIds.includes(r.id));
    const needed = references.map(r => r.kind + ": " + r.question);
    const category = categoryFor(task);
    out.push({
      id: "shift-work:" + shiftDigest([window.shiftId, task.id])
        .slice(0, 32),
      incidentId: investigation.incidentId,
      urgency: urgent(task.priority), priority: task.priority, category,
      source: references[0]?.source ?? null,
      sourceId: references[0]?.sourceId ?? null,
      assignedRole: task.assignedRole, assignedUserId: null,
      explanation: task.description, dueAt: deadlineFor(
        task.priority, window, policy),
      evidenceReferences: references.map(x => x.id).sort(),
      evidenceNeeded: needed,
      underlyingTaskIds: [task.id],
      internalStatus: "PROPOSED", providerWritePermitted: false,
      externallyVerified: false,
    });
  }
  return out.sort(byPriority);
}
function watch(
  category: ShiftWatchpoint["category"],
  priority: InvestigationPriority,
  source: TimelineSource | null, trigger: string, explanation: string,
  role: ShiftWatchpoint["recommendedRole"],
  independent: boolean,
): ShiftWatchpoint {
  return {
    id: "watch:" + shiftDigest([
      category, priority, source, trigger,
    ]).slice(0, 36),
    category, priority, source, trigger, explanation,
    recommendedRole: role,
    requiresIndependentConfirmation: independent,
  };
}
function createWatchpoints(args: {
  forensic: ForensicCaseReport; investigation: InvestigationCasebook;
  inventory: ShiftSourceInventory[];
  policy: ShiftPolicy; window: ShiftWindow;
  activity: ShiftActivity[];
}) {
  const out: ShiftWatchpoint[] = [];
  if (!args.forensic.inventoryComplete) {
    out.push(watch("COVERAGE", "P1", null,
      "SOURCE_INVENTORY_UNCONFIRMED",
      "Faltan garantías de integridad del inventario",
      "AUDITOR", true));
  }
  if (args.forensic.integrity === "CONFLICT") {
    out.push(watch("INTEGRITY", "P0", null,
      "FORENSIC_SOURCE_CONFLICT",
      "El historial incluye discrepancias incompatibles entre revisiones",
      "AUDITOR", true));
  } else if (args.forensic.integrity === "INCOMPLETE") {
    out.push(watch("INTEGRITY", "P2", null,
      "FORENSIC_SOURCE_INCOMPLETE",
      "La trazabilidad sigue sin prueba completa de origen",
      "AUDITOR", true));
  }
  for (const source of args.inventory) {
    if (source.eventCount === 0) {
      out.push(watch("COVERAGE", "P2", source.source,
        "SOURCE_NO_EVENTS", "No consta historial de esta familia",
        "AUDITOR", true));
    } else if (source.staleMinutes === null) {
      out.push(watch("TIMING", "P2", source.source,
        "SOURCE_CLOCK_UNAVAILABLE",
        "El último evento no permite calcular frescura confiable",
        "AUDITOR", true));
    } else if (source.staleMinutes > args.policy.maxSourceStalenessMinutes) {
      out.push(watch("FRESHNESS", "P2", source.source,
        "SOURCE_STALE",
        "No hay actividad reciente dentro del umbral de frescura",
        "ADMIN", true));
    }
  }
  const unresolved = args.investigation.tasks;
  if (unresolved.some(t => t.priority === "P0")) {
    out.push(watch("UNREVIEWED_WORK", "P0", null,
      "CRITICAL_INVESTIGATION_PENDING",
      "La investigación requiere revisión humana prioritaria",
      "OWNER", true));
  }
  if (args.investigation.requests.some(r =>
      r.kind === "PROVIDER_RECEIPT")) {
    out.push(watch("PRIVILEGE_BOUNDARY", "P0", null,
      "PROVIDER_PROOF_MISSING",
      "No convertir un resultado interno en verificación del proveedor",
      "OWNER", true));
  }
  const future = args.activity.filter(x =>
    x.at > args.window.evaluatedAt);
  if (future.length) {
    out.push(watch("TIMING", "P1", null,
      "FUTURE_EVENT_IN_SOURCE",
      "Hay eventos registrados después de la evaluación",
      "AUDITOR", true));
  }
  const upcoming = unresolved.filter(t =>
    t.priority === "P0" || t.priority === "P1");
  if (upcoming.length) {
    out.push(watch("UPCOMING_DEADLINE", "P1", null,
      "HIGH_PRIORITY_DUE",
      "Hay tareas de prioridad alta sin aceptación persistida",
      "OWNER", true));
  }
  return out.sort(byPriority);
}
export function buildIncidentShiftBriefing(args: {
  organizationId: string; incidentId: string; incidentRevision: number;
  window: ShiftWindow; policy?: ShiftPolicy;
  events: TimelineEvent[];
  forensics: ForensicCaseReport;
  investigation: InvestigationCasebook;
}): ShiftBriefing {
  const policy = args.policy ?? defaultShiftPolicy();
  validateShiftInput({ ...args, policy });
  const activityAll = timelineActivity(args.events, args.window);
  const inventory = sourceInventories(args.events, args.window,
    args.forensics.inventoryComplete);
  const workAll = workFromInvestigation(
    args.investigation, args.window, policy);
  const watchAll = createWatchpoints({
    forensic: args.forensics, investigation: args.investigation,
    inventory, policy, window: args.window, activity: activityAll,
  });
  const activity = activityAll.filter(x => x.belongsToWindow)
    .slice(0, policy.maximumActivities);
  const workItems = workAll.slice(0, policy.maximumWorkItems);
  const watchpoints = watchAll.slice(0, policy.maximumWatchpoints);
  const activityTruncated = activityAll.filter(x => x.belongsToWindow).length >
    activity.length;
  const workTruncated = workAll.length > workItems.length;
  const watchpointsTruncated = watchAll.length > watchpoints.length;
  const priorityCounts = Object.fromEntries(priorityNames.map(p => [
    p, workAll.filter(item => item.priority === p).length,
  ])) as Record<InvestigationPriority, number>;
  const limitations = [
    "Esta es una propuesta de briefing, no una transferencia aceptada",
    "Los propietarios son roles propuestos sin asignación humana registrada",
    "No hay operaciones LIVE ni notificaciones externas",
    "La presencia de snapshots no equivale a prueba independiente",
    "Un estado de caso no acredita revocación, purga ni aislamiento",
  ];
  if (activityTruncated || workTruncated || watchpointsTruncated)
    limitations.push("La representación fue limitada por política de capacidad");
  if (!args.forensics.inventoryComplete)
    limitations.push("El inventario de origen no está completo");
  const operationalConfidence = args.forensics.integrity === "CONFLICT" ||
    !args.forensics.inventoryComplete ? "INSUFFICIENT" as const :
    "LOCAL_ONLY" as const;
  const base = {
    schema: "cyberpilot.incident.shift.briefing.v1" as const,
    organizationId: args.organizationId, incidentId: args.incidentId,
    incidentRevision: args.incidentRevision, window: args.window,
    policyDigest: shiftDigest(policy),
    forensicDigest: args.forensics.digest,
    investigationDigest: args.investigation.digest,
    activity, sourceInventory: inventory, workItems, watchpoints,
    workTruncated, activityTruncated, watchpointsTruncated,
    sourceEvents: args.events.length,
    openEvidenceRequests: args.investigation.requests.length,
    priorityCounts,
    completeness: args.forensics.inventoryComplete ?
      "PARTIAL" as const : "UNKNOWN" as const,
    operationalConfidence, limitations,
    receiptIssued: false as const, handoffAcknowledged: false as const,
    externalActions: 0 as const,
    providerOutcomesIndependentlyVerified: false as const,
  };
  return { ...base, digest: shiftDigest(base) };
}
export function verifyIncidentShiftBriefing(value: ShiftBriefing): string[] {
  const problems: string[] = [];
  if (!value || value.schema !== "cyberpilot.incident.shift.briefing.v1" ||
      !id(value.organizationId) || !id(value.incidentId) ||
      !Number.isSafeInteger(value.incidentRevision) ||
      value.incidentRevision < 1)
    problems.push("SHIFT_BRIEF_HEADER_INVALID");
  if (!sha(value?.policyDigest) || !sha(value?.forensicDigest) ||
      !sha(value?.investigationDigest) ||
      !sha(value?.digest) || value.digest !== shiftDigest({
        ...value, digest: undefined,
      })) problems.push("SHIFT_BRIEF_HASH_INVALID");
  if (value?.receiptIssued !== false ||
      value?.handoffAcknowledged !== false ||
      value?.externalActions !== 0 ||
      value?.providerOutcomesIndependentlyVerified !== false)
    problems.push("SHIFT_BRIEF_FALSE_ACCEPTANCE_OR_EXECUTION");
  if (validateShiftWindow(value?.window).length)
    problems.push("SHIFT_BRIEF_WINDOW_INVALID");
  if (!Array.isArray(value?.activity) ||
      !Array.isArray(value?.workItems) ||
      !Array.isArray(value?.watchpoints) ||
      !Array.isArray(value?.sourceInventory))
    problems.push("SHIFT_BRIEF_ARRAYS_INVALID");
  else {
    if (value.activity.some(e => !sourceNames.includes(e.source) ||
        e.providerReceiptAvailable !== false ||
        !id(e.sourceId) || !id(e.eventId) ||
        !iso(e.at) || !e.belongsToWindow))
      problems.push("SHIFT_BRIEF_ACTIVITY_INVALID");
    if (value.workItems.some(w => w.incidentId !== value.incidentId ||
        w.providerWritePermitted !== false ||
        w.externallyVerified !== false ||
        w.internalStatus !== "PROPOSED" ||
        w.assignedUserId !== null || !iso(w.dueAt)))
      problems.push("SHIFT_BRIEF_WORK_UNSAFE");
    if (value.sourceInventory.some(x =>
        x.independentlyVerified !== false))
      problems.push("SHIFT_BRIEF_SOURCE_FORGERY");
    if (new Set(value.workItems.map(w => w.id)).size !==
        value.workItems.length)
      problems.push("SHIFT_BRIEF_DUPLICATE_WORK");
  }
  return [...new Set(problems)];
}
export function previewShiftAcceptance(args: {
  briefing: ShiftBriefing; actorId: string;
  actorRole: "OWNER" | "ADMIN" | "AUDITOR";
  action: ShiftAcceptancePreview["action"];
  checkedAt: string; expectedDigest: string;
}): ShiftAcceptancePreview {
  const brief = args.briefing;
  if (verifyIncidentShiftBriefing(brief).length)
    fail("SHIFT_ACCEPTANCE_BRIEF_INVALID");
  if (!id(args.actorId) || !roles.includes(args.actorRole) ||
      !iso(args.checkedAt) ||
      !["REVIEW_PREVIEW", "REQUEST_RECONCILIATION"].includes(args.action))
    fail("SHIFT_ACCEPTANCE_ACTOR_INVALID");
  if (args.expectedDigest !== brief.digest)
    fail("SHIFT_ACCEPTANCE_STALE_DIGEST");
  if (args.checkedAt < brief.window.evaluatedAt)
    fail("SHIFT_ACCEPTANCE_TIME_REGRESSION");
  if (brief.window.incomingUserId !== null &&
      args.actorId !== brief.window.incomingUserId)
    fail("SHIFT_ACCEPTANCE_WRONG_RESPONDER");
  const concerns = [
    ...brief.watchpoints.filter(w => w.priority === "P0")
      .map(w => w.trigger),
  ];
  if (brief.activityTruncated || brief.workTruncated ||
      brief.watchpointsTruncated)
    concerns.push("SHIFT_INPUTS_TRUNCATED");
  if (brief.operationalConfidence === "INSUFFICIENT")
    concerns.push("SHIFT_CONFIDENCE_INSUFFICIENT");
  if (brief.openEvidenceRequests > 0)
    concerns.push("SHIFT_EVIDENCE_OUTSTANDING");
  const requiredSourceChecks = brief.sourceInventory.map(x =>
    x.source + ": " + x.eventCount + " local events; " +
    x.completeness + "; independent proof unavailable");
  const base = {
    schema: "cyberpilot.incident.shift.acceptance-preview.v1" as const,
    organizationId: brief.organizationId, incidentId: brief.incidentId,
    shiftId: brief.window.shiftId, expectedBriefingDigest: brief.digest,
    actorId: args.actorId, actorRole: args.actorRole,
    action: args.action, checkedAt: args.checkedAt,
    requiredSourceChecks, concerns,
    canAcknowledgeAfterPersistence: concerns.length === 0 &&
      args.action === "REVIEW_PREVIEW",
    locallyRecorded: false as const,
    providerActionsAuthorized: false as const,
  };
  return { ...base, digest: shiftDigest(base) };
}
export function compareShiftBriefings(
  earlier: ShiftBriefing, later: ShiftBriefing,
): ShiftTransitionDelta {
  if (verifyIncidentShiftBriefing(earlier).length ||
      verifyIncidentShiftBriefing(later).length)
    fail("SHIFT_COMPARE_INVALID");
  if (earlier.organizationId !== later.organizationId ||
      earlier.incidentId !== later.incidentId)
    fail("SHIFT_COMPARE_CROSS_TENANT_OR_INCIDENT");
  if (earlier.window.evaluatedAt > later.window.evaluatedAt)
    fail("SHIFT_COMPARE_TIME_REVERSED");
  const oldEvents = new Set(earlier.activity.map(a => a.id));
  const newEvents = new Set(later.activity.map(a => a.id));
  const oldWork = new Set(earlier.workItems.map(a => a.id));
  const newWork = new Set(later.workItems.map(a => a.id));
  const sourceRegressions = later.sourceInventory.filter(
    source => {
      const previous = earlier.sourceInventory.find(
        s => s.source === source.source);
      return previous && (source.eventCount < previous.eventCount ||
        source.ledgerCount < previous.ledgerCount);
    }).map(x => x.source);
  return {
    schema: "cyberpilot.incident.shift.delta.v1",
    organizationId: later.organizationId, incidentId: later.incidentId,
    earlierDigest: earlier.digest, laterDigest: later.digest,
    newEvents: later.activity.filter(x => !oldEvents.has(x.id)),
    disappearedEvents: earlier.activity.filter(x => !newEvents.has(x.id)),
    newWorkItems: later.workItems.filter(x => !oldWork.has(x.id)),
    missingWorkItems: earlier.workItems.filter(x => !newWork.has(x.id)),
    sourceRegressions, acknowledgementProven: false,
    mitigationProven: false,
  };
}
export function shiftRoleWorkload(briefing: ShiftBriefing) {
  if (verifyIncidentShiftBriefing(briefing).length)
    fail("SHIFT_WORKLOAD_BRIEF_INVALID");
  return roles.map(role => {
    const selected = briefing.workItems.filter(x =>
      x.assignedRole === role);
    const urgent = selected.filter(item =>
      item.urgency === "IMMEDIATE" || item.urgency === "BEFORE_END");
    return {
      role, openWork: selected.length, urgentWork: urgent.length,
      evidenceRequirements: selected.reduce((sum, item) =>
        sum + item.evidenceNeeded.length, 0),
      categoryCount: new Set(selected.map(x => x.category)).size,
      isConfirmedOwner: false,
    };
  });
}
export function shiftProofMatrix(briefing: ShiftBriefing) {
  if (verifyIncidentShiftBriefing(briefing).length)
    fail("SHIFT_PROOF_BRIEF_INVALID");
  return briefing.sourceInventory.map(source => ({
    source: source.source, observedRecords: source.eventCount,
    localLedgerRecords: source.eventCount,
    forensicFindings: briefing.watchpoints.filter(x =>
      x.source === source.source &&
      x.category === "INTEGRITY").length,
    sourceFreshnessMinutes: source.staleMinutes,
    independentlyVerifiedEvents: 0,
    providerReceipts: 0,
    operationConfirmedExternally: false,
    interpretation: source.eventCount > 0 ?
      "LOCAL_EVIDENCE_ONLY" as const : "UNKNOWN" as const,
  }));
}
export function shiftPrioritizedQueue(
  briefing: ShiftBriefing, role?: "OWNER" | "ADMIN" | "AUDITOR",
) {
  if (verifyIncidentShiftBriefing(briefing).length)
    fail("SHIFT_QUEUE_BRIEF_INVALID");
  return briefing.workItems.filter(x => !role || x.assignedRole === role)
    .sort((a, b) => rank(a.priority) - rank(b.priority) ||
      a.dueAt.localeCompare(b.dueAt) || a.id.localeCompare(b.id));
}
function csvField(value: string) {
  const safe = /^[\s]*[=+@-]/.test(value) ||
    /^[\s]*[\t\r]/.test(value) ? "'" + value : value;
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function exportShiftJSON(brief: ShiftBriefing) {
  if (verifyIncidentShiftBriefing(brief).length)
    fail("SHIFT_EXPORT_INVALID");
  return JSON.stringify(brief, null, 2);
}
export function exportShiftWorkCSV(brief: ShiftBriefing) {
  if (verifyIncidentShiftBriefing(brief).length)
    fail("SHIFT_EXPORT_INVALID");
  const head = [
    "workId", "priority", "urgency", "category", "assignedRole",
    "source", "sourceId", "dueAt", "description",
    "status", "evidenceNeeded", "providerWrites",
  ];
  return [head.join(","), ...brief.workItems.map(w => [
    w.id, w.priority, w.urgency, w.category, w.assignedRole,
    w.source ?? "", w.sourceId ?? "", w.dueAt, w.explanation,
    w.internalStatus, w.evidenceNeeded.join(";"), "0",
  ].map(csvField).join(","))].join("\r\n") + "\r\n";
}
export function exportShiftMarkdown(brief: ShiftBriefing) {
  if (verifyIncidentShiftBriefing(brief).length)
    fail("SHIFT_EXPORT_INVALID");
  const safe = (s: string) => s.replace(/[\r\n|<>]/g, " ").trim();
  const rows = brief.workItems.map(w =>
    "| " + [w.priority, w.category, w.assignedRole, w.dueAt,
      w.explanation].map(safe).join(" | ") + " |");
  return [
    "# CyberPilot — briefing de relevo interno",
    "",
    "Incidente: " + safe(brief.incidentId),
    "Turno: " + safe(brief.window.shiftId),
    "Generado: " + safe(brief.window.evaluatedAt),
    "Digest: " + brief.digest,
    "",
    "No acredita contención, aceptación ni acciones de proveedor.",
    "La ausencia de registros no demuestra ausencia de incidentes.",
    "",
    "## Trabajo propuesto",
    "",
    "| Prioridad | Clase | Rol | Plazo | Explicación |",
    "|---|---|---|---|---|",
    ...rows,
    "",
    "## Limitaciones",
    "",
    ...brief.limitations.map(s => "- " + safe(s)),
    "",
  ].join("\n");
}
