import { createHash } from "node:crypto";
import { getIncidentPlaybook, digestIncidentPlaybook,
  type IncidentType, type IncidentState, type IncidentRole,
  type IncidentCommand, type StepState, type EvidenceVerdict } from "./incident-playbook-catalog";

export type IncidentEvidence = {
  id: string; stepId: string; source: string; sourceReference: string;
  observedAt: string | null; recordedAt: string;
  verdict: EvidenceVerdict; summary: string;
  independent: boolean; providerOperation: false;
};
export type IncidentApproval = {
  stepId: string; approvedById: string; approvedAt: string;
  reason: string; scopeDigest: string; expiresAt: string;
  forExecution: false;
};
export type IncidentStepProgress = {
  stepId: string; status: StepState; assignedTo: string | null;
  lastChangedAt: string; note: string | null;
  evidenceIds: string[]; verifiedById: string | null;
};
export type IncidentSnapshot = {
  schema: "cyberpilot.incident.case.v1"; id: string; organizationId: string;
  type: IncidentType; playbookDigest: string; playbookVersion: 1;
  title: string; severity: string; status: IncidentState;
  revision: number; ownerUserId: string | null;
  subjectReference: string; createdById: string;
  createdAt: string; updatedAt: string; updatedById: string;
  steps: IncidentStepProgress[]; evidence: IncidentEvidence[];
  approvals: IncidentApproval[]; reviewNote: string | null;
  relatedDecisionCaseId: string | null;
  providerOperations: 0; containmentVerified: false;
  customerConsentEstablished: false; cyberScoreModified: false;
};
export type IncidentEvent = {
  organizationId: string; incidentId: string; revision: number;
  kind: IncidentCommand | "CREATE"; actorUserId: string;
  occurredAt: string; previousState: IncidentState;
  nextState: IncidentState; snapshotDigest: string;
  providerWrite: false; independentlyClosed: false;
};
export type IncidentMutation = {
  organizationId: string; incidentId: string; actorUserId: string;
  role: IncidentRole; expectedRevision: number; kind: IncidentCommand;
  at: string; stepId?: string; reason?: string;
  ownerUserId?: string | null; evidence?: IncidentEvidence;
  approval?: IncidentApproval;
};
export type IncidentOutcome = { accepted: boolean; code: string;
  snapshot: IncidentSnapshot; event: IncidentEvent | null;
  providerWrites: 0; securityOutcomeProven: false };
const ident = (s: unknown) => typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const timestamp = (s: unknown): s is string => typeof s === "string" &&
  Number.isFinite(Date.parse(s)) && new Date(s).toISOString() === s;
const text = (s: unknown, limit: number): s is string =>
  typeof s === "string" && s.trim().length > 0 && s.length <= limit &&
  !/[\u0000-\u001f\u007f]/.test(s);
// PostgreSQL JSONB does not preserve object member insertion order.
function canonicalIncidentJson(value: unknown): string {
  if (value === null || typeof value === "string" ||
      typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value))
      throw new Error("INCIDENT_NONFINITE_NUMBER");
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return "[" + value.map(canonicalIncidentJson).join(",") + "]";
  if (value && typeof value === "object")
    return "{" + Object.entries(value).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0).map(([key, item]) =>
        JSON.stringify(key) + ":" + canonicalIncidentJson(item)).join(",") + "}";
  throw new Error("INCIDENT_NONCANONICAL_INPUT");
}
const digest = (x: unknown) => createHash("sha256")
  .update(canonicalIncidentJson(x)).digest("hex");
export function incidentDigest(snapshot: IncidentSnapshot) { return digest(snapshot); }
export function incidentCreationEvent(s: IncidentSnapshot): IncidentEvent {
  if (validateIncidentSnapshot(s).length || s.revision !== 1)
    throw new Error("INCIDENT_INITIAL_SNAPSHOT_INVALID");
  return {
    organizationId: s.organizationId, incidentId: s.id,
    revision: 1, kind: "CREATE", actorUserId: s.createdById,
    occurredAt: s.createdAt, previousState: "OPEN", nextState: "OPEN",
    snapshotDigest: incidentDigest(s), providerWrite: false, independentlyClosed: false,
  };
}
export function createIncident(input: { id: string; organizationId: string;
  type: IncidentType; title: string; subjectReference: string;
  actorUserId: string; at: string; ownerUserId: string | null;
  relatedDecisionCaseId?: string | null; }): IncidentSnapshot {
  const book = getIncidentPlaybook(input.type);
  const s: IncidentSnapshot = {
    schema: "cyberpilot.incident.case.v1", id: input.id,
    organizationId: input.organizationId, type: book.id,
    playbookDigest: digestIncidentPlaybook(book), playbookVersion: 1,
    title: input.title, severity: book.severity, status: "OPEN",
    revision: 1, ownerUserId: input.ownerUserId,
    subjectReference: input.subjectReference, createdById: input.actorUserId,
    createdAt: input.at, updatedAt: input.at, updatedById: input.actorUserId,
    steps: book.steps.map(step => ({ stepId: step.id, status: "PENDING",
      assignedTo: null, lastChangedAt: input.at, note: null, evidenceIds: [],
      verifiedById: null })), evidence: [], approvals: [], reviewNote: null,
    relatedDecisionCaseId: input.relatedDecisionCaseId ?? null,
    providerOperations: 0, containmentVerified: false,
    customerConsentEstablished: false, cyberScoreModified: false,
  };
  const issues = validateIncidentSnapshot(s);
  if (issues.length) throw new Error("INCIDENT_CREATE_INVALID:" + issues.join(","));
  return s;
}
export function validateIncidentSnapshot(s: IncidentSnapshot): string[] {
  const issues: string[] = [];
  if (s.schema !== "cyberpilot.incident.case.v1" ||
      !ident(s.id) || !ident(s.organizationId) || !ident(s.createdById) ||
      !ident(s.updatedById)) issues.push("SCOPE_INVALID");
  let book: ReturnType<typeof getIncidentPlaybook> | null = null;
  try { book = getIncidentPlaybook(s.type); } catch { issues.push("PLAYBOOK_UNKNOWN"); }
  if (book && (s.playbookDigest !== digestIncidentPlaybook(book) ||
      s.playbookVersion !== 1 || s.severity !== book.severity))
    issues.push("PLAYBOOK_DRIFT");
  if (!text(s.title, 180) || !text(s.subjectReference, 220))
    issues.push("CASE_FIELDS_INVALID");
  if (!["OPEN", "TRIAGE", "CONTAINMENT", "RECOVERY", "REVIEW", "CLOSED"].includes(s.status) ||
      !Number.isSafeInteger(s.revision) || s.revision < 1 ||
      !timestamp(s.createdAt) || !timestamp(s.updatedAt) ||
      s.updatedAt < s.createdAt) issues.push("STATE_INVALID");
  if (s.ownerUserId !== null && !ident(s.ownerUserId) ||
      s.relatedDecisionCaseId !== null && !ident(s.relatedDecisionCaseId))
    issues.push("RELATION_INVALID");
  if (s.reviewNote !== null && !text(s.reviewNote, 4000))
    issues.push("REVIEW_INVALID");
  if (s.providerOperations !== 0 || s.containmentVerified !== false ||
      s.customerConsentEstablished !== false || s.cyberScoreModified !== false)
    issues.push("UNSUPPORTED_SECURITY_CLAIM");
  if (!Array.isArray(s.steps) || !Array.isArray(s.evidence) ||
      !Array.isArray(s.approvals) || s.evidence.length > 150 ||
      s.approvals.length > 150) {
    issues.push("COLLECTION_INVALID"); return [...new Set(issues)];
  }
  const ids = book?.steps.map(x => x.id) ?? [];
  if (s.steps.length !== ids.length || s.steps.some((x, i) => x.stepId !== ids[i]))
    issues.push("STEP_CATALOG_MISMATCH");
  const evidenceIds = new Set<string>();
  for (const item of s.evidence) {
    if (!ident(item.id) || evidenceIds.has(item.id) ||
        !ids.includes(item.stepId) || !text(item.source, 100) ||
        !text(item.sourceReference, 300) || !text(item.summary, 1000) ||
        !timestamp(item.recordedAt) || item.observedAt !== null &&
        !timestamp(item.observedAt) || !["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"]
        .includes(item.verdict) || item.providerOperation !== false)
      issues.push("EVIDENCE_INVALID");
    evidenceIds.add(item.id);
  }
  for (const item of s.steps) {
    if (!["PENDING", "IN_PROGRESS", "BLOCKED", "REPORTED_DONE", "VERIFIED"]
      .includes(item.status) || !timestamp(item.lastChangedAt) ||
      item.assignedTo !== null && !ident(item.assignedTo) ||
      item.note !== null && !text(item.note, 4000) ||
      item.verifiedById !== null && !ident(item.verifiedById) ||
      !Array.isArray(item.evidenceIds) || item.evidenceIds.length > 30 ||
      new Set(item.evidenceIds).size !== item.evidenceIds.length ||
      item.evidenceIds.some(x => !evidenceIds.has(x) ||
        s.evidence.find(e => e.id === x)?.stepId !== item.stepId))
      issues.push("STEP_PROGRESS_INVALID");
    if (item.status === "VERIFIED" && !item.verifiedById)
      issues.push("VERIFICATION_ACTOR_REQUIRED");
  }
  for (const a of s.approvals) {
    if (!ids.includes(a.stepId) || !ident(a.approvedById) ||
        !timestamp(a.approvedAt) || !timestamp(a.expiresAt) ||
        a.expiresAt <= a.approvedAt || !text(a.reason, 2000) ||
        !/^[a-f0-9]{64}$/.test(a.scopeDigest) || a.forExecution !== false)
      issues.push("APPROVAL_INVALID");
  }
  return [...new Set(issues)];
}
function rejected(s: IncidentSnapshot, code: string): IncidentOutcome {
  return { accepted: false, code, snapshot: s, event: null,
    providerWrites: 0, securityOutcomeProven: false };
}
const allowedStates: Partial<Record<IncidentCommand, IncidentState[]>> = {
  START_TRIAGE: ["OPEN"], START_CONTAINMENT: ["TRIAGE"],
  START_RECOVERY: ["CONTAINMENT"], REQUEST_REVIEW: ["TRIAGE", "CONTAINMENT", "RECOVERY"],
  CLOSE: ["REVIEW"], REOPEN: ["CLOSED"],
};
const resultingState: Partial<Record<IncidentCommand, IncidentState>> = {
  START_TRIAGE: "TRIAGE", START_CONTAINMENT: "CONTAINMENT",
  START_RECOVERY: "RECOVERY", REQUEST_REVIEW: "REVIEW",
  CLOSE: "CLOSED", REOPEN: "TRIAGE",
};
const sensitive = new Set<IncidentCommand>(["CLOSE", "REOPEN", "RECORD_APPROVAL", "STEP_VERIFY"]);
export function applyIncidentCommand(s: IncidentSnapshot, c: IncidentMutation): IncidentOutcome {
  if (validateIncidentSnapshot(s).length) return rejected(s, "INVALID_PREVIOUS_SNAPSHOT");
  if (c.organizationId !== s.organizationId || c.incidentId !== s.id ||
      !ident(c.actorUserId)) return rejected(s, "INCIDENT_SCOPE_OR_ACTOR_INVALID");
  if (c.expectedRevision !== s.revision) return rejected(s, "INCIDENT_REVISION_CONFLICT");
  if (!timestamp(c.at) || c.at < s.updatedAt) return rejected(s, "INCIDENT_TIME_INVALID");
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(c.role) ||
      c.role === "AUDITOR" || sensitive.has(c.kind) && !["OWNER", "ADMIN"].includes(c.role))
    return rejected(s, "INCIDENT_ROLE_DENIED");
  if (s.status === "CLOSED" && c.kind !== "REOPEN" && c.kind !== "COMMENT")
    return rejected(s, "INCIDENT_CLOSED");
  const next: IncidentSnapshot = structuredClone(s);
  const book = getIncidentPlaybook(s.type);
  const reason = c.reason?.trim();
  if (c.reason !== undefined && !text(c.reason, 4000)) return rejected(s, "INCIDENT_REASON_INVALID");
  if (allowedStates[c.kind] && !allowedStates[c.kind]!.includes(s.status))
    return rejected(s, "INCIDENT_STATE_TRANSITION_INVALID");
  if (["CLOSE", "REOPEN", "REQUEST_REVIEW", "STEP_BLOCK", "STEP_RESET"].includes(c.kind) &&
      (!reason || reason.length < 15)) return rejected(s, "INCIDENT_SUBSTANTIVE_REASON_REQUIRED");
  if (resultingState[c.kind]) {
    next.status = resultingState[c.kind]!;
    if (reason) next.reviewNote = reason;
  } else if (c.kind === "ASSIGN") {
    if (c.ownerUserId !== null && !ident(c.ownerUserId))
      return rejected(s, "INCIDENT_OWNER_INVALID");
    next.ownerUserId = c.ownerUserId ?? null;
  } else if (c.kind === "COMMENT") {
    if (!reason) return rejected(s, "INCIDENT_COMMENT_REQUIRED");
    next.reviewNote = reason;
  } else {
    const progress = next.steps.find(x => x.stepId === c.stepId);
    const spec = book.steps.find(x => x.id === c.stepId);
    if (!progress || !spec) return rejected(s, "INCIDENT_STEP_UNKNOWN");
    if (c.kind === "ATTACH_EVIDENCE") {
      const e = c.evidence;
      if (!e || e.stepId !== progress.stepId || next.evidence.some(x => x.id === e.id) ||
          next.evidence.length >= 150 || progress.evidenceIds.length >= 30)
        return rejected(s, "INCIDENT_EVIDENCE_DUPLICATE_OR_LIMIT");
      next.evidence.push(e); progress.evidenceIds.push(e.id);
    } else if (c.kind === "RECORD_APPROVAL") {
      const a = c.approval;
      if (!a || a.stepId !== progress.stepId || !spec.requiresApproval ||
          a.approvedById !== c.actorUserId || a.scopeDigest !==
          createHash("sha256").update(s.id + ":" + s.subjectReference + ":" +
            progress.stepId + ":" + s.playbookDigest).digest("hex"))
        return rejected(s, "INCIDENT_APPROVAL_SCOPE_INVALID");
      next.approvals.push(a);
    } else if (c.kind === "STEP_START") {
      if (!["PENDING", "BLOCKED"].includes(progress.status))
        return rejected(s, "INCIDENT_STEP_NOT_STARTABLE");
      progress.status = "IN_PROGRESS";
    } else if (c.kind === "STEP_BLOCK") {
      if (progress.status === "VERIFIED") return rejected(s, "INCIDENT_VERIFIED_STEP_IMMUTABLE");
      progress.status = "BLOCKED"; progress.note = reason ?? null;
    } else if (c.kind === "STEP_REPORT") {
      if (!["IN_PROGRESS", "BLOCKED"].includes(progress.status))
        return rejected(s, "INCIDENT_STEP_NOT_REPORTABLE");
      if (progress.evidenceIds.length === 0)
        return rejected(s, "INCIDENT_STEP_EVIDENCE_REQUIRED");
      progress.status = "REPORTED_DONE"; progress.note = reason ?? null;
    } else if (c.kind === "STEP_VERIFY") {
      if (progress.status !== "REPORTED_DONE")
        return rejected(s, "INCIDENT_STEP_NOT_REPORTED");
      const linked = next.evidence.filter(x => progress.evidenceIds.includes(x.id));
      if (!linked.some(x => x.verdict === "OBSERVED" && x.independent))
        return rejected(s, "INCIDENT_INDEPENDENT_EVIDENCE_REQUIRED");
      if (spec.requiresApproval && !next.approvals.some(a =>
        a.stepId === spec.id && a.approvedAt <= c.at && a.expiresAt > c.at))
        return rejected(s, "INCIDENT_STEP_APPROVAL_REQUIRED");
      if (!spec.requiredEvidence.every(needed =>
        needed === "approval" ? next.approvals.some(a =>
          a.stepId === spec.id && a.expiresAt > c.at) :
          linked.some(e => e.source === needed && e.verdict === "OBSERVED" && e.independent)))
        return rejected(s, "INCIDENT_PROOF_CATEGORIES_MISSING");
      progress.status = "VERIFIED"; progress.verifiedById = c.actorUserId;
    } else if (c.kind === "STEP_RESET") {
      if (progress.status !== "VERIFIED" && progress.status !== "REPORTED_DONE")
        return rejected(s, "INCIDENT_STEP_NOT_RESETTABLE");
      progress.status = "PENDING"; progress.verifiedById = null;
      progress.note = reason ?? null;
    } else return rejected(s, "INCIDENT_COMMAND_UNKNOWN");
    progress.lastChangedAt = c.at;
  }
  if (c.kind === "CLOSE") {
    if (next.steps.some(p => p.status !== "VERIFIED")) return rejected(s, "INCIDENT_OPEN_STEPS");
    if (next.evidence.some(e => e.verdict === "ERROR" || e.verdict === "UNKNOWN"))
      return rejected(s, "INCIDENT_UNRESOLVED_EVIDENCE");
  }
  next.revision++; next.updatedAt = c.at; next.updatedById = c.actorUserId;
  const errors = validateIncidentSnapshot(next);
  if (errors.length) return rejected(s, errors[0]!);
  const event: IncidentEvent = {
    organizationId: s.organizationId, incidentId: s.id,
    revision: next.revision, kind: c.kind, actorUserId: c.actorUserId,
    occurredAt: c.at, previousState: s.status, nextState: next.status,
    snapshotDigest: incidentDigest(next), providerWrite: false, independentlyClosed: false,
  };
  return { accepted: true, code: "ACCEPTED", snapshot: next, event,
    providerWrites: 0, securityOutcomeProven: false };
}
export function auditIncident(s: IncidentSnapshot, events: IncidentEvent[], truncated = false) {
  const errors = validateIncidentSnapshot(s);
  const sorted = [...events].sort((a, b) => a.revision - b.revision);
  if (truncated || sorted.length !== s.revision ||
      sorted.some((x, i) => x.revision !== i + 1 ||
        x.organizationId !== s.organizationId || x.incidentId !== s.id ||
        i > 0 && x.previousState !== sorted[i - 1]!.nextState))
    errors.push("INCIDENT_EVENT_CHAIN_INCOMPLETE");
  const last = sorted.at(-1);
  if (last?.snapshotDigest !== incidentDigest(s) || last?.nextState !== s.status)
    errors.push("INCIDENT_LATEST_DIGEST_INVALID");
  if (sorted.some(x => x.providerWrite !== false || x.independentlyClosed !== false))
    errors.push("INCIDENT_UNSUPPORTED_EVENT_CLAIM");
  return { valid: errors.length === 0, errors: [...new Set(errors)],
    observedEvents: events.length, latestRevision: last?.revision ?? null,
    independentlyClosed: false as const };
}
export function incidentApprovalScope(s: IncidentSnapshot, stepId: string) {
  if (!getIncidentPlaybook(s.type).steps.some(x => x.id === stepId))
    throw new Error("INCIDENT_STEP_UNKNOWN");
  return createHash("sha256").update(s.id + ":" + s.subjectReference + ":" +
    stepId + ":" + s.playbookDigest).digest("hex");
}
