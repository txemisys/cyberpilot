import {
  createCoordination, evolveCoordination, coordinationDigest,
  type CoordinationEnvelope, type CoordinationCommand,
  type CoordinationReceipt,
} from "./incident-coordination-ledger-domain";
import type {
  InvestigationCasebook, InvestigationTask,
  InvestigationEvidenceKind, InvestigationPriority,
} from "./incident-timeline-investigation-domain";
export type InvestigationDecisionStatus =
  "UNASSIGNED" | "ASSIGNED" | "IN_PROGRESS" | "WAITING_EVIDENCE" |
  "READY_FOR_REVIEW" | "RETURNED" | "REVIEWED_INTERNAL" | "REOPENED";
export type InvestigationEvidence = {
  id: string; requestId: string; kind: InvestigationEvidenceKind;
  reference: string; description: string; recordedBy: string; recordedAt: string;
  digest: string; provenance: "INTERNAL" | "EXTERNAL_REFERENCE_UNVERIFIED";
  independentProviderProof: false;
};
export type InvestigationWork = {
  id: string; sourceTaskId: string; priority: InvestigationPriority;
  assignedRole: "OWNER" | "ADMIN" | "AUDITOR";
  assignedUserId: string | null; assignedBy: string | null;
  assignedAt: string | null; status: InvestigationDecisionStatus;
  lastActorId: string; updatedAt: string;
  evidenceRequestIds: string[];
  attachedEvidenceIds: string[];
  reviewRequestedBy: string | null;
  reviewedBy: string | null; reviewedAt: string | null;
  reviewDisposition: "SUFFICIENT_INTERNAL" | "NEEDS_EVIDENCE" | null;
  reviewExplanation: string | null;
  notes: Array<{ id: string; authorId: string; at: string; text: string }>;
  providerActionCompleted: false;
};
export type InvestigationReviewPayload = {
  schema: "cyberpilot.incident.investigation.work.v1";
  originalCasebookDigest: string;
  originalForensicDigest: string;
  sourceIncidentRevision: number;
  sourceComplete: boolean;
  work: InvestigationWork[];
  evidence: InvestigationEvidence[];
  sourceLimitations: string[];
  reviewedInternally: number;
  waitingEvidence: number;
  providerActionsConfirmed: 0;
  independentContainmentProof: false;
};
export type InvestigationReviewCommandAction =
  | { kind: "ASSIGN"; workId: string; assigneeId: string; reason: string }
  | { kind: "START"; workId: string; reason: string }
  | { kind: "REQUEST_EVIDENCE"; workId: string; reason: string }
  | { kind: "ADD_EVIDENCE"; workId: string; evidenceId: string;
      requestId: string; evidenceKind: InvestigationEvidenceKind;
      reference: string; description: string;
      provenance: InvestigationEvidence["provenance"]; reason: string }
  | { kind: "ADD_NOTE"; workId: string; noteId: string; reason: string }
  | { kind: "SUBMIT_REVIEW"; workId: string; reason: string }
  | { kind: "REVIEW"; workId: string;
      disposition: "SUFFICIENT_INTERNAL" | "NEEDS_EVIDENCE"; reason: string }
  | { kind: "REOPEN"; workId: string; reason: string }
  | { kind: "CLOSE"; reason: string };
const id = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const sha = (v: unknown): v is string => typeof v === "string" &&
  /^[a-f0-9]{64}$/.test(v);
const iso = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const fail = (x: string): never => { throw Error(x); };
const statuses: InvestigationDecisionStatus[] = [
  "UNASSIGNED", "ASSIGNED", "IN_PROGRESS", "WAITING_EVIDENCE",
  "READY_FOR_REVIEW", "RETURNED", "REVIEWED_INTERNAL", "REOPENED",
];
const evidenceKinds: InvestigationEvidenceKind[] = [
  "AUDIT_EVENT", "SNAPSHOT", "SOURCE_CHAIN", "OPERATOR_CONFIRMATION",
  "PROVIDER_RECEIPT", "ACCESS_REVIEW", "COMPLETENESS_REVIEW",
];
function deriveCounts(works: InvestigationWork[]) {
  return {
    reviewedInternally: works.filter(w =>
      w.status === "REVIEWED_INTERNAL").length,
    waitingEvidence: works.filter(w =>
      w.status === "WAITING_EVIDENCE" || w.status === "RETURNED").length,
  };
}
export function validateInvestigationReviewPayload(
  payload: InvestigationReviewPayload,
): string[] {
  const problems: string[] = [];
  if (!payload || payload.schema !==
      "cyberpilot.incident.investigation.work.v1" ||
      !sha(payload.originalCasebookDigest) ||
      !sha(payload.originalForensicDigest) ||
      !Number.isSafeInteger(payload.sourceIncidentRevision) ||
      payload.sourceIncidentRevision < 1 ||
      typeof payload.sourceComplete !== "boolean")
    problems.push("INVESTIGATION_WORK_HEADER_INVALID");
  if (!Array.isArray(payload?.work) || payload.work.length > 500 ||
      !Array.isArray(payload?.evidence) || payload.evidence.length > 1500 ||
      !Array.isArray(payload?.sourceLimitations))
    return [...problems, "INVESTIGATION_WORK_BOUNDS_INVALID"];
  const workIds = new Set<string>();
  const evidenceIds = new Set<string>();
  for (const w of payload.work) {
    if (!w || !id(w.id) || workIds.has(w.id) ||
        !id(w.sourceTaskId) || !statuses.includes(w.status) ||
        !["OWNER", "ADMIN", "AUDITOR"].includes(w.assignedRole) ||
        !iso(w.updatedAt) || !id(w.lastActorId) ||
        w.providerActionCompleted !== false)
      problems.push("INVESTIGATION_WORK_ENTRY_INVALID");
    if (w && id(w.id)) workIds.add(w.id);
    if (!w || !Array.isArray(w.evidenceRequestIds) ||
        !Array.isArray(w.attachedEvidenceIds) ||
        !Array.isArray(w.notes) || w.notes.length > 1000)
      problems.push("INVESTIGATION_WORK_LIST_INVALID");
    else if (w.notes.some(n => !n || !id(n.id) ||
        !id(n.authorId) || !iso(n.at) ||
        typeof n.text !== "string" || !n.text.trim() ||
        n.text.length > 2000))
      problems.push("INVESTIGATION_WORK_NOTE_INVALID");
    if (w && w.assignedUserId !== null && !id(w.assignedUserId))
      problems.push("INVESTIGATION_WORK_ASSIGNEE_INVALID");
    if (w && w.reviewedBy !== null && !id(w.reviewedBy))
      problems.push("INVESTIGATION_WORK_REVIEWER_INVALID");
    if (w && w.status === "REVIEWED_INTERNAL" &&
        (!id(w.reviewedBy) || !iso(w.reviewedAt) ||
         !w.reviewDisposition || !w.reviewExplanation))
      problems.push("INVESTIGATION_WORK_REVIEW_INCOMPLETE");
  }
  for (const e of payload.evidence) {
    if (!e || !id(e.id) || evidenceIds.has(e.id) ||
        !id(e.requestId) || !evidenceKinds.includes(e.kind) ||
        !id(e.recordedBy) || !iso(e.recordedAt) ||
        typeof e.reference !== "string" || e.reference.length > 300 ||
        !e.reference.trim() ||
        !sha(e.digest) || e.digest !== coordinationDigest({
          requestId: e.requestId, kind: e.kind, reference: e.reference,
          description: e.description, recordedBy: e.recordedBy,
          recordedAt: e.recordedAt, provenance: e.provenance,
        }) || e.independentProviderProof !== false)
      problems.push("INVESTIGATION_EVIDENCE_INVALID");
    if (e && id(e.id)) evidenceIds.add(e.id);
  }
  for (const w of payload.work) {
    if (w?.attachedEvidenceIds.some(x => !evidenceIds.has(x)))
      problems.push("INVESTIGATION_EVIDENCE_ORPHANED");
  }
  const counts = deriveCounts(payload.work);
  if (payload.reviewedInternally !== counts.reviewedInternally ||
      payload.waitingEvidence !== counts.waitingEvidence)
    problems.push("INVESTIGATION_COUNTER_TAMPERED");
  if (payload.providerActionsConfirmed !== 0 ||
      payload.independentContainmentProof !== false)
    problems.push("INVESTIGATION_PROVIDER_CLAIM_FORGED");
  return [...new Set(problems)];
}
export function beginInvestigationReview(args: {
  recordId: string; incidentId: string; organizationId: string;
  incidentRevision: number; actorId: string; commandId: string;
  at: string; casebook: InvestigationCasebook;
}) {
  const b = args.casebook;
  if (!b || b.organizationId !== args.organizationId ||
      b.incidentId !== args.incidentId ||
      !sha(b.digest) || !sha(b.sourceReportDigest) ||
      b.providerOutcomesVerified !== false ||
      b.externalWrites !== 0)
    fail("INVESTIGATION_CASEBOOK_SCOPE_INVALID");
  const work: InvestigationWork[] = b.tasks.map(t => ({
    id: t.id, sourceTaskId: t.id,
    priority: t.priority, assignedRole: t.assignedRole,
    assignedUserId: null, assignedBy: null, assignedAt: null,
    status: "UNASSIGNED", lastActorId: args.actorId,
    updatedAt: args.at, evidenceRequestIds: [...t.evidenceRequestIds],
    attachedEvidenceIds: [], reviewRequestedBy: null,
    reviewedBy: null, reviewedAt: null,
    reviewDisposition: null, reviewExplanation: null,
    notes: [], providerActionCompleted: false,
  }));
  const payload: InvestigationReviewPayload = {
    schema: "cyberpilot.incident.investigation.work.v1",
    originalCasebookDigest: b.digest,
    originalForensicDigest: b.sourceReportDigest,
    sourceIncidentRevision: args.incidentRevision,
    sourceComplete: b.inventoryComplete,
    work, evidence: [], sourceLimitations: [...b.limitations],
    ...deriveCounts(work),
    providerActionsConfirmed: 0, independentContainmentProof: false,
  };
  if (validateInvestigationReviewPayload(payload).length)
    fail("INVESTIGATION_INITIAL_PAYLOAD_INVALID");
  return createCoordination({
    id: args.recordId, organizationId: args.organizationId,
    incidentId: args.incidentId, kind: "INVESTIGATION",
    state: "OPEN", sourceDigest: b.digest,
    actorId: args.actorId, at: args.at, commandId: args.commandId,
    payload,
  });
}
function reason(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 12 ||
      value.length > 2000)
    fail("INVESTIGATION_REASON_INVALID");
  return (value as string).trim();
}
function note(
  work: InvestigationWork, text: string, id: string,
  actor: string, at: string,
) {
  if (!id || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(id) ||
      work.notes.some(n => n.id === id) || work.notes.length >= 1000)
    fail("INVESTIGATION_NOTE_DUPLICATE_OR_LIMIT");
  work.notes.push({ id, authorId: actor, at, text });
}
function copyWork(item: InvestigationWork): InvestigationWork {
  return { ...item, notes: item.notes.map(n => ({ ...n })),
    attachedEvidenceIds: [...item.attachedEvidenceIds],
    evidenceRequestIds: [...item.evidenceRequestIds] };
}
export function applyInvestigationReview(
  current: CoordinationEnvelope<InvestigationReviewPayload>,
  command: CoordinationCommand<InvestigationReviewCommandAction>,
  lastEventDigest: string,
) {
  if (current.kind !== "INVESTIGATION" ||
      validateInvestigationReviewPayload(current.payload).length)
    fail("INVESTIGATION_CURRENT_CORRUPT");
  if (!["OWNER", "ADMIN"].includes(command.role))
    fail("INVESTIGATION_WRITE_ROLE_DENIED");
  if (current.state === "CLOSED_INTERNAL")
    fail("INVESTIGATION_CLOSED");
  const action = command.action;
  if (!action || typeof action.kind !== "string")
    fail("INVESTIGATION_ACTION_INVALID");
  const payload = current.payload;
  const work = payload.work.map(copyWork);
  const evidence = payload.evidence.map(e => ({ ...e }));
  const target = "workId" in action ?
    work.find(w => w.id === action.workId) : null;
  if (action.kind !== "CLOSE" && !target)
    fail("INVESTIGATION_WORK_NOT_FOUND");
  const explanation = reason(action.reason);
  const actor = command.actorId;
  const at = command.at;
  if (action.kind === "ASSIGN") {
    if (!id(action.assigneeId))
      fail("INVESTIGATION_ASSIGNEE_INVALID");
    if (!["UNASSIGNED", "ASSIGNED", "RETURNED", "REOPENED"].includes(
        target!.status))
      fail("INVESTIGATION_ASSIGN_STATE_INVALID");
    target!.assignedUserId = action.assigneeId;
    target!.assignedBy = actor; target!.assignedAt = at;
    target!.status = "ASSIGNED";
  } else if (action.kind === "START") {
    if (target!.assignedUserId !== actor ||
        !["ASSIGNED", "REOPENED"].includes(target!.status))
      fail("INVESTIGATION_START_ASSIGNEE_OR_STATE");
    target!.status = "IN_PROGRESS";
  } else if (action.kind === "REQUEST_EVIDENCE") {
    if (target!.assignedUserId !== actor ||
        !["ASSIGNED", "IN_PROGRESS", "RETURNED"].includes(target!.status))
      fail("INVESTIGATION_EVIDENCE_REQUEST_DENIED");
    target!.status = "WAITING_EVIDENCE";
  } else if (action.kind === "ADD_NOTE") {
    if (!["ASSIGNED", "IN_PROGRESS", "WAITING_EVIDENCE", "RETURNED",
      "READY_FOR_REVIEW", "REOPENED"].includes(target!.status))
      fail("INVESTIGATION_NOTE_STATE_DENIED");
    note(target!, explanation, action.noteId, actor, at);
  } else if (action.kind === "ADD_EVIDENCE") {
    if (!["IN_PROGRESS", "WAITING_EVIDENCE", "RETURNED"].includes(
        target!.status))
      fail("INVESTIGATION_EVIDENCE_STATE_INVALID");
    if (target!.assignedUserId !== actor ||
        !target!.evidenceRequestIds.includes(action.requestId))
      fail("INVESTIGATION_EVIDENCE_OWNER_OR_REQUEST");
    if (!id(action.evidenceId) || !evidenceKinds.includes(action.evidenceKind) ||
        evidence.some(e => e.id === action.evidenceId) ||
        !action.reference?.trim() || action.reference.length > 300 ||
        !action.description?.trim() || action.description.length > 2000 ||
        !["INTERNAL", "EXTERNAL_REFERENCE_UNVERIFIED"].includes(
          action.provenance))
      fail("INVESTIGATION_EVIDENCE_INPUT_INVALID");
    const e: Omit<InvestigationEvidence, "digest"> = {
      id: action.evidenceId, requestId: action.requestId,
      kind: action.evidenceKind, reference: action.reference,
      description: action.description, recordedBy: actor,
      recordedAt: at, provenance: action.provenance,
      independentProviderProof: false,
    };
    evidence.push({ ...e, digest: coordinationDigest({
      requestId: e.requestId, kind: e.kind, reference: e.reference,
      description: e.description, recordedBy: e.recordedBy,
      recordedAt: e.recordedAt, provenance: e.provenance,
    }) });
    target!.attachedEvidenceIds.push(action.evidenceId);
    target!.status = "IN_PROGRESS";
  } else if (action.kind === "SUBMIT_REVIEW") {
    if (target!.assignedUserId !== actor ||
        !["IN_PROGRESS", "WAITING_EVIDENCE"].includes(target!.status) ||
        target!.attachedEvidenceIds.length === 0)
      fail("INVESTIGATION_REVIEW_EVIDENCE_MISSING");
    target!.status = "READY_FOR_REVIEW";
    target!.reviewRequestedBy = actor;
  } else if (action.kind === "REVIEW") {
    if (target!.status !== "READY_FOR_REVIEW" ||
        target!.reviewRequestedBy === actor ||
        target!.assignedUserId === actor ||
        !["OWNER", "ADMIN"].includes(command.role))
      fail("INVESTIGATION_REVIEW_INDEPENDENCE_DENIED");
    if (!["SUFFICIENT_INTERNAL", "NEEDS_EVIDENCE"].includes(
        action.disposition))
      fail("INVESTIGATION_DISPOSITION_INVALID");
    target!.status = action.disposition === "SUFFICIENT_INTERNAL" ?
      "REVIEWED_INTERNAL" : "RETURNED";
    target!.reviewedBy = actor; target!.reviewedAt = at;
    target!.reviewDisposition = action.disposition;
    target!.reviewExplanation = explanation;
  } else if (action.kind === "REOPEN") {
    if (target!.status !== "REVIEWED_INTERNAL" ||
        target!.reviewedBy === actor)
      fail("INVESTIGATION_REOPEN_STATE_OR_INDEPENDENCE");
    target!.status = "REOPENED";
    target!.reviewRequestedBy = null;
    target!.reviewedBy = null; target!.reviewedAt = null;
    target!.reviewDisposition = null; target!.reviewExplanation = null;
  } else if (action.kind === "CLOSE") {
    if (work.length === 0 || work.some(w =>
        w.status !== "REVIEWED_INTERNAL"))
      fail("INVESTIGATION_CLOSE_UNREVIEWED_WORK");
    if (payload.sourceComplete !== true)
      fail("INVESTIGATION_CLOSE_INCOMPLETE_SOURCE");
  } else fail("INVESTIGATION_ACTION_UNSUPPORTED");
  if (target) {
    target.lastActorId = actor; target.updatedAt = at;
    if (action.kind !== "ADD_NOTE") note(
      target, explanation, command.commandId, actor, at);
  }
  const nextPayload: InvestigationReviewPayload = {
    ...payload, work, evidence, ...deriveCounts(work),
    independentContainmentProof: false, providerActionsConfirmed: 0,
  };
  if (validateInvestigationReviewPayload(nextPayload).length)
    fail("INVESTIGATION_MUTATION_PAYLOAD_INVALID");
  const nextState = action.kind === "CLOSE" ? "CLOSED_INTERNAL" :
    work.every(w => w.status === "REVIEWED_INTERNAL") ?
      "PENDING_REVIEW" : "ACTIVE";
  return evolveCoordination({
    current, command, lastEventDigest, nextPayload,
    nextState, operation: action.kind,
  });
}
export function summarizeInvestigationReview(
  value: CoordinationEnvelope<InvestigationReviewPayload>,
) {
  if (value.kind !== "INVESTIGATION" ||
      validateInvestigationReviewPayload(value.payload).length)
    fail("INVESTIGATION_SUMMARY_INVALID");
  const p = value.payload;
  return {
    schema: "cyberpilot.incident.investigation.review-summary.v1" as const,
    recordId: value.id, incidentId: value.incidentId,
    revision: value.revision, state: value.state,
    workTotal: p.work.length, reviewedInternally: p.reviewedInternally,
    waitingEvidence: p.waitingEvidence,
    attachedEvidence: p.evidence.length,
    unassigned: p.work.filter(w => w.assignedUserId === null).length,
    readyForReview: p.work.filter(w =>
      w.status === "READY_FOR_REVIEW").length,
    sourceComplete: p.sourceComplete,
    providerActionsConfirmed: 0 as const,
    independentContainmentProof: false as const,
  };
}
export function investigationWorkQueue(
  value: CoordinationEnvelope<InvestigationReviewPayload>,
  userId?: string,
) {
  if (validateInvestigationReviewPayload(value.payload).length)
    fail("INVESTIGATION_QUEUE_INVALID");
  const priority = ["P0", "P1", "P2", "P3"];
  return value.payload.work.filter(w =>
    !userId || w.assignedUserId === userId).sort((a, b) =>
      priority.indexOf(a.priority) - priority.indexOf(b.priority) ||
      a.updatedAt.localeCompare(b.updatedAt) ||
      a.id.localeCompare(b.id));
}
export function investigationEvidenceGapMatrix(
  value: CoordinationEnvelope<InvestigationReviewPayload>,
) {
  if (validateInvestigationReviewPayload(value.payload).length)
    fail("INVESTIGATION_MATRIX_INVALID");
  const evidence = new Map(value.payload.evidence.map(e => [e.id, e]));
  return value.payload.work.map(w => {
    const attached = w.attachedEvidenceIds.map(id => evidence.get(id)!);
    const covered = new Set(attached.map(x => x.requestId));
    return {
      workId: w.id, priority: w.priority, status: w.status,
      expectedRequests: w.evidenceRequestIds.length,
      coveredRequests: covered.size,
      uncoveredRequestIds: w.evidenceRequestIds.filter(x => !covered.has(x)),
      independentProviderReceipts: 0,
      locallyReviewed: w.status === "REVIEWED_INTERNAL",
      providerOutcomeConfirmed: false,
    };
  });
}
function csvField(s: string) {
  const escaped = /^[\s]*[=+@-]/.test(s) ? "'" + s : s;
  return '"' + escaped.replace(/"/g, '""') + '"';
}
export function exportInvestigationReviewCSV(
  value: CoordinationEnvelope<InvestigationReviewPayload>,
) {
  if (validateInvestigationReviewPayload(value.payload).length)
    fail("INVESTIGATION_EXPORT_INVALID");
  const columns = ["workId", "priority", "status", "assignedRole",
    "assignedUserId", "reviewedBy", "attachedEvidence", "providerVerified"];
  return [columns.join(","), ...value.payload.work.map(w => [
    w.id, w.priority, w.status, w.assignedRole,
    w.assignedUserId ?? "", w.reviewedBy ?? "",
    String(w.attachedEvidenceIds.length), "false",
  ].map(csvField).join(","))].join("\r\n") + "\r\n";
}
