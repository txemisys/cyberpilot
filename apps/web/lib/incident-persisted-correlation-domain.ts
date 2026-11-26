import {
  createCoordination, evolveCoordination, coordinationDigest,
  assertCoordinationPreconditions,
  type CoordinationEnvelope, type CoordinationCommand,
} from "./incident-coordination-ledger-domain";
import type {
  CorrelationReport, CorrelationFinding, CorrelationKind,
  CorrelationPriority,
} from "./incident-crosscase-correlation-domain";
/**
 * The persisted 6W correlation board manages hypotheses, NOT identities.
 * A matched actor or source key cannot promote to a verified compromise.
 */
export type CorrelationReviewState =
  "OPEN" | "ASSIGNED" | "ANALYZING" | "EVIDENCE_REQUIRED" |
  "READY_FOR_REVIEW" | "SUPPORTED_INTERNAL" | "REJECTED_INTERNAL" |
  "INCONCLUSIVE" | "REOPENED";
export type CorrelationReviewEvidence = {
  id: string; findingId: string; reference: string;
  sourceIncidentId: string; recordedBy: string; recordedAt: string;
  sourceCategory: "LOCAL_AUDIT" | "EXTERNAL_UNVERIFIED" |
    "OPERATOR_ATTESTATION";
  scopeChecked: boolean; digest: string;
  externalIdentityVerified: false;
};
export type CorrelationHypothesis = {
  id: string; sourceFindingId: string;
  incidentIds: [string, string]; kind: CorrelationKind;
  priority: CorrelationPriority; originalExplanation: string;
  originalEvidenceDigest: string;
  state: CorrelationReviewState;
  assignedUserId: string | null; assignedBy: string | null;
  ownerRole: "OWNER" | "ADMIN" | "AUDITOR";
  explanation: string | null;
  alternateExplanations: string[];
  attachedEvidenceIds: string[];
  submittedBy: string | null; submittedAt: string | null;
  reviewedBy: string | null; reviewedAt: string | null;
  reviewConclusion: string | null;
  lastChangedAt: string;
  locallyCorrelated: boolean;
  independentProviderIdentityProven: false;
  compromiseEstablished: false;
};
export type CorrelationBoardPayload = {
  schema: "cyberpilot.incident.correlation.review-board.v1";
  sourceReportDigest: string; sourceSelectionDigest: string;
  selectedIncidentIds: string[]; sourceReportWasTruncated: boolean;
  sourceInventoryComplete: false;
  hypotheses: CorrelationHypothesis[];
  evidence: CorrelationReviewEvidence[];
  decisions: Array<{
    hypothesisId: string; reviewedBy: string; at: string;
    conclusion: "SUPPORTED_INTERNAL" | "REJECTED_INTERNAL" |
      "INCONCLUSIVE"; explanation: string;
  }>;
  supportedInternally: number; rejectedInternally: number;
  inconclusive: number; pendingReview: number;
  externalMutations: 0; providerCompromisesConfirmed: 0;
};
export type CorrelationBoardAction =
  | { kind: "ASSIGN"; hypothesisId: string;
      assigneeId: string; reason: string }
  | { kind: "START"; hypothesisId: string; reason: string }
  | { kind: "ALTERNATIVE"; hypothesisId: string; reason: string }
  | { kind: "ADD_EVIDENCE"; hypothesisId: string; evidenceId: string;
      incidentId: string; reference: string;
      sourceCategory: CorrelationReviewEvidence["sourceCategory"];
      scopeChecked: boolean; reason: string }
  | { kind: "REQUIRE_EVIDENCE"; hypothesisId: string; reason: string }
  | { kind: "SUBMIT"; hypothesisId: string; reason: string }
  | { kind: "DECIDE"; hypothesisId: string;
      conclusion: "SUPPORTED_INTERNAL" | "REJECTED_INTERNAL" |
        "INCONCLUSIVE"; reason: string }
  | { kind: "REOPEN"; hypothesisId: string; reason: string }
  | { kind: "CLOSE"; reason: string };
const id = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const sha = (v: unknown): v is string => typeof v === "string" &&
  /^[0-9a-f]{64}$/.test(v);
const iso = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const states: CorrelationReviewState[] = [
  "OPEN", "ASSIGNED", "ANALYZING", "EVIDENCE_REQUIRED",
  "READY_FOR_REVIEW", "SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
  "INCONCLUSIVE", "REOPENED",
];
const kinds: CorrelationKind[] = [
  "SHARED_ACTOR", "REPEATED_OPERATION", "COMMON_SOURCE_KEY",
  "NEARBY_ACTIVITY", "REPEATED_FORENSIC_FINDING", "JOINT_COVERAGE_GAP",
  "SOURCE_CONFLICT_CLUSTER",
];
const fail = (code: string): never => { throw Error(code); };
function goodReason(input: unknown): string {
  if (typeof input !== "string" || input.trim().length < 15 ||
      input.length > 2000) fail("CORRELATION_REVIEW_REASON_INVALID");
  return (input as string).trim();
}
function tally(hypotheses: CorrelationHypothesis[]) {
  return {
    supportedInternally: hypotheses.filter(x =>
      x.state === "SUPPORTED_INTERNAL").length,
    rejectedInternally: hypotheses.filter(x =>
      x.state === "REJECTED_INTERNAL").length,
    inconclusive: hypotheses.filter(x =>
      x.state === "INCONCLUSIVE").length,
    pendingReview: hypotheses.filter(x =>
      x.state === "READY_FOR_REVIEW").length,
  };
}
export function validateCorrelationBoardPayload(
  payload: CorrelationBoardPayload,
): string[] {
  const issues: string[] = [];
  if (!payload || payload.schema !==
      "cyberpilot.incident.correlation.review-board.v1" ||
      !sha(payload.sourceReportDigest) ||
      !sha(payload.sourceSelectionDigest) ||
      typeof payload.sourceReportWasTruncated !== "boolean" ||
      payload.sourceInventoryComplete !== false)
    issues.push("CORRELATION_BOARD_HEADER_INVALID");
  if (!Array.isArray(payload?.selectedIncidentIds) ||
      payload.selectedIncidentIds.length < 2 ||
      payload.selectedIncidentIds.length > 50 ||
      payload.selectedIncidentIds.some(x => !id(x)) ||
      new Set(payload.selectedIncidentIds).size !==
        payload.selectedIncidentIds.length)
    issues.push("CORRELATION_BOARD_SELECTION_INVALID");
  if (!Array.isArray(payload?.hypotheses) ||
      payload.hypotheses.length > 2000 ||
      !Array.isArray(payload?.evidence) ||
      payload.evidence.length > 5000 ||
      !Array.isArray(payload?.decisions) ||
      payload.decisions.length > 10000)
    return [...issues, "CORRELATION_BOARD_BOUNDS_INVALID"];
  const hypothesisIds = new Set<string>();
  const evidenceIds = new Set<string>();
  for (const h of payload.hypotheses) {
    if (!h || !id(h.id) || hypothesisIds.has(h.id) ||
        !id(h.sourceFindingId) || !kinds.includes(h.kind) ||
        !states.includes(h.state) || !sha(h.originalEvidenceDigest) ||
        !iso(h.lastChangedAt) ||
        !Array.isArray(h.incidentIds) || h.incidentIds.length !== 2 ||
        h.incidentIds.some(x => !payload.selectedIncidentIds.includes(x)) ||
        h.incidentIds[0] === h.incidentIds[1] ||
        h.independentProviderIdentityProven !== false ||
        h.compromiseEstablished !== false)
      issues.push("CORRELATION_HYPOTHESIS_INVALID");
    if (h && id(h.id)) hypothesisIds.add(h.id);
    if (h && (!Array.isArray(h.alternateExplanations) ||
        h.alternateExplanations.length > 100 ||
        !Array.isArray(h.attachedEvidenceIds) ||
        h.attachedEvidenceIds.length > 1500))
      issues.push("CORRELATION_HYPOTHESIS_LIST_INVALID");
    if (h && h.assignedUserId !== null && !id(h.assignedUserId))
      issues.push("CORRELATION_HYPOTHESIS_OWNER_INVALID");
    if (h && ["SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
        "INCONCLUSIVE"].includes(h.state) &&
        (!id(h.reviewedBy) || !iso(h.reviewedAt) ||
         !h.reviewConclusion))
      issues.push("CORRELATION_HYPOTHESIS_UNREVIEWED");
  }
  for (const e of payload.evidence) {
    if (!e || !id(e.id) || evidenceIds.has(e.id) ||
        !hypothesisIds.has(e.findingId) ||
        !payload.selectedIncidentIds.includes(e.sourceIncidentId) ||
        !id(e.recordedBy) || !iso(e.recordedAt) ||
        typeof e.reference !== "string" || !e.reference.trim() ||
        e.reference.length > 300 ||
        typeof e.scopeChecked !== "boolean" ||
        e.externalIdentityVerified !== false ||
        e.digest !== coordinationDigest({
          findingId: e.findingId, reference: e.reference,
          sourceIncidentId: e.sourceIncidentId, recordedBy: e.recordedBy,
          recordedAt: e.recordedAt, sourceCategory: e.sourceCategory,
          scopeChecked: e.scopeChecked,
        }))
      issues.push("CORRELATION_EVIDENCE_INVALID");
    if (e && id(e.id)) evidenceIds.add(e.id);
  }
  for (const h of payload.hypotheses) {
    if (h?.attachedEvidenceIds.some(x => !evidenceIds.has(x)))
      issues.push("CORRELATION_EVIDENCE_ORPHAN");
  }
  for (const decision of payload.decisions) {
    if (!decision || !hypothesisIds.has(decision.hypothesisId) ||
        !id(decision.reviewedBy) || !iso(decision.at) ||
        !["SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
          "INCONCLUSIVE"].includes(decision.conclusion) ||
        !decision.explanation?.trim())
      issues.push("CORRELATION_DECISION_INVALID");
  }
  const totals = tally(payload.hypotheses);
  if (Object.entries(totals).some(([k, v]) =>
      payload[k as keyof typeof totals] !== v))
    issues.push("CORRELATION_BOARD_COUNTER_INVALID");
  if (payload.externalMutations !== 0 ||
      payload.providerCompromisesConfirmed !== 0)
    issues.push("CORRELATION_BOARD_EXTERNAL_CLAIM_FORGED");
  return [...new Set(issues)];
}
function fingerprint(f: CorrelationFinding): string {
  return coordinationDigest({
    id: f.id, kind: f.kind, priority: f.priority,
    left: f.leftIncidentId, right: f.rightIncidentId,
    evidence: f.evidence, strength: f.strength,
  });
}
export function beginCorrelationBoard(args: {
  organizationId: string; incidentId: string; recordId: string;
  actorId: string; at: string; commandId: string;
  report: CorrelationReport;
}) {
  const r = args.report;
  if (r.organizationId !== args.organizationId ||
      !r.selectedIncidentIds.includes(args.incidentId) ||
      r.externalActions !== 0 ||
      r.providerIdentityConfirmed !== false ||
      r.providerContainmentConfirmed !== false ||
      !sha(r.digest) || r.findings.length > 2000)
    fail("CORRELATION_SOURCE_UNSAFE");
  const hypotheses: CorrelationHypothesis[] = r.findings.map(f => ({
    id: "hypothesis:" + coordinationDigest(f.id).slice(0, 36),
    sourceFindingId: f.id,
    incidentIds: [f.leftIncidentId, f.rightIncidentId],
    kind: f.kind, priority: f.priority,
    originalExplanation: f.explanation,
    originalEvidenceDigest: fingerprint(f),
    state: "OPEN", assignedUserId: null, assignedBy: null,
    ownerRole: "ADMIN", explanation: null, alternateExplanations: [],
    attachedEvidenceIds: [], submittedBy: null, submittedAt: null,
    reviewedBy: null, reviewedAt: null, reviewConclusion: null,
    lastChangedAt: args.at, locallyCorrelated: false,
    independentProviderIdentityProven: false,
    compromiseEstablished: false,
  }));
  const payload: CorrelationBoardPayload = {
    schema: "cyberpilot.incident.correlation.review-board.v1",
    sourceReportDigest: r.digest,
    sourceSelectionDigest: r.selectionDigest,
    selectedIncidentIds: [...r.selectedIncidentIds],
    sourceReportWasTruncated: r.resultsTruncated,
    sourceInventoryComplete: false,
    hypotheses, evidence: [], decisions: [], ...tally(hypotheses),
    externalMutations: 0, providerCompromisesConfirmed: 0,
  };
  if (validateCorrelationBoardPayload(payload).length)
    fail("CORRELATION_INITIAL_BOARD_INVALID");
  return createCoordination({
    id: args.recordId, organizationId: args.organizationId,
    incidentId: args.incidentId, kind: "CORRELATION",
    state: "OPEN", sourceDigest: r.digest, payload,
    actorId: args.actorId, commandId: args.commandId, at: args.at,
  });
}
export function applyCorrelationBoard(
  current: CoordinationEnvelope<CorrelationBoardPayload>,
  command: CoordinationCommand<CorrelationBoardAction>,
  lastEventDigest: string,
) {
  assertCoordinationPreconditions(current, command);
  if (current.kind !== "CORRELATION" ||
      validateCorrelationBoardPayload(current.payload).length)
    fail("CORRELATION_CURRENT_BOARD_INVALID");
  if (command.role === "AUDITOR")
    fail("CORRELATION_REVIEW_WRITE_DENIED");
  if (current.state === "CLOSED_INTERNAL")
    fail("CORRELATION_BOARD_CLOSED");
  const action = command.action;
  const reason = goodReason(action.reason);
  const actor = command.actorId;
  const at = command.at;
  const previous = current.payload;
  const hypotheses = previous.hypotheses.map(h => ({
    ...h, alternateExplanations: [...h.alternateExplanations],
    attachedEvidenceIds: [...h.attachedEvidenceIds],
    incidentIds: [...h.incidentIds] as [string, string],
  }));
  const evidence = previous.evidence.map(e => ({ ...e }));
  const decisions = previous.decisions.map(d => ({ ...d }));
  const target = "hypothesisId" in action ?
    hypotheses.find(h => h.id === action.hypothesisId) : null;
  if (action.kind !== "CLOSE" && !target)
    fail("CORRELATION_HYPOTHESIS_NOT_FOUND");
  if (action.kind === "ASSIGN") {
    if (!id(action.assigneeId) ||
        !["OPEN", "ASSIGNED", "REOPENED"].includes(target!.state))
      fail("CORRELATION_ASSIGN_INVALID");
    target!.assignedUserId = action.assigneeId;
    target!.assignedBy = actor; target!.state = "ASSIGNED";
  } else if (action.kind === "START") {
    if (target!.assignedUserId !== actor ||
        !["ASSIGNED", "REOPENED"].includes(target!.state))
      fail("CORRELATION_START_DENIED");
    target!.state = "ANALYZING";
  } else if (action.kind === "ALTERNATIVE") {
    if (target!.assignedUserId !== actor ||
        !["ANALYZING", "EVIDENCE_REQUIRED"].includes(target!.state) ||
        target!.alternateExplanations.length >= 100)
      fail("CORRELATION_ALTERNATIVE_DENIED");
    target!.alternateExplanations.push(reason);
  } else if (action.kind === "ADD_EVIDENCE") {
    if (target!.assignedUserId !== actor ||
        !["ANALYZING", "EVIDENCE_REQUIRED"].includes(target!.state) ||
        !id(action.evidenceId) ||
        !target!.incidentIds.includes(action.incidentId) ||
        !action.reference?.trim() || action.reference.length > 300 ||
        !["LOCAL_AUDIT", "EXTERNAL_UNVERIFIED",
          "OPERATOR_ATTESTATION"].includes(action.sourceCategory) ||
        typeof action.scopeChecked !== "boolean" ||
        evidence.some(e => e.id === action.evidenceId))
      fail("CORRELATION_EVIDENCE_DENIED");
    const fields = {
      findingId: target!.id, reference: action.reference,
      sourceIncidentId: action.incidentId, recordedBy: actor,
      recordedAt: at, sourceCategory: action.sourceCategory,
      scopeChecked: action.scopeChecked,
    };
    evidence.push({
      ...fields, id: action.evidenceId,
      digest: coordinationDigest(fields), externalIdentityVerified: false,
    });
    target!.attachedEvidenceIds.push(action.evidenceId);
    target!.state = "ANALYZING";
  } else if (action.kind === "REQUIRE_EVIDENCE") {
    if (target!.assignedUserId !== actor ||
        target!.state !== "ANALYZING")
      fail("CORRELATION_EVIDENCE_STATE_DENIED");
    target!.state = "EVIDENCE_REQUIRED";
  } else if (action.kind === "SUBMIT") {
    if (target!.assignedUserId !== actor ||
        !["ANALYZING", "EVIDENCE_REQUIRED"].includes(target!.state) ||
        target!.alternateExplanations.length === 0 ||
        target!.attachedEvidenceIds.length === 0)
      fail("CORRELATION_SUBMISSION_INCOMPLETE");
    target!.state = "READY_FOR_REVIEW";
    target!.submittedBy = actor; target!.submittedAt = at;
  } else if (action.kind === "DECIDE") {
    if (target!.state !== "READY_FOR_REVIEW" ||
        target!.submittedBy === actor ||
        target!.assignedUserId === actor ||
        !["SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
          "INCONCLUSIVE"].includes(action.conclusion))
      fail("CORRELATION_REVIEW_INDEPENDENCE_DENIED");
    target!.state = action.conclusion;
    target!.reviewedBy = actor; target!.reviewedAt = at;
    target!.reviewConclusion = reason;
    target!.locallyCorrelated = action.conclusion === "SUPPORTED_INTERNAL";
    decisions.push({
      hypothesisId: target!.id, reviewedBy: actor,
      at, conclusion: action.conclusion, explanation: reason,
    });
  } else if (action.kind === "REOPEN") {
    if (!["SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
        "INCONCLUSIVE"].includes(target!.state) ||
        target!.reviewedBy === actor)
      fail("CORRELATION_REOPEN_DENIED");
    target!.state = "REOPENED"; target!.submittedBy = null;
    target!.submittedAt = null; target!.reviewedBy = null;
    target!.reviewedAt = null; target!.reviewConclusion = null;
    target!.locallyCorrelated = false;
  } else if (action.kind === "CLOSE") {
    if (hypotheses.some(h => !["SUPPORTED_INTERNAL",
        "REJECTED_INTERNAL", "INCONCLUSIVE"].includes(h.state)) ||
        previous.sourceReportWasTruncated)
      fail("CORRELATION_CLOSE_UNRESOLVED_OR_TRUNCATED");
  } else fail("CORRELATION_ACTION_INVALID");
  if (target) {
    target.lastChangedAt = at; target.explanation = reason;
  }
  const payload: CorrelationBoardPayload = {
    ...previous, hypotheses, evidence, decisions, ...tally(hypotheses),
    sourceInventoryComplete: false,
    externalMutations: 0, providerCompromisesConfirmed: 0,
  };
  if (validateCorrelationBoardPayload(payload).length)
    fail("CORRELATION_MUTATED_BOARD_INVALID");
  const nextState = action.kind === "CLOSE" ? "CLOSED_INTERNAL" :
    hypotheses.some(h => h.state === "READY_FOR_REVIEW") ?
      "PENDING_REVIEW" : "ACTIVE";
  return evolveCoordination({
    current, command, lastEventDigest,
    nextPayload: payload, nextState, operation: action.kind,
  });
}
export function summarizeCorrelationBoard(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  if (record.kind !== "CORRELATION" ||
      validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_SUMMARY_INVALID");
  const p = record.payload;
  return {
    schema: "cyberpilot.incident.correlation.review-summary.v1" as const,
    recordId: record.id, incidentIds: p.selectedIncidentIds,
    selectedCases: p.selectedIncidentIds.length,
    candidates: p.hypotheses.length,
    supportedInternally: p.supportedInternally,
    rejectedInternally: p.rejectedInternally,
    inconclusive: p.inconclusive, pendingReview: p.pendingReview,
    unassigned: p.hypotheses.filter(h => h.assignedUserId === null).length,
    evidenceReferences: p.evidence.length,
    identityConfirmedByProvider: false as const,
    providerActions: 0 as const,
    sourceTruncated: p.sourceReportWasTruncated,
  };
}
export function correlationHypothesisQueue(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
  assigneeId?: string,
) {
  if (validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_QUEUE_INVALID");
  const priorities = ["P0", "P1", "P2", "P3"];
  return record.payload.hypotheses.filter(h =>
    !assigneeId || h.assignedUserId === assigneeId).sort((a, b) =>
      priorities.indexOf(a.priority) - priorities.indexOf(b.priority) ||
      a.lastChangedAt.localeCompare(b.lastChangedAt) ||
      a.id.localeCompare(b.id));
}
export function correlationReviewIntegrityMatrix(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  if (validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_MATRIX_INVALID");
  return record.payload.hypotheses.map(h => {
    const localSources = record.payload.evidence.filter(e =>
      h.attachedEvidenceIds.includes(e.id));
    const scopeUnchecked = localSources.filter(e => !e.scopeChecked).length;
    return {
      hypothesisId: h.id, priority: h.priority,
      originalSourceDigest: h.originalEvidenceDigest,
      currentState: h.state, evidenceCount: localSources.length,
      scopeUnchecked, alternateExplanations: h.alternateExplanations.length,
      independentlyReviewed: !!h.reviewedBy && !!h.reviewedAt &&
        h.reviewedBy !== h.submittedBy,
      providerIdentityVerified: false,
      externalContainmentVerified: false,
    };
  });
}
function csvSafe(value: string) {
  const safe = /^[\s]*[=+@-]/.test(value) ? "'" + value : value;
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function exportCorrelationBoardCSV(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  if (validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_EXPORT_INVALID");
  const head = ["hypothesisId", "incidentOne", "incidentTwo", "kind",
    "priority", "status", "assignee", "reviewer", "localEvidence",
    "identityVerified", "providerMutations"];
  return [head.join(","), ...record.payload.hypotheses.map(h => [
    h.id, h.incidentIds[0], h.incidentIds[1], h.kind, h.priority,
    h.state, h.assignedUserId ?? "", h.reviewedBy ?? "",
    String(h.attachedEvidenceIds.length), "false", "0",
  ].map(csvSafe).join(","))].join("\r\n") + "\r\n";
}
export function compareCorrelationBoards(
  before: CoordinationEnvelope<CorrelationBoardPayload>,
  after: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  if (validateCorrelationBoardPayload(before.payload).length ||
      validateCorrelationBoardPayload(after.payload).length ||
      before.organizationId !== after.organizationId ||
      before.id !== after.id || before.incidentId !== after.incidentId)
    fail("CORRELATION_COMPARE_INVALID");
  const earlier = new Map(before.payload.hypotheses.map(x => [x.id, x]));
  const later = new Map(after.payload.hypotheses.map(x => [x.id, x]));
  return {
    schema: "cyberpilot.incident.correlation.review-diff.v1" as const,
    changed: after.payload.hypotheses.filter(x =>
      earlier.get(x.id)?.state !== x.state),
    newCandidates: after.payload.hypotheses.filter(x =>
      !earlier.has(x.id)),
    disappearedCandidates: before.payload.hypotheses.filter(x =>
      !later.has(x.id)),
    sourceChanged: before.sourceDigest !== after.sourceDigest,
    previousDigest: coordinationDigest(before),
    currentDigest: coordinationDigest(after),
    independentIdentityProven: false as const,
    disappearanceDoesNotProveContainment: true as const,
  };
}

export type CorrelationReadiness = {
  hypothesisId: string;
  state: CorrelationReviewState;
  assigned: boolean;
  hasAlternativeExplanation: boolean;
  hasScopedEvidence: boolean;
  hasUnscopedEvidence: boolean;
  independentReviewerAvailable: boolean;
  canSubmitForReview: boolean;
  canCompleteInternally: boolean;
  blockers: string[];
  independentProviderConfirmation: false;
};
export function assessCorrelationReadiness(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
): CorrelationReadiness[] {
  if (validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_READINESS_SOURCE_INVALID");
  const evidence = new Map(record.payload.evidence.map(x => [x.id, x]));
  return record.payload.hypotheses.map(h => {
    const attached = h.attachedEvidenceIds.map(id => evidence.get(id)!);
    const hasScopedEvidence = attached.some(e => e.scopeChecked);
    const hasUnscopedEvidence = attached.some(e => !e.scopeChecked);
    const hasAlternativeExplanation = h.alternateExplanations.length > 0;
    const assigned = h.assignedUserId !== null;
    const independentReviewerAvailable = h.submittedBy !== null &&
      h.assignedUserId !== null;
    const blockers: string[] = [];
    if (!assigned) blockers.push("ASSIGNEE_REQUIRED");
    if (!hasAlternativeExplanation) blockers.push("ALTERNATIVE_MISSING");
    if (!attached.length) blockers.push("EVIDENCE_MISSING");
    if (!hasScopedEvidence) blockers.push("SCOPED_EVIDENCE_MISSING");
    if (hasUnscopedEvidence) blockers.push("UNSCOPED_REFERENCE_REVIEW");
    if (record.payload.sourceReportWasTruncated)
      blockers.push("SOURCE_REPORT_TRUNCATED");
    const canSubmitForReview = assigned &&
      hasAlternativeExplanation && attached.length > 0 &&
      ["ANALYZING", "EVIDENCE_REQUIRED"].includes(h.state);
    const canCompleteInternally =
      ["SUPPORTED_INTERNAL", "REJECTED_INTERNAL",
        "INCONCLUSIVE"].includes(h.state) &&
      h.reviewedBy !== null && h.submittedBy !== null &&
      h.reviewedBy !== h.submittedBy;
    return {
      hypothesisId: h.id, state: h.state, assigned,
      hasAlternativeExplanation, hasScopedEvidence,
      hasUnscopedEvidence, independentReviewerAvailable,
      canSubmitForReview, canCompleteInternally, blockers,
      independentProviderConfirmation: false,
    };
  });
}
export function correlationPendingReviewQueue(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  const readiness = assessCorrelationReadiness(record);
  const priorityOrder = ["P0", "P1", "P2", "P3"];
  return record.payload.hypotheses.filter(h =>
    h.state === "READY_FOR_REVIEW").map(h => {
      const inspection = readiness.find(x => x.hypothesisId === h.id)!;
      return {
        hypothesisId: h.id, priority: h.priority,
        assignedUserId: h.assignedUserId,
        submittedBy: h.submittedBy, submittedAt: h.submittedAt,
        selectedIncidentIds: h.incidentIds,
        unscopedEvidence: inspection.hasUnscopedEvidence,
        alternateExplanations: h.alternateExplanations.length,
        reviewerMustDifferFromSubmitter: true as const,
        providerIdentityConfirmed: false as const,
      };
    }).sort((a, b) =>
      priorityOrder.indexOf(a.priority) -
        priorityOrder.indexOf(b.priority) ||
      (a.submittedAt ?? "").localeCompare(b.submittedAt ?? "") ||
      a.hypothesisId.localeCompare(b.hypothesisId));
}
export function correlationDecisionLedger(
  record: CoordinationEnvelope<CorrelationBoardPayload>,
) {
  if (validateCorrelationBoardPayload(record.payload).length)
    fail("CORRELATION_DECISION_LEDGER_INVALID");
  const reviews = new Map<string, number>();
  return record.payload.decisions.map((decision, index) => {
    const sequence = (reviews.get(decision.hypothesisId) ?? 0) + 1;
    reviews.set(decision.hypothesisId, sequence);
    const h = record.payload.hypotheses.find(
      x => x.id === decision.hypothesisId)!;
    return {
      sequence: index + 1, hypothesisSequence: sequence,
      hypothesisId: decision.hypothesisId,
      reviewedBy: decision.reviewedBy,
      conclusion: decision.conclusion, at: decision.at,
      explanation: decision.explanation,
      selectedIncidentIds: h.incidentIds,
      sourceReportDigest: record.payload.sourceReportDigest,
      internalOnly: true as const,
      externalProviderVerified: false as const,
    };
  });
}
