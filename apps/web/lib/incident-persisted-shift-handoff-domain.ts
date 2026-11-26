import {
  createCoordination, evolveCoordination, coordinationDigest,
  assertCoordinationPreconditions,
  type CoordinationEnvelope, type CoordinationCommand,
} from "./incident-coordination-ledger-domain";
import type {
  ShiftBriefing, ShiftWindow, ShiftWorkItem, ShiftWatchpoint,
} from "./incident-shift-briefing-domain";
/**
 * 6X handoff is a durable internal receipt of review, NOT proof that
 * an external action occurred. Incoming and outgoing actors are distinct.
 */
export type ShiftHandoffStatus =
  "PREPARED" | "SUBMITTED" | "RETURNED" | "ACCEPTED_INTERNAL" |
  "REOPENED" | "CLOSED_INTERNAL";
export type ShiftHandoffAcceptance = {
  reviewedBy: string; at: string;
  receivedDigest: string; notedWorkIds: string[];
  outstandingConcernIds: string[];
  explanation: string;
  acceptedInternally: true;
  providerContainmentConfirmed: false;
};
export type ShiftHandoffReturn = {
  returnedBy: string; at: string;
  explanation: string; reasonCategory:
    "MISSING_EVIDENCE" | "INCORRECT_SCOPE" |
    "STALE_SOURCE" | "OPERATIONAL_DISAGREEMENT";
  previousDigest: string;
};
export type ShiftHandoffNote = {
  id: string; actorId: string; at: string;
  workId: string | null; category:
    "RISK" | "MISSING_EVIDENCE" | "SOURCE_DRIFT" |
    "OWNERSHIP" | "SHIFT_CONTINUITY";
  text: string;
  digest: string;
};
export type ShiftHandoffPayload = {
  schema: "cyberpilot.incident.shift.handoff.v1";
  shiftId: string; incidentRevision: number;
  originalBriefingDigest: string;
  originalForensicDigest: string;
  originalInvestigationDigest: string;
  originalPolicyDigest: string;
  outgoingUserId: string;
  incomingUserId: string;
  outgoingRole: "OWNER" | "ADMIN";
  incomingRole: "OWNER" | "ADMIN";
  window: ShiftWindow;
  workItems: Array<Pick<ShiftWorkItem,
    "id" | "priority" | "category" | "dueAt" | "assignedRole" |
    "providerWritePermitted">>;
  watchpoints: Array<Pick<ShiftWatchpoint,
    "id" | "category" | "priority" | "trigger">>;
  sourceEvents: number; sourceComplete: boolean;
  acknowledgedWorkIds: string[];
  outstandingConcernIds: string[];
  status: ShiftHandoffStatus;
  submissionCount: number;
  submittedAt: string | null;
  submittedBy: string | null;
  accepted: ShiftHandoffAcceptance | null;
  returned: ShiftHandoffReturn[];
  notes: ShiftHandoffNote[];
  lastActorId: string; lastUpdatedAt: string;
  independentProviderProof: false;
  externalNotifications: 0; providerWrites: 0;
};
export type ShiftHandoffAction =
  | { kind: "ADD_NOTE"; noteId: string; workId: string | null;
      category: ShiftHandoffNote["category"]; reason: string }
  | { kind: "MARK_REVIEWED"; workId: string; reason: string }
  | { kind: "RAISE_CONCERN"; concernId: string; reason: string }
  | { kind: "CLEAR_CONCERN"; concernId: string; reason: string }
  | { kind: "SUBMIT"; reason: string }
  | { kind: "ACCEPT"; expectedSubmittedDigest: string; reason: string }
  | { kind: "RETURN"; expectedSubmittedDigest: string;
      category: ShiftHandoffReturn["reasonCategory"]; reason: string }
  | { kind: "REOPEN"; reason: string }
  | { kind: "CLOSE"; reason: string };
const id = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const sha = (v: unknown): v is string => typeof v === "string" &&
  /^[0-9a-f]{64}$/.test(v);
const iso = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const fail = (code: string): never => { throw Error(code); };
const statuses: ShiftHandoffStatus[] = [
  "PREPARED", "SUBMITTED", "RETURNED", "ACCEPTED_INTERNAL",
  "REOPENED", "CLOSED_INTERNAL",
];
const noteCategories: ShiftHandoffNote["category"][] = [
  "RISK", "MISSING_EVIDENCE", "SOURCE_DRIFT",
  "OWNERSHIP", "SHIFT_CONTINUITY",
];
function reason(x: unknown): string {
  if (typeof x !== "string" || x.trim().length < 15 ||
      x.length > 2000) fail("SHIFT_HANDOFF_REASON_INVALID");
  return (x as string).trim();
}
export function validateShiftHandoffPayload(
  value: ShiftHandoffPayload,
): string[] {
  const errors: string[] = [];
  if (!value || value.schema !== "cyberpilot.incident.shift.handoff.v1" ||
      !id(value.shiftId) || !id(value.outgoingUserId) ||
      !id(value.incomingUserId) ||
      value.outgoingUserId === value.incomingUserId ||
      ![value.originalBriefingDigest, value.originalForensicDigest,
        value.originalInvestigationDigest, value.originalPolicyDigest]
        .every(sha) ||
      !Number.isSafeInteger(value.incidentRevision) ||
      value.incidentRevision < 1 || !iso(value.lastUpdatedAt) ||
      !id(value.lastActorId))
    errors.push("SHIFT_HANDOFF_HEADER_INVALID");
  if (!statuses.includes(value?.status) ||
      !Number.isSafeInteger(value?.submissionCount) ||
      value.submissionCount < 0 || value.submissionCount > 100)
    errors.push("SHIFT_HANDOFF_STATUS_INVALID");
  if (value?.window?.acknowledgedBy !== null ||
      value?.window?.acceptedAt !== null ||
      value?.window?.incomingUserId !== null ||
      value?.window?.outgoingUserId !== value?.outgoingUserId)
    errors.push("SHIFT_HANDOFF_WINDOW_FORGED");
  if (!Array.isArray(value?.workItems) ||
      value.workItems.length > 1500 ||
      !Array.isArray(value?.watchpoints) ||
      value.watchpoints.length > 1500 ||
      !Array.isArray(value?.acknowledgedWorkIds) ||
      !Array.isArray(value?.outstandingConcernIds) ||
      !Array.isArray(value?.notes) || value.notes.length > 2000 ||
      !Array.isArray(value?.returned) || value.returned.length > 100)
    return [...errors, "SHIFT_HANDOFF_BOUNDS_INVALID"];
  const work = new Set(value.workItems.map(x => x.id));
  const watch = new Set(value.watchpoints.map(x => x.id));
  if (work.size !== value.workItems.length ||
      watch.size !== value.watchpoints.length ||
      value.workItems.some(x => !id(x.id) ||
        x.providerWritePermitted !== false) ||
      value.watchpoints.some(x => !id(x.id)))
    errors.push("SHIFT_HANDOFF_SOURCE_WORK_INVALID");
  if (new Set(value.acknowledgedWorkIds).size !==
        value.acknowledgedWorkIds.length ||
      value.acknowledgedWorkIds.some(x => !work.has(x)) ||
      new Set(value.outstandingConcernIds).size !==
        value.outstandingConcernIds.length ||
      value.outstandingConcernIds.some(x => !watch.has(x)))
    errors.push("SHIFT_HANDOFF_ACKNOWLEDGEMENT_INVALID");
  const notes = new Set<string>();
  for (const n of value.notes) {
    if (!n || !id(n.id) || notes.has(n.id) ||
        !id(n.actorId) || !iso(n.at) ||
        n.workId !== null && !work.has(n.workId) ||
        !noteCategories.includes(n.category) ||
        typeof n.text !== "string" || n.text.length > 2000 ||
        !n.text.trim() || n.digest !== coordinationDigest({
          actorId: n.actorId, at: n.at,
          workId: n.workId, category: n.category, text: n.text,
        }))
      errors.push("SHIFT_HANDOFF_NOTE_INVALID");
    if (n && id(n.id)) notes.add(n.id);
  }
  for (const item of value.returned) {
    if (!item || !id(item.returnedBy) || !iso(item.at) ||
        !sha(item.previousDigest) ||
        !item.explanation?.trim())
      errors.push("SHIFT_HANDOFF_RETURN_INVALID");
  }
  if (value.accepted !== null) {
    if (!id(value.accepted.reviewedBy) || !iso(value.accepted.at) ||
        !sha(value.accepted.receivedDigest) ||
        value.accepted.reviewedBy !== value.incomingUserId ||
        value.accepted.acceptedInternally !== true ||
        value.accepted.providerContainmentConfirmed !== false)
      errors.push("SHIFT_HANDOFF_ACCEPTANCE_INVALID");
  }
  if (["ACCEPTED_INTERNAL", "CLOSED_INTERNAL"].includes(value.status) &&
      value.accepted === null)
    errors.push("SHIFT_HANDOFF_ACCEPTANCE_MISSING");
  if (value.independentProviderProof !== false ||
      value.externalNotifications !== 0 || value.providerWrites !== 0)
    errors.push("SHIFT_HANDOFF_FALSE_EXTERNAL_CLAIM");
  return [...new Set(errors)];
}
export function beginShiftHandoff(args: {
  recordId: string; organizationId: string; incidentId: string;
  actorId: string; incomingUserId: string;
  commandId: string; at: string; briefing: ShiftBriefing;
}) {
  const brief = args.briefing;
  if (!brief || brief.organizationId !== args.organizationId ||
      brief.incidentId !== args.incidentId ||
      !sha(brief.digest) || !sha(brief.forensicDigest) ||
      brief.window.outgoingUserId !== args.actorId ||
      brief.window.incomingUserId !== null ||
      brief.receiptIssued !== false ||
      brief.handoffAcknowledged !== false ||
      brief.providerOutcomesIndependentlyVerified !== false ||
      brief.externalActions !== 0 ||
      !id(args.incomingUserId) ||
      args.incomingUserId === args.actorId)
    fail("SHIFT_HANDOFF_SOURCE_INVALID");
  const payload: ShiftHandoffPayload = {
    schema: "cyberpilot.incident.shift.handoff.v1",
    shiftId: brief.window.shiftId,
    incidentRevision: brief.incidentRevision,
    originalBriefingDigest: brief.digest,
    originalForensicDigest: brief.forensicDigest,
    originalInvestigationDigest: brief.investigationDigest,
    originalPolicyDigest: brief.policyDigest,
    outgoingUserId: args.actorId,
    incomingUserId: args.incomingUserId,
    outgoingRole: brief.window.outgoingRole as "OWNER" | "ADMIN",
    incomingRole: brief.window.incomingRole as "OWNER" | "ADMIN",
    window: brief.window,
    workItems: brief.workItems.map(w => ({
      id: w.id, priority: w.priority, category: w.category,
      dueAt: w.dueAt, assignedRole: w.assignedRole,
      providerWritePermitted: false,
    })),
    watchpoints: brief.watchpoints.map(w => ({
      id: w.id, category: w.category,
      priority: w.priority, trigger: w.trigger,
    })),
    sourceEvents: brief.sourceEvents,
    sourceComplete: brief.completeness !== "UNKNOWN",
    acknowledgedWorkIds: [], outstandingConcernIds: [],
    status: "PREPARED", submissionCount: 0,
    submittedAt: null, submittedBy: null,
    accepted: null, returned: [], notes: [],
    lastActorId: args.actorId, lastUpdatedAt: args.at,
    independentProviderProof: false, externalNotifications: 0,
    providerWrites: 0,
  };
  if (validateShiftHandoffPayload(payload).length)
    fail("SHIFT_HANDOFF_INITIAL_PAYLOAD_INVALID");
  return createCoordination({
    id: args.recordId, organizationId: args.organizationId,
    incidentId: args.incidentId, kind: "SHIFT", state: "OPEN",
    sourceDigest: brief.digest, actorId: args.actorId,
    commandId: args.commandId, at: args.at, payload,
  });
}
export function applyShiftHandoff(
  current: CoordinationEnvelope<ShiftHandoffPayload>,
  command: CoordinationCommand<ShiftHandoffAction>,
  lastEventDigest: string,
) {
  assertCoordinationPreconditions(current, command);
  if (current.kind !== "SHIFT" ||
      validateShiftHandoffPayload(current.payload).length)
    fail("SHIFT_HANDOFF_CURRENT_INVALID");
  const p = current.payload;
  if (p.status === "CLOSED_INTERNAL")
    fail("SHIFT_HANDOFF_CLOSED");
  if (command.role === "AUDITOR")
    fail("SHIFT_HANDOFF_ROLE_DENIED");
  const action = command.action;
  const explanation = reason(action.reason);
  const at = command.at, actor = command.actorId;
  const outgoing = actor === p.outgoingUserId;
  const incoming = actor === p.incomingUserId;
  if (!outgoing && !incoming)
    fail("SHIFT_HANDOFF_ACTOR_NOT_PARTICIPANT");
  const next: ShiftHandoffPayload = {
    ...p, window: { ...p.window },
    workItems: p.workItems.map(x => ({ ...x })),
    watchpoints: p.watchpoints.map(x => ({ ...x })),
    acknowledgedWorkIds: [...p.acknowledgedWorkIds],
    outstandingConcernIds: [...p.outstandingConcernIds],
    returned: p.returned.map(x => ({ ...x })),
    notes: p.notes.map(x => ({ ...x })),
    accepted: p.accepted && {
      ...p.accepted, notedWorkIds: [...p.accepted.notedWorkIds],
      outstandingConcernIds: [...p.accepted.outstandingConcernIds],
    },
    lastActorId: actor, lastUpdatedAt: at,
    independentProviderProof: false,
    externalNotifications: 0, providerWrites: 0,
  };
  const prepared = ["PREPARED", "RETURNED", "REOPENED"].includes(p.status);
  if (action.kind === "ADD_NOTE") {
    if (!outgoing && p.status !== "SUBMITTED" && p.status !==
        "ACCEPTED_INTERNAL")
      fail("SHIFT_HANDOFF_NOTE_ROLE_DENIED");
    if (!id(action.noteId) || next.notes.some(x => x.id === action.noteId) ||
        next.notes.length >= 2000 ||
        action.workId !== null && !next.workItems.some(x =>
          x.id === action.workId) ||
        !noteCategories.includes(action.category))
      fail("SHIFT_HANDOFF_NOTE_INVALID");
    const fields = { actorId: actor, at, workId: action.workId,
      category: action.category, text: explanation };
    next.notes.push({
      id: action.noteId, ...fields,
      digest: coordinationDigest(fields),
    });
  } else if (action.kind === "MARK_REVIEWED") {
    if (!outgoing || !prepared ||
        !next.workItems.some(x => x.id === action.workId) ||
        next.acknowledgedWorkIds.includes(action.workId))
      fail("SHIFT_HANDOFF_WORK_MARK_DENIED");
    next.acknowledgedWorkIds.push(action.workId);
    next.acknowledgedWorkIds.sort();
  } else if (action.kind === "RAISE_CONCERN") {
    if (!next.watchpoints.some(x => x.id === action.concernId) ||
        next.outstandingConcernIds.includes(action.concernId))
      fail("SHIFT_HANDOFF_CONCERN_INVALID");
    next.outstandingConcernIds.push(action.concernId);
    next.outstandingConcernIds.sort();
  } else if (action.kind === "CLEAR_CONCERN") {
    if (!outgoing || !prepared ||
        !next.outstandingConcernIds.includes(action.concernId))
      fail("SHIFT_HANDOFF_CONCERN_CLEAR_DENIED");
    next.outstandingConcernIds = next.outstandingConcernIds.filter(x =>
      x !== action.concernId);
  } else if (action.kind === "SUBMIT") {
    if (!outgoing || !prepared || p.submissionCount >= 100)
      fail("SHIFT_HANDOFF_SUBMISSION_DENIED");
    if (p.workItems.length && next.acknowledgedWorkIds.length !==
        p.workItems.length)
      fail("SHIFT_HANDOFF_WORK_UNREVIEWED");
    next.status = "SUBMITTED"; next.submittedBy = actor;
    next.submittedAt = at; next.submissionCount++;
    next.accepted = null;
  } else if (action.kind === "ACCEPT" ||
      action.kind === "RETURN") {
    if (!incoming || p.status !== "SUBMITTED" ||
        !sha(action.expectedSubmittedDigest) ||
        action.expectedSubmittedDigest !== coordinationDigest(current))
      fail("SHIFT_HANDOFF_STALE_OR_UNAUTHORIZED_RESPONSE");
    if (action.kind === "ACCEPT") {
      if (next.outstandingConcernIds.length)
        fail("SHIFT_HANDOFF_CONCERNS_UNRESOLVED");
      next.accepted = {
        reviewedBy: actor, at, receivedDigest: coordinationDigest(current),
        notedWorkIds: [...next.acknowledgedWorkIds],
        outstandingConcernIds: [], explanation,
        acceptedInternally: true, providerContainmentConfirmed: false,
      };
      next.status = "ACCEPTED_INTERNAL";
    } else {
      if (!["MISSING_EVIDENCE", "INCORRECT_SCOPE",
          "STALE_SOURCE", "OPERATIONAL_DISAGREEMENT"].includes(
            action.category))
        fail("SHIFT_HANDOFF_RETURN_CATEGORY_INVALID");
      next.returned.push({
        returnedBy: actor, at, explanation,
        reasonCategory: action.category,
        previousDigest: coordinationDigest(current),
      });
      next.status = "RETURNED";
      next.acknowledgedWorkIds = [];
    }
  } else if (action.kind === "REOPEN") {
    if (!outgoing || p.status !== "ACCEPTED_INTERNAL")
      fail("SHIFT_HANDOFF_REOPEN_DENIED");
    next.status = "REOPENED"; next.accepted = null;
    next.acknowledgedWorkIds = [];
  } else if (action.kind === "CLOSE") {
    if (!outgoing || p.status !== "ACCEPTED_INTERNAL" ||
        p.accepted?.reviewedBy !== p.incomingUserId)
      fail("SHIFT_HANDOFF_CLOSE_REQUIRES_RECEIPT");
    next.status = "CLOSED_INTERNAL";
  } else fail("SHIFT_HANDOFF_ACTION_INVALID");
  if (validateShiftHandoffPayload(next).length)
    fail("SHIFT_HANDOFF_EVOLVED_PAYLOAD_INVALID");
  const state = next.status === "CLOSED_INTERNAL" ?
    "CLOSED_INTERNAL" : next.status === "ACCEPTED_INTERNAL" ?
      "ACCEPTED_INTERNAL" : next.status === "SUBMITTED" ?
      "PENDING_REVIEW" : next.status === "RETURNED" ?
      "REJECTED_INTERNAL" : "ACTIVE";
  return evolveCoordination({
    current, command, lastEventDigest,
    nextPayload: next, nextState: state, operation: action.kind,
  });
}
export function summarizeShiftHandoff(
  record: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (record.kind !== "SHIFT" ||
      validateShiftHandoffPayload(record.payload).length)
    fail("SHIFT_HANDOFF_SUMMARY_INVALID");
  const p = record.payload;
  return {
    schema: "cyberpilot.incident.shift.handoff-summary.v1" as const,
    recordId: record.id, incidentId: record.incidentId,
    outgoingUserId: p.outgoingUserId, incomingUserId: p.incomingUserId,
    status: p.status, revision: record.revision,
    workTotal: p.workItems.length,
    acknowledgedWork: p.acknowledgedWorkIds.length,
    outstandingConcerns: p.outstandingConcernIds.length,
    submissionCount: p.submissionCount,
    acceptedInternally: p.status === "ACCEPTED_INTERNAL" ||
      p.status === "CLOSED_INTERNAL",
    returnedCount: p.returned.length,
    notes: p.notes.length,
    externalReceipt: false as const,
    providerOutcomeVerified: false as const,
  };
}
export function pendingShiftHandoffWork(
  record: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (validateShiftHandoffPayload(record.payload).length)
    fail("SHIFT_HANDOFF_WORK_INVALID");
  return record.payload.workItems.filter(w =>
    !record.payload.acknowledgedWorkIds.includes(w.id));
}
export function shiftHandoffContinuityMatrix(
  record: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (validateShiftHandoffPayload(record.payload).length)
    fail("SHIFT_HANDOFF_MATRIX_INVALID");
  return record.payload.workItems.map(w => ({
    workId: w.id, priority: w.priority,
    reviewedByOutgoing: record.payload.acknowledgedWorkIds.includes(w.id),
    incomingAcknowledged: !!record.payload.accepted &&
      record.payload.accepted.notedWorkIds.includes(w.id),
    noteCount: record.payload.notes.filter(n => n.workId === w.id).length,
    dueAt: w.dueAt,
    providerActionCompleted: false as const,
  }));
}
export function shiftHandoffResponsibility(
  record: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (validateShiftHandoffPayload(record.payload).length)
    fail("SHIFT_HANDOFF_RESPONSIBILITY_INVALID");
  return {
    outgoing: { userId: record.payload.outgoingUserId,
      role: record.payload.outgoingRole,
      submitted: record.payload.submittedBy !== null,
      mustResolve: record.payload.outstandingConcernIds.length },
    incoming: { userId: record.payload.incomingUserId,
      role: record.payload.incomingRole,
      accepted: record.payload.accepted !== null,
      canRespond: record.payload.status === "SUBMITTED" },
    cannotProveExternalAction: true as const,
  };
}
export function compareShiftHandoffSnapshots(
  before: CoordinationEnvelope<ShiftHandoffPayload>,
  after: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (validateShiftHandoffPayload(before.payload).length ||
      validateShiftHandoffPayload(after.payload).length ||
      before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId ||
      before.id !== after.id)
    fail("SHIFT_HANDOFF_COMPARE_INVALID");
  const oldNotes = new Set(before.payload.notes.map(x => x.id));
  const oldReturned = before.payload.returned.length;
  return {
    schema: "cyberpilot.incident.shift.handoff-diff.v1" as const,
    previousDigest: coordinationDigest(before),
    nextDigest: coordinationDigest(after),
    acceptedNow: before.payload.accepted === null &&
      after.payload.accepted !== null,
    acceptanceRetracted: before.payload.accepted !== null &&
      after.payload.accepted === null,
    newNotes: after.payload.notes.filter(x => !oldNotes.has(x.id)),
    newReturns: after.payload.returned.slice(oldReturned),
    newReviewedWorkIds: after.payload.acknowledgedWorkIds.filter(x =>
      !before.payload.acknowledgedWorkIds.includes(x)),
    providerContainmentProven: false as const,
  };
}
function csvSafe(value: string) {
  const safe = /^[\s]*[=+@-]/.test(value) ? "'" + value : value;
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function exportShiftHandoffCSV(
  record: CoordinationEnvelope<ShiftHandoffPayload>,
) {
  if (validateShiftHandoffPayload(record.payload).length)
    fail("SHIFT_HANDOFF_EXPORT_DENIED");
  const header = ["workId", "priority", "dueAt", "outgoingReviewed",
    "incomingReceived", "providerActions"];
  const body = shiftHandoffContinuityMatrix(record).map(w => [
    w.workId, w.priority, w.dueAt,
    String(w.reviewedByOutgoing), String(w.incomingAcknowledged), "0",
  ].map(csvSafe).join(","));
  return [header.join(","), ...body].join("\r\n") + "\r\n";
}
