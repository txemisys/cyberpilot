import type { InvestigationBacklog, InvestigationTask } from "./work-integrity-investigation-backlog";

/**
 * An offline planning ledger for investigation tasks. Entries are immutable
 * declarations; no task execution, human review or production mutation occurs.
 */
export type TaskDisposition = "PLANNED" | "BLOCKED" | "READY" | "IN_PROGRESS" |
  "DONE" | "CANCELLED";
export type LedgerEventKind = "START" | "BLOCK" | "UNBLOCK" | "COMPLETE" |
  "CANCEL" | "REOPEN" | "NOTE";
export type LedgerEvent = {
  id: string;
  taskId: string;
  kind: LedgerEventKind;
  at: string;
  actorId: string;
  rationale: string;
  evidenceReference: string | null;
};
export type LedgerPolicy = {
  maximumEvents: number;
  maximumEventsPerTask: number;
  requireEvidenceForCompletion: boolean;
  allowReopen: boolean;
  allowCancellation: boolean;
  enforceDependencies: boolean;
  allowPartialSource: boolean;
};
export type TaskLedgerState = {
  taskId: string;
  disposition: TaskDisposition;
  lastEventId: string | null;
  lastEventAt: string | null;
  actorId: string | null;
  evidenceReferences: string[];
  eventCount: number;
  blockedBy: string[];
  noteCount: number;
};
export type LedgerViolation = {
  eventId: string;
  taskId: string;
  code: "UNKNOWN_TASK" | "DUPLICATE_EVENT" | "NONMONOTONIC_TIME" |
    "INVALID_TRANSITION" | "MISSING_EVIDENCE" | "DEPENDENCY_NOT_COMPLETE" |
    "INCOMPLETE_SOURCE" | "POLICY_LIMIT";
  message: string;
};
export type InvestigationLedger = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  evaluatedAt: string | null;
  complete: boolean;
  policy: LedgerPolicy;
  events: LedgerEvent[];
  states: TaskLedgerState[];
  violations: LedgerViolation[];
  valid: boolean;
  completed: number;
  blocked: number;
  active: number;
  remainingMinutes: number;
  warnings: string[];
};
export const DEFAULT_LEDGER_POLICY: LedgerPolicy = {
  maximumEvents: 100000,
  maximumEventsPerTask: 1000,
  requireEvidenceForCompletion: true,
  allowReopen: true,
  allowCancellation: false,
  enforceDependencies: true,
  allowPartialSource: false,
};
const kinds: LedgerEventKind[] = [
  "START", "BLOCK", "UNBLOCK", "COMPLETE", "CANCEL", "REOPEN", "NOTE",
];
function identifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > 500 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
}
function timestamp(value: string): number {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw new Error("Invalid ledger timestamp.");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value)
    throw new Error("Noncanonical ledger timestamp.");
  return ms;
}
export function validateLedgerPolicy(input: LedgerPolicy): LedgerPolicy {
  if (!input || !Number.isSafeInteger(input.maximumEvents) ||
      input.maximumEvents < 1 || input.maximumEvents > 100000 ||
      !Number.isSafeInteger(input.maximumEventsPerTask) ||
      input.maximumEventsPerTask < 1 || input.maximumEventsPerTask > 10000)
    throw new Error("Invalid ledger event limits.");
  for (const key of ["requireEvidenceForCompletion", "allowReopen",
    "allowCancellation", "enforceDependencies", "allowPartialSource"] as const)
    if (typeof input[key] !== "boolean") throw new Error(`Invalid ledger flag: ${key}.`);
  return { ...input };
}
export function validateLedgerEvent(event: LedgerEvent): LedgerEvent {
  if (!event || typeof event !== "object") throw new Error("Invalid ledger event.");
  identifier(event.id, "event ID");
  identifier(event.taskId, "task ID");
  identifier(event.actorId, "actor ID");
  if (!kinds.includes(event.kind)) throw new Error("Invalid ledger event kind.");
  timestamp(event.at);
  if (typeof event.rationale !== "string" || !event.rationale.trim() ||
      event.rationale.length > 4000)
    throw new Error("Invalid ledger rationale.");
  if (event.evidenceReference !== null)
    identifier(event.evidenceReference, "evidence reference");
  return { ...event };
}
function initialState(task: InvestigationTask): TaskLedgerState {
  return {
    taskId: task.id, disposition: "PLANNED",
    lastEventId: null, lastEventAt: null, actorId: null,
    evidenceReferences: [], eventCount: 0, blockedBy: [],
    noteCount: 0,
  };
}
function transition(
  current: TaskDisposition, kind: LedgerEventKind, policy: LedgerPolicy,
): TaskDisposition | null {
  if (kind === "NOTE") return current;
  if (kind === "START")
    return current === "PLANNED" || current === "READY" ? "IN_PROGRESS" : null;
  if (kind === "BLOCK")
    return ["PLANNED", "READY", "IN_PROGRESS"].includes(current) ? "BLOCKED" : null;
  if (kind === "UNBLOCK") return current === "BLOCKED" ? "READY" : null;
  if (kind === "COMPLETE")
    return current === "IN_PROGRESS" ? "DONE" : null;
  if (kind === "CANCEL")
    return policy.allowCancellation && current !== "DONE" &&
      current !== "CANCELLED" ? "CANCELLED" : null;
  if (kind === "REOPEN")
    return policy.allowReopen && current === "DONE" ? "READY" : null;
  return null;
}
/**
 * Replays events in supplied order. Invalid entries are recorded and ignored,
 * so a corrupt event never silently changes the state of a later entry.
 */
export function replayInvestigationLedger(
  backlog: InvestigationBacklog,
  input: readonly LedgerEvent[],
  inputPolicy: LedgerPolicy = DEFAULT_LEDGER_POLICY,
): InvestigationLedger {
  const policy = validateLedgerPolicy(inputPolicy);
  if (!Array.isArray(input) || input.length > policy.maximumEvents)
    throw new Error("Ledger exceeds maximum event count.");
  const byId = new Map(backlog.tasks.map(task => [task.id, task]));
  if (byId.size !== backlog.tasks.length)
    throw new Error("Duplicate task identifiers in backlog.");
  const states = new Map(backlog.tasks.map(task =>
    [task.id, initialState(task)] as const));
  const seen = new Set<string>();
  const violations: LedgerViolation[] = [];
  const accepted: LedgerEvent[] = [];
  let lastGlobalAt = -Infinity;
  const reject = (event: LedgerEvent, code: LedgerViolation["code"], message: string) => {
    violations.push({ eventId: event.id, taskId: event.taskId, code, message });
  };
  for (const raw of input) {
    const event = validateLedgerEvent(raw);
    const at = timestamp(event.at);
    const state = states.get(event.taskId);
    if (seen.has(event.id)) {
      reject(event, "DUPLICATE_EVENT", "Event identifier has already been used.");
      continue;
    }
    seen.add(event.id);
    if (!state) {
      reject(event, "UNKNOWN_TASK", "Task is not part of the selected backlog.");
      continue;
    }
    if (at < lastGlobalAt) {
      reject(event, "NONMONOTONIC_TIME", "Events must be ordered chronologically.");
      continue;
    }
    if (state.eventCount >= policy.maximumEventsPerTask) {
      reject(event, "POLICY_LIMIT", "Task exceeds its event limit.");
      continue;
    }
    if (!backlog.complete && !policy.allowPartialSource &&
        event.kind !== "NOTE" && event.kind !== "BLOCK") {
      reject(event, "INCOMPLETE_SOURCE", "Source coverage is incomplete.");
      continue;
    }
    const next = transition(state.disposition, event.kind, policy);
    if (!next) {
      reject(event, "INVALID_TRANSITION",
        `Cannot apply ${event.kind} to ${state.disposition}.`);
      continue;
    }
    if (event.kind === "COMPLETE" && policy.requireEvidenceForCompletion &&
        !event.evidenceReference) {
      reject(event, "MISSING_EVIDENCE",
        "A completion event must reference evidence.");
      continue;
    }
    if (event.kind === "START" && policy.enforceDependencies) {
      const task = byId.get(event.taskId)!;
      const blockedBy = task.dependsOn.filter(id =>
        states.get(id)?.disposition !== "DONE");
      if (blockedBy.length) {
        reject(event, "DEPENDENCY_NOT_COMPLETE",
          `Prerequisites are not completed: ${blockedBy.join(", ")}.`);
        continue;
      }
    }
    state.disposition = next;
    state.lastEventId = event.id;
    state.lastEventAt = event.at;
    state.actorId = event.actorId;
    state.eventCount++;
    if (event.kind === "NOTE") state.noteCount++;
    if (event.evidenceReference &&
        !state.evidenceReferences.includes(event.evidenceReference))
      state.evidenceReferences.push(event.evidenceReference);
    state.blockedBy = next === "BLOCKED"
      ? byId.get(event.taskId)!.dependsOn.filter(id =>
        states.get(id)?.disposition !== "DONE") : [];
    accepted.push(event);
    lastGlobalAt = at;
  }
  const values = [...states.values()].sort((a, b) => a.taskId.localeCompare(b.taskId));
  const completed = values.filter(item => item.disposition === "DONE").length;
  const blocked = values.filter(item => item.disposition === "BLOCKED").length;
  const active = values.filter(item => item.disposition === "IN_PROGRESS").length;
  const remainingMinutes = backlog.tasks.reduce((sum, task) =>
    sum + (states.get(task.id)?.disposition === "DONE" ||
      states.get(task.id)?.disposition === "CANCELLED" ? 0 : task.estimatedMinutes), 0);
  return {
    version: 1, organizationId: backlog.organizationId,
    capturedAt: backlog.capturedAt,
    evaluatedAt: accepted.at(-1)?.at ?? null,
    complete: backlog.complete,
    policy, events: accepted, states: values, violations,
    valid: violations.length === 0,
    completed, blocked, active, remainingMinutes,
    warnings: [
      "The ledger is an offline record of declared actions, not proof they occurred.",
      "Evidence references are not cryptographically verified or independently authenticated.",
      ...(!backlog.complete ? ["Partial source collection can omit additional tasks."] : []),
    ],
  };
}
export type LedgerComparison = {
  organizationId: string;
  newlyCompleted: string[];
  reopened: string[];
  newlyBlocked: string[];
  unblocked: string[];
  changed: string[];
  uncertain: string[];
};
export function compareInvestigationLedgers(
  before: InvestigationLedger, after: InvestigationLedger,
): LedgerComparison {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare ledgers across organizations.");
  const old = new Map(before.states.map(item => [item.taskId, item]));
  const current = new Map(after.states.map(item => [item.taskId, item]));
  const newlyCompleted: string[] = [], reopened: string[] = [];
  const newlyBlocked: string[] = [], unblocked: string[] = [];
  const changed: string[] = [], uncertain: string[] = [];
  for (const id of [...new Set([...old.keys(), ...current.keys()])].sort()) {
    const a = old.get(id), b = current.get(id);
    if (!a || !b || !before.complete || !after.complete) {
      uncertain.push(id);
      continue;
    }
    if (a.disposition === b.disposition) continue;
    changed.push(id);
    if (b.disposition === "DONE") newlyCompleted.push(id);
    if (a.disposition === "DONE" && b.disposition !== "DONE") reopened.push(id);
    if (b.disposition === "BLOCKED") newlyBlocked.push(id);
    if (a.disposition === "BLOCKED" && b.disposition !== "BLOCKED") unblocked.push(id);
  }
  return { organizationId: before.organizationId, newlyCompleted,
    reopened, newlyBlocked, unblocked, changed, uncertain };
}
export type LedgerProgress = {
  organizationId: string;
  total: number;
  completed: number;
  completionRatio: number;
  blocked: number;
  active: number;
  remainingMinutes: number;
  byDisposition: Record<TaskDisposition, number>;
  invalidEvents: number;
};
export function investigationLedgerProgress(ledger: InvestigationLedger): LedgerProgress {
  const byDisposition: Record<TaskDisposition, number> = {
    PLANNED: 0, BLOCKED: 0, READY: 0, IN_PROGRESS: 0, DONE: 0, CANCELLED: 0,
  };
  for (const state of ledger.states) byDisposition[state.disposition]++;
  return {
    organizationId: ledger.organizationId,
    total: ledger.states.length, completed: ledger.completed,
    completionRatio: ledger.states.length ? ledger.completed / ledger.states.length : 1,
    blocked: ledger.blocked, active: ledger.active,
    remainingMinutes: ledger.remainingMinutes,
    byDisposition, invalidEvents: ledger.violations.length,
  };
}
function csvCell(value: unknown): string {
  const raw = String(value ?? "");
  const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
  return '"' + neutralized.replace(/"/g, '""') + '"';
}
export function investigationLedgerCsv(ledger: InvestigationLedger): string {
  const lines = [["taskId", "disposition", "lastEventId", "lastEventAt",
    "actorId", "evidenceReferences", "eventCount", "noteCount",
    "blockedBy"].map(csvCell).join(",")];
  for (const state of ledger.states)
    lines.push([state.taskId, state.disposition, state.lastEventId,
      state.lastEventAt, state.actorId, state.evidenceReferences.join(";"),
      state.eventCount, state.noteCount, state.blockedBy.join(";")]
      .map(csvCell).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function investigationLedgerJson(ledger: InvestigationLedger): string {
  return JSON.stringify(ledger, null, 2) + "\n";
}
