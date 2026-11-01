import { createHash } from "node:crypto";
import { type SnapshotReadinessReport, type ReadinessCheckId } from "./work-integrity-snapshot-readiness";

/**
 * Turn a completed operational readiness assessment into an actionable,
 * deterministic work queue. Tasks are proposals; this module does not create
 * remediation records, assign real users, or mark findings as resolved.
 */
export type ReadinessWorkPriority = "P0" | "P1" | "P2" | "P3";
export type ReadinessWorkCategory =
  | "CUSTODY" | "COLLECTION" | "QUALITY" | "REGRESSION"
  | "INGESTION" | "SCHEDULE" | "HISTORY" | "VALIDATION";
export type ReadinessWorkState =
  | "OPEN" | "ACKNOWLEDGED" | "IN_PROGRESS" | "BLOCKED"
  | "DONE" | "DISMISSED";
export type ReadinessWorkItem = {
  id: string;
  organizationId: string;
  source: string | null;
  title: string;
  description: string;
  category: ReadinessWorkCategory;
  priority: ReadinessWorkPriority;
  state: ReadinessWorkState;
  relatedChecks: ReadinessCheckId[];
  blockingChecks: ReadinessCheckId[];
  createdAt: string;
  updatedAt: string;
  dueAt: string | null;
  assigneeId: string | null;
  resolution: string | null;
  evidenceReferences: string[];
  dependencies: string[];
};
export type ReadinessWorkPolicy = {
  maxItems: number;
  p0DueHours: number;
  p1DueHours: number;
  p2DueHours: number;
  p3DueHours: number;
  requireEvidenceForCompletion: boolean;
  allowDismissBlockers: boolean;
  preserveExistingStates: boolean;
  allowUnassignedItems: boolean;
  minimumResolutionCharacters: number;
};
export type ReadinessWorkEvent = {
  id: string;
  organizationId: string;
  itemId: string;
  actorId: string;
  at: string;
  previousState: ReadinessWorkState;
  nextState: ReadinessWorkState;
  explanation: string;
  evidenceReferences: string[];
};
export type ReadinessWorkQueue = {
  version: 1;
  organizationId: string;
  evaluatedAt: string;
  items: ReadinessWorkItem[];
  events: ReadinessWorkEvent[];
  counts: Record<ReadinessWorkState, number>;
  overdue: number;
  blocked: number;
  unresolvedCritical: number;
  warnings: string[];
};
export type ReadinessWorkTransition = {
  itemId: string;
  expectedState: ReadinessWorkState;
  nextState: ReadinessWorkState;
  actorId: string;
  at: string;
  explanation: string;
  evidenceReferences: string[];
  assigneeId?: string | null;
};
const STATES: ReadinessWorkState[] = [
  "OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "BLOCKED", "DONE", "DISMISSED",
];
const TERMINAL = new Set<ReadinessWorkState>(["DONE", "DISMISSED"]);
const TRANSITIONS: Record<ReadinessWorkState, ReadinessWorkState[]> = {
  OPEN: ["ACKNOWLEDGED", "IN_PROGRESS", "BLOCKED", "DISMISSED"],
  ACKNOWLEDGED: ["IN_PROGRESS", "BLOCKED", "DISMISSED"],
  IN_PROGRESS: ["BLOCKED", "DONE", "DISMISSED"],
  BLOCKED: ["ACKNOWLEDGED", "IN_PROGRESS", "DISMISSED"],
  DONE: ["OPEN"],
  DISMISSED: ["OPEN"],
};
function validText(value: unknown, label: string, max = 2000): string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value;
}
function date(value: unknown, label: string): number {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    throw new Error(`Invalid ${label}.`);
  return Date.parse(value);
}
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function validatedPolicy(policy: ReadinessWorkPolicy): ReadinessWorkPolicy {
  integer(policy.maxItems, 1, 10000, "work item limit");
  for (const key of ["p0DueHours", "p1DueHours", "p2DueHours", "p3DueHours"] as const)
    integer(policy[key], 1, 87600, key);
  integer(policy.minimumResolutionCharacters, 1, 1000, "resolution minimum");
  for (const key of [
    "requireEvidenceForCompletion", "allowDismissBlockers",
    "preserveExistingStates", "allowUnassignedItems",
  ] as const)
    if (typeof policy[key] !== "boolean")
      throw new Error(`Invalid work policy flag: ${key}.`);
  return policy;
}
function hash(parts: readonly unknown[]): string {
  return createHash("sha256").update(JSON.stringify(parts), "utf8")
    .digest("hex").slice(0, 32);
}
function priority(checks: ReadinessCheckId[], blocking: boolean): ReadinessWorkPriority {
  if (blocking && checks.some(id =>
    ["JOURNAL_INTEGRITY", "CUSTODY_RECONCILIATION", "SOURCE_COVERAGE",
      "SOURCE_FRESHNESS", "INCIDENT_BLOCKERS"].includes(id))) return "P0";
  if (blocking) return "P1";
  if (checks.some(id => ["INCIDENT_WARNINGS", "SOURCE_QUALITY",
    "CAPTURE_COMPLETENESS", "INGESTION_REJECTIONS"].includes(id))) return "P1";
  if (checks.some(id => ["MINIMUM_HISTORY", "CAPTURE_FRESHNESS"].includes(id)))
    return "P3";
  return "P2";
}
function category(checks: ReadinessCheckId[]): ReadinessWorkCategory {
  if (checks.some(id => ["JOURNAL_INTEGRITY", "CUSTODY_RECONCILIATION"].includes(id)))
    return "CUSTODY";
  if (checks.some(id => ["SOURCE_COVERAGE", "SOURCE_FRESHNESS"].includes(id)))
    return "COLLECTION";
  if (checks.some(id => ["SOURCE_QUALITY", "CAPTURE_COMPLETENESS"].includes(id)))
    return "QUALITY";
  if (checks.some(id => ["INCIDENT_BLOCKERS", "INCIDENT_WARNINGS"].includes(id)))
    return "REGRESSION";
  if (checks.some(id => ["INGESTION_REJECTIONS", "INGESTION_SKIPS"].includes(id)))
    return "INGESTION";
  if (checks.includes("UNSCHEDULED_SOURCES")) return "SCHEDULE";
  if (checks.includes("MINIMUM_HISTORY")) return "HISTORY";
  return "VALIDATION";
}
function dueDate(now: number, priority: ReadinessWorkPriority,
  policy: ReadinessWorkPolicy): string {
  const hours = priority === "P0" ? policy.p0DueHours :
    priority === "P1" ? policy.p1DueHours :
      priority === "P2" ? policy.p2DueHours : policy.p3DueHours;
  return new Date(now + hours * 3600000).toISOString();
}
function compareItems(a: ReadinessWorkItem, b: ReadinessWorkItem): number {
  const ranks = { P0: 0, P1: 1, P2: 2, P3: 3 };
  return ranks[a.priority] - ranks[b.priority] ||
    (a.dueAt ?? "").localeCompare(b.dueAt ?? "") ||
    (a.source ?? "").localeCompare(b.source ?? "") ||
    a.id.localeCompare(b.id);
}
function counts(items: ReadinessWorkItem[]): Record<ReadinessWorkState, number> {
  const result = Object.fromEntries(STATES.map(state => [state, 0])) as
    Record<ReadinessWorkState, number>;
  for (const item of items) result[item.state]++;
  return result;
}
function queue(
  organizationId: string, evaluatedAt: string,
  items: ReadinessWorkItem[], events: ReadinessWorkEvent[],
): ReadinessWorkQueue {
  const now = date(evaluatedAt, "work queue evaluation time");
  items.sort(compareItems);
  return {
    version: 1, organizationId, evaluatedAt: new Date(now).toISOString(),
    items, events, counts: counts(items),
    overdue: items.filter(item => !TERMINAL.has(item.state) &&
      item.dueAt !== null && date(item.dueAt, "due date") < now).length,
    blocked: items.filter(item => item.state === "BLOCKED").length,
    unresolvedCritical: items.filter(item => item.priority === "P0" &&
      !TERMINAL.has(item.state)).length,
    warnings: [
      "This queue contains work proposals and does not persist remediation records.",
      "A DONE state is an operator assertion, not independent evidence of remediation.",
      "Source readiness is an operational diagnostic, not a compliance certification.",
    ],
  };
}
export function createReadinessWorkQueue(
  report: SnapshotReadinessReport, organizationId: string,
  evaluatedAt: string, policy: ReadinessWorkPolicy,
  existing?: ReadinessWorkQueue,
): ReadinessWorkQueue {
  validatedPolicy(policy);
  if (report.organizationId !== organizationId ||
      existing && existing.organizationId !== organizationId)
    throw new Error("Cross-organization readiness work queue forbidden.");
  const now = date(evaluatedAt, "queue evaluation time");
  if (report.version !== 1 || !Array.isArray(report.checks) ||
      !Array.isArray(report.nextActions))
    throw new Error("Invalid readiness report.");
  const previous = new Map(existing?.items.map(item => [item.id, item]) ?? []);
  const items: ReadinessWorkItem[] = [];
  const seen = new Set<string>();
  for (const action of report.nextActions) {
    if (items.length >= policy.maxItems)
      throw new Error("Readiness work item limit exceeded.");
    const checks = [...new Set(action.relatedChecks)].sort();
    if (!checks.length) throw new Error("Work action has no supporting check.");
    const blockingChecks = checks.filter(id =>
      report.checks.some(item => item.id === id && item.decision === "BLOCK"));
    const source = action.source;
    if (source !== null) validText(source, "work source", 1000);
    const title = validText(action.action, "work action");
    const id = hash([organizationId, source, title, checks]);
    if (seen.has(id)) continue;
    seen.add(id);
    const rank = priority(checks, blockingChecks.length > 0);
    const old = previous.get(id);
    const keep = Boolean(old && policy.preserveExistingStates);
    items.push({
      id, organizationId, source, title,
      description: `Operational checks: ${checks.join(", ")}. ${title}`,
      category: category(checks), priority: rank,
      state: keep ? old!.state : "OPEN",
      relatedChecks: checks, blockingChecks,
      createdAt: keep ? old!.createdAt : new Date(now).toISOString(),
      updatedAt: keep ? old!.updatedAt : new Date(now).toISOString(),
      dueAt: keep ? old!.dueAt : dueDate(now, rank, policy),
      assigneeId: keep ? old!.assigneeId : null,
      resolution: keep ? old!.resolution : null,
      evidenceReferences: keep ? [...old!.evidenceReferences] : [],
      dependencies: keep ? [...old!.dependencies] : [],
    });
  }
  return queue(organizationId, evaluatedAt, items,
    policy.preserveExistingStates ? [...existing?.events ?? []] : []);
}
export function transitionReadinessWorkItem(
  input: ReadinessWorkQueue, transition: ReadinessWorkTransition,
  organizationId: string, policy: ReadinessWorkPolicy,
): ReadinessWorkQueue {
  validatedPolicy(policy);
  if (input.organizationId !== organizationId || input.version !== 1)
    throw new Error("Cross-organization work transition forbidden.");
  const actorId = validText(transition.actorId, "work actor", 256);
  const explanation = validText(transition.explanation, "work explanation", 4000);
  const at = new Date(date(transition.at, "transition time")).toISOString();
  const item = input.items.find(item => item.id === transition.itemId);
  if (!item) throw new Error("Unknown readiness work item.");
  if (item.state !== transition.expectedState)
    throw new Error("Work item optimistic concurrency conflict.");
  if (!TRANSITIONS[item.state].includes(transition.nextState))
    throw new Error("Invalid work item state transition.");
  if (date(at, "transition time") < date(item.updatedAt, "last update"))
    throw new Error("Work transition cannot precede the previous update.");
  if (transition.nextState === "DISMISSED" &&
      item.blockingChecks.length && !policy.allowDismissBlockers)
    throw new Error("Cannot dismiss an unresolved blocking work item.");
  if (transition.nextState === "DONE" &&
      explanation.trim().length < policy.minimumResolutionCharacters)
    throw new Error("Work completion requires a substantive resolution.");
  const references = transition.evidenceReferences.map(reference =>
    validText(reference, "evidence reference", 512));
  if (new Set(references).size !== references.length)
    throw new Error("Duplicate work evidence reference.");
  if (transition.nextState === "DONE" &&
      policy.requireEvidenceForCompletion &&
      !(references.length || item.evidenceReferences.length))
    throw new Error("Work completion requires a supporting evidence reference.");
  const assigneeId = transition.assigneeId === undefined ?
    item.assigneeId : transition.assigneeId;
  if (assigneeId !== null) validText(assigneeId, "work assignee", 256);
  if (!policy.allowUnassignedItems &&
      ["ACKNOWLEDGED", "IN_PROGRESS", "DONE"].includes(transition.nextState) &&
      assigneeId === null)
    throw new Error("Work assignment is required for this transition.");
  const event: ReadinessWorkEvent = {
    id: hash([organizationId, item.id, actorId, at,
      transition.nextState, input.events.length]),
    organizationId, itemId: item.id, actorId, at,
    previousState: item.state, nextState: transition.nextState,
    explanation, evidenceReferences: references,
  };
  if (input.events.some(previous => previous.id === event.id))
    throw new Error("Duplicate readiness work event.");
  const items = input.items.map(current => current.id === item.id ? {
    ...current, state: transition.nextState, updatedAt: at,
    assigneeId, resolution: transition.nextState === "DONE" ||
      transition.nextState === "DISMISSED" ? explanation : null,
    evidenceReferences: [...new Set([...current.evidenceReferences, ...references])],
  } : current);
  return queue(organizationId, at, items, [...input.events, event]);
}
export function validateReadinessWorkQueue(
  input: ReadinessWorkQueue, organizationId: string,
): { valid: boolean; errors: string[]; itemCount: number; eventCount: number } {
  const errors: string[] = [];
  if (!input || input.organizationId !== organizationId || input.version !== 1)
    throw new Error("Cross-organization work queue verification forbidden.");
  if (!Array.isArray(input.items) || !Array.isArray(input.events) ||
      input.items.length > 10000 || input.events.length > 50000)
    return { valid: false, errors: ["Invalid work queue cardinality."],
      itemCount: 0, eventCount: 0 };
  const ids = new Set<string>();
  for (const item of input.items) {
    if (item.organizationId !== organizationId)
      errors.push("Cross-organization work item.");
    if (ids.has(item.id)) errors.push("Duplicate work item identity.");
    ids.add(item.id);
    if (!STATES.includes(item.state)) errors.push("Unknown work item state.");
    if (!item.relatedChecks.length) errors.push("Work item lacks supporting checks.");
    if (item.dueAt !== null && !Number.isFinite(Date.parse(item.dueAt)))
      errors.push("Invalid work item due date.");
  }
  const eventIds = new Set<string>();
  for (const event of input.events) {
    if (event.organizationId !== organizationId)
      errors.push("Cross-organization work event.");
    if (!ids.has(event.itemId)) errors.push("Orphaned work event.");
    if (eventIds.has(event.id)) errors.push("Duplicate work event identity.");
    eventIds.add(event.id);
    if (!STATES.includes(event.previousState) ||
        !STATES.includes(event.nextState) ||
        !TRANSITIONS[event.previousState].includes(event.nextState))
      errors.push("Invalid work event transition.");
  }
  const expectedCounts = counts(input.items);
  for (const state of STATES)
    if (expectedCounts[state] !== input.counts[state])
      errors.push(`Work queue state count mismatch: ${state}.`);
  return {
    valid: errors.length === 0, errors,
    itemCount: input.items.length, eventCount: input.events.length,
  };
}
export function summarizeReadinessWorkQueue(
  input: ReadinessWorkQueue, organizationId: string,
): {
  total: number; unresolved: number; complete: number;
  byPriority: Record<ReadinessWorkPriority, number>;
  byCategory: Record<ReadinessWorkCategory, number>;
  bySource: Array<{ source: string; open: number; critical: number; overdue: number }>;
} {
  const validation = validateReadinessWorkQueue(input, organizationId);
  if (!validation.valid) throw new Error("Cannot summarize an invalid work queue.");
  const byPriority = { P0: 0, P1: 0, P2: 0, P3: 0 };
  const byCategory: Record<ReadinessWorkCategory, number> = {
    CUSTODY: 0, COLLECTION: 0, QUALITY: 0, REGRESSION: 0,
    INGESTION: 0, SCHEDULE: 0, HISTORY: 0, VALIDATION: 0,
  };
  const sources = new Map<string, { source: string; open: number;
    critical: number; overdue: number }>();
  const now = date(input.evaluatedAt, "queue evaluation time");
  for (const item of input.items) {
    byPriority[item.priority]++;
    byCategory[item.category]++;
    const source = item.source ?? "(organization)";
    const row = sources.get(source) ?? { source, open: 0, critical: 0, overdue: 0 };
    if (!TERMINAL.has(item.state)) {
      row.open++;
      if (item.priority === "P0") row.critical++;
      if (item.dueAt && date(item.dueAt, "due time") < now) row.overdue++;
    }
    sources.set(source, row);
  }
  return {
    total: input.items.length,
    unresolved: input.items.filter(item => !TERMINAL.has(item.state)).length,
    complete: input.items.filter(item => item.state === "DONE").length,
    byPriority, byCategory,
    bySource: [...sources.values()].sort((a, b) =>
      b.critical - a.critical || b.open - a.open ||
      a.source.localeCompare(b.source)),
  };
}
