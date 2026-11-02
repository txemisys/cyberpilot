import { WorkInputError, parseWorkId } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, type LinkReviewReport, type LinkReviewAssociation,
} from "./work-integrity-link-review";

export type IntegrityPlanAction = "LINK" | "UNLINK";
export type IntegrityPlanRequest = {
  captureId: string;
  operations: IntegrityPlanOperation[];
  expectedEventCount?: number;
  strict?: boolean;
};
export type IntegrityPlanOperation = {
  operationId: string;
  action: IntegrityPlanAction;
  caseKey?: string;
  workItemId?: string;
  auditId?: string;
};
export type IntegrityPlanDecisionCode =
  | "READY" | "ALREADY_LINKED" | "ALREADY_WITHDRAWN"
  | "NOT_FOUND" | "DUPLICATE_OPERATION" | "DEPENDENCY_CONFLICT"
  | "STALE_HISTORY" | "INTEGRITY_CONFLICT";
export type IntegrityPlanDecision = {
  operationId: string;
  action: IntegrityPlanAction;
  code: IntegrityPlanDecisionCode;
  executable: boolean;
  caseKey: string | null;
  workItemId: string | null;
  auditId: string | null;
  relatedAuditId: string | null;
  message: string;
};
export type IntegrityPlan = {
  schemaVersion: 1;
  captureId: string;
  expectedEventCount: number;
  observedEventCount: number;
  strict: boolean;
  executable: boolean;
  decisions: IntegrityPlanDecision[];
  totals: {
    requested: number;
    ready: number;
    skipped: number;
    rejected: number;
    links: number;
    withdrawals: number;
  };
};
export type IntegrityPlanPartition = {
  readyLinks: IntegrityPlanDecision[];
  readyWithdrawals: IntegrityPlanDecision[];
  skipped: IntegrityPlanDecision[];
  rejected: IntegrityPlanDecision[];
};
export type IntegrityPlanPreview = {
  before: { active: number; withdrawn: number };
  after: { active: number; withdrawn: number };
  cases: {
    caseKey: string;
    before: number;
    after: number;
    delta: number;
  }[];
  workItems: {
    workItemId: string;
    before: number;
    after: number;
    delta: number;
  }[];
};
export type IntegrityPlanExecutionOutcome = {
  operationId: string;
  status: "APPLIED" | "SKIPPED" | "FAILED";
  auditId: string | null;
  errorCode: string | null;
  message: string | null;
};
export type IntegrityPlanExecutionReport = {
  captureId: string;
  requested: number;
  applied: number;
  skipped: number;
  failed: number;
  outcomes: IntegrityPlanExecutionOutcome[];
};
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected an object.");
  return value as Record<string, unknown>;
}
function keys(input: Record<string, unknown>, allowed: readonly string[]) {
  if (Object.keys(input).some(key => !allowed.includes(key)))
    throw new WorkInputError("INVALID", "Unknown planning field.");
}
function caseIdentity(value: unknown): string {
  if (typeof value !== "string" || !value || value.length > 1500 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid diagnostic case identity.");
  return value;
}
export function parseIntegrityPlanRequest(value: unknown): IntegrityPlanRequest {
  const input = object(value);
  keys(input, ["captureId", "operations", "expectedEventCount", "strict"]);
  const captureId = parseWorkId(input.captureId, "capture ID");
  if (!Array.isArray(input.operations) || input.operations.length < 1 ||
      input.operations.length > 250)
    throw new WorkInputError("INVALID", "Plan requires 1–250 operations.");
  if (input.expectedEventCount !== undefined &&
      (!Number.isSafeInteger(input.expectedEventCount) ||
       (input.expectedEventCount as number) < 0))
    throw new WorkInputError("INVALID", "Invalid expected event count.");
  if (input.strict !== undefined && typeof input.strict !== "boolean")
    throw new WorkInputError("INVALID", "Strict must be boolean.");
  const operations = input.operations.map((raw): IntegrityPlanOperation => {
    const item = object(raw);
    keys(item, ["operationId", "action", "caseKey", "workItemId", "auditId"]);
    const operationId = parseWorkId(item.operationId, "operation ID");
    if (item.action === "LINK") {
      if (item.auditId !== undefined)
        throw new WorkInputError("INVALID", "LINK must not specify an audit ID.");
      return {
        operationId, action: "LINK",
        caseKey: caseIdentity(item.caseKey),
        workItemId: parseWorkId(item.workItemId, "work item ID"),
      };
    }
    if (item.action === "UNLINK") {
      if (item.caseKey !== undefined || item.workItemId !== undefined)
        throw new WorkInputError("INVALID", "UNLINK accepts only an audit ID.");
      return {
        operationId, action: "UNLINK",
        auditId: parseWorkId(item.auditId, "audit ID"),
      };
    }
    throw new WorkInputError("INVALID", "Unknown plan operation.");
  });
  const ids = new Set<string>();
  for (const operation of operations) {
    if (ids.has(operation.operationId))
      throw new WorkInputError("INVALID", "Duplicate operation ID.");
    ids.add(operation.operationId);
  }
  return {
    captureId, operations,
    ...(input.expectedEventCount === undefined ? {} :
      { expectedEventCount: input.expectedEventCount as number }),
    strict: input.strict === true,
  };
}
function decision(
  operation: IntegrityPlanOperation,
  code: IntegrityPlanDecisionCode,
  message: string,
  association?: LinkReviewAssociation,
): IntegrityPlanDecision {
  return {
    operationId: operation.operationId, action: operation.action,
    code, executable: code === "READY",
    caseKey: operation.caseKey ?? association?.caseKey ?? null,
    workItemId: operation.workItemId ?? association?.workItemId ?? null,
    auditId: operation.auditId ?? null,
    relatedAuditId: association?.auditId ?? null,
    message,
  };
}
function associationKey(caseKey: string, workItemId: string) {
  return JSON.stringify([caseKey, workItemId]);
}
export function planIntegrityLinkOperations(
  request: IntegrityPlanRequest,
  events: readonly IntegrityLinkHistoryEvent[],
): IntegrityPlan {
  const report = reviewIntegrityLinks(request.captureId, events);
  const activeByPair = new Map<string, LinkReviewAssociation>();
  const byId = new Map(report.associations.map(x => [x.auditId, x]));
  for (const association of report.associations) {
    if (association.state === "ACTIVE")
      activeByPair.set(associationKey(association.caseKey, association.workItemId), association);
  }
  const seenPairs = new Set<string>();
  const seenWithdrawals = new Set<string>();
  const stale = request.expectedEventCount !== undefined &&
    request.expectedEventCount !== report.totalEvents;
  const integrityConflict = report.counts.errors > 0;
  const decisions = request.operations.map(operation => {
    if (stale)
      return decision(operation, "STALE_HISTORY",
        "Audit history changed since the client inspected it.");
    if (request.strict && integrityConflict)
      return decision(operation, "INTEGRITY_CONFLICT",
        "Strict planning rejects audit integrity findings.");
    if (operation.action === "LINK") {
      const key = associationKey(operation.caseKey!, operation.workItemId!);
      if (seenPairs.has(key))
        return decision(operation, "DUPLICATE_OPERATION",
          "The same association appears more than once in this plan.");
      seenPairs.add(key);
      const existing = activeByPair.get(key);
      if (existing)
        return decision(operation, "ALREADY_LINKED",
          "The association is already active.", existing);
      return decision(operation, "READY", "Association can be created.");
    }
    const id = operation.auditId!;
    if (seenWithdrawals.has(id))
      return decision(operation, "DUPLICATE_OPERATION",
        "The same withdrawal appears more than once in this plan.");
    seenWithdrawals.add(id);
    const existing = byId.get(id);
    if (!existing)
      return decision(operation, "NOT_FOUND",
        "Original association does not exist in this capture.");
    if (existing.state === "WITHDRAWN")
      return decision(operation, "ALREADY_WITHDRAWN",
        "Original association was already withdrawn.", existing);
    return decision(operation, "READY", "Association can be withdrawn.", existing);
  });
  const ready = decisions.filter(x => x.code === "READY");
  const skipped = decisions.filter(x =>
    x.code === "ALREADY_LINKED" || x.code === "ALREADY_WITHDRAWN");
  return {
    schemaVersion: 1, captureId: request.captureId,
    expectedEventCount: request.expectedEventCount ?? report.totalEvents,
    observedEventCount: report.totalEvents,
    strict: request.strict ?? false,
    executable: decisions.every(x => x.executable || skipped.includes(x)),
    decisions,
    totals: {
      requested: decisions.length, ready: ready.length, skipped: skipped.length,
      rejected: decisions.length - ready.length - skipped.length,
      links: ready.filter(x => x.action === "LINK").length,
      withdrawals: ready.filter(x => x.action === "UNLINK").length,
    },
  };
}
export function partitionIntegrityPlan(plan: IntegrityPlan): IntegrityPlanPartition {
  return {
    readyLinks: plan.decisions.filter(x => x.executable && x.action === "LINK"),
    readyWithdrawals: plan.decisions.filter(x => x.executable && x.action === "UNLINK"),
    skipped: plan.decisions.filter(x =>
      x.code === "ALREADY_LINKED" || x.code === "ALREADY_WITHDRAWN"),
    rejected: plan.decisions.filter(x =>
      !x.executable && x.code !== "ALREADY_LINKED" && x.code !== "ALREADY_WITHDRAWN"),
  };
}
function tally(associations: readonly LinkReviewAssociation[], key: "caseKey" | "workItemId") {
  const counts = new Map<string, number>();
  for (const item of associations) {
    if (item.state !== "ACTIVE") continue;
    counts.set(item[key], (counts.get(item[key]) ?? 0) + 1);
  }
  return counts;
}
export function previewIntegrityPlan(
  report: LinkReviewReport, plan: IntegrityPlan,
): IntegrityPlanPreview {
  if (report.captureId !== plan.captureId)
    throw new WorkInputError("INVALID", "Plan and report capture mismatch.");
  if (report.totalEvents !== plan.observedEventCount)
    throw new WorkInputError("CONFLICT", "Plan was computed from different history.");
  const beforeCases = tally(report.associations, "caseKey");
  const beforeWork = tally(report.associations, "workItemId");
  const afterCases = new Map(beforeCases);
  const afterWork = new Map(beforeWork);
  let links = 0;
  let withdrawals = 0;
  for (const item of plan.decisions) {
    if (!item.executable || !item.caseKey || !item.workItemId) continue;
    const delta = item.action === "LINK" ? 1 : -1;
    if (delta === 1) links++;
    else withdrawals++;
    afterCases.set(item.caseKey, (afterCases.get(item.caseKey) ?? 0) + delta);
    afterWork.set(item.workItemId, (afterWork.get(item.workItemId) ?? 0) + delta);
  }
  function rows(before: Map<string, number>, after: Map<string, number>) {
    return [...new Set([...before.keys(), ...after.keys()])].sort(compare)
      .map(id => ({
        id, before: before.get(id) ?? 0,
        after: after.get(id) ?? 0,
        delta: (after.get(id) ?? 0) - (before.get(id) ?? 0),
      }));
  }
  return {
    before: { active: report.counts.active, withdrawn: report.counts.withdrawn },
    after: {
      active: report.counts.active + links - withdrawals,
      withdrawn: report.counts.withdrawn + withdrawals,
    },
    cases: rows(beforeCases, afterCases).map(({ id, ...counts }) => ({ caseKey: id, ...counts })),
    workItems: rows(beforeWork, afterWork).map(({ id, ...counts }) => ({ workItemId: id, ...counts })),
  };
}
export function summarizeIntegrityExecution(
  plan: IntegrityPlan, outcomes: readonly IntegrityPlanExecutionOutcome[],
): IntegrityPlanExecutionReport {
  const expected = new Set(plan.decisions.map(x => x.operationId));
  const received = new Set<string>();
  for (const outcome of outcomes) {
    if (!expected.has(outcome.operationId) || received.has(outcome.operationId))
      throw new WorkInputError("INVALID", "Unknown or repeated execution outcome.");
    received.add(outcome.operationId);
  }
  if (received.size !== expected.size)
    throw new WorkInputError("INVALID", "Missing execution outcome.");
  const ordered = plan.decisions.map(x =>
    outcomes.find(y => y.operationId === x.operationId)!);
  for (const [index, outcome] of ordered.entries()) {
    const planned = plan.decisions[index]!;
    if (outcome.status === "APPLIED" && !planned.executable)
      throw new WorkInputError("INVALID", "Non-executable operation marked applied.");
    if (outcome.status === "APPLIED" && !outcome.auditId)
      throw new WorkInputError("INVALID", "Applied operation lacks audit identifier.");
    if (outcome.status === "SKIPPED" && planned.executable)
      throw new WorkInputError("INVALID", "Executable operation was silently skipped.");
  }
  return {
    captureId: plan.captureId, requested: ordered.length,
    applied: ordered.filter(x => x.status === "APPLIED").length,
    skipped: ordered.filter(x => x.status === "SKIPPED").length,
    failed: ordered.filter(x => x.status === "FAILED").length,
    outcomes: ordered,
  };
}
export function buildIntegrityPlanFromPairs(
  captureId: string,
  pairs: readonly { caseKey: string; workItemId: string }[],
  expectedEventCount?: number,
): IntegrityPlanRequest {
  parseWorkId(captureId, "capture ID");
  if (!pairs.length || pairs.length > 250)
    throw new WorkInputError("INVALID", "Invalid number of association pairs.");
  return parseIntegrityPlanRequest({
    captureId, expectedEventCount,
    operations: pairs.map((pair, index) => ({
      operationId: "operation-" + String(index + 1),
      action: "LINK", caseKey: pair.caseKey, workItemId: pair.workItemId,
    })),
  });
}
export function buildIntegrityWithdrawalPlan(
  captureId: string,
  auditIds: readonly string[],
  expectedEventCount?: number,
): IntegrityPlanRequest {
  parseWorkId(captureId, "capture ID");
  if (!auditIds.length || auditIds.length > 250)
    throw new WorkInputError("INVALID", "Invalid number of withdrawals.");
  return parseIntegrityPlanRequest({
    captureId, expectedEventCount,
    operations: auditIds.map((auditId, index) => ({
      operationId: "operation-" + String(index + 1),
      action: "UNLINK", auditId,
    })),
  });
}
