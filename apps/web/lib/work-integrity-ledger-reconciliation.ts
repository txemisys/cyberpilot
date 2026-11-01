import type { InvestigationBacklog } from "./work-integrity-investigation-backlog";
import type { InvestigationLedger, LedgerEvent, TaskLedgerState } from "./work-integrity-investigation-ledger";
import { replayInvestigationLedger, type LedgerPolicy } from "./work-integrity-investigation-ledger";

/** Reconciliation of immutable planning and declared task activity. */
export type LedgerReconciliationFinding = {
  taskId: string;
  code: "MISSING_STATE" | "UNPLANNED_STATE" | "MISSING_DEPENDENCY" |
    "CANCELLED_PREREQUISITE" | "DEPENDENCY_NOT_DONE" |
    "EVIDENCE_NOT_RECORDED" | "UNASSIGNED_ACTIVITY" |
    "INCOMPLETE_COVERAGE";
  blocking: boolean;
  explanation: string;
};
export type LedgerReconciliation = {
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  taskCount: number;
  findings: LedgerReconciliationFinding[];
  blockingCount: number;
  advisoryCount: number;
  readyForIndependentVerification: boolean;
  warnings: string[];
};
export function reconcileInvestigationLedger(
  backlog: InvestigationBacklog,
  ledger: InvestigationLedger,
): LedgerReconciliation {
  if (backlog.organizationId !== ledger.organizationId ||
      backlog.capturedAt !== ledger.capturedAt)
    throw new Error("Ledger and backlog must share organization and capture.");
  const tasks = new Map(backlog.tasks.map(item => [item.id, item]));
  const states = new Map(ledger.states.map(item => [item.taskId, item]));
  const findings: LedgerReconciliationFinding[] = [];
  const add = (taskId: string, code: LedgerReconciliationFinding["code"],
    blocking: boolean, explanation: string) => {
    findings.push({ taskId, code, blocking, explanation });
  };
  for (const task of backlog.tasks) {
    const state = states.get(task.id);
    if (!state) {
      add(task.id, "MISSING_STATE", true, "No replayed state exists for the planned task.");
      continue;
    }
    if (!task.coverageComplete) {
      add(task.id, "INCOMPLETE_COVERAGE", true,
        "Task source coverage is incomplete.");
    }
    if (!task.assignedAnalystId && state.eventCount) {
      add(task.id, "UNASSIGNED_ACTIVITY", false,
        "Declared activity exists without a recommended analyst allocation.");
    }
    if (state.disposition === "DONE" && !state.evidenceReferences.length) {
      add(task.id, "EVIDENCE_NOT_RECORDED", true,
        "Completion has no recorded evidence reference.");
    }
    for (const dependency of task.dependsOn) {
      const prerequisite = states.get(dependency);
      if (!tasks.has(dependency)) {
        add(task.id, "MISSING_DEPENDENCY", true,
          `Required task ${dependency} is absent from the backlog.`);
      } else if (prerequisite?.disposition === "CANCELLED") {
        add(task.id, "CANCELLED_PREREQUISITE", true,
          `Required task ${dependency} was cancelled.`);
      } else if (state.disposition === "DONE" &&
          prerequisite?.disposition !== "DONE") {
        add(task.id, "DEPENDENCY_NOT_DONE", true,
          `Completed task has an unfinished prerequisite: ${dependency}.`);
      }
    }
  }
  for (const state of ledger.states)
    if (!tasks.has(state.taskId))
      add(state.taskId, "UNPLANNED_STATE", true,
        "Ledger contains a task not present in the selected backlog.");
  findings.sort((a, b) => a.taskId.localeCompare(b.taskId) ||
    a.code.localeCompare(b.code));
  const blockingCount = findings.filter(item => item.blocking).length;
  return {
    organizationId: backlog.organizationId, capturedAt: backlog.capturedAt,
    complete: backlog.complete && ledger.complete,
    taskCount: backlog.tasks.length, findings, blockingCount,
    advisoryCount: findings.length - blockingCount,
    readyForIndependentVerification:
      backlog.complete && ledger.complete && ledger.valid && blockingCount === 0,
    warnings: [
      "Reconciliation checks declared records, not actual completion or evidence authenticity.",
      "Independent verification is still required before a security finding can be closed.",
    ],
  };
}
export type LedgerTimelinePoint = {
  at: string;
  acceptedEvents: number;
  rejectedEvents: number;
  completed: number;
  active: number;
  blocked: number;
  remainingMinutes: number;
};
export type LedgerTimeline = {
  organizationId: string;
  capturedAt: string;
  points: LedgerTimelinePoint[];
  totalAccepted: number;
  totalRejected: number;
  warnings: string[];
};
/**
 * Replays successive prefixes for small offline timelines. This is deliberately
 * bounded to avoid quadratic work on untrusted event histories.
 */
export function buildInvestigationLedgerTimeline(
  backlog: InvestigationBacklog,
  events: readonly LedgerEvent[],
  policy: LedgerPolicy,
  maximumEvents = 1000,
): LedgerTimeline {
  if (!Number.isSafeInteger(maximumEvents) || maximumEvents < 1 ||
      maximumEvents > 1000 || events.length > maximumEvents)
    throw new Error("Ledger timeline exceeds bounded replay limit.");
  const points: LedgerTimelinePoint[] = [];
  for (let count = 0; count <= events.length; count++) {
    const ledger = replayInvestigationLedger(backlog, events.slice(0, count), policy);
    points.push({
      at: count ? events[count - 1]!.at : backlog.capturedAt,
      acceptedEvents: ledger.events.length,
      rejectedEvents: ledger.violations.length,
      completed: ledger.completed, active: ledger.active,
      blocked: ledger.blocked, remainingMinutes: ledger.remainingMinutes,
    });
  }
  const last = points.at(-1)!;
  return {
    organizationId: backlog.organizationId, capturedAt: backlog.capturedAt,
    points, totalAccepted: last.acceptedEvents,
    totalRejected: last.rejectedEvents,
    warnings: [
      "Timeline shows replayed declarations, not independently verified activity.",
      "Invalid events do not alter state, but remain counted in the timeline.",
    ],
  };
}
export type LedgerActorActivity = {
  actorId: string;
  eventCount: number;
  distinctTasks: number;
  completedEvents: number;
  blockedEvents: number;
  firstAt: string;
  lastAt: string;
};
export function ledgerActorActivity(
  ledger: InvestigationLedger,
): LedgerActorActivity[] {
  const grouped = new Map<string, LedgerEvent[]>();
  for (const event of ledger.events) {
    const existing = grouped.get(event.actorId) ?? [];
    existing.push(event);
    grouped.set(event.actorId, existing);
  }
  return [...grouped.entries()].map(([actorId, events]) => ({
    actorId, eventCount: events.length,
    distinctTasks: new Set(events.map(item => item.taskId)).size,
    completedEvents: events.filter(item => item.kind === "COMPLETE").length,
    blockedEvents: events.filter(item => item.kind === "BLOCK").length,
    firstAt: events[0]!.at, lastAt: events[events.length - 1]!.at,
  })).sort((a, b) => b.eventCount - a.eventCount ||
    a.actorId.localeCompare(b.actorId));
}
export function ledgerReconciliationCsv(
  report: LedgerReconciliation,
): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [["taskId", "code", "blocking", "explanation"]
    .map(safe).join(",")];
  for (const finding of report.findings)
    lines.push([finding.taskId, finding.code, finding.blocking,
      finding.explanation].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function ledgerTimelineJson(timeline: LedgerTimeline): string {
  return JSON.stringify(timeline, null, 2) + "\n";
}
