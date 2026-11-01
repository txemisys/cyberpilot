import type { LedgerEntry, LedgerPage } from "./work-integrity-audit-ledger";

/**
 * Projects the actual reviewed decision sequence into investigative paths.
 * No attempt is made to resolve events absent from the bounded audit page.
 * This never mutates the authoritative work record or grants review approval.
 */
export type DecisionPathIssueCode =
  | "ILLEGAL_FIRST_REOPEN"
  | "ILLEGAL_REPEAT_REOPEN"
  | "REOPEN_WITHOUT_DISPOSITION"
  | "DECISION_AFTER_DISPOSITION_WITHOUT_REOPEN"
  | "MISSING_DIRECT_PREDECESSOR"
  | "CROSS_CASE_PREDECESSOR"
  | "DECREASING_WORK_REVISION"
  | "REVIEW_EVENT_AFTER_SUCCESSOR"
  | "MULTIPLE_SUCCESSORS"
  | "CYCLE_IN_SELECTED_PAGE";
export type DecisionPathIssue = {
  caseKey: string;
  eventId: string;
  predecessorEventId: string | null;
  code: DecisionPathIssueCode;
  severity: "ERROR" | "REVIEW" | "UNKNOWN";
  explanation: string;
  nextStep: string;
};
export type DecisionPath = {
  caseKey: string;
  workItemId: string;
  resourceId: string;
  diagnosticCode: string;
  firstRecordedEvent: string;
  lastRecordedEvent: string;
  eventsOnPage: number;
  reopenedOnPage: number;
  acknowledgedOnPage: number;
  dismissedOnPage: number;
  investigatingOnPage: number;
  latestRecordedDecision: string;
  linkedPredecessorsOnPage: number;
  predecessorLinksOutsidePage: number;
  issues: DecisionPathIssue[];
  hasAuthoritativeCompleteHistory: false;
};
export type DecisionPathReport = {
  organizationId: string;
  generatedAt: string;
  boundedSourcePage: true;
  totalPaths: number;
  eventsInspected: number;
  issues: number;
  errors: number;
  reviewWarnings: number;
  unknowns: number;
  paths: DecisionPath[];
  limitations: string[];
};
function caseKey(event: LedgerEntry): string {
  return JSON.stringify([event.workItemId, event.code, event.resourceId]);
}
function order(events: readonly LedgerEntry[]): LedgerEntry[] {
  return [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) || a.eventId.localeCompare(b.eventId));
}
export function reconstructDecisionPaths(page: LedgerPage): DecisionPathReport {
  const byCase = new Map<string, LedgerEntry[]>();
  const byId = new Map<string, LedgerEntry>();
  for (const entry of page.entries) {
    if (entry.organizationId !== page.organizationId)
      throw new Error("Cannot reconstruct a cross-organization decision sequence.");
    if (byId.has(entry.eventId))
      throw new Error("Repeated event identity in ledger decision page.");
    byId.set(entry.eventId, entry);
    const key = caseKey(entry);
    const group = byCase.get(key) ?? [];
    group.push(entry);
    byCase.set(key, group);
  }
  const paths: DecisionPath[] = [];
  for (const [key, group] of byCase) {
    const timeline = order(group);
    const issues: DecisionPathIssue[] = [];
    const emit = (
      event: LedgerEntry,
      code: DecisionPathIssueCode,
      severity: DecisionPathIssue["severity"],
      explanation: string,
      nextStep: string,
    ) => issues.push({
      caseKey: key, eventId: event.eventId,
      predecessorEventId: event.predecessorEventId,
      code, severity, explanation, nextStep,
    });
    const successors = new Map<string, number>();
    let linkedPredecessorsOnPage = 0;
    let predecessorLinksOutsidePage = 0;
    for (const event of timeline) {
      const predecessor = event.predecessorEventId ?
        byId.get(event.predecessorEventId) : undefined;
      if (event.predecessorEventId !== null) {
        successors.set(event.predecessorEventId,
          (successors.get(event.predecessorEventId) ?? 0) + 1);
        if (!predecessor) {
          predecessorLinksOutsidePage++;
          emit(event, "MISSING_DIRECT_PREDECESSOR", "UNKNOWN",
            "The preceding decision is not available in this bounded page.",
            "Read the work-specific audit chain before assessing review continuity.");
        } else {
          linkedPredecessorsOnPage++;
          if (caseKey(predecessor) !== key) emit(event,
            "CROSS_CASE_PREDECESSOR", "ERROR",
            "The linked predecessor belongs to another case identity.",
            "Investigate the source audit reference before relying on this decision.");
          else {
            if (predecessor.revision > event.revision) emit(event,
              "DECREASING_WORK_REVISION", "ERROR",
              "The reviewed work revision decreased across linked decisions.",
              "Reconcile work versions with the authoritative audit event order.");
            if (predecessor.occurredAt > event.occurredAt) emit(event,
              "REVIEW_EVENT_AFTER_SUCCESSOR", "REVIEW",
              "The linked predecessor has a later timestamp than its successor.",
              "Inspect source audit clocks and transaction chronology.");
          }
        }
      }
      const seen = new Set<string>();
      let cursor: LedgerEntry | undefined = event;
      while (cursor && !seen.has(cursor.eventId)) {
        seen.add(cursor.eventId);
        cursor = cursor.predecessorEventId ?
          byId.get(cursor.predecessorEventId) : undefined;
      }
      if (cursor) emit(event, "CYCLE_IN_SELECTED_PAGE", "ERROR",
        "A cycle was found in the recorded predecessor references.",
        "Investigate event references in the source audit history.");
    }
    for (const event of timeline) {
      if ((successors.get(event.eventId) ?? 0) > 1) emit(event,
        "MULTIPLE_SUCCESSORS", "ERROR",
        "One audit review has multiple directly linked successor decisions.",
        "Check possible concurrent reviews and optimistic locking history.");
    }
    // Evaluate only direct predecessor transitions when the record is actually
    // on this page. Never infer the first decision of a globally complete chain.
    for (const event of timeline) {
      const previous = event.predecessorEventId ?
        byId.get(event.predecessorEventId) : undefined;
      if (!previous || caseKey(previous) !== key) continue;
      if (event.decision === "REOPEN" && previous.decision === "REOPEN") emit(event,
        "ILLEGAL_REPEAT_REOPEN", "ERROR",
        "A reopen action directly follows another reopen action.",
        "Reconcile the auditable triage state transition.");
      if (event.decision === "REOPEN" &&
          previous.decision !== "ACKNOWLEDGE" &&
          previous.decision !== "DISMISS") emit(event,
        "REOPEN_WITHOUT_DISPOSITION", "ERROR",
        "A reopened review does not directly follow a recorded disposition.",
        "Check predecessor event identity and reconstruct the full decision chain.");
      if ((previous.decision === "ACKNOWLEDGE" ||
          previous.decision === "DISMISS") && event.decision !== "REOPEN") emit(event,
        "DECISION_AFTER_DISPOSITION_WITHOUT_REOPEN", "ERROR",
        "A closed review has a new decision without a preceding reopen.",
        "Review server-side transition enforcement and recorded decisions.");
    }
    // A first-page root is not necessarily the original root, but a row with
    // no predecessor explicitly declares itself as an initial review.
    for (const event of timeline)
      if (event.predecessorEventId === null && event.decision === "REOPEN")
        emit(event, "ILLEGAL_FIRST_REOPEN", "ERROR",
          "A reopen review declares no predecessor decision.",
          "Inspect audit metadata before treating this event as a valid state transition.");
    const first = timeline[0]!;
    const last = timeline[timeline.length - 1]!;
    paths.push({
      caseKey: key, workItemId: first.workItemId,
      resourceId: first.resourceId, diagnosticCode: first.code,
      firstRecordedEvent: first.eventId, lastRecordedEvent: last.eventId,
      eventsOnPage: timeline.length,
      reopenedOnPage: timeline.filter(e => e.decision === "REOPEN").length,
      acknowledgedOnPage: timeline.filter(e => e.decision === "ACKNOWLEDGE").length,
      dismissedOnPage: timeline.filter(e => e.decision === "DISMISS").length,
      investigatingOnPage: timeline.filter(e => e.decision === "INVESTIGATE").length,
      latestRecordedDecision: last.decision,
      linkedPredecessorsOnPage, predecessorLinksOutsidePage,
      issues: issues.sort((a, b) => a.code.localeCompare(b.code) ||
        a.eventId.localeCompare(b.eventId)),
      hasAuthoritativeCompleteHistory: false,
    });
  }
  paths.sort((a, b) => b.issues.filter(i => i.severity === "ERROR").length -
    a.issues.filter(i => i.severity === "ERROR").length ||
    b.predecessorLinksOutsidePage - a.predecessorLinksOutsidePage ||
    a.caseKey.localeCompare(b.caseKey));
  const allIssues = paths.flatMap(path => path.issues);
  return {
    organizationId: page.organizationId,
    generatedAt: page.generatedAt,
    boundedSourcePage: true,
    totalPaths: paths.length,
    eventsInspected: page.entries.length,
    issues: allIssues.length,
    errors: allIssues.filter(i => i.severity === "ERROR").length,
    reviewWarnings: allIssues.filter(i => i.severity === "REVIEW").length,
    unknowns: allIssues.filter(i => i.severity === "UNKNOWN").length,
    paths,
    limitations: [
      "A bounded event page cannot prove an entire review history is present.",
      "Every issue refers to stored human-review metadata, not to verified remediation.",
      "A review decision cannot automatically resolve a diagnostic or security finding.",
      "No audit or work record is modified by this reconstruction.",
    ],
  };
}
export function decisionPathCsv(report: DecisionPathReport): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const columns = [
    "caseKey", "workItemId", "diagnosticCode", "eventsOnPage",
    "latestRecordedDecision", "linkedPredecessorsOnPage",
    "predecessorLinksOutsidePage", "issueCode", "severity",
    "eventId", "predecessorEventId", "explanation", "nextStep",
  ];
  const lines = [columns.map(safe).join(",")];
  for (const path of report.paths) {
    for (const issue of path.issues) {
      lines.push([
        path.caseKey, path.workItemId, path.diagnosticCode,
        path.eventsOnPage, path.latestRecordedDecision,
        path.linkedPredecessorsOnPage, path.predecessorLinksOutsidePage,
        issue.code, issue.severity, issue.eventId, issue.predecessorEventId,
        issue.explanation, issue.nextStep,
      ].map(safe).join(","));
    }
  }
  return lines.join("\r\n") + "\r\n";
}
