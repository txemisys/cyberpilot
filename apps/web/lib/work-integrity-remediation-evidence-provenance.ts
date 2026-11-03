import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";
import type {
  IntegrityRemediationExecutionLedger,
  IntegrityRemediationExecutionEvent,
} from "./work-integrity-remediation-execution";
import type { IntegrityExecutionReviewAudit } from "./work-integrity-remediation-execution-review";

export type IntegrityExecutionEvidenceStatus =
  | "ACTIVE_ASSOCIATION" | "WITHDRAWN_ASSOCIATION"
  | "UNKNOWN_ASSOCIATION" | "AMBIGUOUS_ASSOCIATION"
  | "CROSS_CASE_ASSOCIATION" | "FUTURE_ASSOCIATION"
  | "INVALID_HISTORY";
export type IntegrityExecutionEvidenceFindingCode =
  | "UNMATCHED_REFERENCE" | "WITHDRAWN_REFERENCE"
  | "DUPLICATE_LINK_AUDIT" | "ORPHAN_WITHDRAWAL"
  | "CONFLICTING_LINK_IDENTITY" | "CROSS_CASE_REFERENCE"
  | "REFERENCE_AFTER_COMPLETION" | "HISTORY_CAPTURE_MISMATCH"
  | "UNTRUSTED_EXECUTION_EVENT" | "NO_ACTIVE_ASSOCIATION"
  | "INCOMPLETE_WORK_BINDING";
export type IntegrityExecutionEvidenceFinding = {
  code: IntegrityExecutionEvidenceFindingCode;
  severity: "ERROR" | "WARNING";
  candidateId: string | null;
  eventId: string | null;
  reference: string | null;
  auditId: string | null;
  explanation: string;
};
export type IntegrityExecutionEvidenceReference = {
  reference: string;
  candidateId: string;
  eventId: string;
  attemptId: string;
  submittedAt: string;
  status: IntegrityExecutionEvidenceStatus;
  caseKey: string | null;
  workItemId: string | null;
  linkAuditId: string | null;
  withdrawalAuditId: string | null;
  linkedAt: string | null;
  withdrawnAt: string | null;
  associatedWithCandidate: boolean;
  linkedBeforeSubmission: boolean;
  securityVerified: false;
};
export type IntegrityExecutionEvidenceCandidate = {
  candidateId: string;
  action: string;
  priority: string;
  caseKey: string | null;
  workItemId: string | null;
  executionState: string;
  submittedReferences: number;
  activeAssociations: number;
  withdrawnAssociations: number;
  unmatchedReferences: number;
  crossCaseReferences: number;
  ambiguousReferences: number;
  findings: IntegrityExecutionEvidenceFinding[];
  evidenceProvenanceComplete: boolean;
  securityVerified: false;
};
export type IntegrityExecutionEvidenceReport = {
  schemaVersion: 1;
  captureId: string;
  limitation: string;
  references: IntegrityExecutionEvidenceReference[];
  candidates: IntegrityExecutionEvidenceCandidate[];
  findings: IntegrityExecutionEvidenceFinding[];
  totals: {
    candidates: number;
    executionEvents: number;
    submittedReferences: number;
    distinctReferences: number;
    activeAssociations: number;
    withdrawnAssociations: number;
    unmatchedReferences: number;
    crossCaseReferences: number;
    ambiguousReferences: number;
    findings: number;
    errors: number;
    warnings: number;
    provenanceCompleteCandidates: number;
    securityVerifiedCandidates: 0;
  };
};
export type IntegrityExecutionEvidenceQuery = {
  candidateIds?: string[];
  statuses?: IntegrityExecutionEvidenceStatus[];
  caseKeys?: string[];
  workItemIds?: string[];
  onlyMismatches?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionEvidencePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  references: IntegrityExecutionEvidenceReference[];
};
type LinkRecord = {
  auditId: string;
  caseKey: string;
  workItemId: string;
  occurredAt: string;
  withdrawalAuditId: string | null;
  withdrawnAt: string | null;
  invalid: boolean;
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid execution evidence query.");
  return value as Record<string, unknown>;
}
function strings(value: unknown, label: string, max = 1000) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function finding(
  code: IntegrityExecutionEvidenceFindingCode,
  severity: IntegrityExecutionEvidenceFinding["severity"],
  explanation: string,
  candidateId: string | null = null,
  eventId: string | null = null,
  reference: string | null = null,
  auditId: string | null = null,
): IntegrityExecutionEvidenceFinding {
  return {
    code, severity, explanation, candidateId, eventId, reference, auditId,
  };
}
function associationHistory(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
) {
  const records = new Map<string, LinkRecord>();
  const findings: IntegrityExecutionEvidenceFinding[] = [];
  const seen = new Set<string>();
  const sorted = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.auditId.localeCompare(b.auditId));
  for (const event of sorted) {
    if (event.captureId !== captureId) {
      findings.push(finding("HISTORY_CAPTURE_MISMATCH", "ERROR",
        "Link audit belongs to another capture.", null, null,
        null, event.auditId));
      continue;
    }
    if (seen.has(event.auditId)) {
      findings.push(finding("DUPLICATE_LINK_AUDIT", "ERROR",
        "Audit ID occurs more than once in association history.",
        null, null, null, event.auditId));
      const existing = records.get(event.auditId);
      if (existing) existing.invalid = true;
      continue;
    }
    seen.add(event.auditId);
    if (event.action === "LINK") {
      records.set(event.auditId, {
        auditId: event.auditId, caseKey: event.caseKey,
        workItemId: event.workItemId, occurredAt: event.occurredAt,
        withdrawalAuditId: null, withdrawnAt: null, invalid: false,
      });
      continue;
    }
    if (!event.originalAuditId) {
      findings.push(finding("ORPHAN_WITHDRAWAL", "ERROR",
        "Withdrawal does not identify an original link.",
        null, null, null, event.auditId));
      continue;
    }
    const original = records.get(event.originalAuditId);
    if (!original) {
      findings.push(finding("ORPHAN_WITHDRAWAL", "ERROR",
        "Withdrawal references an unknown or future association.",
        null, null, null, event.auditId));
      continue;
    }
    if (original.caseKey !== event.caseKey ||
        original.workItemId !== event.workItemId ||
        event.occurredAt < original.occurredAt) {
      original.invalid = true;
      findings.push(finding("CONFLICTING_LINK_IDENTITY", "ERROR",
        "Withdrawal does not match original association identity or time.",
        null, null, null, event.auditId));
      continue;
    }
    if (original.withdrawalAuditId) {
      original.invalid = true;
      findings.push(finding("CONFLICTING_LINK_IDENTITY", "ERROR",
        "Association was withdrawn more than once.",
        null, null, null, event.auditId));
      continue;
    }
    original.withdrawalAuditId = event.auditId;
    original.withdrawnAt = event.occurredAt;
  }
  return { records, findings };
}
function resolveReference(
  reference: string,
  event: IntegrityRemediationExecutionEvent,
  planned: IntegrityRemediationPlan["candidates"][number] | undefined,
  records: Map<string, LinkRecord>,
): IntegrityExecutionEvidenceReference {
  const record = records.get(reference);
  let status: IntegrityExecutionEvidenceStatus = "UNKNOWN_ASSOCIATION";
  if (record) {
    if (record.invalid) status = "INVALID_HISTORY";
    else if (record.occurredAt > event.occurredAt)
      status = "FUTURE_ASSOCIATION";
    else if (planned?.caseKey && record.caseKey !== planned.caseKey)
      status = "CROSS_CASE_ASSOCIATION";
    else if (planned?.workItemId && record.workItemId !== planned.workItemId)
      status = "CROSS_CASE_ASSOCIATION";
    else if (record.withdrawnAt && record.withdrawnAt <= event.occurredAt)
      status = "WITHDRAWN_ASSOCIATION";
    else status = "ACTIVE_ASSOCIATION";
  }
  return {
    reference, candidateId: event.candidateId,
    eventId: event.eventId, attemptId: event.attemptId,
    submittedAt: event.occurredAt, status,
    caseKey: record?.caseKey ?? null,
    workItemId: record?.workItemId ?? null,
    linkAuditId: record?.auditId ?? null,
    withdrawalAuditId: record?.withdrawalAuditId ?? null,
    linkedAt: record?.occurredAt ?? null,
    withdrawnAt: record?.withdrawnAt ?? null,
    associatedWithCandidate: !!record && !record.invalid &&
      (!planned?.caseKey || planned.caseKey === record.caseKey) &&
      (!planned?.workItemId || planned.workItemId === record.workItemId),
    linkedBeforeSubmission: !!record &&
      record.occurredAt <= event.occurredAt,
    securityVerified: false,
  };
}
function referenceFindings(
  reference: IntegrityExecutionEvidenceReference,
): IntegrityExecutionEvidenceFinding[] {
  const fields = [
    reference.candidateId, reference.eventId,
    reference.reference, reference.linkAuditId,
  ] as const;
  switch (reference.status) {
    case "UNKNOWN_ASSOCIATION":
      return [finding("UNMATCHED_REFERENCE", "WARNING",
        "Submitted reference is not a known server-side link audit.", ...fields)];
    case "WITHDRAWN_ASSOCIATION":
      return [finding("WITHDRAWN_REFERENCE", "WARNING",
        "Association was withdrawn before evidence was submitted.", ...fields)];
    case "CROSS_CASE_ASSOCIATION":
      return [finding("CROSS_CASE_REFERENCE", "ERROR",
        "Association does not match the remediation case or work item.", ...fields)];
    case "FUTURE_ASSOCIATION":
      return [finding("REFERENCE_AFTER_COMPLETION", "ERROR",
        "Association was created after the execution event.", ...fields)];
    case "INVALID_HISTORY":
      return [finding("CONFLICTING_LINK_IDENTITY", "ERROR",
        "Reference points to an inconsistent association history.", ...fields)];
    default:
      return [];
  }
}
export function reconcileIntegrityExecutionEvidence(
  plan: IntegrityRemediationPlan,
  ledger: IntegrityRemediationExecutionLedger,
  audit: IntegrityExecutionReviewAudit,
  executionEvents: readonly IntegrityRemediationExecutionEvent[],
  history: readonly IntegrityLinkHistoryEvent[],
): IntegrityExecutionEvidenceReport {
  if (plan.captureId !== ledger.captureId ||
      plan.captureId !== audit.captureId)
    throw new WorkInputError("INVALID", "Execution evidence capture mismatch.");
  const links = associationHistory(plan.captureId, history);
  const planned = new Map(plan.candidates.map(x => [x.id, x]));
  const acceptedEvents = new Set(audit.timeline.filter(x => x.accepted)
    .map(x => x.eventId));
  const references: IntegrityExecutionEvidenceReference[] = [];
  const findings = [...links.findings];
  const seenEvents = new Set<string>();
  for (const event of executionEvents) {
    if (seenEvents.has(event.eventId)) continue;
    seenEvents.add(event.eventId);
    if (!acceptedEvents.has(event.eventId)) {
      if (event.evidenceRefs.length)
        findings.push(finding("UNTRUSTED_EXECUTION_EVENT", "WARNING",
          "Evidence submitted in a rejected execution event is not reconciled.",
          event.candidateId, event.eventId));
      continue;
    }
    const candidate = planned.get(event.candidateId);
    for (const ref of event.evidenceRefs) {
      const resolved = resolveReference(ref, event, candidate, links.records);
      references.push(resolved);
      findings.push(...referenceFindings(resolved));
    }
  }
  const candidates: IntegrityExecutionEvidenceCandidate[] =
    ledger.candidates.map(candidate => {
      const planCandidate = planned.get(candidate.candidateId);
      const refs = references.filter(x =>
        x.candidateId === candidate.candidateId);
      const relevant = findings.filter(x =>
        x.candidateId === candidate.candidateId);
      const active = refs.filter(x =>
        x.status === "ACTIVE_ASSOCIATION").length;
      const withdrawn = refs.filter(x =>
        x.status === "WITHDRAWN_ASSOCIATION").length;
      const unmatched = refs.filter(x =>
        x.status === "UNKNOWN_ASSOCIATION").length;
      const crossCase = refs.filter(x =>
        x.status === "CROSS_CASE_ASSOCIATION").length;
      const ambiguous = refs.filter(x =>
        x.status === "AMBIGUOUS_ASSOCIATION" ||
        x.status === "INVALID_HISTORY").length;
      if (candidate.state === "COMPLETED" && active === 0)
        relevant.push(finding("NO_ACTIVE_ASSOCIATION", "WARNING",
          "Completed execution has no active, matching link association.",
          candidate.candidateId));
      if (planCandidate?.workItemId === null &&
          candidate.state === "COMPLETED")
        relevant.push(finding("INCOMPLETE_WORK_BINDING", "WARNING",
          "Completed remediation has no explicit work item binding.",
          candidate.candidateId));
      for (const issue of relevant) {
        if (!findings.includes(issue)) findings.push(issue);
      }
      return {
        candidateId: candidate.candidateId,
        action: candidate.action ?? "UNKNOWN",
        priority: candidate.priority ?? "UNKNOWN",
        caseKey: planCandidate?.caseKey ?? null,
        workItemId: planCandidate?.workItemId ?? null,
        executionState: candidate.state,
        submittedReferences: refs.length,
        activeAssociations: active, withdrawnAssociations: withdrawn,
        unmatchedReferences: unmatched, crossCaseReferences: crossCase,
        ambiguousReferences: ambiguous, findings: relevant,
        evidenceProvenanceComplete: candidate.state === "COMPLETED" &&
          active > 0 && relevant.every(x => x.severity !== "ERROR"),
        securityVerified: false as const,
      };
    });
  return {
    schemaVersion: 1, captureId: plan.captureId,
    limitation: "Audit-link provenance is not evidence-content verification or proof of security.",
    references: references.sort((a, b) =>
      a.submittedAt.localeCompare(b.submittedAt) ||
      a.candidateId.localeCompare(b.candidateId) ||
      a.reference.localeCompare(b.reference)),
    candidates, findings,
    totals: {
      candidates: candidates.length,
      executionEvents: executionEvents.length,
      submittedReferences: references.length,
      distinctReferences: new Set(references.map(x => x.reference)).size,
      activeAssociations: references.filter(x =>
        x.status === "ACTIVE_ASSOCIATION").length,
      withdrawnAssociations: references.filter(x =>
        x.status === "WITHDRAWN_ASSOCIATION").length,
      unmatchedReferences: references.filter(x =>
        x.status === "UNKNOWN_ASSOCIATION").length,
      crossCaseReferences: references.filter(x =>
        x.status === "CROSS_CASE_ASSOCIATION").length,
      ambiguousReferences: references.filter(x =>
        x.status === "AMBIGUOUS_ASSOCIATION" ||
        x.status === "INVALID_HISTORY").length,
      findings: findings.length,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
      provenanceCompleteCandidates: candidates.filter(x =>
        x.evidenceProvenanceComplete).length,
      securityVerifiedCandidates: 0,
    },
  };
}
export function parseIntegrityExecutionEvidenceQuery(
  value: unknown,
): IntegrityExecutionEvidenceQuery {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "candidateIds", "statuses", "caseKeys", "workItemIds",
    "onlyMismatches", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown evidence query field.");
  const statuses = raw.statuses === undefined ? undefined :
    strings(raw.statuses, "evidence statuses", 7);
  const allowedStatuses: IntegrityExecutionEvidenceStatus[] = [
    "ACTIVE_ASSOCIATION", "WITHDRAWN_ASSOCIATION",
    "UNKNOWN_ASSOCIATION", "AMBIGUOUS_ASSOCIATION",
    "CROSS_CASE_ASSOCIATION", "FUTURE_ASSOCIATION", "INVALID_HISTORY",
  ];
  if (statuses?.some(x =>
    !allowedStatuses.includes(x as IntegrityExecutionEvidenceStatus)))
    throw new WorkInputError("INVALID", "Unknown evidence status.");
  if (raw.onlyMismatches !== undefined &&
      typeof raw.onlyMismatches !== "boolean")
    throw new WorkInputError("INVALID", "Invalid mismatch filter.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid evidence pagination.");
  return {
    ...(raw.candidateIds !== undefined ? {
      candidateIds: strings(raw.candidateIds, "candidate IDs"),
    } : {}),
    ...(statuses !== undefined ? {
      statuses: statuses as IntegrityExecutionEvidenceStatus[],
    } : {}),
    ...(raw.caseKeys !== undefined ? {
      caseKeys: strings(raw.caseKeys, "case keys"),
    } : {}),
    ...(raw.workItemIds !== undefined ? {
      workItemIds: strings(raw.workItemIds, "work item IDs"),
    } : {}),
    onlyMismatches: raw.onlyMismatches === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionEvidence(
  report: IntegrityExecutionEvidenceReport,
  query: IntegrityExecutionEvidenceQuery,
): IntegrityExecutionEvidencePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.references.filter(x =>
    (!query.candidateIds || query.candidateIds.includes(x.candidateId)) &&
    (!query.statuses || query.statuses.includes(x.status)) &&
    (!query.caseKeys || (x.caseKey !== null &&
      query.caseKeys.includes(x.caseKey))) &&
    (!query.workItemIds || (x.workItemId !== null &&
      query.workItemIds.includes(x.workItemId))) &&
    (!query.onlyMismatches || x.status !== "ACTIVE_ASSOCIATION"));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    references: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityExecutionEvidence(
  before: IntegrityExecutionEvidenceReport,
  after: IntegrityExecutionEvidenceReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Evidence report capture mismatch.");
  const old = new Map(before.candidates.map(x => [x.candidateId, x]));
  const current = new Map(after.candidates.map(x => [x.candidateId, x]));
  return {
    captureId: before.captureId,
    introduced: after.candidates.filter(x => !old.has(x.candidateId))
      .map(x => x.candidateId),
    removed: before.candidates.filter(x => !current.has(x.candidateId))
      .map(x => x.candidateId),
    provenanceGained: after.candidates.filter(x =>
      x.evidenceProvenanceComplete &&
      !old.get(x.candidateId)?.evidenceProvenanceComplete)
      .map(x => x.candidateId),
    provenanceLost: before.candidates.filter(x =>
      x.evidenceProvenanceComplete &&
      !current.get(x.candidateId)?.evidenceProvenanceComplete)
      .map(x => x.candidateId),
    activeAssociationDelta: after.totals.activeAssociations -
      before.totals.activeAssociations,
    withdrawnAssociationDelta: after.totals.withdrawnAssociations -
      before.totals.withdrawnAssociations,
    errorDelta: after.totals.errors - before.totals.errors,
    warningDelta: after.totals.warnings - before.totals.warnings,
    securityVerifiedCandidates: 0 as const,
  };
}
