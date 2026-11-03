import { WorkInputError, parseWorkId } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";

export type LinkReviewFindingCode =
  | "ORPHAN_WITHDRAWAL" | "DUPLICATE_WITHDRAWAL"
  | "MISMATCHED_WITHDRAWAL" | "WITHDRAWAL_BEFORE_LINK"
  | "DUPLICATE_AUDIT_ID" | "INVALID_TIMESTAMP"
  | "CROSS_CAPTURE_REFERENCE" | "REPEATED_ACTIVE_ASSOCIATION";
export type LinkReviewSeverity = "ERROR" | "WARNING";
export type LinkReviewFinding = {
  code: LinkReviewFindingCode;
  severity: LinkReviewSeverity;
  auditId: string;
  relatedAuditId: string | null;
  captureId: string;
  caseKey: string;
  workItemId: string;
  explanation: string;
};
export type LinkReviewAssociation = {
  auditId: string;
  captureId: string;
  caseKey: string;
  workItemId: string;
  createdAt: string;
  createdBy: string | null;
  withdrawnAt: string | null;
  withdrawnBy: string | null;
  withdrawalAuditId: string | null;
  state: "ACTIVE" | "WITHDRAWN";
};
export type LinkReviewReport = {
  schemaVersion: 1;
  captureId: string;
  totalEvents: number;
  associations: LinkReviewAssociation[];
  findings: LinkReviewFinding[];
  counts: {
    active: number;
    withdrawn: number;
    errors: number;
    warnings: number;
    orphanWithdrawals: number;
    duplicateWithdrawals: number;
  };
};
export type LinkReviewFilter = {
  caseKey?: string;
  workItemId?: string;
  actorUserId?: string;
  state?: "ACTIVE" | "WITHDRAWN";
  since?: string;
  until?: string;
};
export type LinkReviewPage = {
  associations: LinkReviewAssociation[];
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
};
export type LinkReviewTrend = {
  day: string;
  created: number;
  withdrawn: number;
  activeAtEnd: number;
};
export type LinkReviewCase = {
  caseKey: string;
  active: number;
  withdrawn: number;
  workItemIds: string[];
  lastActivityAt: string;
  findings: number;
};
export type LinkReviewWork = {
  workItemId: string;
  active: number;
  withdrawn: number;
  caseKeys: string[];
  lastActivityAt: string;
  findings: number;
};
export type LinkReviewActor = {
  actorUserId: string | null;
  created: number;
  withdrawn: number;
  firstActivityAt: string;
  lastActivityAt: string;
};
export type LinkReviewMatrix = {
  cases: LinkReviewCase[];
  workItems: LinkReviewWork[];
  actors: LinkReviewActor[];
  trends: LinkReviewTrend[];
};
export type LinkReviewChange = {
  auditId: string;
  kind: "ADDED" | "WITHDRAWN" | "UNCHANGED";
  before: LinkReviewAssociation | null;
  after: LinkReviewAssociation | null;
};
export type LinkReviewDiff = {
  added: number;
  withdrawn: number;
  unchanged: number;
  changes: LinkReviewChange[];
};
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const isTimestamp = (value: string) =>
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
function validDate(value: string, label: string): string {
  if (!isTimestamp(value)) throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function assertRange(since?: string, until?: string): void {
  if (since) validDate(since, "since");
  if (until) validDate(until, "until");
  if (since && until && since > until)
    throw new WorkInputError("INVALID", "Since must precede until.");
}
function orderedEvents(events: readonly IntegrityLinkHistoryEvent[]) {
  return [...events].sort((a, b) =>
    compare(a.occurredAt, b.occurredAt) || compare(a.auditId, b.auditId));
}
function finding(
  event: IntegrityLinkHistoryEvent,
  code: LinkReviewFindingCode,
  explanation: string,
  relatedAuditId: string | null = null,
  severity: LinkReviewSeverity = "ERROR",
): LinkReviewFinding {
  return {
    code, severity, auditId: event.auditId, relatedAuditId,
    captureId: event.captureId, caseKey: event.caseKey,
    workItemId: event.workItemId, explanation,
  };
}
function identity(event: IntegrityLinkHistoryEvent) {
  return JSON.stringify([event.captureId, event.caseKey, event.workItemId]);
}
export function reviewIntegrityLinks(
  captureId: string, events: readonly IntegrityLinkHistoryEvent[],
): LinkReviewReport {
  parseWorkId(captureId, "capture ID");
  const findings: LinkReviewFinding[] = [];
  const ids = new Map<string, IntegrityLinkHistoryEvent>();
  const links = new Map<string, IntegrityLinkHistoryEvent>();
  const withdrawals = new Map<string, IntegrityLinkHistoryEvent[]>();
  for (const event of events) {
    if (event.captureId !== captureId)
      throw new WorkInputError("INVALID", "Cross-capture audit data.");
    if (!isTimestamp(event.occurredAt)) {
      findings.push(finding(event, "INVALID_TIMESTAMP", "Audit event has an invalid timestamp."));
      continue;
    }
    if (ids.has(event.auditId)) {
      findings.push(finding(event, "DUPLICATE_AUDIT_ID", "Audit identifier occurs more than once.",
        event.auditId));
      continue;
    }
    ids.set(event.auditId, event);
    if (event.action === "LINK") {
      links.set(event.auditId, event);
    } else if (event.originalAuditId) {
      const existing = withdrawals.get(event.originalAuditId) ?? [];
      existing.push(event);
      withdrawals.set(event.originalAuditId, existing);
    } else {
      findings.push(finding(event, "ORPHAN_WITHDRAWAL",
        "Withdrawal does not identify its original association."));
    }
  }
  for (const [originalId, list] of withdrawals) {
    const original = links.get(originalId);
    if (!original) {
      for (const event of list) {
        findings.push(finding(event, "ORPHAN_WITHDRAWAL",
          "Original association is absent from the audit history.", originalId));
      }
      continue;
    }
    const sorted = orderedEvents(list);
    for (const event of sorted) {
      if (identity(event) !== identity(original)) {
        findings.push(finding(event, "MISMATCHED_WITHDRAWAL",
          "Withdrawal identity differs from its original association.", originalId));
      }
      if (event.occurredAt < original.occurredAt) {
        findings.push(finding(event, "WITHDRAWAL_BEFORE_LINK",
          "Withdrawal predates the original association.", originalId));
      }
    }
    for (const event of sorted.slice(1)) {
      findings.push(finding(event, "DUPLICATE_WITHDRAWAL",
        "Multiple withdrawals target the same association.", originalId));
    }
  }
  const associations: LinkReviewAssociation[] = [...links.values()].map(event => {
    const first = orderedEvents(withdrawals.get(event.auditId) ?? [])[0];
    return {
      auditId: event.auditId, captureId, caseKey: event.caseKey,
      workItemId: event.workItemId, createdAt: event.occurredAt,
      createdBy: event.actorUserId, withdrawnAt: first?.occurredAt ?? null,
      withdrawnBy: first?.actorUserId ?? null,
      withdrawalAuditId: first?.auditId ?? null,
      state: first ? "WITHDRAWN" as const : "ACTIVE" as const,
    };
  }).sort((a, b) => compare(a.createdAt, b.createdAt) || compare(a.auditId, b.auditId));
  const activeIdentities = new Map<string, LinkReviewAssociation>();
  for (const association of associations) {
    if (association.state !== "ACTIVE") continue;
    const key = JSON.stringify([association.caseKey, association.workItemId]);
    const previous = activeIdentities.get(key);
    if (previous) {
      const source = links.get(association.auditId)!;
      findings.push(finding(source, "REPEATED_ACTIVE_ASSOCIATION",
        "Two active links connect the same case and work item.",
        previous.auditId, "WARNING"));
    } else activeIdentities.set(key, association);
  }
  findings.sort((a, b) => compare(a.auditId, b.auditId) || compare(a.code, b.code));
  return {
    schemaVersion: 1, captureId, totalEvents: events.length,
    associations, findings,
    counts: {
      active: associations.filter(x => x.state === "ACTIVE").length,
      withdrawn: associations.filter(x => x.state === "WITHDRAWN").length,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
      orphanWithdrawals: findings.filter(x => x.code === "ORPHAN_WITHDRAWAL").length,
      duplicateWithdrawals: findings.filter(x => x.code === "DUPLICATE_WITHDRAWAL").length,
    },
  };
}
export function filterIntegrityAssociations(
  associations: readonly LinkReviewAssociation[], filter: LinkReviewFilter,
): LinkReviewAssociation[] {
  assertRange(filter.since, filter.until);
  return associations.filter(x =>
    (filter.caseKey === undefined || x.caseKey === filter.caseKey) &&
    (filter.workItemId === undefined || x.workItemId === filter.workItemId) &&
    (filter.actorUserId === undefined ||
      x.createdBy === filter.actorUserId || x.withdrawnBy === filter.actorUserId) &&
    (filter.state === undefined || x.state === filter.state) &&
    (filter.since === undefined || x.createdAt >= filter.since) &&
    (filter.until === undefined || x.createdAt <= filter.until));
}
export function paginateIntegrityAssociations(
  associations: readonly LinkReviewAssociation[], offset = 0, limit = 100,
): LinkReviewPage {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid review pagination.");
  return {
    associations: associations.slice(offset, offset + limit),
    total: associations.length, offset, limit,
    hasMore: offset + limit < associations.length,
  };
}
function updateLast(a: string, b: string): string { return a > b ? a : b; }
export function buildIntegrityReviewMatrix(report: LinkReviewReport): LinkReviewMatrix {
  const cases = new Map<string, LinkReviewCase>();
  const works = new Map<string, LinkReviewWork>();
  const actors = new Map<string, LinkReviewActor>();
  const daily = new Map<string, { created: number; withdrawn: number }>();
  function actorActivity(id: string | null, at: string, kind: "created" | "withdrawn") {
    const key = id ?? "";
    const row = actors.get(key) ?? {
      actorUserId: id, created: 0, withdrawn: 0,
      firstActivityAt: at, lastActivityAt: at,
    };
    row[kind]++;
    if (at < row.firstActivityAt) row.firstActivityAt = at;
    row.lastActivityAt = updateLast(row.lastActivityAt, at);
    actors.set(key, row);
  }
  function dailyActivity(at: string, kind: "created" | "withdrawn") {
    const day = at.slice(0, 10);
    const row = daily.get(day) ?? { created: 0, withdrawn: 0 };
    row[kind]++;
    daily.set(day, row);
  }
  for (const association of report.associations) {
    const c = cases.get(association.caseKey) ?? {
      caseKey: association.caseKey, active: 0, withdrawn: 0,
      workItemIds: [], lastActivityAt: association.createdAt, findings: 0,
    };
    const w = works.get(association.workItemId) ?? {
      workItemId: association.workItemId, active: 0, withdrawn: 0,
      caseKeys: [], lastActivityAt: association.createdAt, findings: 0,
    };
    const kind = association.state === "ACTIVE" ? "active" : "withdrawn";
    c[kind]++;
    w[kind]++;
    if (!c.workItemIds.includes(association.workItemId))
      c.workItemIds.push(association.workItemId);
    if (!w.caseKeys.includes(association.caseKey))
      w.caseKeys.push(association.caseKey);
    const last = association.withdrawnAt ?? association.createdAt;
    c.lastActivityAt = updateLast(c.lastActivityAt, last);
    w.lastActivityAt = updateLast(w.lastActivityAt, last);
    cases.set(c.caseKey, c);
    works.set(w.workItemId, w);
    actorActivity(association.createdBy, association.createdAt, "created");
    dailyActivity(association.createdAt, "created");
    if (association.withdrawnAt) {
      actorActivity(association.withdrawnBy, association.withdrawnAt, "withdrawn");
      dailyActivity(association.withdrawnAt, "withdrawn");
    }
  }
  for (const issue of report.findings) {
    const c = cases.get(issue.caseKey);
    const w = works.get(issue.workItemId);
    if (c) c.findings++;
    if (w) w.findings++;
  }
  let active = 0;
  const trends = [...daily.entries()].sort(([a], [b]) => compare(a, b))
    .map(([day, value]) => {
      active += value.created - value.withdrawn;
      return { day, ...value, activeAtEnd: active };
    });
  return {
    cases: [...cases.values()].map(x => ({
      ...x, workItemIds: x.workItemIds.sort(compare),
    })).sort((a, b) => compare(a.caseKey, b.caseKey)),
    workItems: [...works.values()].map(x => ({
      ...x, caseKeys: x.caseKeys.sort(compare),
    })).sort((a, b) => compare(a.workItemId, b.workItemId)),
    actors: [...actors.values()].sort((a, b) =>
      compare(a.actorUserId ?? "", b.actorUserId ?? "")),
    trends,
  };
}
export function diffIntegrityReviews(
  before: LinkReviewReport, after: LinkReviewReport,
): LinkReviewDiff {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare different captures.");
  const old = new Map(before.associations.map(x => [x.auditId, x]));
  const current = new Map(after.associations.map(x => [x.auditId, x]));
  const changes: LinkReviewChange[] = [];
  for (const [auditId, association] of current) {
    const previous = old.get(auditId) ?? null;
    if (!previous) {
      changes.push({ auditId, kind: "ADDED", before: null, after: association });
    } else {
      const kind = previous.state === "ACTIVE" && association.state === "WITHDRAWN"
        ? "WITHDRAWN" : "UNCHANGED";
      changes.push({ auditId, kind, before: previous, after: association });
    }
  }
  for (const [auditId, previous] of old) {
    if (!current.has(auditId))
      throw new WorkInputError("CONFLICT", "Append-only audit history lost an association.");
    const next = current.get(auditId)!;
    if (previous.caseKey !== next.caseKey ||
        previous.workItemId !== next.workItemId ||
        previous.createdAt !== next.createdAt ||
        (previous.state === "WITHDRAWN" && next.state !== "WITHDRAWN"))
      throw new WorkInputError("CONFLICT", "Immutable association changed.");
  }
  changes.sort((a, b) => compare(a.auditId, b.auditId));
  return {
    added: changes.filter(x => x.kind === "ADDED").length,
    withdrawn: changes.filter(x => x.kind === "WITHDRAWN").length,
    unchanged: changes.filter(x => x.kind === "UNCHANGED").length,
    changes,
  };
}
