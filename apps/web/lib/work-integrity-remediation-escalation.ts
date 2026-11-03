import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationSlaEntry,
  IntegrityRemediationSlaReport,
  IntegrityRemediationSlaStatus,
} from "./work-integrity-remediation-sla";
import type {
  IntegrityRemediationDecisionRecord,
} from "./work-integrity-remediation-workspace";

export type IntegrityEscalationLevel = "NOTICE" | "WARNING" | "CRITICAL";
export type IntegrityEscalationChannel = "IN_APP" | "EMAIL" | "WEBHOOK";
export type IntegrityEscalationRule = {
  id: string;
  level: IntegrityEscalationLevel;
  statuses: IntegrityRemediationSlaStatus[];
  minimumOverdueMinutes: number;
  minimumRiskPoints: number;
  channels: IntegrityEscalationChannel[];
  recipients: string[];
  suppressWhenDeferred: boolean;
  suppressWhenRejected: boolean;
  repeatAfterMinutes: number;
};
export type IntegrityEscalationPolicy = {
  schemaVersion: 1;
  rules: IntegrityEscalationRule[];
  maxAlertsPerCandidate: number;
  maxAlertsPerEvaluation: number;
  includeResolved: boolean;
};
export type IntegrityEscalationAcknowledgement = {
  alertId: string;
  acknowledgedBy: string;
  acknowledgedAt: string;
  note: string;
};
export type IntegrityEscalationAlert = {
  id: string;
  captureId: string;
  candidateId: string;
  ruleId: string;
  level: IntegrityEscalationLevel;
  status: IntegrityRemediationSlaStatus;
  priority: IntegrityRemediationSlaEntry["priority"];
  caseKey: string | null;
  workItemId: string | null;
  riskPoints: number;
  overdueMinutes: number;
  generatedAt: string;
  channels: IntegrityEscalationChannel[];
  recipients: string[];
  summary: string;
  acknowledged: boolean;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  acknowledgementNote: string | null;
};
export type IntegrityEscalationSuppression = {
  candidateId: string;
  ruleId: string;
  reason: "DEFERRED" | "REJECTED" | "COOLDOWN" |
    "ACKNOWLEDGED" | "LIMIT_REACHED";
};
export type IntegrityEscalationReport = {
  schemaVersion: 1;
  captureId: string;
  generatedAt: string;
  alerts: IntegrityEscalationAlert[];
  suppressed: IntegrityEscalationSuppression[];
  totals: {
    alerts: number;
    acknowledged: number;
    unacknowledged: number;
    suppressed: number;
    critical: number;
    warnings: number;
    notices: number;
    affectedCandidates: number;
    affectedCases: number;
    affectedWorkItems: number;
    exposedRiskPoints: number;
  };
  byChannel: Record<IntegrityEscalationChannel, number>;
  byLevel: Record<IntegrityEscalationLevel, number>;
};
export type IntegrityEscalationQuery = {
  levels?: IntegrityEscalationLevel[];
  channels?: IntegrityEscalationChannel[];
  acknowledged?: boolean;
  candidateIds?: string[];
  caseKeys?: string[];
  workItemIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityEscalationPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  alerts: IntegrityEscalationAlert[];
};
const levels: IntegrityEscalationLevel[] = ["CRITICAL", "WARNING", "NOTICE"];
const channels: IntegrityEscalationChannel[] = ["IN_APP", "EMAIL", "WEBHOOK"];
const statuses: IntegrityRemediationSlaStatus[] = [
  "RESOLVED", "ON_TIME", "RESPONSE_OVERDUE",
  "RESOLUTION_OVERDUE", "ESCALATION_OVERDUE", "DEFERRED", "REJECTED",
];
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function id(value: unknown, label: string) {
  if (typeof value !== "string" || value.length < 1 ||
      value.length > 1500 || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (!Number.isSafeInteger(value) || (value as number) < min ||
      (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
function stringList(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || x.length < 1 ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function validTime(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}
export function parseIntegrityEscalationPolicy(
  value: unknown,
): IntegrityEscalationPolicy {
  const raw = object(value, "escalation policy");
  if (Object.keys(raw).some(x => ![
    "schemaVersion", "rules", "maxAlertsPerCandidate",
    "maxAlertsPerEvaluation", "includeResolved",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown escalation policy field.");
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1)
    throw new WorkInputError("INVALID", "Unsupported escalation policy version.");
  if (!Array.isArray(raw.rules) || raw.rules.length < 1 ||
      raw.rules.length > 100)
    throw new WorkInputError("INVALID", "Invalid escalation rules.");
  if (raw.includeResolved !== undefined && typeof raw.includeResolved !== "boolean")
    throw new WorkInputError("INVALID", "Invalid resolved alert flag.");
  const seen = new Set<string>();
  const rules: IntegrityEscalationRule[] = [];
  for (const entry of raw.rules) {
    const rule = object(entry, "escalation rule");
    if (Object.keys(rule).some(x => ![
      "id", "level", "statuses", "minimumOverdueMinutes",
      "minimumRiskPoints", "channels", "recipients",
      "suppressWhenDeferred", "suppressWhenRejected", "repeatAfterMinutes",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown escalation rule field.");
    const key = id(rule.id, "escalation rule ID");
    if (seen.has(key))
      throw new WorkInputError("INVALID", "Duplicate escalation rule ID.");
    seen.add(key);
    if (!levels.includes(rule.level as IntegrityEscalationLevel))
      throw new WorkInputError("INVALID", "Invalid escalation level.");
    const selectedStatuses = stringList(rule.statuses, "escalation statuses", 7);
    if (selectedStatuses.length < 1 ||
        selectedStatuses.some(x => !statuses.includes(x as IntegrityRemediationSlaStatus)))
      throw new WorkInputError("INVALID", "Unknown escalation status.");
    const selectedChannels = stringList(rule.channels, "escalation channels", 3);
    if (selectedChannels.length < 1 ||
        selectedChannels.some(x => !channels.includes(x as IntegrityEscalationChannel)))
      throw new WorkInputError("INVALID", "Unknown escalation channel.");
    const recipients = stringList(rule.recipients ?? [], "escalation recipients", 100);
    for (const flag of ["suppressWhenDeferred", "suppressWhenRejected"]) {
      if (rule[flag] !== undefined && typeof rule[flag] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid escalation suppression flag.");
    }
    rules.push({
      id: key, level: rule.level as IntegrityEscalationLevel,
      statuses: selectedStatuses as IntegrityRemediationSlaStatus[],
      minimumOverdueMinutes: integer(
        rule.minimumOverdueMinutes ?? 0, "minimum overdue", 0, 10000000),
      minimumRiskPoints: integer(
        rule.minimumRiskPoints ?? 0, "minimum risk", 0, 10000000),
      channels: selectedChannels as IntegrityEscalationChannel[],
      recipients,
      suppressWhenDeferred: rule.suppressWhenDeferred !== false,
      suppressWhenRejected: rule.suppressWhenRejected !== false,
      repeatAfterMinutes: integer(
        rule.repeatAfterMinutes ?? 1440, "repeat interval", 0, 10000000),
    });
  }
  return {
    schemaVersion: 1, rules,
    maxAlertsPerCandidate: integer(
      raw.maxAlertsPerCandidate ?? 5, "candidate alert limit", 1, 100),
    maxAlertsPerEvaluation: integer(
      raw.maxAlertsPerEvaluation ?? 10000, "evaluation alert limit", 1, 100000),
    includeResolved: raw.includeResolved === true,
  };
}
export function parseIntegrityEscalationAcknowledgements(
  value: unknown,
): IntegrityEscalationAcknowledgement[] {
  if (!Array.isArray(value) || value.length > 10000)
    throw new WorkInputError("INVALID", "Invalid alert acknowledgements.");
  const seen = new Set<string>();
  return value.map(entry => {
    const row = object(entry, "alert acknowledgement");
    if (Object.keys(row).some(x => ![
      "alertId", "acknowledgedBy", "acknowledgedAt", "note",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown acknowledgement field.");
    const alertId = id(row.alertId, "alert ID");
    if (seen.has(alertId))
      throw new WorkInputError("INVALID", "Duplicate alert acknowledgement.");
    seen.add(alertId);
    const acknowledgedBy = id(row.acknowledgedBy, "acknowledgement actor");
    if (!validTime(row.acknowledgedAt))
      throw new WorkInputError("INVALID", "Invalid acknowledgement time.");
    if (typeof row.note !== "string" || row.note.length > 4000)
      throw new WorkInputError("INVALID", "Invalid acknowledgement note.");
    return {
      alertId, acknowledgedBy, acknowledgedAt: row.acknowledgedAt,
      note: row.note,
    };
  });
}
function overdue(entry: IntegrityRemediationSlaEntry) {
  return Math.max(
    entry.responseOverdueMinutes,
    entry.resolutionOverdueMinutes,
    entry.escalationOverdueMinutes);
}
function alertId(candidateId: string, ruleId: string) {
  return JSON.stringify([candidateId, ruleId]);
}
function summary(entry: IntegrityRemediationSlaEntry, level: IntegrityEscalationLevel) {
  return level + ": " + entry.action + " (" + entry.priority +
    ") status " + entry.status + ", overdue " + overdue(entry) +
    " minutes.";
}
function isSuppressedByDecision(
  entry: IntegrityRemediationSlaEntry,
  rule: IntegrityEscalationRule,
  decision: IntegrityRemediationDecisionRecord | undefined,
): IntegrityEscalationSuppression["reason"] | null {
  if (decision?.decision === "DEFER" && rule.suppressWhenDeferred)
    return "DEFERRED";
  if (decision?.decision === "REJECT" && rule.suppressWhenRejected)
    return "REJECTED";
  return null;
}
export function evaluateIntegrityEscalations(
  sla: IntegrityRemediationSlaReport,
  policy: IntegrityEscalationPolicy,
  decisions: readonly IntegrityRemediationDecisionRecord[] = [],
  acknowledgements: readonly IntegrityEscalationAcknowledgement[] = [],
  previous?: IntegrityEscalationReport,
): IntegrityEscalationReport {
  if (previous && previous.captureId !== sla.captureId)
    throw new WorkInputError("INVALID", "Previous alert capture mismatch.");
  const decided = new Map(decisions.map(x => [x.candidateId, x]));
  const acknowledged = new Map(acknowledgements.map(x => [x.alertId, x]));
  const previousAlerts = new Map(previous?.alerts.map(x => [x.id, x]) ?? []);
  const alerts: IntegrityEscalationAlert[] = [];
  const suppressed: IntegrityEscalationSuppression[] = [];
  const byChannel: Record<IntegrityEscalationChannel, number> = {
    IN_APP: 0, EMAIL: 0, WEBHOOK: 0,
  };
  const byLevel: Record<IntegrityEscalationLevel, number> = {
    CRITICAL: 0, WARNING: 0, NOTICE: 0,
  };
  for (const entry of sla.entries) {
    if (entry.status === "RESOLVED" && !policy.includeResolved) continue;
    let count = 0;
    for (const rule of policy.rules) {
      if (!rule.statuses.includes(entry.status) ||
          overdue(entry) < rule.minimumOverdueMinutes ||
          entry.riskPoints < rule.minimumRiskPoints)
        continue;
      const reason = isSuppressedByDecision(entry, rule,
        decided.get(entry.candidateId));
      if (reason) {
        suppressed.push({
          candidateId: entry.candidateId, ruleId: rule.id, reason,
        });
        continue;
      }
      const key = alertId(entry.candidateId, rule.id);
      const ack = acknowledged.get(key);
      const old = previousAlerts.get(key);
      if (ack && old && ack.acknowledgedAt >= old.generatedAt) {
        suppressed.push({
          candidateId: entry.candidateId, ruleId: rule.id,
          reason: "ACKNOWLEDGED",
        });
        continue;
      }
      if (old && Date.parse(sla.evaluatedAt) -
          Date.parse(old.generatedAt) < rule.repeatAfterMinutes * 60000) {
        suppressed.push({
          candidateId: entry.candidateId, ruleId: rule.id,
          reason: "COOLDOWN",
        });
        continue;
      }
      if (count >= policy.maxAlertsPerCandidate ||
          alerts.length >= policy.maxAlertsPerEvaluation) {
        suppressed.push({
          candidateId: entry.candidateId, ruleId: rule.id,
          reason: "LIMIT_REACHED",
        });
        continue;
      }
      count++;
      for (const channel of rule.channels) byChannel[channel]++;
      byLevel[rule.level]++;
      alerts.push({
        id: key, captureId: sla.captureId,
        candidateId: entry.candidateId, ruleId: rule.id,
        level: rule.level, status: entry.status,
        priority: entry.priority, caseKey: entry.caseKey,
        workItemId: entry.workItemId, riskPoints: entry.riskPoints,
        overdueMinutes: overdue(entry), generatedAt: sla.evaluatedAt,
        channels: [...rule.channels], recipients: [...rule.recipients],
        summary: summary(entry, rule.level),
        acknowledged: ack !== undefined,
        acknowledgedBy: ack?.acknowledgedBy ?? null,
        acknowledgedAt: ack?.acknowledgedAt ?? null,
        acknowledgementNote: ack?.note ?? null,
      });
    }
  }
  alerts.sort((a, b) =>
    levels.indexOf(a.level) - levels.indexOf(b.level) ||
    b.overdueMinutes - a.overdueMinutes ||
    a.id.localeCompare(b.id));
  const affected = new Set(alerts.map(x => x.candidateId));
  const affectedCases = new Set(alerts.flatMap(x =>
    x.caseKey === null ? [] : [x.caseKey]));
  const affectedWorkItems = new Set(alerts.flatMap(x =>
    x.workItemId === null ? [] : [x.workItemId]));
  const riskByCandidate = new Map<string, number>();
  for (const alert of alerts)
    riskByCandidate.set(alert.candidateId, alert.riskPoints);
  return {
    schemaVersion: 1, captureId: sla.captureId,
    generatedAt: sla.evaluatedAt, alerts, suppressed,
    byChannel, byLevel,
    totals: {
      alerts: alerts.length,
      acknowledged: alerts.filter(x => x.acknowledged).length,
      unacknowledged: alerts.filter(x => !x.acknowledged).length,
      suppressed: suppressed.length,
      critical: byLevel.CRITICAL, warnings: byLevel.WARNING,
      notices: byLevel.NOTICE,
      affectedCandidates: affected.size,
      affectedCases: affectedCases.size,
      affectedWorkItems: affectedWorkItems.size,
      exposedRiskPoints: [...riskByCandidate.values()].reduce(
        (sum, x) => sum + x, 0),
    },
  };
}
export function parseIntegrityEscalationQuery(
  value: unknown,
): IntegrityEscalationQuery {
  const raw = object(value, "escalation query");
  if (Object.keys(raw).some(x => ![
    "levels", "channels", "acknowledged", "candidateIds",
    "caseKeys", "workItemIds", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown escalation query field.");
  if (raw.acknowledged !== undefined && typeof raw.acknowledged !== "boolean")
    throw new WorkInputError("INVALID", "Invalid acknowledgement filter.");
  const selectedLevels = raw.levels === undefined
    ? undefined : stringList(raw.levels, "escalation levels", 3);
  const selectedChannels = raw.channels === undefined
    ? undefined : stringList(raw.channels, "escalation channels", 3);
  if (selectedLevels?.some(x => !levels.includes(x as IntegrityEscalationLevel)) ||
      selectedChannels?.some(x => !channels.includes(x as IntegrityEscalationChannel)))
    throw new WorkInputError("INVALID", "Unknown escalation filter.");
  return {
    ...(selectedLevels !== undefined ? {
      levels: selectedLevels as IntegrityEscalationLevel[],
    } : {}),
    ...(selectedChannels !== undefined ? {
      channels: selectedChannels as IntegrityEscalationChannel[],
    } : {}),
    ...(raw.acknowledged !== undefined ? {
      acknowledged: raw.acknowledged as boolean,
    } : {}),
    ...(raw.candidateIds !== undefined ? {
      candidateIds: stringList(raw.candidateIds, "candidate IDs", 1000),
    } : {}),
    ...(raw.caseKeys !== undefined ? {
      caseKeys: stringList(raw.caseKeys, "case keys", 1000),
    } : {}),
    ...(raw.workItemIds !== undefined ? {
      workItemIds: stringList(raw.workItemIds, "work IDs", 1000),
    } : {}),
    offset: raw.offset === undefined ? 0 :
      integer(raw.offset, "escalation offset", 0, 1000000),
    limit: raw.limit === undefined ? 100 :
      integer(raw.limit, "escalation limit", 1, 1000),
  };
}
export function queryIntegrityEscalations(
  report: IntegrityEscalationReport,
  query: IntegrityEscalationQuery,
): IntegrityEscalationPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid escalation pagination.");
  const selected = report.alerts.filter(alert =>
    (!query.levels || query.levels.includes(alert.level)) &&
    (!query.channels || query.channels.some(x =>
      alert.channels.includes(x))) &&
    (query.acknowledged === undefined ||
      alert.acknowledged === query.acknowledged) &&
    (!query.candidateIds || query.candidateIds.includes(alert.candidateId)) &&
    (!query.caseKeys || (alert.caseKey !== null &&
      query.caseKeys.includes(alert.caseKey))) &&
    (!query.workItemIds || (alert.workItemId !== null &&
      query.workItemIds.includes(alert.workItemId))));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    alerts: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityEscalationReports(
  before: IntegrityEscalationReport,
  after: IntegrityEscalationReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Escalation captures differ.");
  const old = new Map(before.alerts.map(x => [x.id, x]));
  const current = new Map(after.alerts.map(x => [x.id, x]));
  const introduced = after.alerts.filter(x => !old.has(x.id));
  const resolved = before.alerts.filter(x => !current.has(x.id));
  const escalated: {
    alertId: string;
    from: IntegrityEscalationLevel;
    to: IntegrityEscalationLevel;
  }[] = [];
  const newlyAcknowledged: string[] = [];
  const reopened: string[] = [];
  for (const alert of after.alerts) {
    const previous = old.get(alert.id);
    if (!previous) continue;
    if (alert.level !== previous.level &&
        levels.indexOf(alert.level) < levels.indexOf(previous.level))
      escalated.push({
        alertId: alert.id, from: previous.level, to: alert.level,
      });
    if (alert.acknowledged && !previous.acknowledged)
      newlyAcknowledged.push(alert.id);
    if (!alert.acknowledged && previous.acknowledged)
      reopened.push(alert.id);
  }
  return {
    captureId: before.captureId,
    from: before.generatedAt, to: after.generatedAt,
    introduced, resolved, escalated,
    newlyAcknowledged: newlyAcknowledged.sort(),
    reopened: reopened.sort(),
    criticalDelta: after.totals.critical - before.totals.critical,
    unacknowledgedDelta: after.totals.unacknowledged -
      before.totals.unacknowledged,
    riskDelta: after.totals.exposedRiskPoints -
      before.totals.exposedRiskPoints,
  };
}
export function buildIntegrityEscalationDeliveryManifest(
  report: IntegrityEscalationReport,
  channelsFilter?: IntegrityEscalationChannel[],
) {
  const manifest = new Map<string, {
    channel: IntegrityEscalationChannel;
    recipient: string;
    alerts: IntegrityEscalationAlert[];
  }>();
  for (const alert of report.alerts) {
    if (alert.acknowledged) continue;
    for (const channel of alert.channels) {
      if (channelsFilter && !channelsFilter.includes(channel)) continue;
      const recipients = alert.recipients.length
        ? alert.recipients : ["DEFAULT"];
      for (const recipient of recipients) {
        const key = JSON.stringify([channel, recipient]);
        const row = manifest.get(key) ?? {
          channel, recipient, alerts: [],
        };
        row.alerts.push(alert);
        manifest.set(key, row);
      }
    }
  }
  return [...manifest.values()].map(x => ({
    channel: x.channel, recipient: x.recipient,
    alertIds: x.alerts.map(y => y.id).sort(),
    highestLevel: x.alerts.reduce<IntegrityEscalationLevel>(
      (best, alert) => levels.indexOf(alert.level) < levels.indexOf(best)
        ? alert.level : best, "NOTICE"),
    count: x.alerts.length,
    riskPoints: [...new Map(x.alerts.map(y =>
      [y.candidateId, y.riskPoints])).values()].reduce(
      (sum, value) => sum + value, 0),
  })).sort((a, b) =>
    levels.indexOf(a.highestLevel) - levels.indexOf(b.highestLevel) ||
    a.channel.localeCompare(b.channel) ||
    a.recipient.localeCompare(b.recipient));
}
