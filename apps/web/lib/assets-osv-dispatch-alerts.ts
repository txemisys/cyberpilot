import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  inspectSignedDispatchOperations,
  parseDispatchOperationalPolicy,
} from "./assets-osv-dispatch-observability";
import type {
  DispatchOperationalPolicy, DispatchOperationalReport,
} from "./assets-osv-dispatch-observability";

/**
 * Incident assessment is operator-triggered and local to PostgreSQL.
 * It does NOT poll a remote OSV provider, install a scheduler, deliver
 * notifications, retry failed jobs, refund quota or alter CyberScore.
 */
export type DispatchAlertState = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
export type DispatchAlertSeverity = "WARNING" | "CRITICAL";
export type DispatchAlertObservation = {
  code: string;
  subjectKey: string;
  severity: DispatchAlertSeverity;
  summary: string;
  nextAction: string;
  evidenceDigest: string;
  evidence: {
    evaluatedAt: string;
    source: "LOCAL_DISPATCH_LEDGER";
    metrics: Record<string, string | number | boolean | null>;
    warnings: string[];
  };
};
export type DispatchAlertRow = {
  id: string;
  organizationId: string;
  code: string;
  subjectKey: string;
  severity: DispatchAlertSeverity;
  state: DispatchAlertState;
  revision: number;
  firstSeenAt: string;
  lastSeenAt: string;
  observedCount: number;
  evidenceDigest: string;
  evidence: unknown;
  acknowledgementReason: string | null;
  acknowledgedAt: string | null;
  acknowledgedByUserId: string | null;
  resolutionReason: string | null;
  resolvedAt: string | null;
  resolvedByUserId: string | null;
};
export type DispatchAlertPage = {
  schema: "cyberpilot.assets.osv.dispatch.alerts.v1";
  organizationId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  alerts: DispatchAlertRow[];
  warnings: string[];
};
export type DispatchAlertScan = {
  schema: "cyberpilot.assets.osv.dispatch.alert.scan.v1";
  organizationId: string;
  evaluatedAt: string;
  reportDigest: string;
  observed: number;
  opened: number;
  updated: number;
  reopened: number;
  retainedAcknowledgements: number;
  unchanged: number;
  findings: DispatchAlertObservation[];
  warnings: string[];
};
export type DispatchAlertAction = {
  alertId: string;
  expectedRevision: number;
  operation: "ACKNOWLEDGE" | "RESOLVE" | "REOPEN";
  reason: string;
  expectedEvidenceDigest: string;
};
export type DispatchAlertTransition = {
  schema: "cyberpilot.assets.osv.dispatch.alert.transition.v1";
  organizationId: string;
  alert: DispatchAlertRow;
  operation: DispatchAlertAction["operation"];
  auditRecorded: true;
  providerContacted: false;
  quotaChanged: false;
  scheduleChanged: false;
  warnings: string[];
};
export type DispatchAlertQuery = {
  offset: number;
  limit: number;
  state: DispatchAlertState | null;
  severity: DispatchAlertSeverity | null;
};
const schema = "cyberpilot.assets.osv.dispatch.alerts.v1" as const;
function reject(message: string,
  code: "INVALID" | "CONFLICT" = "INVALID"): never {
  throw new WorkInputError(code, message);
}
function record(value: unknown) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    reject("Dispatch alert request must be an object.");
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(value).some(key => !allowed.includes(key)))
    reject("Unexpected dispatch alert parameter.");
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    reject("Invalid dispatch alert " + label + ".");
  return value;
}
function text(value: unknown, label: string, max: number) {
  if (typeof value !== "string" || value.length < 1 ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    reject("Invalid dispatch alert " + label + ".");
  return value;
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function assertManager(scope: AssetScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "OSV dispatch incident management requires administrator access.");
}
export function parseDispatchAlertQuery(input: unknown = {}): DispatchAlertQuery {
  const raw = record(input);
  keys(raw, ["offset", "limit", "state", "severity"]);
  const state = raw.state ?? null;
  const severity = raw.severity ?? null;
  if (state !== null && !["OPEN", "ACKNOWLEDGED", "RESOLVED"].includes(
    String(state)))
    reject("Unsupported dispatch incident state.");
  if (severity !== null && !["WARNING", "CRITICAL"].includes(
    String(severity)))
    reject("Unsupported dispatch incident severity.");
  return {
    offset: integer(raw.offset ?? 0, "offset", 0, 100000),
    limit: integer(raw.limit ?? 25, "limit", 1, 100),
    state: state as DispatchAlertState | null,
    severity: severity as DispatchAlertSeverity | null,
  };
}
export function parseDispatchAlertAction(input: unknown): DispatchAlertAction {
  const raw = record(input);
  keys(raw, [
    "alertId", "expectedRevision", "operation", "reason",
    "expectedEvidenceDigest",
  ]);
  const operation = raw.operation;
  if (operation !== "ACKNOWLEDGE" && operation !== "RESOLVE" &&
      operation !== "REOPEN")
    reject("Unsupported incident action.");
  const alertId = text(raw.alertId, "ID", 150);
  if (!/^[A-Za-z0-9_-]{8,150}$/.test(alertId))
    reject("Invalid incident identifier.");
  const expectedEvidenceDigest = text(raw.expectedEvidenceDigest,
    "evidence fingerprint", 64);
  if (!/^[a-f0-9]{64}$/.test(expectedEvidenceDigest))
    reject("Expected evidence fingerprint must be SHA-256.");
  const reason = text(raw.reason, "investigation reason", 500).trim();
  if (reason.length < 20)
    reject("A concrete investigation reason of at least 20 characters is required.");
  return {
    alertId, operation,
    expectedRevision: integer(raw.expectedRevision,
      "revision", 1, 100000000),
    expectedEvidenceDigest, reason,
  };
}
export function normalizeAlertObservation(
  code: string, subjectKey: string, severity: DispatchAlertSeverity,
  summary: string, nextAction: string,
  metrics: Record<string, string | number | boolean | null>,
  evaluatedAt: string,
): DispatchAlertObservation {
  if (!/^[A-Z][A-Z0-9_]{3,79}$/.test(code))
    reject("Invalid alert code.");
  if (!/^[A-Za-z0-9:_-]{3,100}$/.test(subjectKey))
    reject("Invalid alert subject.");
  const evidence = {
    evaluatedAt, source: "LOCAL_DISPATCH_LEDGER" as const,
    metrics, warnings: [
      "Diagnostic counts are snapshots, not proof of provider delivery.",
      "An acknowledged incident is not automatically remediated.",
    ],
  };
  // Event time is not part of identity, which allows a repeated assessment
  // with unchanged metrics to avoid spurious revisions and audit entries.
  return {
    code, subjectKey, severity, summary, nextAction,
    evidence, evidenceDigest: digest({
      code, subjectKey, severity, summary, nextAction, metrics,
    }),
  };
}
export function evaluateDispatchAlertObservations(
  report: DispatchOperationalReport,
): DispatchAlertObservation[] {
  const rows: DispatchAlertObservation[] = [];
  const stamp = report.evaluatedAt;
  const orgKey = "tenant";
  for (const alert of report.alerts) {
    if (!/^[A-Z][A-Z0-9_]{3,79}$/.test(alert.code))
      continue;
    rows.push(normalizeAlertObservation(
      alert.code, orgKey, alert.severity,
      alert.summary, alert.action, {
        accepted: report.acceptedNoncesInWindow,
        unmatched: report.unmatchedAcceptedNonces,
        failed: report.failedClaimsInWindow,
        unknown: report.unknownClaimsInWindow,
        unsettled: report.unsettledClaims,
        oldestUnsettledMinutes: report.oldestUnsettledMinutes,
        tenantKeyConfigured: report.configuration.hasTenantKey,
      }, stamp));
  }
  // Per-request diagnostic anomalies are tracked independently. The request
  // digest is the subject; the nonce or signing key is not used as an ID.
  for (const item of report.recent) {
    if (!item.warningCode) continue;
    rows.push(normalizeAlertObservation(
      item.warningCode, "req:" + item.requestDigest.slice(0, 48),
      item.warningCode === "INCOMPLETE_SCHEDULE_CLAIM" ?
        "CRITICAL" : "WARNING",
      "A signed dispatch has an uncertain local scheduling result.",
      "Inspect the signed request audit, exact schedule slot and quota before manual recovery.",
      {
        requestDigest: item.requestDigest,
        keyId: item.keyId, scheduleId: item.scheduleId,
        matchedRun: item.hasRunClaim,
        runState: item.runState,
        ageMinutes: item.minutesSinceAccepted,
      }, stamp));
  }
  return rows.sort((a, b) =>
    a.code.localeCompare(b.code) ||
    a.subjectKey.localeCompare(b.subjectKey));
}
function mapAlert(value: {
  id: string; organizationId: string; code: string;
  subjectKey: string; severity: string; state: string;
  revision: number; firstSeenAt: Date; lastSeenAt: Date;
  observedCount: number; evidenceDigest: string;
  evidence: unknown;
  acknowledgementReason: string | null;
  acknowledgedAt: Date | null;
  acknowledgedByUserId: string | null;
  resolutionReason: string | null;
  resolvedAt: Date | null;
  resolvedByUserId: string | null;
}): DispatchAlertRow {
  return {
    id: value.id, organizationId: value.organizationId,
    code: value.code, subjectKey: value.subjectKey,
    severity: value.severity as DispatchAlertSeverity,
    state: value.state as DispatchAlertState,
    revision: value.revision,
    firstSeenAt: value.firstSeenAt.toISOString(),
    lastSeenAt: value.lastSeenAt.toISOString(),
    observedCount: value.observedCount,
    evidenceDigest: value.evidenceDigest,
    evidence: value.evidence,
    acknowledgementReason: value.acknowledgementReason,
    acknowledgedAt: value.acknowledgedAt?.toISOString() ?? null,
    acknowledgedByUserId: value.acknowledgedByUserId,
    resolutionReason: value.resolutionReason,
    resolvedAt: value.resolvedAt?.toISOString() ?? null,
    resolvedByUserId: value.resolvedByUserId,
  };
}
export function alertTransitionAllowed(
  current: DispatchAlertState, requested: DispatchAlertAction["operation"],
) {
  return current === "OPEN" && requested === "ACKNOWLEDGE" ||
    current === "ACKNOWLEDGED" && requested === "RESOLVE" ||
    current === "RESOLVED" && requested === "REOPEN";
}
export async function listDispatchAlerts(
  scope: AssetScope, input: unknown = {},
): Promise<DispatchAlertPage> {
  assertManager(scope);
  const query = parseDispatchAlertQuery(input);
  const where = {
    organizationId: scope.organizationId,
    ...(query.state ? { state: query.state } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
  };
  const [total, items] = await db.$transaction([
    db.assetOsvDispatchAlert.count({ where }),
    db.assetOsvDispatchAlert.findMany({
      where,
      orderBy: [{ lastSeenAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
    }),
  ]);
  return {
    schema, organizationId: scope.organizationId,
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + items.length < total,
    alerts: items.map(mapAlert),
    warnings: [
      "Alerts are observed only when an administrator explicitly initiates a scan.",
      "ACKNOWLEDGED does not mean remediated or provider-confirmed.",
      "Alerts cannot change OSV quota, endpoint findings or CyberScore.",
    ],
  };
}
export async function scanDispatchAlerts(
  scope: AssetScope, input: unknown = {},
  now = new Date(),
  dependencies: {
    inspect?: typeof inspectSignedDispatchOperations;
  } = {},
): Promise<DispatchAlertScan> {
  assertManager(scope);
  if (!Number.isFinite(now.getTime()))
    reject("Invalid dispatch assessment time.");
  const policy: DispatchOperationalPolicy =
    parseDispatchOperationalPolicy(input);
  const report = await (dependencies.inspect ??
    inspectSignedDispatchOperations)(scope, policy, now);
  if (report.organizationId !== scope.organizationId)
    reject("Dispatch audit belongs to another organization.", "CONFLICT");
  if (report.truncated)
    reject("Cannot persist alerts from a truncated dispatch history.", "CONFLICT");
  const observations = evaluateDispatchAlertObservations(report);
  if (observations.length > 200)
    reject("Dispatch alert scan exceeds bounded assessment capacity.", "CONFLICT");
  const counts = {
    opened: 0, updated: 0, reopened: 0,
    retainedAcknowledgements: 0, unchanged: 0,
  };
  for (const finding of observations) {
    await db.$transaction(async tx => {
      const unique = {
        organizationId_code_subjectKey: {
          organizationId: scope.organizationId,
          code: finding.code, subjectKey: finding.subjectKey,
        },
      };
      const previous = await tx.assetOsvDispatchAlert.findUnique({
        where: unique,
      });
      if (!previous) {
        // The unique index makes concurrent scans fail closed instead of
        // accidentally recording duplicate incident identities.
        const alert = await tx.assetOsvDispatchAlert.create({
          data: {
            organizationId: scope.organizationId,
            code: finding.code, subjectKey: finding.subjectKey,
            severity: finding.severity, state: "OPEN",
            firstSeenAt: now, lastSeenAt: now,
            evidenceDigest: finding.evidenceDigest,
            evidence: JSON.parse(JSON.stringify(finding.evidence)),
          },
        });
        await tx.auditEvent.create({ data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "assets.osv.dispatch.alert.opened",
          resourceType: "AssetOsvDispatchAlert", resourceId: alert.id,
          metadata: {
            schema, code: alert.code, subjectKey: alert.subjectKey,
            evidenceDigest: alert.evidenceDigest, revision: alert.revision,
          },
        } });
        counts.opened++;
        return;
      }
      if (previous.evidenceDigest === finding.evidenceDigest) {
        counts.unchanged++;
        return;
      }
      const reopen = previous.state === "RESOLVED";
      const changed = await tx.assetOsvDispatchAlert.updateMany({
        where: {
          id: previous.id, organizationId: scope.organizationId,
          revision: previous.revision,
          evidenceDigest: previous.evidenceDigest,
        },
        data: {
          revision: { increment: 1 }, lastSeenAt: now,
          observedCount: { increment: 1 },
          evidenceDigest: finding.evidenceDigest,
          evidence: JSON.parse(JSON.stringify(finding.evidence)),
          severity: finding.severity,
          ...(reopen ? {
            state: "OPEN", resolutionReason: null,
            resolvedByUserId: null, resolvedAt: null,
            acknowledgementReason: null,
            acknowledgedByUserId: null, acknowledgedAt: null,
          } : {}),
        },
      });
      if (changed.count !== 1)
        throw new WorkInputError("CONFLICT",
          "Dispatch alert evidence changed during assessment.");
      await tx.auditEvent.create({ data: {
        organizationId: scope.organizationId, actorType: "USER",
        actorUserId: scope.userId,
        action: reopen ? "assets.osv.dispatch.alert.reobserved" :
          "assets.osv.dispatch.alert.updated",
        resourceType: "AssetOsvDispatchAlert", resourceId: previous.id,
        metadata: {
          schema, code: finding.code, subjectKey: finding.subjectKey,
          previousDigest: previous.evidenceDigest,
          evidenceDigest: finding.evidenceDigest,
          acknowledgementRetained: previous.state === "ACKNOWLEDGED",
          reopensResolvedAlert: reopen,
        },
      } });
      if (reopen) counts.reopened++;
      else {
        counts.updated++;
        if (previous.state === "ACKNOWLEDGED")
          counts.retainedAcknowledgements++;
      }
    });
  }
  return {
    schema: "cyberpilot.assets.osv.dispatch.alert.scan.v1",
    organizationId: scope.organizationId,
    evaluatedAt: now.toISOString(),
    reportDigest: digest({
      schema, organizationId: scope.organizationId,
      reportEvaluatedAt: report.evaluatedAt,
      observations: observations.map(f => [
        f.code, f.subjectKey, f.evidenceDigest,
      ]),
    }),
    observed: observations.length, ...counts,
    findings: observations,
    warnings: [
      "Scan is explicitly user-triggered; it does not install a background alert delivery service.",
      "An unchanged diagnostic does not duplicate audit entries or event counters.",
      "A previously resolved alert reopens only when new evidence is observed.",
      "All updates are isolated by tenant and recorded without contacting OSV.dev.",
    ],
  };
}
export async function transitionDispatchAlert(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<DispatchAlertTransition> {
  assertManager(scope);
  if (!Number.isFinite(now.getTime()))
    reject("Invalid alert transition time.");
  const action = parseDispatchAlertAction(input);
  const existing = await db.assetOsvDispatchAlert.findFirst({
    where: {
      id: action.alertId, organizationId: scope.organizationId,
    },
  });
  if (!existing)
    throw new WorkInputError("MISSING", "Dispatch alert does not exist.");
  if (existing.revision !== action.expectedRevision ||
      existing.evidenceDigest !== action.expectedEvidenceDigest)
    throw new WorkInputError("CONFLICT",
      "Dispatch incident evidence or revision has changed.");
  if (!alertTransitionAllowed(
    existing.state as DispatchAlertState, action.operation))
    throw new WorkInputError("CONFLICT",
      "Invalid dispatch incident lifecycle transition.");
  const state: DispatchAlertState = action.operation === "ACKNOWLEDGE" ?
    "ACKNOWLEDGED" : action.operation === "RESOLVE" ?
    "RESOLVED" : "OPEN";
  const updated = await db.$transaction(async tx => {
    const changed = await tx.assetOsvDispatchAlert.updateMany({
      where: {
        id: existing.id, organizationId: scope.organizationId,
        revision: action.expectedRevision,
        state: existing.state,
        evidenceDigest: action.expectedEvidenceDigest,
      },
      data: {
        state, revision: { increment: 1 },
        ...(action.operation === "ACKNOWLEDGE" ? {
          acknowledgementReason: action.reason,
          acknowledgedByUserId: scope.userId,
          acknowledgedAt: now,
        } : {}),
        ...(action.operation === "RESOLVE" ? {
          resolutionReason: action.reason,
          resolvedByUserId: scope.userId, resolvedAt: now,
        } : {}),
        ...(action.operation === "REOPEN" ? {
          acknowledgementReason: null, acknowledgedAt: null,
          acknowledgedByUserId: null,
          resolutionReason: null, resolvedAt: null,
          resolvedByUserId: null,
        } : {}),
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT",
        "Concurrent dispatch incident transition detected.");
    const current = await tx.assetOsvDispatchAlert.findUniqueOrThrow({
      where: { id: existing.id },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId, actorType: "USER",
      actorUserId: scope.userId,
      action: "assets.osv.dispatch.alert." +
        action.operation.toLowerCase(),
      resourceType: "AssetOsvDispatchAlert",
      resourceId: current.id,
      metadata: {
        schema, previousState: existing.state, newState: state,
        reason: action.reason, revisionBefore: existing.revision,
        revisionAfter: current.revision,
        evidenceDigest: current.evidenceDigest,
        providerContacted: false, quotaChanged: false,
      },
    } });
    return current;
  });
  return {
    schema: "cyberpilot.assets.osv.dispatch.alert.transition.v1",
    organizationId: scope.organizationId,
    alert: mapAlert(updated),
    operation: action.operation, auditRecorded: true,
    providerContacted: false, quotaChanged: false,
    scheduleChanged: false,
    warnings: [
      "This is a human incident triage state, not verification of CVE remediation.",
      "No provider query, quota refund or schedule modification occurred.",
      "ACKNOWLEDGED and RESOLVED depend on operator investigation, not automatic recovery.",
    ],
  };
}
