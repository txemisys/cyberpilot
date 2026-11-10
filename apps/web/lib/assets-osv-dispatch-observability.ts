import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  configuredDispatchKeys, inspectDispatchConfiguration,
} from "./assets-osv-signed-dispatch";
import type { DispatchReadiness } from "./assets-osv-signed-dispatch";

export type DispatchOperationalPolicy = {
  lookbackHours: number;
  maximumRecent: number;
  alertAfterMinutes: number;
  alertFailureThreshold: number;
  alertUnsettledThreshold: number;
};
export type DispatchOperationalRow = {
  requestDigest: string;
  nonceDigest: string;
  keyId: string;
  scheduleId: string;
  acceptedAt: string;
  expiresAt: string;
  minutesSinceAccepted: number;
  hasRunClaim: boolean;
  runId: string | null;
  runState: string | null;
  associatedSlotAt: string | null;
  warningCode: string | null;
};
export type DispatchOperationalReport = {
  schema: "cyberpilot.assets.osv.signed-dispatch.operations.v1";
  organizationId: string;
  evaluatedAt: string;
  policy: DispatchOperationalPolicy;
  configuration: DispatchReadiness;
  acceptedNoncesInWindow: number;
  displayed: number;
  truncated: boolean;
  unmatchedAcceptedNonces: number;
  failedClaimsInWindow: number;
  unknownClaimsInWindow: number;
  unsettledClaims: number;
  oldestUnsettledMinutes: number | null;
  recent: DispatchOperationalRow[];
  alerts: Array<{
    code: string;
    severity: "WARNING" | "CRITICAL";
    summary: string;
    action: string;
  }>;
  warnings: string[];
};
function failure(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" &&
    !Array.isArray(value));
}
function integer(value: unknown, name: string,
  minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    failure("Invalid signed dispatch operational " + name + ".");
  return value;
}
export function parseDispatchOperationalPolicy(
  input: unknown = {},
): DispatchOperationalPolicy {
  if (!isObject(input))
    failure("Signed dispatch operational policy must be an object.");
  if (Object.keys(input).some(key => ![
    "lookbackHours", "maximumRecent", "alertAfterMinutes",
    "alertFailureThreshold", "alertUnsettledThreshold",
  ].includes(key))) failure("Unrecognized signed dispatcher diagnostic field.");
  return {
    lookbackHours: integer(input.lookbackHours ?? 24, "lookback", 1, 720),
    maximumRecent: integer(input.maximumRecent ?? 50, "page size", 1, 100),
    alertAfterMinutes: integer(input.alertAfterMinutes ?? 45,
      "alert interval", 15, 1440),
    alertFailureThreshold: integer(input.alertFailureThreshold ?? 3,
      "failure threshold", 1, 50),
    alertUnsettledThreshold: integer(input.alertUnsettledThreshold ?? 1,
      "unsettled threshold", 1, 50),
  };
}
export type DispatchObservation = {
  requestDigest: string;
  nonceDigest: string;
  keyId: string;
  scheduleId: string;
  acceptedAt: Date;
  expiresAt: Date;
};
export type DispatchRunObservation = {
  id: string;
  scheduleId: string;
  claimedAt: Date;
  slotAt: Date;
  state: string;
  commandDigest: string;
};
export function correlateSignedDispatch(
  nonces: DispatchObservation[],
  runs: DispatchRunObservation[],
  now: Date, policy: DispatchOperationalPolicy,
): {
  rows: DispatchOperationalRow[];
  unmatched: number;
} {
  if (!Number.isFinite(now.getTime()))
    failure("Invalid signed dispatcher observation clock.");
  const grouped = new Map<string, DispatchRunObservation[]>();
  for (const run of runs) {
    const list = grouped.get(run.scheduleId) ?? [];
    list.push(run);
    grouped.set(run.scheduleId, list);
  }
  for (const values of grouped.values())
    values.sort((a, b) =>
      a.claimedAt.getTime() - b.claimedAt.getTime() ||
      a.id.localeCompare(b.id));
  const result: DispatchOperationalRow[] = [];
  for (const nonce of nonces) {
    // Run records do not persist a signing nonce: matching a schedule
    // and close timestamps is an operational hint, NOT cryptographic
    // proof that any particular request produced that run.
    const candidates = (grouped.get(nonce.scheduleId) ?? []).filter(row =>
      row.claimedAt.getTime() >= nonce.acceptedAt.getTime() - 10000 &&
      row.claimedAt.getTime() <= nonce.acceptedAt.getTime() + 60000);
    const run = candidates.length === 1 ? candidates[0] : null;
    const age = (now.getTime() - nonce.acceptedAt.getTime()) / 60000;
    const stale = age >= policy.alertAfterMinutes;
    const warningCode = candidates.length > 1 ?
      "AMBIGUOUS_RUN_ASSOCIATION" :
      !run && stale ? "ACCEPTED_WITHOUT_OBSERVED_CLAIM" :
      run?.state === "UNKNOWN" ? "UNKNOWN_PROVIDER_RESULT" :
      run?.state === "FAILED" ? "DISPATCH_FAILED" :
      run?.state === "CLAIMED" && stale ?
        "INCOMPLETE_SCHEDULE_CLAIM" : null;
    result.push({
      requestDigest: nonce.requestDigest,
      nonceDigest: nonce.nonceDigest, keyId: nonce.keyId,
      scheduleId: nonce.scheduleId,
      acceptedAt: nonce.acceptedAt.toISOString(),
      expiresAt: nonce.expiresAt.toISOString(),
      minutesSinceAccepted: Number.isFinite(age) ? Math.floor(age) : -1,
      hasRunClaim: Boolean(run),
      runId: run?.id ?? null,
      runState: run?.state ?? null,
      associatedSlotAt: run?.slotAt.toISOString() ?? null,
      warningCode,
    });
  }
  return {
    rows: result, unmatched: result.filter(item =>
      !item.hasRunClaim).length,
  };
}
export function summarizeSignedDispatchAlerts(
  input: {
    unmatched: number;
    failureCount: number;
    unknownCount: number;
    unsettledCount: number;
    oldestUnsettledMinutes: number | null;
    credentialReady: boolean;
  }, policy: DispatchOperationalPolicy,
): DispatchOperationalReport["alerts"] {
  const alerts: DispatchOperationalReport["alerts"] = [];
  if (!input.credentialReady) alerts.push({
    code: "SERVICE_CREDENTIAL_NOT_READY",
    severity: "WARNING",
    summary: "Signed dispatch is disabled or lacks a scoped organization key.",
    action: "Install a distinct tenant key through the deployment secret manager and enable explicitly after acceptance.",
  });
  if (input.unmatched > 0) alerts.push({
    code: "UNMATCHED_SIGNED_DISPATCH",
    severity: "WARNING",
    summary: "One or more accepted signatures have no unambiguous matching run claim.",
    action: "Check audit records, deployment errors, schedule revisions and consumed nonces without automatically retrying.",
  });
  if (input.failureCount >= policy.alertFailureThreshold) alerts.push({
    code: "DISPATCH_FAILURE_THRESHOLD",
    severity: "CRITICAL",
    summary: "Recent failed OSV schedule runs exceed the configured diagnostic threshold.",
    action: "Investigate upstream and database failures, claims and quotas before further manual dispatch.",
  });
  if (input.unknownCount > 0) alerts.push({
    code: "UNKNOWN_PROVIDER_OUTCOME",
    severity: "WARNING",
    summary: "Some historical schedule runs have unknown remote outcomes.",
    action: "Review incident evidence; do not infer provider failure or release reserved quota.",
  });
  if (input.unsettledCount >= policy.alertUnsettledThreshold) alerts.push({
    code: "UNSETTLED_CLAIM_THRESHOLD",
    severity: "CRITICAL",
    summary: "Unsettled schedule runs require manual intervention.",
    action: "Use the audited UNKNOWN classification workflow after the claim expires and investigation delay elapses.",
  });
  if (input.oldestUnsettledMinutes !== null &&
      input.oldestUnsettledMinutes >= policy.alertAfterMinutes)
    alerts.push({
      code: "STALE_SCHEDULE_CLAIM",
      severity: "CRITICAL",
      summary: "A schedule claim exceeds the configured age threshold.",
      action: "Inspect the claim expiry and correlated provider quota before classifying the result.",
    });
  return alerts;
}
export async function inspectSignedDispatchOperations(
  scope: AssetScope, input: unknown = {},
  now = new Date(),
): Promise<DispatchOperationalReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Signed dispatcher diagnostics require organization administrator access.");
  if (!Number.isFinite(now.getTime()))
    failure("Invalid dispatch operational report time.");
  const policy = parseDispatchOperationalPolicy(input);
  const config = configuredDispatchKeys();
  const configuration = inspectDispatchConfiguration(config,
    scope.organizationId);
  const cutoff = new Date(now.getTime() -
    policy.lookbackHours * 3600000);
  const [total, recent, runs, unsettled] = await Promise.all([
    db.assetOsvDispatchNonce.count({
      where: {
        organizationId: scope.organizationId,
        acceptedAt: { gte: cutoff, lte: now },
      },
    }),
    db.assetOsvDispatchNonce.findMany({
      where: {
        organizationId: scope.organizationId,
        acceptedAt: { gte: cutoff, lte: now },
      },
      orderBy: [{ acceptedAt: "desc" }, { id: "desc" }],
      take: policy.maximumRecent,
      select: {
        requestDigest: true, nonceDigest: true,
        keyId: true, scheduleId: true,
        acceptedAt: true, expiresAt: true,
      },
    }),
    db.assetOsvRenewalRun.findMany({
      where: {
        organizationId: scope.organizationId,
        claimedAt: { gte: cutoff, lte: now },
      },
      orderBy: [{ claimedAt: "desc" }, { id: "desc" }],
      take: 10001,
      select: {
        id: true, scheduleId: true, claimedAt: true,
        slotAt: true, state: true, commandDigest: true,
      },
    }),
    db.assetOsvRenewalRun.findMany({
      where: {
        organizationId: scope.organizationId,
        state: "CLAIMED",
      },
      orderBy: [{ claimedAt: "asc" }],
      take: 10001,
      select: { claimedAt: true },
    }),
  ]);
  if (runs.length > 10000 || unsettled.length > 10000)
    throw new WorkInputError("CONFLICT",
      "Signed dispatch audit dataset exceeds bounded capacity.");
  const correlated = correlateSignedDispatch(
    recent, runs, now, policy);
  const failureCount = runs.filter(x => x.state === "FAILED").length;
  const unknownCount = runs.filter(x => x.state === "UNKNOWN").length;
  const oldest = unsettled.length ?
    Math.max(0, Math.floor((now.getTime() -
      unsettled[0]!.claimedAt.getTime()) / 60000)) : null;
  const alerts = summarizeSignedDispatchAlerts({
    unmatched: correlated.unmatched,
    failureCount, unknownCount,
    unsettledCount: unsettled.length,
    oldestUnsettledMinutes: oldest,
    credentialReady: configuration.hasTenantKey,
  }, policy);
  return {
    schema: "cyberpilot.assets.osv.signed-dispatch.operations.v1",
    organizationId: scope.organizationId, evaluatedAt: now.toISOString(),
    policy, configuration,
    acceptedNoncesInWindow: total, displayed: correlated.rows.length,
    truncated: total > correlated.rows.length,
    unmatchedAcceptedNonces: correlated.unmatched,
    failedClaimsInWindow: failureCount,
    unknownClaimsInWindow: unknownCount,
    unsettledClaims: unsettled.length,
    oldestUnsettledMinutes: oldest,
    recent: correlated.rows, alerts,
    warnings: [
      "Time-proximity correlation is diagnostic and cannot prove causality.",
      "No signing secrets or HTTP Authorization headers are returned or stored.",
      "Alerts are displayed on demand; no alert delivery, mail or pager has been configured.",
      "Signed dispatch is independent of external Google Workspace and Microsoft 365 tenants.",
      "Only independently authorized provider calls may occur after consent and the full quota gate.",
    ],
  };
}
