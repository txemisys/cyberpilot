"use client";

import { useEffect, useState } from "react";

type OperationalRow = {
  requestDigest: string; nonceDigest: string; keyId: string;
  scheduleId: string; acceptedAt: string; expiresAt: string;
  minutesSinceAccepted: number;
  hasRunClaim: boolean; runId: string | null;
  runState: string | null; associatedSlotAt: string | null;
  warningCode: string | null;
};
type Alert = {
  code: string; severity: "WARNING" | "CRITICAL";
  summary: string; action: string;
};
type Report = {
  schema: string; evaluatedAt: string;
  configuration: {
    enabled: boolean; scopedKeys: number; hasTenantKey: boolean;
    eligibleKeyIds: string[]; installsCron: false;
    grantsScheduleCreation: false;
    grantsConsentModification: false;
    grantsQuotaOverride: false;
    replayStorage: "POSTGRESQL";
  };
  acceptedNoncesInWindow: number; displayed: number;
  truncated: boolean; unmatchedAcceptedNonces: number;
  failedClaimsInWindow: number; unknownClaimsInWindow: number;
  unsettledClaims: number; oldestUnsettledMinutes: number | null;
  recent: OperationalRow[]; alerts: Alert[]; warnings: string[];
};
const when = (value: string | null) => {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid timestamp";
};
function ErrorMessage({ value }: { value: unknown }) {
  return <p role="alert">{value instanceof Error ?
    value.message : "Signed dispatcher report could not be loaded."}</p>;
}
function Measurement({ label, value }: {
  label: string; value: number;
}) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 10,
  }}><strong>{value}</strong><p>{label}</p></div>;
}
async function load(url: string): Promise<Report> {
  const response = await fetch(url, {
    method: "GET", cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const item = data as { error?: string };
    throw new Error(item.error ?? "Signed dispatch HTTP " +
      response.status);
  }
  return data as Report;
}
export function AssetOsvSignedDispatchOperations({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" +
    encodeURIComponent(slug) +
    "/assets/osv-dispatch-observability";
  const [lookback, setLookback] = useState(24);
  const [limit, setLimit] = useState(25);
  const [alertAge, setAlertAge] = useState(45);
  const [failureThreshold, setFailureThreshold] = useState(3);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    setLoading(true);
    const url = base + "?" + new URLSearchParams({
      lookbackHours: String(lookback),
      maximumRecent: String(limit),
      alertAfterMinutes: String(alertAge),
      alertFailureThreshold: String(failureThreshold),
      alertUnsettledThreshold: "1",
    });
    void load(url).then(data => {
      if (!cancelled) { setReport(data); setError(null); }
    }).catch(cause => {
      if (!cancelled) { setError(cause instanceof Error ? cause : new Error("Signed dispatch diagnostic failed.")); setReport(null); }
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [base, canManage, lookback, limit,
    alertAge, failureThreshold, revision]);
  if (!canManage) return null;
  return <section aria-label="OSV signed dispatch observability"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>Signed OSV service dispatch diagnostics</h2>
    <p>The internal dispatcher is disabled unless a deployment
      operator explicitly installs tenant-specific signing keys
      and enables the server-side flag. This console cannot
      create keys, activate the dispatcher, change schedules
      or submit provider requests.</p>
    {error && <ErrorMessage value={error}/>}
    {loading && <p role="status">Reading signed dispatch audit…</p>}
    <fieldset>
      <legend>Audit observation filters</legend>
      <label>Historical lookback
        <select value={lookback}
          onChange={event => setLookback(Number(event.target.value))}>
          {[1, 6, 24, 72, 168, 720].map(value =>
            <option key={value} value={value}>
              {value} hours
            </option>)}
        </select>
      </label>
      <label>Visible signed requests
        <select value={limit}
          onChange={event => setLimit(Number(event.target.value))}>
          {[10, 25, 50, 100].map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <label>Claim age warning
        <select value={alertAge}
          onChange={event => setAlertAge(Number(event.target.value))}>
          {[15, 30, 45, 60, 120, 360].map(value =>
            <option key={value} value={value}>
              {value} minutes
            </option>)}
        </select>
      </label>
      <label>Failed-run alert threshold
        <select value={failureThreshold}
          onChange={event => setFailureThreshold(Number(event.target.value))}>
          {[1, 2, 3, 5, 10].map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button type="button" onClick={() => setRevision(n => n + 1)}
        disabled={loading}>Refresh diagnostic snapshot</button>
    </fieldset>
    {report && <section>
      <h3>Runtime capability</h3>
      <p>Signed endpoint: <strong>{report.configuration.enabled ?
        "EXPLICITLY ENABLED" : "DISABLED"}</strong>.
        Tenant signing key configured:
        {" "}<strong>{report.configuration.hasTenantKey ? "Yes" : "No"}</strong>.
        Replay prevention: {report.configuration.replayStorage}.
        Background cron installed: <strong>No</strong>.</p>
      <p>Do not include secret key material in incident tickets,
        logs, URLs or source control. Only key identifiers and
        SHA-256 request digests are shown here.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Measurement label="Signed requests accepted"
          value={report.acceptedNoncesInWindow}/>
        <Measurement label="Unmatched accepted requests"
          value={report.unmatchedAcceptedNonces}/>
        <Measurement label="Recent failed claims"
          value={report.failedClaimsInWindow}/>
        <Measurement label="Uncertain claims"
          value={report.unknownClaimsInWindow}/>
        <Measurement label="Still claimed"
          value={report.unsettledClaims}/>
        <Measurement label="Recent rows displayed"
          value={report.displayed}/>
      </div>
      <h3>Operational alert assessment</h3>
      {report.alerts.length === 0 && <p>
        No active diagnostic threshold has been reached
        in the available historical window.</p>}
      {report.alerts.map(alert =>
        <article key={alert.code} style={{
          border: "1px solid #8885",
          borderRadius: 8, padding: 12, marginBlock: 8,
        }}>
          <strong>{alert.severity} · {alert.code}</strong>
          <p>{alert.summary}</p>
          <p>Operational action: {alert.action}</p>
        </article>)}
      <h3>Signed dispatch journal</h3>
      {report.truncated && <p role="alert">
        Additional signed requests exist outside the visible
        page. Review a wider range before drawing conclusions.
      </p>}
      {report.recent.length === 0 && <p>
        No signed service request has been accepted in
        the selected observation interval.</p>}
      {report.recent.map((row, index) =>
        <article key={row.nonceDigest + index} style={{
          border: "1px solid #8885", borderRadius: 8,
          padding: 12, marginBlock: 8,
        }}>
          <strong>Key {row.keyId} · {row.scheduleId}</strong>
          <p>Accepted: {when(row.acceptedAt)}.
            Expires: {when(row.expiresAt)}.
            Time since acceptance: {row.minutesSinceAccepted} minutes.</p>
          <p>Matching claim: {row.hasRunClaim ? "Possible" : "Not observed"}.
            State: {row.runState ?? "Unknown"}.
            Slot: {when(row.associatedSlotAt)}.</p>
          {row.warningCode && <p role="alert">
            {row.warningCode}</p>}
          <details>
            <summary>Request and nonce fingerprints</summary>
            <p>Request digest:
              {" "}<code style={{ overflowWrap: "anywhere" }}>
                {row.requestDigest}</code></p>
            <p>Nonce digest:
              {" "}<code style={{ overflowWrap: "anywhere" }}>
                {row.nonceDigest}</code></p>
          </details>
        </article>)}
      <details>
        <summary>Limits of operational evidence</summary>
        <ul>{report.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
        <p>Time-adjacent run records are only heuristic
          associations; they do not establish that an
          individual signed request caused the run.</p>
        <p>Warnings are computed on demand.
          No email, pager, push notification or recurring
          monitoring service is installed.</p>
      </details>
    </section>}
  </section>;
}
