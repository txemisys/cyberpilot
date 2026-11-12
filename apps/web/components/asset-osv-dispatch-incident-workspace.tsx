"use client";

import { useEffect, useState } from "react";

type State = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
type Severity = "WARNING" | "CRITICAL";
type AlertRow = {
  id: string;
  organizationId: string;
  code: string;
  subjectKey: string;
  severity: Severity;
  state: State;
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
type AlertPage = {
  schema: string;
  organizationId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  alerts: AlertRow[];
  warnings: string[];
};
type Scan = {
  schema: string;
  organizationId: string;
  evaluatedAt: string;
  observed: number;
  opened: number;
  updated: number;
  reopened: number;
  retainedAcknowledgements: number;
  unchanged: number;
  reportDigest: string;
  warnings: string[];
};
type Transition = {
  operation: "ACKNOWLEDGE" | "RESOLVE" | "REOPEN";
  alert: AlertRow;
  auditRecorded: true;
  providerContacted: false;
  quotaChanged: false;
  scheduleChanged: false;
  warnings: string[];
};
async function request<T>(
  url: string, method: "GET" | "POST" | "PATCH",
  value?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, credentials: "same-origin", cache: "no-store",
    headers: method === "GET" ? {
      Accept: "application/json",
    } : {
      Accept: "application/json", "Content-Type": "application/json",
    },
    ...(method === "GET" ? {} : {
      body: JSON.stringify(value),
    }),
  });
  const result: unknown = await response.json();
  if (!response.ok) {
    const error = result as { error?: string };
    throw new Error(error.error ?? "Dispatch alert HTTP " + response.status);
  }
  return result as T;
}
function readableDate(value: string | null) {
  if (!value) return "Not recorded";
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ?
    parsed.toLocaleString() : "Invalid timestamp";
}
function errorMessage(value: unknown) {
  return value instanceof Error ? value.message :
    "Dispatch incident management unavailable.";
}
function Counter({ label, value }: { label: string; value: number }) {
  return <div style={{
    padding: 10, border: "1px solid #8885",
    borderRadius: 8,
  }}>
    <strong>{value}</strong>
    <p>{label}</p>
  </div>;
}
function Evidence({ value }: { value: AlertRow }) {
  const evidence = value.evidence &&
    typeof value.evidence === "object" &&
    !Array.isArray(value.evidence) ?
      value.evidence as Record<string, unknown> : null;
  return <details>
    <summary>Local incident evidence and fingerprint</summary>
    <p>Alert identifier: <code>{value.id}</code>.</p>
    <p>Evidence fingerprint:
      {" "}<code style={{ overflowWrap: "anywhere" }}>
        {value.evidenceDigest}</code></p>
    <p>Evidence origin: {typeof evidence?.source === "string" ?
      evidence.source : "Unknown"}.</p>
    <pre style={{
      overflowX: "auto", whiteSpace: "pre-wrap",
      overflowWrap: "anywhere", fontSize: "0.83rem",
    }}>{JSON.stringify(evidence?.metrics ?? {}, null, 2)}</pre>
  </details>;
}
export function AssetOsvDispatchIncidentWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/osv-dispatch-alerts";
  const [page, setPage] = useState<AlertPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState<State | "ALL">("ALL");
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [lookbackHours, setLookbackHours] = useState(24);
  const [alertAfterMinutes, setAlertAfterMinutes] = useState(45);
  const [failureThreshold, setFailureThreshold] = useState(3);
  const [selected, setSelected] = useState("");
  const [expectedEvidenceDigest, setExpectedEvidenceDigest] = useState("");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<"IDLE" | "READING" | "SCANNING" |
    "UPDATING">("IDLE");
  const [scan, setScan] = useState<Scan | null>(null);
  const [transition, setTransition] = useState<Transition | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const limit = 20;
  const current = page?.alerts.find(row => row.id === selected);
  const operation: Transition["operation"] | null =
    current?.state === "OPEN" ? "ACKNOWLEDGE" :
    current?.state === "ACKNOWLEDGED" ? "RESOLVE" :
    current?.state === "RESOLVED" ? "REOPEN" : null;
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    setBusy(current => current === "IDLE" ? "READING" : current);
    const url = base + "?" + new URLSearchParams({
      offset: String(offset), limit: String(limit),
      ...(state === "ALL" ? {} : { state }),
      ...(severity === "ALL" ? {} : { severity }),
    });
    void request<AlertPage>(url, "GET").then(data => {
      if (cancelled) return;
      setPage(data); setError(null);
    }).catch(cause => {
      if (!cancelled) setError(errorMessage(cause));
    }).finally(() => {
      if (!cancelled) setBusy("IDLE");
    });
    return () => { cancelled = true; };
  }, [base, canManage, offset, state, severity, revision]);
  function resetAction() {
    setSelected(""); setExpectedEvidenceDigest("");
    setReason(""); setConfirm(false); setTransition(null);
  }
  async function scanNow() {
    if (busy !== "IDLE") return;
    setBusy("SCANNING"); setError(null); resetAction();
    try {
      const report = await request<Scan>(base, "POST", {
        lookbackHours,
        maximumRecent: 50,
        alertAfterMinutes,
        alertFailureThreshold: failureThreshold,
        alertUnsettledThreshold: 1,
      });
      setScan(report);
      setOffset(0);
      setRevision(n => n + 1);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy("IDLE");
    }
  }
  async function transitionNow() {
    if (!current || !operation || busy !== "IDLE" ||
        !confirm || reason.trim().length < 20 ||
        expectedEvidenceDigest !== current.evidenceDigest) return;
    setBusy("UPDATING"); setError(null);
    try {
      const result = await request<Transition>(base, "PATCH", {
        alertId: current.id, operation,
        expectedRevision: current.revision,
        expectedEvidenceDigest,
        reason,
      });
      setTransition(result);
      setSelected("");
      setReason(""); setConfirm(false);
      setExpectedEvidenceDigest("");
      setRevision(n => n + 1);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally { setBusy("IDLE"); }
  }
  if (!canManage) return null;
  return <section aria-label="Persistent OSV dispatch incident triage"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>OSV dispatch incident triage</h2>
    <p>Persist local dispatcher health signals as an auditable,
      organization-scoped incident register. Scans are explicit and
      read only local logs. They never contact OSV.dev, install a
      scheduler or retry uncertain provider requests.</p>
    {error && <p role="alert">{error}</p>}
    {busy !== "IDLE" && <p role="status">
      {busy === "SCANNING" ? "Assessing and recording local incidents…" :
        busy === "UPDATING" ? "Auditing incident decision…" :
        "Loading existing incident register…"}
    </p>}
    <fieldset disabled={busy !== "IDLE"}>
      <legend>Run a bounded local incident assessment</legend>
      <label>Lookback
        <select value={lookbackHours}
          onChange={event => setLookbackHours(Number(event.target.value))}>
          {[1, 6, 24, 72, 168].map(value =>
            <option key={value} value={value}>
              {value} hours
            </option>)}
        </select>
      </label>
      <label>Claim warning after
        <select value={alertAfterMinutes}
          onChange={event =>
            setAlertAfterMinutes(Number(event.target.value))}>
          {[15, 30, 45, 60, 120].map(value =>
            <option key={value} value={value}>
              {value} minutes
            </option>)}
        </select>
      </label>
      <label>Critical failure threshold
        <select value={failureThreshold}
          onChange={event =>
            setFailureThreshold(Number(event.target.value))}>
          {[1, 2, 3, 5, 10].map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button type="button" onClick={() => void scanNow()}>
        Scan local dispatch incidents
      </button>
    </fieldset>
    {scan && <section role="status">
      <h3>Assessment stored</h3>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Counter label="Observed" value={scan.observed}/>
        <Counter label="New incidents" value={scan.opened}/>
        <Counter label="Updated" value={scan.updated}/>
        <Counter label="Reopened" value={scan.reopened}/>
        <Counter label="Unchanged" value={scan.unchanged}/>
        <Counter label="Acknowledgements preserved"
          value={scan.retainedAcknowledgements}/>
      </div>
      <p>Examined: {readableDate(scan.evaluatedAt)}.</p>
      <details>
        <summary>Assessment fingerprint and limitations</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>
          {scan.reportDigest}</code></p>
        <ul>{scan.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
      </details>
    </section>}
    <fieldset disabled={busy !== "IDLE"}>
      <legend>Filter persisted incidents</legend>
      <label>Lifecycle state
        <select value={state} onChange={event => {
          setState(event.target.value as State | "ALL");
          setOffset(0); resetAction();
        }}>
          {(["ALL", "OPEN", "ACKNOWLEDGED", "RESOLVED"] as const)
            .map(value =>
              <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <label>Severity
        <select value={severity} onChange={event => {
          setSeverity(event.target.value as Severity | "ALL");
          setOffset(0); resetAction();
        }}>
          {(["ALL", "WARNING", "CRITICAL"] as const)
            .map(value =>
              <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button type="button" onClick={() => setRevision(n => n + 1)}>
        Reload incident register
      </button>
    </fieldset>
    {page && <section>
      <h3>Incident register</h3>
      <p>{page.total} incidents match the current filters.
        {" "}{page.alerts.length} shown in this page.</p>
      {page.alerts.length === 0 &&
        <p>No persisted incidents in this filter.</p>}
      {page.alerts.map(row => <article key={row.id} style={{
        border: "1px solid #8885", borderRadius: 8,
        padding: 12, marginBlock: 8,
      }}>
        <strong>{row.severity} · {row.code}</strong>
        <p>Subject: {row.subjectKey}.
          Status: <strong>{row.state}</strong>.
          Revision: {row.revision}.
          Observations: {row.observedCount}.</p>
        <p>First observed: {readableDate(row.firstSeenAt)}.
          Last change observed: {readableDate(row.lastSeenAt)}.</p>
        {row.acknowledgementReason &&
          <p>Acknowledgement: {row.acknowledgementReason}.
            {" "}At: {readableDate(row.acknowledgedAt)}.</p>}
        {row.resolutionReason &&
          <p>Operator resolution: {row.resolutionReason}.
            {" "}At: {readableDate(row.resolvedAt)}.</p>}
        <Evidence value={row}/>
        <button type="button" disabled={busy !== "IDLE"}
          onClick={() => {
            setSelected(row.id); setExpectedEvidenceDigest("");
            setConfirm(false); setReason(""); setTransition(null);
          }}>
          Review this incident
        </button>
      </article>)}
      <div style={{
        display: "flex", gap: 10, marginBlock: 12,
      }}>
        <button type="button" disabled={offset === 0 ||
          busy !== "IDLE"}
          onClick={() => { setOffset(n => Math.max(0, n - limit));
            resetAction(); }}>
          Previous page
        </button>
        <button type="button" disabled={!page.hasMore ||
          busy !== "IDLE"}
          onClick={() => { setOffset(n => n + limit);
            resetAction(); }}>
          Next page
        </button>
      </div>
    </section>}
    {current && operation && <fieldset disabled={busy !== "IDLE"}>
      <legend>Human incident transition: {operation}</legend>
      <p>Review <code>{current.id}</code>. An ACKNOWLEDGED state
        records an investigation assignment, not proof of recovery.
        Resolution requires a documented operator assessment,
        without changing the actual provider observation.</p>
      <label>Copy exact evidence fingerprint
        <input value={expectedEvidenceDigest}
          maxLength={64}
          onChange={event =>
            setExpectedEvidenceDigest(event.target.value)}
          placeholder={current.evidenceDigest}/>
      </label>
      <label>Investigation decision (20–500 characters)
        <textarea rows={4} maxLength={500} value={reason}
          onChange={event => setReason(event.target.value)}
          placeholder="Record concrete investigation and next operational action"/>
      </label>
      <label>
        <input type="checkbox" checked={confirm}
          onChange={event => setConfirm(event.target.checked)}/>
        I understand this action only changes the incident
        register; it neither changes CyberScore nor
        establishes provider health or endpoint remediation.
      </label>
      <button type="button"
        disabled={!confirm ||
          reason.trim().length < 20 ||
          expectedEvidenceDigest !== current.evidenceDigest}
        onClick={() => void transitionNow()}>
        Save audited incident {operation.toLowerCase()}
      </button>
    </fieldset>}
    {transition && <section role="status">
      <h3>Incident transition recorded</h3>
      <p>{transition.alert.code}: {transition.alert.state}.
        Audit recorded: {transition.auditRecorded ? "Yes" : "No"}.
        Remote provider contacted:
        {" "}{transition.providerContacted ? "Yes" : "No"}.
        Quota changed: {transition.quotaChanged ? "Yes" : "No"}.</p>
      <ul>{transition.warnings.map((warning, index) =>
        <li key={index}>{warning}</li>)}</ul>
    </section>}
    {page && <details>
      <summary>Register scope and limitations</summary>
      <ul>{page.warnings.map((warning, index) =>
        <li key={index}>{warning}</li>)}</ul>
    </details>}
  </section>;
}
