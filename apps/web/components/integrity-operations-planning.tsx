"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type PlanningRow = {
  taskId: string;
  captureId: string;
  title: string;
  severity: string;
  disposition: string;
  dueAt: string;
  ownerAssigned: boolean;
  urgency: string;
  priority: number;
  actions: string[];
  signals: string[];
  provider: { latestOutcome: string | null; checkedAt: string | null };
  inbox: { unread: number };
  work: { active: number };
};
type PlanningReport = {
  schema: string;
  generatedAt: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  digest: string;
  summary: {
    scanned: number;
    overdue: number;
    dueInHorizon: number;
    unassigned: number;
    escalated: number;
    missingProvider: number;
    failingProvider: number;
    unreadNotifications: number;
  };
  rows: PlanningRow[];
  warnings: string[];
};
type CohortRow = {
  captureId: string;
  createdAt: string;
  totalTasks: number;
  open: number;
  overdue: number;
  unassigned: number;
  resolved: number;
  waived: number;
  activeEscalations: number;
  unread: number;
  providerFailingTasks: number;
  providerUnknownTasks: number;
  medianOpenHours: number;
  coverage: {
    activeOwnerPercent: number;
    providerCheckedPercent: number;
    closedPercent: number;
  };
  anomalies: string[];
  digest: string;
};
type CohortReport = {
  schema: string;
  generatedAt: string;
  totalCaptures: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  digest: string;
  rows: CohortRow[];
  limitations: string[];
};
type ReportView = "PLANNING" | "CAPTURES";
function formatDate(value: string | null) {
  if (!value) return "Not observed";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Invalid timestamp" :
    parsed.toLocaleString();
}
function message(error: unknown) {
  return error instanceof Error ? error.message : "The operation could not be completed.";
}
async function getReport<T>(url: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(url, {
    method: "GET", signal, credentials: "same-origin",
    cache: "no-store", headers: { Accept: "application/json" },
  });
  const value: unknown = await response.json();
  if (!response.ok) {
    const record = value as { error?: string };
    throw new Error(record.error || "HTTP " + response.status);
  }
  return value as T;
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{ padding: 12, border: "1px solid #8885", borderRadius: 8 }}>
    <strong>{value}</strong><div>{label}</div>
  </div>;
}
function Warnings({ values }: { values: string[] }) {
  return <details style={{ marginTop: 12 }}>
    <summary>Scope and interpretation ({values.length})</summary>
    <ul>{values.map(value => <li key={value}>{value}</li>)}</ul>
  </details>;
}
export function IntegrityOperationsPlanning({ slug, canManage }: {
  slug: string;
  canManage: boolean;
}) {
  const [view, setView] = useState<ReportView>("PLANNING");
  const [captureId, setCaptureId] = useState("");
  const [horizon, setHorizon] = useState("72");
  const [includeClosed, setIncludeClosed] = useState(false);
  const [cohortOrder, setCohortOrder] = useState("RECENT");
  const [offset, setOffset] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [planning, setPlanning] = useState<PlanningReport | null>(null);
  const [cohorts, setCohorts] = useState<CohortReport | null>(null);
  const size = 25;
  const endpoint = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(offset), limit: String(size),
    });
    if (captureId.trim()) params.set("captureId", captureId.trim());
    if (view === "PLANNING") {
      params.set("horizonHours", horizon);
      params.set("includeClosed", String(includeClosed));
    } else {
      params.set("order", cohortOrder);
      params.set("includeEmpty", "true");
    }
    return "/api/organizations/" + encodeURIComponent(slug) +
      "/actions/work/integrity/" +
      (view === "PLANNING" ? "operational-planning" : "capture-cohorts") +
      "?" + params.toString();
  }, [slug, offset, captureId, horizon, includeClosed, cohortOrder, view]);
  const refresh = useCallback(() => setReloadKey(value => value + 1), []);
  useEffect(() => {
    if (!canManage) return;
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    if (view === "PLANNING") setPlanning(null);
    else setCohorts(null);
    const run = async () => {
      try {
        if (view === "PLANNING") {
          const result = await getReport<PlanningReport>(endpoint, controller.signal);
          if (!controller.signal.aborted) setPlanning(result);
        } else {
          const result = await getReport<CohortReport>(endpoint, controller.signal);
          if (!controller.signal.aborted) setCohorts(result);
        }
      } catch (cause) {
        if (!controller.signal.aborted) setError(message(cause));
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    };
    void run();
    return () => controller.abort();
  }, [endpoint, canManage, view, reloadKey]);
  if (!canManage) return null;
  const current = view === "PLANNING" ? planning : cohorts;
  function navigate(next: ReportView) {
    setView(next);
    setOffset(0);
    setError(null);
  }
  return <section aria-label="Operational planning and capture cohorts"
    style={{ marginBlock: 28, padding: 16, border: "1px solid #8885", borderRadius: 12 }}>
    <header>
      <h2>Operational planning and capture cohorts</h2>
      <p>
        Read-only, historical operational intelligence. These diagnostics
        do not independently verify a security control or change CyberScore.
      </p>
    </header>
    <nav aria-label="Operational report">
      <button type="button" aria-pressed={view === "PLANNING"}
        onClick={() => navigate("PLANNING")}>Task planning</button>
      <button type="button" aria-pressed={view === "CAPTURES"}
        onClick={() => navigate("CAPTURES")}>Capture cohorts</button>
    </nav>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBlock: 12 }}>
      <label>Capture ID (optional)
        <input value={captureId} onChange={event => {
          setCaptureId(event.target.value); setOffset(0);
        }} placeholder="All captures" maxLength={100} />
      </label>
      {view === "PLANNING" ? <>
        <label>Planning horizon
          <select value={horizon} onChange={event => {
            setHorizon(event.target.value); setOffset(0);
          }}>
            {[24, 48, 72, 168, 336].map(hours =>
              <option key={hours} value={hours}>{hours} hours</option>)}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={includeClosed}
            onChange={event => {
              setIncludeClosed(event.target.checked); setOffset(0);
            }} />
          Include closed reviews
        </label>
      </> : <label>Capture ordering
        <select value={cohortOrder} onChange={event => {
          setCohortOrder(event.target.value); setOffset(0);
        }}>
          <option value="RECENT">Newest first</option>
          <option value="OLDEST">Oldest first</option>
          <option value="MOST_OPEN">Most open (on page)</option>
          <option value="MOST_OVERDUE">Most overdue (on page)</option>
        </select>
      </label>}
      <button type="button" onClick={refresh} disabled={busy}>Refresh</button>
    </div>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Loading operational records…</p>}
    {current && <>
      <p>
        Generated {formatDate(current.generatedAt)} · Page {Math.floor(offset / size) + 1}
        {" · "}{view === "PLANNING" ?
          (planning?.total ?? 0) + " matching tasks" :
          (cohorts?.totalCaptures ?? 0) + " matching captures"}
      </p>
      {!current.complete && <p role="status">
        Partial result: statistics and rankings apply to the selected page.
      </p>}
      <details><summary>Report SHA-256 digest</summary>
        <code style={{ overflowWrap: "anywhere" }}>{current.digest}</code>
      </details>
    </>}
    {view === "PLANNING" && planning && <>
      <div style={{
        display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
        gap: 10,
      }}>
        <Metric label="Overdue" value={planning.summary.overdue} />
        <Metric label="Due in horizon" value={planning.summary.dueInHorizon} />
        <Metric label="Unassigned" value={planning.summary.unassigned} />
        <Metric label="Active escalations" value={planning.summary.escalated} />
        <Metric label="Provider gaps" value={planning.summary.missingProvider} />
        <Metric label="Unread in-app" value={planning.summary.unreadNotifications} />
      </div>
      {planning.rows.length === 0 && <p>No tasks on this page.</p>}
      <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
        {planning.rows.map(row => <article key={row.taskId}
          style={{ padding: 12, border: "1px solid #8885", borderRadius: 8 }}>
          <h3>{row.title}</h3>
          <p>{row.severity} · {row.disposition} · {row.urgency}
            {" · "}priority {row.priority}</p>
          <p>Deadline: {formatDate(row.dueAt)}
            {" · "}Owner: {row.ownerAssigned ? "Assigned" : "Unassigned"}
            {" · "}Provider: {row.provider.latestOutcome ?? "No observation"}</p>
          <p>Signals: {row.signals.join(", ") || "None"}</p>
          <p>Suggested actions: {row.actions.join(", ")}</p>
          <small>Active work links: {row.work.active}
            {" · "}Unread notifications: {row.inbox.unread}
            {" · "}Task ID: {row.taskId}</small>
        </article>)}
      </div>
      <Warnings values={planning.warnings} />
    </>}
    {view === "CAPTURES" && cohorts && <>
      {cohorts.rows.length === 0 && <p>No captures on this page.</p>}
      <div style={{ display: "grid", gap: 12 }}>
        {cohorts.rows.map(row => <article key={row.captureId}
          style={{ padding: 12, border: "1px solid #8885", borderRadius: 8 }}>
          <h3>Capture {row.captureId}</h3>
          <p>{formatDate(row.createdAt)} · {row.totalTasks} tasks</p>
          <p>Open: {row.open} · Overdue: {row.overdue}
            {" · "}Unassigned: {row.unassigned}
            {" · "}Resolved: {row.resolved} · Waived: {row.waived}</p>
          <p>Active escalations: {row.activeEscalations}
            {" · "}Unread: {row.unread}
            {" · "}Provider failures: {row.providerFailingTasks}</p>
          <p>Owner coverage: {row.coverage.activeOwnerPercent}%
            {" · "}Provider observations: {row.coverage.providerCheckedPercent}%
            {" · "}Closed: {row.coverage.closedPercent}%</p>
          {row.anomalies.length > 0 &&
            <p role="status">Anomalies: {row.anomalies.join(", ")}</p>}
        </article>)}
      </div>
      <Warnings values={cohorts.limitations} />
    </>}
    {current && <div style={{ display: "flex", gap: 12, marginTop: 16 }}>
      <button type="button" disabled={busy || offset === 0}
        onClick={() => setOffset(value => Math.max(0, value - size))}>
        Previous page
      </button>
      <button type="button" disabled={busy || !current.hasMore}
        onClick={() => setOffset(value => value + size)}>
        Next page
      </button>
    </div>}
  </section>;
}
