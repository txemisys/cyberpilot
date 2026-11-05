"use client";

import { useEffect, useMemo, useState } from "react";

type AuditEntry = {
  eventId: string;
  taskId: string;
  action: string;
  timestamp: string;
  actorHash: string | null;
  idempotencyHash: string | null;
  beforeRevision: number | null;
  afterRevision: number | null;
  recipientCount: number | null;
  notificationCount: number | null;
  anomalies: string[];
  fingerprint: string;
};
type AuditGroup = {
  taskId: string;
  actions: number;
  assignments: number;
  unassignments: number;
  notices: number;
  notifications: number;
  duplicateKeys: number;
  anomalies: number;
  firstActionAt: string;
  lastActionAt: string;
};
type AuditReport = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  entries: AuditEntry[];
  groups: AuditGroup[];
  anomalyCounts: Record<string, number>;
  actionCounts: Record<string, number>;
  digest: string;
  limitations: string[];
};
function readableTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
export function IntegrityInterventionHistory({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const [captureId, setCaptureId] = useState("");
  const [taskId, setTaskId] = useState("");
  const [action, setAction] = useState("");
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const limit = 50;
  const url = useMemo(() => {
    const params = new URLSearchParams({
      captureId: captureId.trim(),
      limit: String(limit), offset: String(offset),
    });
    if (taskId.trim()) params.set("taskId", taskId.trim());
    if (action) params.set("action", action);
    return "/api/organizations/" + encodeURIComponent(slug) +
      "/actions/work/integrity/intervention-history?" + params;
  }, [slug, captureId, taskId, action, offset]);
  useEffect(() => {
    if (!enabled || !canManage || !captureId.trim()) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setReport(null);
    const read = async () => {
      try {
        const response = await fetch(url, {
          credentials: "same-origin", cache: "no-store",
          signal: controller.signal,
        });
        const value: unknown = await response.json();
        if (!response.ok) {
          const data = value as { error?: string };
          throw new Error(data.error ?? "History HTTP " + response.status);
        }
        if (!controller.signal.aborted) setReport(value as AuditReport);
      } catch (cause) {
        if (!controller.signal.aborted) setError(
          cause instanceof Error ? cause.message : "History unavailable.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    void read();
    return () => controller.abort();
  }, [url, revision, enabled, canManage, captureId]);
  if (!canManage) return null;
  function filterChange(setter: (next: string) => void, value: string) {
    setter(value); setOffset(0); setEnabled(false);
    setReport(null); setError(null);
  }
  return <section aria-label="Audited intervention history"
    style={{ padding: 16, border: "1px solid #8885", borderRadius: 12,
      marginBlock: 24 }}>
    <h2>Intervention audit investigation</h2>
    <p>
      Inspect persisted human triage decisions, recipient counts and unusual
      events. Hashed user identifiers are pseudonymous, not anonymous.
    </p>
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
      <label>Capture ID
        <input value={captureId} maxLength={100}
          onChange={event => filterChange(setCaptureId, event.target.value)}
          placeholder="Required" />
      </label>
      <label>Task ID (optional)
        <input value={taskId} maxLength={100}
          onChange={event => filterChange(setTaskId, event.target.value)} />
      </label>
      <label>Action
        <select value={action}
          onChange={event => filterChange(setAction, event.target.value)}>
          <option value="">All triage events</option>
          <option value="ASSIGN">Assign</option>
          <option value="UNASSIGN">Unassign</option>
          <option value="NOTIFY_OWNER">Notify owner</option>
          <option value="NOTIFY_ADMINS">Notify admins</option>
          <option value="SET_DUE_REMINDER">Set reminder</option>
          <option value="CLEAR_DUE_REMINDER">Clear reminder</option>
        </select>
      </label>
      <button type="button" disabled={!captureId.trim() || loading}
        onClick={() => {
          setEnabled(true);
          setRevision(value => value + 1);
        }}>Inspect audit events</button>
    </div>
    {loading && <p role="status">Reading scoped audit events…</p>}
    {error && <p role="alert">{error}</p>}
    {report && <>
      <p>{report.total} matching persisted events ·
        page {Math.floor(report.offset / report.limit) + 1}</p>
      {!report.complete && <p role="status">
        Partial page. Counts and anomaly detection do not cover the full ledger.
      </p>}
      <details>
        <summary>Report digest and interpretation</summary>
        <code style={{ overflowWrap: "anywhere" }}>{report.digest}</code>
        <ul>{report.limitations.map(item =>
          <li key={item}>{item}</li>)}</ul>
      </details>
      <h3>Actions on this page</h3>
      <ul>{Object.entries(report.actionCounts).map(([key, count]) =>
        <li key={key}>{key}: {count}</li>)}</ul>
      {Object.keys(report.anomalyCounts).length > 0 && <>
        <h3>Audit anomalies</h3>
        <ul>{Object.entries(report.anomalyCounts).map(([key, count]) =>
          <li key={key}>{key}: {count}</li>)}</ul>
      </>}
      <h3>Tasks with audited activity</h3>
      {report.groups.map(group => <article key={group.taskId}
        style={{ border: "1px solid #8885", borderRadius: 8, padding: 12,
          marginBottom: 8 }}>
        <strong>{group.taskId}</strong>
        <p>Actions {group.actions} · Assignments {group.assignments} ·
          Notices {group.notices} · Notifications {group.notifications}</p>
        <p>Anomalies {group.anomalies} · First {readableTime(group.firstActionAt)}
          {" · "}Last {readableTime(group.lastActionAt)}</p>
      </article>)}
      <h3>Source audit events</h3>
      <div style={{ display: "grid", gap: 10 }}>
        {report.entries.map(event => <article key={event.eventId}
          style={{ border: "1px solid #8885", borderRadius: 8, padding: 12 }}>
          <strong>{event.action}</strong>
          <p>{event.taskId} · {readableTime(event.timestamp)}</p>
          <p>Review revision {event.beforeRevision ?? "?"}
            {" → "}{event.afterRevision ?? "?"}
            {" · "}Recipients {event.recipientCount ?? "unknown"}
            {" · "}Messages {event.notificationCount ?? "unknown"}</p>
          {event.anomalies.length > 0 &&
            <p role="status">Issues: {event.anomalies.join(", ")}</p>}
          <details>
            <summary>Audit fingerprint</summary>
            <code style={{ overflowWrap: "anywhere" }}>{event.fingerprint}</code>
          </details>
        </article>)}
      </div>
      <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
        <button type="button" disabled={loading || offset === 0}
          onClick={() => setOffset(value => Math.max(0, value - limit))}>
          Previous page
        </button>
        <button type="button" disabled={loading || !report.hasMore}
          onClick={() => setOffset(value => value + limit)}>
          Next page
        </button>
      </div>
    </>}
  </section>;
}
