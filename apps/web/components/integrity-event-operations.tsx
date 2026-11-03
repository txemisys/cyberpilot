"use client";

import { useCallback, useState } from "react";

type EventReconcileRow = {
  taskId: string;
  source: string;
  sourceId: string;
  kind: string;
  recipients: number;
  created: number;
  replayed: number;
  skipped: boolean;
  reason: string;
};
type EventReconcileReport = {
  dryRun: boolean;
  totalTasks: number;
  scannedTasks: number;
  hasMore: boolean;
  sourceLimitReached: boolean;
  plannedNotifications: number;
  selectedNotifications: number;
  capReached: boolean;
  created: number;
  replayed: number;
  rows: EventReconcileRow[];
  limitations: string[];
};
type InspectionRow = {
  notificationId: string;
  taskId: string;
  kind: string;
  source: string;
  consistent: boolean;
  issues: string[];
  auditCount: number;
};
type InspectionReport = {
  total: number;
  consistent: number;
  inconsistent: number;
  hasMore: boolean;
  rows: InspectionRow[];
  digest: string;
};
async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store", credentials: "same-origin",
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const error = data as { error?: string };
    throw new Error(error.error ?? ("HTTP " + response.status));
  }
  return data as T;
}
export function IntegrityEventOperations({
  slug, canManage,
}: {
  slug: string;
  canManage: boolean;
}) {
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const [captureId, setCaptureId] = useState("");
  const [includeReviewEvents, setIncludeReviewEvents] = useState(true);
  const [includeProviderChecks, setIncludeProviderChecks] = useState(true);
  const [maxNotifications, setMaxNotifications] = useState(100);
  const [offset, setOffset] = useState(0);
  const [preview, setPreview] = useState<EventReconcileReport | null>(null);
  const [inspection, setInspection] = useState<InspectionReport | null>(null);
  const [inspectionOffset, setInspectionOffset] = useState(0);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const reconcile = useCallback(async (dryRun: boolean) => {
    if (!captureId.trim() || pending) return;
    setPending(true);
    setError(null);
    setSuccess(null);
    try {
      const report = await requestJson<EventReconcileReport>(
        base + "/event-notifications", {
          method: "POST",
          body: JSON.stringify({
            captureId: captureId.trim(),
            includeReviewEvents,
            includeProviderChecks,
            maxNotifications,
            offset, limit: 25, dryRun,
          }),
        },
      );
      setPreview(report);
      if (!dryRun)
        setSuccess(
          report.created + " in-app notifications created; " +
          report.replayed + " already existed.",
        );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Reconciliation failed.");
    } finally {
      setPending(false);
    }
  }, [
    base, captureId, includeReviewEvents, includeProviderChecks,
    maxNotifications, offset, pending,
  ]);
  const inspect = useCallback(async (page: number) => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const query = new URLSearchParams({
        offset: String(page), limit: "25",
      });
      const report = await requestJson<InspectionReport>(
        base + "/notification-inspection?" + query.toString(),
      );
      setInspection(report);
      setInspectionOffset(page);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Inspection failed.");
    } finally {
      setPending(false);
    }
  }, [base, pending]);
  return (
    <section aria-label="Integrity event operations"
      style={{ borderTop: "1px solid #8885", marginTop: 36, paddingTop: 20 }}>
      <h2>Event reconciliation and notification audit</h2>
      <p>
        Review completion and provider observations can produce internal
        notifications. Preview first; no automatic external messages are sent.
      </p>
      <div style={{ display: "grid", gap: 12, maxWidth: 640 }}>
        <label>
          Capture ID
          <input value={captureId}
            onChange={event => {
              setCaptureId(event.target.value);
              setOffset(0);
              setPreview(null);
            }}
            placeholder="Existing integrity capture ID"
            style={{ width: "100%" }} />
        </label>
        <label>
          <input type="checkbox" checked={includeReviewEvents}
            onChange={event => setIncludeReviewEvents(event.target.checked)} />
          Include human review resolution events
        </label>
        <label>
          <input type="checkbox" checked={includeProviderChecks}
            onChange={event => setIncludeProviderChecks(event.target.checked)} />
          Include independent provider check observations
        </label>
        <label>
          Maximum notifications per request
          <input type="number" min={1} max={1000}
            value={maxNotifications}
            onChange={event => setMaxNotifications(
              Math.max(1, Math.min(1000, Number(event.target.value) || 1)),
            )} />
        </label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
          <button type="button"
            disabled={pending || !captureId.trim() ||
              (!includeReviewEvents && !includeProviderChecks)}
            onClick={() => void reconcile(true)}>
            Preview event notifications
          </button>
          {canManage && (
            <button type="button"
              disabled={pending || !preview?.dryRun || !captureId.trim() ||
                (!includeReviewEvents && !includeProviderChecks)}
              onClick={() => void reconcile(false)}>
              Dispatch in-app notifications
            </button>
          )}
          <button type="button" disabled={pending}
            onClick={() => void inspect(0)}>
            Inspect notification provenance
          </button>
        </div>
      </div>
      {pending && <p role="status">Processing…</p>}
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
      {success && <p role="status">{success}</p>}
      {preview && (
        <section aria-label="Reconciliation results">
          <h3>{preview.dryRun ? "Preview" : "Dispatch results"}</h3>
          <p>
            {preview.scannedTasks} of {preview.totalTasks} tasks scanned.
            {" "}{preview.plannedNotifications} notifications planned;
            {" "}{preview.created} created and {preview.replayed} replayed.
          </p>
          {(preview.capReached || preview.sourceLimitReached) &&
            <p role="alert">
              A safety limit was reached. This report is incomplete.
            </p>}
          <ul>
            {preview.rows.map(row => (
              <li key={row.source + row.sourceId}>
                {row.kind} · {row.recipients} recipients ·
                {" "}{row.created} created · {row.replayed} replayed
                {row.skipped ? " · Not dispatched" : ""}
              </li>
            ))}
          </ul>
          <div style={{ display: "flex", gap: 10 }}>
            <button type="button" disabled={offset === 0 || pending}
              onClick={() => {
                setOffset(Math.max(0, offset - 25));
                setPreview(null);
              }}>Previous task page</button>
            <button type="button" disabled={!preview.hasMore || pending}
              onClick={() => {
                setOffset(offset + 25);
                setPreview(null);
              }}>Next task page</button>
          </div>
        </section>
      )}
      {inspection && (
        <section aria-label="Notification audit inspection">
          <h3>Notification integrity report</h3>
          <p>
            {inspection.total} matching notifications.
            {" "}{inspection.consistent} consistent and
            {" "}{inspection.inconsistent} with detected issues on this page.
          </p>
          <p>Page digest: <code>{inspection.digest}</code></p>
          <ul>
            {inspection.rows.map(row => (
              <li key={row.notificationId}>
                {row.kind} · {row.source} ·
                {" "}{row.consistent ? "No detected issues" :
                  row.issues.join(", ")}
                {" · "}{row.auditCount} creation audit records
              </li>
            ))}
          </ul>
          <div style={{ display: "flex", gap: 10 }}>
            <button type="button"
              disabled={pending || inspectionOffset === 0}
              onClick={() => void inspect(Math.max(0, inspectionOffset - 25))}>
              Previous audit page
            </button>
            <button type="button"
              disabled={pending || !inspection.hasMore}
              onClick={() => void inspect(inspectionOffset + 25)}>
              Next audit page
            </button>
          </div>
        </section>
      )}
    </section>
  );
}
