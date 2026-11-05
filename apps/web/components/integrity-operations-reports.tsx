"use client";

import { useCallback, useMemo, useState } from "react";

type ManifestEntry = {
  category: string;
  id: string;
  taskId: string;
  at: string;
  revision: number | null;
  outcome: string;
  sourceDigest: string;
};
type Manifest = {
  schema: string;
  captureId: string;
  totalTasks: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  generatedAt: string;
  pageDigest: string;
  counts: Record<string, number>;
  entries: ManifestEntry[];
  warnings: string[];
};
type DiagnosticsBucket = {
  key: string;
  total: number;
  unread: number;
  read: number;
  dismissed: number;
  readWithin24Hours: number;
  medianReadMinutes: number | null;
  revisionAnomalies: number;
};
type Diagnostics = {
  total: number;
  scanned: number;
  truncated: boolean;
  from: string;
  to: string;
  digest: string;
  groupBy: string;
  summary: {
    total: number;
    unread: number;
    read: number;
    dismissed: number;
    readWithin24Hours: number;
    uniqueRecipients: number;
    uniqueTasks: number;
  };
  buckets: DiagnosticsBucket[];
  limitations: string[];
};
async function readReport<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store", credentials: "same-origin",
  });
  const payload: unknown = await response.json();
  if (!response.ok)
    throw new Error(
      (payload as { error?: string }).error ??
      "Report request failed (HTTP " + response.status + ").",
    );
  return payload as T;
}
export function IntegrityOperationsReports({
  slug, canManage,
}: {
  slug: string;
  canManage: boolean;
}) {
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const [captureId, setCaptureId] = useState("");
  const [offset, setOffset] = useState(0);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const [groupBy, setGroupBy] = useState<"KIND" | "TASK" | "RECIPIENT">("KIND");
  const [includeDismissed, setIncludeDismissed] = useState(true);
  const [includeReviewEvents, setIncludeReviewEvents] = useState(true);
  const [includeProviderObservations, setIncludeProviderObservations] =
    useState(true);
  const [includeEscalationHistory, setIncludeEscalationHistory] = useState(true);
  const [includeNotificationMetadata, setIncludeNotificationMetadata] =
    useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const manifestParams = useMemo(() => new URLSearchParams({
    captureId: captureId.trim(),
    offset: String(offset), limit: "20",
    includeReviewEvents: String(includeReviewEvents),
    includeProviderObservations: String(includeProviderObservations),
    includeEscalationHistory: String(includeEscalationHistory),
    includeNotificationMetadata: String(includeNotificationMetadata),
  }), [
    captureId, offset, includeReviewEvents,
    includeProviderObservations, includeEscalationHistory,
    includeNotificationMetadata,
  ]);
  const loadManifest = useCallback(async () => {
    if (!captureId.trim() || pending) return;
    setPending(true);
    setError(null);
    try {
      const result = await readReport<Manifest>(
        base + "/operations-manifest?" + manifestParams.toString(),
      );
      setManifest(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Manifest failed.");
    } finally {
      setPending(false);
    }
  }, [base, captureId, manifestParams, pending]);
  const loadDiagnostics = useCallback(async () => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        groupBy, includeDismissed: String(includeDismissed),
        limit: "10000",
      });
      if (captureId.trim()) params.set("captureId", captureId.trim());
      const result = await readReport<Diagnostics>(
        base + "/delivery-diagnostics?" + params.toString(),
      );
      setDiagnostics(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Diagnostics failed.");
    } finally {
      setPending(false);
    }
  }, [base, captureId, groupBy, includeDismissed, pending]);
  if (!canManage)
    return (
      <section aria-label="Operational audit reports">
        <h2>Operational audit reports</h2>
        <p>Administrator access is required for cross-recipient reports.</p>
      </section>
    );
  return (
    <section aria-label="Operational audit reports"
      style={{ borderTop: "1px solid #8885", marginTop: 36, paddingTop: 20 }}>
      <h2>Operational evidence and delivery reports</h2>
      <p>
        Reports summarize recorded application activity. They are not
        technical security certifications and never include raw OAuth tokens.
      </p>
      <div style={{ display: "grid", gap: 12, maxWidth: 680 }}>
        <label>
          Capture ID (required for manifest; optional for diagnostics)
          <input style={{ width: "100%" }}
            value={captureId}
            onChange={event => {
              setCaptureId(event.target.value);
              setOffset(0);
              setManifest(null);
              setDiagnostics(null);
            }}
            placeholder="Existing integrity capture ID" />
        </label>
        <fieldset>
          <legend>Manifest content</legend>
          {([
            ["Review events", includeReviewEvents, setIncludeReviewEvents],
            ["Provider observations", includeProviderObservations,
              setIncludeProviderObservations],
            ["Escalation history", includeEscalationHistory,
              setIncludeEscalationHistory],
            ["Notification metadata", includeNotificationMetadata,
              setIncludeNotificationMetadata],
          ] as const).map(([label, value, setter]) => (
            <label key={label} style={{ display: "block" }}>
              <input type="checkbox" checked={value}
                onChange={event => setter(event.target.checked)} />
              {label}
            </label>
          ))}
        </fieldset>
        <button type="button"
          disabled={pending || !captureId.trim()}
          onClick={() => void loadManifest()}>
          Generate manifest page
        </button>
        <label>
          Delivery grouping
          <select value={groupBy}
            onChange={event => setGroupBy(
              event.target.value as "KIND" | "TASK" | "RECIPIENT",
            )}>
            <option value="KIND">Notification kind</option>
            <option value="TASK">Review task</option>
            <option value="RECIPIENT">Hashed recipient</option>
          </select>
        </label>
        <label>
          <input type="checkbox" checked={includeDismissed}
            onChange={event => setIncludeDismissed(event.target.checked)} />
          Include dismissed notifications
        </label>
        <button type="button" disabled={pending}
          onClick={() => void loadDiagnostics()}>
          Analyze in-app delivery
        </button>
      </div>
      {pending && <p role="status">Loading operational report…</p>}
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
      {manifest && (
        <section aria-label="Operational evidence manifest">
          <h3>Manifest page</h3>
          <p>
            {manifest.entries.length} entries for {manifest.totalTasks} tasks.
            {" "}{manifest.complete ? "No query cap detected." :
              "Incomplete: a query limit was reached."}
          </p>
          <p>Page SHA-256: <code>{manifest.pageDigest}</code></p>
          <ul>
            {manifest.entries.map(entry => (
              <li key={entry.category + ":" + entry.id}>
                {entry.category} · {entry.outcome} ·
                {" "}{entry.at} · task {entry.taskId}
              </li>
            ))}
          </ul>
          <div style={{ display: "flex", gap: 12 }}>
            <button type="button" disabled={pending || offset === 0}
              onClick={() => {
                setOffset(Math.max(0, offset - 20));
                setManifest(null);
              }}>Previous manifest page</button>
            <button type="button" disabled={pending || !manifest.hasMore}
              onClick={() => {
                setOffset(offset + 20);
                setManifest(null);
              }}>Next manifest page</button>
          </div>
        </section>
      )}
      {diagnostics && (
        <section aria-label="In-app delivery diagnostics">
          <h3>Delivery diagnostics</h3>
          <p>
            {diagnostics.scanned} of {diagnostics.total} notifications scanned;
            {" "}{diagnostics.summary.unread} unread and
            {" "}{diagnostics.summary.read} marked read.
          </p>
          {diagnostics.truncated &&
            <p role="alert">The query was truncated; results are partial.</p>}
          <p>Report SHA-256: <code>{diagnostics.digest}</code></p>
          <table>
            <thead>
              <tr>
                <th scope="col">Group</th>
                <th scope="col">Total</th>
                <th scope="col">Unread</th>
                <th scope="col">Read within 24h</th>
                <th scope="col">Anomalies</th>
              </tr>
            </thead>
            <tbody>
              {diagnostics.buckets.map(bucket => (
                <tr key={bucket.key}>
                  <td>{bucket.key}</td>
                  <td>{bucket.total}</td>
                  <td>{bucket.unread}</td>
                  <td>{bucket.readWithin24Hours}</td>
                  <td>{bucket.revisionAnomalies}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </section>
  );
}
