"use client";

import { useCallback, useState } from "react";

type SlaBreach = {
  entity: string;
  id: string;
  taskId: string;
  category: string;
  elapsedMinutes: number;
  thresholdMinutes: number;
  exceededMinutes: number;
  active: boolean;
  state: string;
};
type SlaReport = {
  totalTasks: number;
  scannedTasks: number;
  truncated: boolean;
  active: number;
  historical: number;
  affectedTasks: number;
  digest: string;
  breaches: SlaBreach[];
  warnings: string[];
};
type ConsistencyIssue = {
  code: string;
  entity: string;
  entityId: string;
  severity: string;
};
type ConsistencyTask = {
  taskId: string;
  disposition: string;
  consistent: boolean;
  revision: number;
  issues: ConsistencyIssue[];
};
type ConsistencyReport = {
  totalTasks: number;
  scanned: number;
  consistent: number;
  inconsistent: number;
  hasMore: boolean;
  complete: boolean;
  digest: string;
  tasks: ConsistencyTask[];
  limitations: string[];
};
async function getReport<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store", credentials: "same-origin",
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const error = data as { error?: string };
    throw new Error(error.error ?? "Report failed.");
  }
  return data as T;
}
export function IntegrityOperationalAssurance({
  slug, canManage,
}: {
  slug: string;
  canManage: boolean;
}) {
  const [captureId, setCaptureId] = useState("");
  const [offset, setOffset] = useState(0);
  const [responseMinutes, setResponseMinutes] = useState(1440);
  const [resolutionMinutes, setResolutionMinutes] = useState(10080);
  const [notificationReadMinutes, setNotificationReadMinutes] = useState(1440);
  const [escalationAckMinutes, setEscalationAckMinutes] = useState(240);
  const [includeClosed, setIncludeClosed] = useState(true);
  const [sla, setSla] = useState<SlaReport | null>(null);
  const [consistency, setConsistency] = useState<ConsistencyReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const request = useCallback(async <T,>(
    route: string, params: URLSearchParams, set: (value: T) => void,
  ) => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const result = await getReport<T>(base + "/" + route +
        "?" + params.toString());
      set(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Report failed.");
    } finally {
      setPending(false);
    }
  }, [base, pending]);
  const common = () => {
    const params = new URLSearchParams();
    if (captureId.trim()) params.set("captureId", captureId.trim());
    return params;
  };
  const loadSla = () => {
    const params = common();
    params.set("responseMinutes", String(responseMinutes));
    params.set("resolutionMinutes", String(resolutionMinutes));
    params.set("notificationReadMinutes", String(notificationReadMinutes));
    params.set("escalationAckMinutes", String(escalationAckMinutes));
    params.set("includeClosed", String(includeClosed));
    void request<SlaReport>("sla-report", params, setSla);
  };
  const loadConsistency = () => {
    const params = common();
    params.set("offset", String(offset));
    params.set("limit", "50");
    params.set("includeResolved", String(includeClosed));
    void request<ConsistencyReport>(
      "workflow-consistency", params, setConsistency,
    );
  };
  if (!canManage) return null;
  const thresholds = [
    ["First response", responseMinutes, setResponseMinutes],
    ["Resolution", resolutionMinutes, setResolutionMinutes],
    ["Notification read", notificationReadMinutes, setNotificationReadMinutes],
    ["Escalation acknowledgement", escalationAckMinutes, setEscalationAckMinutes],
  ] as const;
  return (
    <section aria-label="Operational SLA and consistency"
      style={{ marginTop: 32, borderTop: "1px solid #8885", paddingTop: 20 }}>
      <h2>Operational SLA and consistency</h2>
      <p>
        These read-only reports investigate stored workflow activity.
        Thresholds are configurable and do not establish contractual
        service levels or independent security assurance.
      </p>
      <div style={{ display: "grid", gap: 12, maxWidth: 650 }}>
        <label>
          Optional capture ID
          <input style={{ width: "100%" }} value={captureId}
            onChange={event => {
              setCaptureId(event.target.value);
              setOffset(0);
              setSla(null);
              setConsistency(null);
            }} />
        </label>
        <fieldset>
          <legend>Reporting thresholds (minutes)</legend>
          {thresholds.map(([label, value, setter]) => (
            <label key={label} style={{ display: "block" }}>
              {label}
              <input type="number" min={1} max={525600}
                value={value}
                onChange={event => setter(Number(event.target.value))} />
            </label>
          ))}
        </fieldset>
        <label>
          <input type="checkbox" checked={includeClosed}
            onChange={event => setIncludeClosed(event.target.checked)} />
          Include closed reviews
        </label>
        <div style={{ display: "flex", gap: 12 }}>
          <button type="button" disabled={pending} onClick={loadSla}>
            Investigate SLA breaches
          </button>
          <button type="button" disabled={pending}
            onClick={loadConsistency}>
            Audit workflow consistency
          </button>
        </div>
      </div>
      {pending && <p role="status">Loading operational investigation…</p>}
      {error && <p role="alert">{error}</p>}
      {sla && (
        <section aria-label="SLA investigation results">
          <h3>SLA investigation</h3>
          <p>
            {sla.scannedTasks} of {sla.totalTasks} reviews examined;
            {" "}{sla.active} active and {sla.historical} historical breaches.
            {" "}{sla.affectedTasks} affected reviews.
          </p>
          {sla.truncated &&
            <p role="alert">Partial report: record limit reached.</p>}
          <p>SHA-256: <code>{sla.digest}</code></p>
          <table>
            <thead><tr>
              <th scope="col">Task</th>
              <th scope="col">Category</th>
              <th scope="col">Exceeded (min)</th>
              <th scope="col">State</th>
            </tr></thead>
            <tbody>
              {sla.breaches.map(breach => (
                <tr key={breach.entity + breach.id + breach.category}>
                  <td>{breach.taskId}</td>
                  <td>{breach.category}</td>
                  <td>{breach.exceededMinutes}</td>
                  <td>{breach.active ? "Active" : "Historical"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      {consistency && (
        <section aria-label="Workflow consistency results">
          <h3>Workflow consistency</h3>
          <p>
            {consistency.scanned} of {consistency.totalTasks} reviews;
            {" "}{consistency.consistent} consistent,
            {" "}{consistency.inconsistent} with findings.
          </p>
          {!consistency.complete &&
            <p role="alert">Related history was truncated.</p>}
          <p>SHA-256: <code>{consistency.digest}</code></p>
          <ul>
            {consistency.tasks.map(task => (
              <li key={task.taskId}>
                {task.taskId} · {task.disposition} · revision {task.revision}
                {task.consistent ? " · No findings" :
                  " · " + task.issues.map(issue => issue.code).join(", ")}
              </li>
            ))}
          </ul>
          <div style={{ display: "flex", gap: 12 }}>
            <button type="button" disabled={pending || offset === 0}
              onClick={() => {
                setOffset(Math.max(0, offset - 50));
                setConsistency(null);
              }}>Previous page</button>
            <button type="button"
              disabled={pending || !consistency.hasMore}
              onClick={() => {
                setOffset(offset + 50);
                setConsistency(null);
              }}>Next page</button>
          </div>
        </section>
      )}
    </section>
  );
}
