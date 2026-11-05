"use client";

import { useCallback, useMemo, useState } from "react";

type Proposal = {
  taskId: string;
  severity: string;
  status: string;
  proposedLevel: number | null;
  dueAt: string | null;
  overdueHours: number;
  reason: string;
};
type Simulation = {
  totalTasks: number;
  hasMore: boolean;
  complete: boolean;
  eligible: number;
  statusCounts: Record<string, number>;
  proposals: Proposal[];
  digest: string;
  warnings: string[];
};
type AgingBucket = {
  key: string;
  count: number;
  unread: number;
  read: number;
  dismissed: number;
  olderThan24Hours: number;
  olderThan72Hours: number;
  maxAgeHours: number;
  medianAgeHours: number;
  anomalies: number;
};
type Aging = {
  total: number;
  hasMore: boolean;
  buckets: AgingBucket[];
  digest: string;
  warnings: string[];
};
async function readReport<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store", credentials: "same-origin",
  });
  const payload: unknown = await response.json();
  if (!response.ok) {
    const error = payload as { error?: string };
    throw new Error(error.error ?? "Operational request failed.");
  }
  return payload as T;
}
export function IntegrityPolicyDiagnostics({
  slug, canManage,
}: {
  slug: string;
  canManage: boolean;
}) {
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const [captureId, setCaptureId] = useState("");
  const [horizonHours, setHorizonHours] = useState(0);
  const [warningHours, setWarningHours] = useState(48);
  const [errorHours, setErrorHours] = useState(12);
  const [infoHours, setInfoHours] = useState(120);
  const [repeatHours, setRepeatHours] = useState(24);
  const [maxLevel, setMaxLevel] = useState(3);
  const [minAgeHours, setMinAgeHours] = useState(24);
  const [maxAgeDays, setMaxAgeDays] = useState(365);
  const [groupBy, setGroupBy] =
    useState<"AGE_BUCKET" | "KIND" | "RECIPIENT" | "TASK">("AGE_BUCKET");
  const [includeClosed, setIncludeClosed] = useState(false);
  const [includeRead, setIncludeRead] = useState(false);
  const [includeDismissed, setIncludeDismissed] = useState(false);
  const [simulationOffset, setSimulationOffset] = useState(0);
  const [agingOffset, setAgingOffset] = useState(0);
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [aging, setAging] = useState<Aging | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const policy = useMemo(() => ({
    warningHours, errorHours, infoHours, repeatHours, maxLevel,
  }), [warningHours, errorHours, infoHours, repeatHours, maxLevel]);
  const request = useCallback(async <T,>(
    route: string, params: URLSearchParams,
    onSuccess: (value: T) => void,
  ) => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const report = await readReport<T>(
        base + "/" + route + "?" + params.toString(),
      );
      onSuccess(report);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed.");
    } finally {
      setPending(false);
    }
  }, [base, pending]);
  const common = () => {
    const params = new URLSearchParams();
    if (captureId.trim()) params.set("captureId", captureId.trim());
    return params;
  };
  const loadSimulation = () => {
    const params = common();
    params.set("offset", String(simulationOffset));
    params.set("limit", "50");
    params.set("horizonHours", String(horizonHours));
    params.set("includeClosed", String(includeClosed));
    for (const [key, value] of Object.entries(policy))
      params.set(key, String(value));
    void request<Simulation>(
      "escalation-simulation", params, setSimulation,
    );
  };
  const loadAging = () => {
    const params = common();
    params.set("offset", String(agingOffset));
    params.set("limit", "100");
    params.set("minAgeHours", String(minAgeHours));
    params.set("maxAgeDays", String(maxAgeDays));
    params.set("groupBy", groupBy);
    params.set("includeRead", String(includeRead));
    params.set("includeDismissed", String(includeDismissed));
    void request<Aging>("notification-aging", params, setAging);
  };
  if (!canManage) return null;
  const policyInputs = [
    ["Warning threshold (hours)", warningHours, setWarningHours],
    ["Error threshold (hours)", errorHours, setErrorHours],
    ["Info threshold (hours)", infoHours, setInfoHours],
    ["Repeat threshold (hours)", repeatHours, setRepeatHours],
    ["Maximum level", maxLevel, setMaxLevel],
  ] as const;
  return (
    <section aria-label="Escalation simulation and inbox aging"
      style={{ marginTop: 32, borderTop: "1px solid #8885", paddingTop: 20 }}>
      <h2>Escalation policy simulation and inbox aging</h2>
      <p>
        Explore policy consequences and pending in-app notifications.
        Simulation is read-only: it does not schedule escalations,
        notify recipients, close reviews or alter security scores.
      </p>
      <label>
        Optional capture ID
        <input value={captureId} style={{ width: "100%" }}
          onChange={event => {
            setCaptureId(event.target.value);
            setSimulationOffset(0);
            setAgingOffset(0);
            setSimulation(null);
            setAging(null);
          }} />
      </label>
      <fieldset>
        <legend>Escalation policy</legend>
        <div style={{ display: "grid", gap: 8, maxWidth: 600 }}>
          {policyInputs.map(([label, value, setter]) => (
            <label key={label}>
              {label}
              <input type="number" min={1} max={8760}
                value={value}
                onChange={event => setter(Number(event.target.value))} />
            </label>
          ))}
          <label>
            Future horizon (hours)
            <input type="number" min={0} max={720}
              value={horizonHours}
              onChange={event => setHorizonHours(Number(event.target.value))} />
          </label>
          <label>
            <input type="checkbox" checked={includeClosed}
              onChange={event => setIncludeClosed(event.target.checked)} />
            Include closed reviews
          </label>
          <button type="button" disabled={pending}
            onClick={loadSimulation}>
            Simulate policy without changes
          </button>
        </div>
      </fieldset>
      {simulation && (
        <section aria-label="Escalation simulation results">
          <h3>Simulated escalations</h3>
          <p>
            {simulation.eligible} eligible reviews on this page;
            {" "}{simulation.totalTasks} total reviews match the filter.
          </p>
          {!simulation.complete &&
            <p role="alert">Escalation history reached its query limit.</p>}
          <p>SHA-256: <code>{simulation.digest}</code></p>
          <table>
            <thead><tr>
              <th scope="col">Review</th>
              <th scope="col">Severity</th>
              <th scope="col">Simulation</th>
              <th scope="col">Next level</th>
              <th scope="col">Overdue hours</th>
            </tr></thead>
            <tbody>
              {simulation.proposals.map(proposal => (
                <tr key={proposal.taskId}>
                  <td>{proposal.taskId}</td>
                  <td>{proposal.severity}</td>
                  <td title={proposal.reason}>{proposal.status}</td>
                  <td>{proposal.proposedLevel ?? "—"}</td>
                  <td>{proposal.overdueHours}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: "flex", gap: 12 }}>
            <button type="button"
              disabled={pending || simulationOffset === 0}
              onClick={() => {
                setSimulationOffset(Math.max(0, simulationOffset - 50));
                setSimulation(null);
              }}>Previous simulation page</button>
            <button type="button"
              disabled={pending || !simulation.hasMore}
              onClick={() => {
                setSimulationOffset(simulationOffset + 50);
                setSimulation(null);
              }}>Next simulation page</button>
          </div>
        </section>
      )}
      <fieldset>
        <legend>Inbox aging</legend>
        <div style={{ display: "grid", gap: 8, maxWidth: 600 }}>
          <label>
            Minimum age (hours)
            <input type="number" min={0} max={8760}
              value={minAgeHours}
              onChange={event => setMinAgeHours(Number(event.target.value))} />
          </label>
          <label>
            Maximum age (days)
            <input type="number" min={1} max={366}
              value={maxAgeDays}
              onChange={event => setMaxAgeDays(Number(event.target.value))} />
          </label>
          <label>
            Group results
            <select value={groupBy}
              onChange={event => setGroupBy(event.target.value as
                "AGE_BUCKET" | "KIND" | "RECIPIENT" | "TASK")}>
              <option value="AGE_BUCKET">Age bucket</option>
              <option value="KIND">Notification type</option>
              <option value="RECIPIENT">Hashed recipient</option>
              <option value="TASK">Review task</option>
            </select>
          </label>
          <label>
            <input type="checkbox" checked={includeRead}
              onChange={event => setIncludeRead(event.target.checked)} />
            Include read
          </label>
          <label>
            <input type="checkbox" checked={includeDismissed}
              onChange={event => setIncludeDismissed(event.target.checked)} />
            Include dismissed
          </label>
          <button type="button" disabled={pending} onClick={loadAging}>
            Investigate inbox aging
          </button>
        </div>
      </fieldset>
      {aging && (
        <section aria-label="Inbox aging results">
          <h3>Inbox aging</h3>
          <p>{aging.total} notifications match the filter.</p>
          <p>SHA-256: <code>{aging.digest}</code></p>
          <table>
            <thead><tr>
              <th scope="col">Group</th>
              <th scope="col">Count</th>
              <th scope="col">Unread</th>
              <th scope="col">Older than 72h</th>
              <th scope="col">Maximum age (h)</th>
              <th scope="col">Anomalies</th>
            </tr></thead>
            <tbody>
              {aging.buckets.map(bucket => (
                <tr key={bucket.key}>
                  <td>{bucket.key}</td>
                  <td>{bucket.count}</td>
                  <td>{bucket.unread}</td>
                  <td>{bucket.olderThan72Hours}</td>
                  <td>{bucket.maxAgeHours}</td>
                  <td>{bucket.anomalies}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: "flex", gap: 12 }}>
            <button type="button"
              disabled={pending || agingOffset === 0}
              onClick={() => {
                setAgingOffset(Math.max(0, agingOffset - 100));
                setAging(null);
              }}>Previous aging page</button>
            <button type="button" disabled={pending || !aging.hasMore}
              onClick={() => {
                setAgingOffset(agingOffset + 100);
                setAging(null);
              }}>Next aging page</button>
          </div>
        </section>
      )}
      {pending && <p role="status">Loading diagnostic report…</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
