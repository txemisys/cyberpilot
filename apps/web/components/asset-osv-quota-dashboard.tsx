"use client";

import { useEffect, useState } from "react";

type Reservation = {
  reservationId: string;
  requestKey: string;
  inventoryImportId: string;
  state: string;
  reservedRequests: number;
  actualRequests: number;
  startedAt: string;
  finishedAt: string | null;
};
type QuotaSnapshot = {
  schema: "cyberpilot.assets.osv.quota.snapshot.v1";
  organizationId: string;
  utcDay: string;
  inspectionLimit: number;
  requestLimit: number;
  inspectionsReserved: number;
  requestsReserved: number;
  inspectionsRemaining: number;
  requestsRemaining: number;
  reservations: Reservation[];
  reservationsTotal: number;
  hasMore: boolean;
  warnings: string[];
};
function displayDate(value: string | null) {
  if (!value) return "Not settled";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid timestamp";
}
async function loadQuota(slug: string, maxRows: number): Promise<QuotaSnapshot> {
  const address = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/osv-quota?limit=" +
    encodeURIComponent(String(maxRows));
  const response = await fetch(address, {
    method: "GET", cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const raw: unknown = await response.json();
  if (!response.ok) {
    const error = raw as { error?: string };
    throw new Error(error.error ?? "Quota request failed.");
  }
  return raw as QuotaSnapshot;
}
function ReservationItem({ value }: { value: Reservation }) {
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <h4>Quota reservation · {value.state}</h4>
    <p>Reserved HTTP requests: {value.reservedRequests}.
      {" "}Reported HTTP pages: {value.actualRequests}.
      {" "}Unused reservations are not refunded.</p>
    <p>Created: {displayDate(value.startedAt)}.
      {" "}Settled: {displayDate(value.finishedAt)}.</p>
    <p>Inventory: <code>{value.inventoryImportId}</code></p>
    <details>
      <summary>Idempotency and reservation IDs</summary>
      <p>Request key: <code style={{ overflowWrap: "anywhere" }}>
        {value.requestKey}</code></p>
      <p>Reservation: <code style={{ overflowWrap: "anywhere" }}>
        {value.reservationId}</code></p>
    </details>
    {value.state === "RESERVED" && <p>
      An unsettled reservation remains charged. A worker interruption
      must be investigated before any manual corrective action.
    </p>}
    {value.state === "FAILED" && <p>
      A failed provider operation may have transmitted requests.
      The reserved capacity remains charged conservatively.
    </p>}
  </article>;
}
function QuotaNumber({ value, label }: {
  value: number; label: string;
}) {
  return <div style={{
    padding: 12, borderRadius: 8, border: "1px solid #8885",
  }}>
    <strong>{value}</strong>
    <div>{label}</div>
  </div>;
}
export function AssetOsvQuotaDashboard({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const [quota, setQuota] = useState<QuotaSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [pageSize, setPageSize] = useState(25);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!canManage) return;
    let canceled = false;
    void loadQuota(slug, pageSize).then(result => {
      if (!canceled) {
        setQuota(result);
        setError(null);
      }
    }).catch(cause => {
      if (!canceled) {
        setError(cause instanceof Error ? cause.message :
          "OSV quota snapshot unavailable.");
      }
    });
    return () => { canceled = true; };
  }, [slug, pageSize, canManage, revision]);
  async function refresh() {
    if (loading || !canManage) return;
    setLoading(true); setError(null);
    try {
      setQuota(await loadQuota(slug, pageSize));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Unable to refresh OSV quota.");
    } finally {
      setLoading(false);
    }
  }
  if (!canManage) return null;
  return <section aria-label="Atomic OSV provider quota"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      marginBlock: 20, padding: 16,
    }}>
    <h2>OSV provider request quotas — atomic enforcement</h2>
    <p>The application charges a reserved worst-case number of
      HTTP pages before an authorized OSV.dev query. This daily
      per-organization capacity is enforced by PostgreSQL
      atomic updates, including requests from concurrent workers.</p>
    <p>Reservations persist after errors, including cases where
      the remote provider might have received the requests.
      Limits reset for a new UTC day, not according to the
      local browser time.</p>
    {error && <p role="alert">{error}</p>}
    <fieldset disabled={loading}>
      <legend>Quota journal controls</legend>
      <button type="button" onClick={() => void refresh()}>
        Refresh quota counters
      </button>
      <label>Maximum visible reservations
        <select value={pageSize} onChange={event => {
          setPageSize(Number(event.target.value));
          setQuota(null);
          setRevision(value => value + 1);
        }}>
          {[10, 25, 50, 100].map(count =>
            <option key={count} value={count}>{count}</option>)}
        </select>
      </label>
    </fieldset>
    {loading && <p role="status">Reading OSV quota ledger…</p>}
    {quota && <section>
      <h3>UTC quota day · {quota.utcDay}</h3>
      <p>Organization: <code>{quota.organizationId}</code></p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <QuotaNumber label="Reserved inspections"
          value={quota.inspectionsReserved}/>
        <QuotaNumber label="Inspection limit"
          value={quota.inspectionLimit}/>
        <QuotaNumber label="Inspections remaining"
          value={quota.inspectionsRemaining}/>
        <QuotaNumber label="Reserved HTTP requests"
          value={quota.requestsReserved}/>
        <QuotaNumber label="Request limit"
          value={quota.requestLimit}/>
        <QuotaNumber label="Requests remaining"
          value={quota.requestsRemaining}/>
      </div>
      {quota.inspectionsRemaining === 0 && <p role="alert">
        Today's inspection quota has been exhausted.
      </p>}
      {quota.requestsRemaining === 0 && <p role="alert">
        Today's reserved OSV HTTP request capacity is exhausted.
      </p>}
      <h3>Quota reservation journal</h3>
      <p>{quota.reservationsTotal} total reservations;
        {" "}{quota.reservations.length} displayed.
        {" "}{quota.hasMore ?
          "Additional historical reservations are not shown." :
          "All today's reservations are shown."}</p>
      {quota.reservations.map(item =>
        <ReservationItem key={item.reservationId} value={item}/>)}
      {quota.reservations.length === 0 && <p>
        No provider reservations have been recorded today.
      </p>}
      <details>
        <summary>Quota enforcement guarantees and limits</summary>
        <ul>{quota.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
        <p>The quota applies only to OSV queries passing through
          this application service. It cannot count external
          clients, unrelated deployments or provider-side quotas.</p>
        <p>Inspecting the quota dashboard makes no provider
          requests and changes no inventory or CyberScore data.</p>
      </details>
    </section>}
  </section>;
}
