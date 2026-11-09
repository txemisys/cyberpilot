"use client";

import { useEffect, useState } from "react";

type StalledReservation = {
  id: string;
  requestKey: string;
  requestDigest: string;
  inventoryImportId: string;
  startedAt: string;
  ageMinutes: number;
  reservedRequests: number;
  state: string;
  eligible: boolean;
  reason: string;
};
type Preview = {
  schema: string;
  organizationId: string;
  generatedAt: string;
  minimumAgeMinutes: number;
  totalStalled: number;
  inspected: number;
  eligible: number;
  incomplete: boolean;
  reservations: StalledReservation[];
  digest: string;
  warnings: string[];
};
type Recovery = {
  schema: string;
  organizationId: string;
  reservationId: string;
  state: string;
  changed: boolean;
  reservedRequests: number;
  effectiveRefund: number;
  auditedAt: string;
  digest: string;
  warnings: string[];
};
async function request<T>(target: string,
  method: "GET" | "POST", data?: unknown): Promise<T> {
  const response = await fetch(target, {
    method, cache: "no-store",
    credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(data) } : {}),
  });
  const raw: unknown = await response.json();
  if (!response.ok) {
    const error = raw as { error?: string };
    throw new Error(error.error ?? "Recovery HTTP " + response.status);
  }
  return raw as T;
}
function message(error: unknown) {
  return error instanceof Error ? error.message :
    "OSV reservation review unavailable.";
}
export function AssetOsvQuotaRecovery({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const api = "/api/organizations/" + encodeURIComponent(slug) +
    "/assets/osv-quota-recovery";
  const [preview, setPreview] = useState<Preview | null>(null);
  const [selected, setSelected] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [reason, setReason] = useState("");
  const [minimumAge, setMinimumAge] = useState(30);
  const [accepted, setAccepted] = useState(false);
  const [result, setResult] = useState<Recovery | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    void request<Preview>(
      api + "?minimumAgeMinutes=" + minimumAge +
      "&maximumListed=50", "GET",
    ).then(data => {
      if (!cancelled) {
        setPreview(data);
        setError(null);
      }
    }).catch(cause => {
      if (!cancelled) setError(message(cause));
    });
    return () => { cancelled = true; };
  }, [api, minimumAge, canManage, revision]);
  const current = preview?.reservations.find(row =>
    row.id === selected) ?? null;
  async function classify() {
    if (busy || !current || !current.eligible ||
        confirmation !== current.id || reason.trim().length < 20 ||
        !accepted) return;
    setBusy(true); setError(null); setResult(null);
    try {
      const data = await request<Recovery>(api, "POST", {
        reservationId: current.id,
        confirmReservationId: confirmation,
        expectedRequestDigest: current.requestDigest,
        minimumAgeMinutes: minimumAge,
        reason,
      });
      setResult(data);
      setSelected("");
      setConfirmation("");
      setReason("");
      setAccepted(false);
      setRevision(n => n + 1);
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  if (!canManage) return null;
  return <section aria-label="Unsettled OSV reservation recovery"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>Review interrupted OSV provider reservations</h2>
    <p>This administrative operation marks a sufficiently old
      unsettled reservation as UNKNOWN. It is an audit classification,
      not cancellation of a remote request. It does not return
      any reserved capacity or retry the provider call.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Recording the requested audit action…</p>}
    <fieldset disabled={busy}>
      <legend>Detect potentially interrupted reservations</legend>
      <label>Investigation delay after reservation
        <select value={minimumAge} onChange={event => {
          setMinimumAge(Number(event.target.value));
          setSelected(""); setConfirmation(""); setAccepted(false);
          setPreview(null);
        }}>
          {[30, 60, 120, 360, 1440].map(value =>
            <option value={value} key={value}>{value} minutes</option>)}
        </select>
      </label>
      <button type="button" onClick={() => setRevision(n => n + 1)}>
        Refresh unsettled reservation list
      </button>
      {preview && <>
        <p>{preview.totalStalled} unsettled reservations in the
          organization; {preview.inspected} inspected in this page,
          {" "}{preview.eligible} eligible for investigation.</p>
        {preview.incomplete && <p>
          Additional reservations exist beyond the bounded page.
        </p>}
        <label>Reservation for explicit review
          <select value={selected} onChange={event => {
            setSelected(event.target.value);
            setConfirmation(""); setAccepted(false); setResult(null);
          }}>
            <option value="">Select unsettled reservation</option>
            {preview.reservations.map(row =>
              <option key={row.id} value={row.id}>
                {row.id} · {row.ageMinutes} minutes ·
                {" "}{row.reservedRequests} reserved HTTP pages
                {row.eligible ? "" : " · NOT ELIGIBLE"}
              </option>)}
          </select>
        </label>
      </>}
    </fieldset>
    {current && <section>
      <h3>Inspect before classification</h3>
      <p>Reservation: <code>{current.id}</code></p>
      <p>Inventory: <code>{current.inventoryImportId}</code></p>
      <p>Age: {current.ageMinutes} minutes.
        {" "}Classification: {current.state}.</p>
      <p>Assessment: {current.reason}</p>
      <p>Reserved HTTP pages: {current.reservedRequests}.
        These remain charged for the UTC day.</p>
      <details>
        <summary>Request identity and exact digest</summary>
        <p>Request key: <code style={{ overflowWrap: "anywhere" }}>
          {current.requestKey}</code></p>
        <p>Digest: <code style={{ overflowWrap: "anywhere" }}>
          {current.requestDigest}</code></p>
      </details>
      <fieldset disabled={busy || !current.eligible}>
        <legend>Explicit UNKNOWN status confirmation</legend>
        <label>Re-enter exact reservation ID
          <input value={confirmation}
            onChange={event => setConfirmation(event.target.value)}
            maxLength={150}
            placeholder="Paste exact reservation ID" />
        </label>
        <label>Human investigation reason (at least 20 characters)
          <textarea value={reason} rows={3} maxLength={500}
            onChange={event => setReason(event.target.value)}
            placeholder="Describe why the provider outcome is unknown" />
        </label>
        <label>
          <input type="checkbox" checked={accepted}
            onChange={event => setAccepted(event.target.checked)}/>
          I confirm the remote OSV request may have reached the
          provider and the quota must remain charged.
        </label>
        <button type="button" disabled={!current.eligible ||
          confirmation !== current.id || reason.trim().length < 20 ||
          !accepted || busy} onClick={() => void classify()}>
          Mark uncertain outcome UNKNOWN and audit
        </button>
      </fieldset>
    </section>}
    {result && <div role="status">
      <p>Reservation {result.reservationId}:
        {" "}{result.state}. Changed: {result.changed ? "Yes" : "No"}.
        Reserved pages: {result.reservedRequests}.
        Quota refunded: {result.effectiveRefund}.</p>
      <p>Audit digest: <code style={{ overflowWrap: "anywhere" }}>
        {result.digest}</code></p>
    </div>}
    {preview && <details>
      <summary>Investigation and audit limitations</summary>
      <ul>{preview.warnings.map(value =>
        <li key={value}>{value}</li>)}</ul>
    </details>}
  </section>;
}
