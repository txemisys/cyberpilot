"use client";

import { useEffect, useMemo, useState } from "react";

type Check = {
  id: string; level: "PASS" | "WARN" | "BLOCK";
  category: string; summary: string;
  evidence: string | number | boolean | null; required: boolean;
};
type Schedule = {
  scheduleId: string; scheduleName: string; revision: number;
  enabled: boolean; consented: boolean; inventoryImportId: string;
  dueAt: string; nextDueAt: string;
  canConsiderManualDispatch: boolean; authorizingKeyIds: string[];
  checks: Check[]; blocked: number; warnings: number; passed: number;
};
type Preflight = {
  schema: string; organizationId: string; evaluatedAt: string;
  selectedScheduleId: string | null;
  totalSchedules: number; scannedSchedules: number;
  truncated: boolean; blockedSchedules: number;
  manuallyReviewableSchedules: number;
  remainingRequests: number; remainingInspections: number;
  quotaReservationsOpen: number; claimsOpen: number;
  criticalIncidentsOpen: number; keysEnabled: boolean;
  previewOnly: true; outboundRequests: 0; noncesConsumed: 0;
  cronInstalled: false; schedules: Schedule[];
  digest: string; warnings: string[];
};
type Challenge = {
  schema: string; organizationId: string;
  scheduleId: string; scheduleRevision: number;
  keyId: string; protocolMatched: boolean;
  crossTenantRejected: boolean;
  signatureMutationRejected: boolean;
  expiredRejected: boolean; replayStoragePresent: boolean;
  authenticationAccepted: boolean; signedRequestSent: false;
  noncePersisted: false; providerContacted: false;
  scheduleChanged: false; preflightDigest: string;
  preflightBlocked: boolean; warnings: string[];
};
function at(value: string) {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ?
    parsed.toLocaleString() : "Invalid date";
}
function message(value: unknown) {
  return value instanceof Error ? value.message :
    "Signed dispatch preflight could not be completed.";
}
async function fetchJson<T>(
  url: string, method: "GET" | "POST" | "PUT",
  value?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ? {
      Accept: "application/json",
    } : {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    ...(method === "GET" ? {} : { body: JSON.stringify(value) }),
  });
  const result: unknown = await response.json();
  if (!response.ok) {
    const error = result as { error?: string };
    throw new Error(error.error ??
      "OSV preflight HTTP " + response.status);
  }
  return result as T;
}
function Count({ label, value }: {
  label: string; value: number;
}) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}><strong>{value}</strong><p>{label}</p></div>;
}
function Checklist({ data }: { data: Schedule }) {
  const byCategory = [...new Set(data.checks.map(row => row.category))];
  return <section>
    {byCategory.map(category => <details key={category}
      open={data.checks.some(row =>
        row.category === category && row.level === "BLOCK")}>
      <summary>{category} · {data.checks.filter(row =>
        row.category === category && row.level === "BLOCK").length
      } blockers</summary>
      <ul>{data.checks.filter(row =>
        row.category === category).map(check =>
          <li key={check.id}>
            <strong>{check.level} · {check.id}</strong>
            <p>{check.summary}</p>
            <p>Evidence: {String(check.evidence)}.
              Required: {check.required ? "Yes" : "No"}.</p>
          </li>)}</ul>
    </details>)}
  </section>;
}
function ChallengeSummary({ result }: { result: Challenge }) {
  const signals = [
    ["Signature accepted", result.authenticationAccepted],
    ["Protocol matched", result.protocolMatched],
    ["Cross-tenant forgery rejected", result.crossTenantRejected],
    ["Altered schedule signature rejected", result.signatureMutationRejected],
    ["Expired request rejected", result.expiredRejected],
    ["Replay ledger configured", result.replayStoragePresent],
  ] as const;
  return <section>
    <h4>In-process HMAC challenge</h4>
    <p>Key identifier: {result.keyId}.
      Schedule: {result.scheduleId}.
      Revision: {result.scheduleRevision}.</p>
    <ul>{signals.map(([label, passed]) =>
      <li key={label}>
        <strong>{passed ? "PASS" : "FAIL"}</strong> · {label}
      </li>)}</ul>
    <p>Schedule preflight:
      {" "}<strong>{result.preflightBlocked ?
        "BLOCKED" : "NO KNOWN BLOCKS"}</strong>.
      Signed request transmitted: No.
      Nonce persisted: No.
      Provider contacted: No.</p>
    <p>For production admission, all crypto checks must pass
      and every mandatory schedule, quota and incident gate
      must be satisfied independently at execution time.</p>
    <details>
      <summary>Challenge limitations and preflight fingerprint</summary>
      <p><code style={{ overflowWrap: "anywhere" }}>
        {result.preflightDigest}</code></p>
      <ul>{result.warnings.map((warning, index) =>
        <li key={index}>{warning}</li>)}</ul>
    </details>
  </section>;
}
export function AssetOsvDispatchPreflightWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/osv-dispatch-preflight";
  const [report, setReport] = useState<Preflight | null>(null);
  const [selected, setSelected] = useState("");
  const [keyId, setKeyId] = useState("");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [policy, setPolicy] = useState({
    maxSchedules: 25, maximumObservations: 1000,
    requireNoOpenCriticalIncidents: true,
    requireNoUnsettledClaims: true,
    requireNoUnsettledQuotas: true,
    requireFreshInventory: true,
    inspectSignatureAuthentication: true,
    minimumRemainingRequests: 1,
    minimumRemainingInspections: 1,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const current = useMemo(() =>
    report?.schedules.find(row => row.scheduleId === selected) ?? null,
  [report, selected]);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    void fetchJson<Preflight>(endpoint, "GET").then(data => {
      if (!cancelled) {
        setReport(data); setError(null);
      }
    }).catch(cause => {
      if (!cancelled) setError(message(cause));
    });
    return () => { cancelled = true; };
  }, [canManage, endpoint, revision]);
  async function preview() {
    if (busy) return;
    setBusy(true); setError(null); setChallenge(null);
    try {
      const result = await fetchJson<Preflight>(endpoint, "POST", {
        scheduleId: showAll ? null : selected || null,
        policy,
      });
      setReport(result);
      if (!result.schedules.some(row => row.scheduleId === selected))
        setSelected("");
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  async function runChallenge() {
    if (!current || busy) return;
    setBusy(true); setError(null); setChallenge(null);
    try {
      setChallenge(await fetchJson<Challenge>(
        endpoint, "PUT", {
          scheduleId: current.scheduleId,
          expectedRevision: current.revision,
          ...(keyId ? { keyId } : {}),
        }));
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  function alterPolicy(name: keyof typeof policy,
    value: number | boolean) {
    setPolicy(old => ({ ...old, [name]: value }));
    setChallenge(null);
  }
  if (!canManage) return null;
  return <section aria-label="OSV signed dispatch preflight"
    style={{
      padding: 16, border: "1px solid #8885",
      borderRadius: 12, marginBlock: 20,
    }}>
    <h2>Signed OSV dispatcher acceptance preflight</h2>
    <p>This is a read-only operational assessment. It checks
      authorization, consent, schedule state, inventory,
      quotas, unresolved claims, critical incidents and
      scoped HMAC keys. No schedule is claimed, no provider
      request is made, and no nonce is consumed.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Evaluating local operational gates…</p>}
    <fieldset disabled={busy}>
      <legend>Choose acceptance scope and requirements</legend>
      <label>
        <input type="checkbox" checked={showAll}
          onChange={event => {
            setShowAll(event.target.checked); setChallenge(null);
          }}/>
        Assess all schedules (bounded to 50)
      </label>
      <label>Schedule
        <select value={selected} disabled={showAll}
          onChange={event => {
            setSelected(event.target.value); setChallenge(null);
          }}>
          <option value="">Choose schedule</option>
          {report?.schedules.map(row =>
            <option key={row.scheduleId} value={row.scheduleId}>
              {row.scheduleName} · {row.scheduleId}
            </option>)}
        </select>
      </label>
      <div style={{
        display: "grid", gap: 10,
        gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))",
      }}>
        <label>Maximum schedules
          <select value={policy.maxSchedules}
            onChange={event =>
              alterPolicy("maxSchedules", Number(event.target.value))}>
            {[5, 10, 25, 50].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Minimum HTTP request budget
          <select value={policy.minimumRemainingRequests}
            onChange={event =>
              alterPolicy("minimumRemainingRequests",
                Number(event.target.value))}>
            {[0, 1, 2, 5, 10, 20].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Minimum inspection budget
          <select value={policy.minimumRemainingInspections}
            onChange={event =>
              alterPolicy("minimumRemainingInspections",
                Number(event.target.value))}>
            {[0, 1, 2, 5, 10].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      {([
        ["requireNoOpenCriticalIncidents", "Block on open critical incidents"],
        ["requireNoUnsettledClaims", "Block on unfinished schedule claims"],
        ["requireNoUnsettledQuotas", "Block on unsettled provider quotas"],
        ["requireFreshInventory", "Require committed original inventory"],
        ["inspectSignatureAuthentication", "Inspect signer configuration"],
      ] as const).map(([name, label]) =>
        <label key={name}>
          <input type="checkbox" checked={policy[name]}
            onChange={event =>
              alterPolicy(name, event.target.checked)}/>
          {label}
        </label>)}
      <button type="button" onClick={() => void preview()}>
        Evaluate signed dispatch preflight
      </button>
      <button type="button" onClick={() => setRevision(x => x + 1)}>
        Refresh default preflight
      </button>
    </fieldset>
    {report && <section>
      <h3>Preflight snapshot</h3>
      <p>Evaluated: {at(report.evaluatedAt)}.
        Dispatcher enabled: {report.keysEnabled ? "YES" : "NO"}.
        Data truncated: {report.truncated ? "YES" : "NO"}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Count label="Schedules examined"
          value={report.scannedSchedules}/>
        <Count label="Blocked schedules"
          value={report.blockedSchedules}/>
        <Count label="Manually reviewable"
          value={report.manuallyReviewableSchedules}/>
        <Count label="Open schedule claims"
          value={report.claimsOpen}/>
        <Count label="Open provider reservations"
          value={report.quotaReservationsOpen}/>
        <Count label="Critical incidents"
          value={report.criticalIncidentsOpen}/>
        <Count label="HTTP pages remaining"
          value={report.remainingRequests}/>
        <Count label="Inspections remaining"
          value={report.remainingInspections}/>
      </div>
      <p>Read-only preview: YES. Provider calls: 0.
        Signing nonces consumed: 0.
        Recurring cron installed: NO.</p>
      <h3>Schedule security checks</h3>
      {report.schedules.map(item =>
        <article key={item.scheduleId} style={{
          border: "1px solid #8885", borderRadius: 8,
          padding: 12, marginBlock: 8,
        }}>
          <strong>{item.scheduleName}</strong>
          <p>Schedule {item.scheduleId} · revision {item.revision}.
            Due: {at(item.dueAt)}.
            Next interval: {at(item.nextDueAt)}.</p>
          <p>Status: <strong>{item.canConsiderManualDispatch ?
            "REVIEWABLE" : "BLOCKED"}</strong>.
            Checks: {item.passed} passed, {item.blocked} blocked,
            {" "}{item.warnings} advisory.</p>
          <Checklist data={item}/>
          <button type="button" disabled={busy}
            onClick={() => {
              setSelected(item.scheduleId);
              setKeyId("");
              setChallenge(null);
            }}>
            Select for cryptographic challenge
          </button>
        </article>)}
      <details>
        <summary>Scope limitations and report digest</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>
          {report.digest}</code></p>
        <ul>{report.warnings.map((text, index) =>
          <li key={index}>{text}</li>)}</ul>
      </details>
    </section>}
    {current && <fieldset disabled={busy}>
      <legend>Local HMAC protocol challenge</legend>
      <p>Selected schedule {current.scheduleId}, revision
        {" "}{current.revision}. This creates a fresh synthetic
        nonce in memory and tests a valid signature plus
        cross-tenant, altered-payload and expired signatures.
        No HTTP request or database write is performed.</p>
      <label>Existing tenant key ID (optional)
        <select value={keyId}
          onChange={event => setKeyId(event.target.value)}>
          <option value="">First scoped key</option>
          {current.authorizingKeyIds.map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button type="button" onClick={() => void runChallenge()}>
        Run synthetic signature challenge
      </button>
    </fieldset>}
    {challenge && <ChallengeSummary result={challenge}/>}
  </section>;
}
