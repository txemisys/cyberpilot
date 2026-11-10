"use client";

import { useEffect, useState } from "react";

type Candidate = {
  runId: string;
  scheduleId: string;
  slotAt: string;
  claimedAt: string;
  claimExpiresAt: string;
  expiredMinutes: number;
  eligible: boolean;
  state: string;
  commandDigest: string;
  sourceRequestKey: string;
  associatedInspectionId: string | null;
  associatedQuotaState: string | null;
  associatedQuotaRequests: number | null;
  reason: string;
};
type RecoveryPreview = {
  schema: string;
  checkedAt: string;
  totalClaimed: number;
  displayed: number;
  eligible: number;
  truncated: boolean;
  policy: {
    minimumExpiredMinutes: number;
    maximumListed: number;
    includeRecentlyClaimed: boolean;
  };
  candidates: Candidate[];
  digest: string;
  warnings: string[];
};
type Recovered = {
  schema: string;
  runId: string;
  state: "UNKNOWN";
  changed: boolean;
  auditRecorded: boolean;
  quotaRefunded: false;
  slotReleased: false;
  providerRetried: false;
  recoveredAt: string;
  digest: string;
  warnings: string[];
};
type ReadinessEntry = {
  scheduleId: string;
  name: string;
  due: boolean;
  enabled: boolean;
  consentConsistent: boolean;
  activeInventory: boolean;
  eligibleForManualReview: boolean;
  nextDueAt: string;
  blockingReasons: string[];
};
type Readiness = {
  schema: string;
  checkedAt: string;
  schedulesExamined: number;
  dueSchedules: number;
  blockedSchedules: number;
  stalledRunCount: number;
  unsettledQuotaCount: number;
  unknownRunCount: number;
  failureRunCount: number;
  quotaRequestsRemaining: number;
  quotaInspectionsRemaining: number;
  manualDispatchCandidates: ReadinessEntry[];
  automationReady: false;
  externalWorkerInstalled: false;
  warnings: string[];
  proposedWorkerContract: {
    actorType: "SERVICE";
    permittedActions: string[];
    maximumClaimsPerPoll: number;
    maximumParallelClaimsPerTenant: number;
    mayOverrideQuota: false;
    mayAlterFindings: false;
    mayUpdateCyberScore: false;
    requiresOperationalActivation: true;
    requiresAuditedCredential: true;
    requiresTenantScoping: true;
    requiresSignedDispatch: true;
  };
};
async function json<T>(url: string, method: "GET" | "POST",
  input?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(input) } : {}),
  });
  const raw: unknown = await response.json();
  if (!response.ok) {
    const error = raw as { error?: string };
    throw new Error(error.error ?? "OSV incident API " + response.status);
  }
  return raw as T;
}
function message(value: unknown) {
  return value instanceof Error ? value.message :
    "Unable to inspect OSV schedule incidents.";
}
function timestamp(value: string | null) {
  if (!value) return "Not recorded";
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ?
    parsed.toLocaleString() : "Invalid stored date";
}
function Value({ title, value }: { title: string; value: number }) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}>
    <strong>{value}</strong>
    <p>{title}</p>
  </div>;
}
export function AssetOsvWorkerOperations({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets";
  const recoveryApi = base + "/osv-run-recovery";
  const workerApi = base + "/osv-worker-readiness";
  const [preview, setPreview] = useState<RecoveryPreview | null>(null);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [selected, setSelected] = useState("");
  const [confirmRunId, setConfirmRunId] = useState("");
  const [reason, setReason] = useState("");
  const [consent, setConsent] = useState(false);
  const [minimumAge, setMinimumAge] = useState(30);
  const [includeRecent, setIncludeRecent] = useState(false);
  const [recovered, setRecovered] = useState<Recovered | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const current = preview?.candidates.find(row =>
    row.runId === selected) ?? null;
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    const url = recoveryApi + "?" + new URLSearchParams({
      minimumExpiredMinutes: String(minimumAge),
      maximumListed: "50",
      includeRecentlyClaimed: String(includeRecent),
    });
    void Promise.all([
      json<RecoveryPreview>(url, "GET"),
      json<Readiness>(workerApi, "GET"),
    ]).then(([a, b]) => {
      if (cancelled) return;
      setPreview(a); setReadiness(b); setError(null);
    }).catch(cause => {
      if (!cancelled) setError(message(cause));
    });
    return () => { cancelled = true; };
  }, [canManage, recoveryApi, workerApi,
    minimumAge, includeRecent, revision]);
  function clearConfirmation() {
    setConfirmRunId("");
    setReason("");
    setConsent(false);
    setRecovered(null);
  }
  async function classifyUnknown() {
    if (busy || !current?.eligible ||
        confirmRunId !== current.runId ||
        reason.trim().length < 20 || !consent) return;
    setBusy(true); setError(null);
    try {
      const result = await json<Recovered>(
        recoveryApi, "POST", {
          runId: current.runId,
          confirmRunId,
          expectedCommandDigest: current.commandDigest,
          minimumExpiredMinutes: minimumAge,
          reason, acknowledgeUnknownNetwork: true,
        });
      setRecovered(result);
      setSelected("");
      clearConfirmation();
      setRecovered(result);
      setRevision(n => n + 1);
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  if (!canManage) return null;
  return <section aria-label="OSV scheduler incident and worker readiness"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>OSV schedule incident recovery and worker readiness</h2>
    <p>This is an administrator-only operational console. A claimed
      run can remain unfinished after a process crash, even after the
      provider receives a request. Classifying its outcome UNKNOWN
      never issues a retry, refunds quota or reopens its unique slot.</p>
    <p>No autonomous worker, machine credential or timed dispatch
      is installed by this diagnostic.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">
      Recording an audited UNKNOWN incident classification…
    </p>}
    <fieldset disabled={busy}>
      <legend>Incident investigation controls</legend>
      <label>Minimum minutes after claim expiry
        <select value={minimumAge} onChange={event => {
          setMinimumAge(Number(event.target.value));
          setSelected(""); clearConfirmation(); setPreview(null);
        }}>
          {[15, 30, 60, 120, 360, 1440].map(value =>
            <option key={value} value={value}>
              {value} minutes
            </option>)}
        </select>
      </label>
      <label>
        <input type="checkbox" checked={includeRecent}
          onChange={event => {
            setIncludeRecent(event.target.checked);
            setSelected(""); clearConfirmation();
          }}/>
        Include recently claimed slots for diagnosis
      </label>
      <button type="button" onClick={() =>
        setRevision(n => n + 1)}>
        Refresh incident status and readiness
      </button>
    </fieldset>
    {readiness && <section>
      <h3>Current manual operations readiness</h3>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Value title="Schedules reviewed"
          value={readiness.schedulesExamined}/>
        <Value title="Due schedules" value={readiness.dueSchedules}/>
        <Value title="Blocked schedules" value={readiness.blockedSchedules}/>
        <Value title="Stalled claims" value={readiness.stalledRunCount}/>
        <Value title="Unsettled quota"
          value={readiness.unsettledQuotaCount}/>
        <Value title="Uncertain runs"
          value={readiness.unknownRunCount}/>
        <Value title="HTTP pages remaining"
          value={readiness.quotaRequestsRemaining}/>
        <Value title="Inspections remaining"
          value={readiness.quotaInspectionsRemaining}/>
      </div>
      <p>Autonomous worker installed:
        {" "}<strong>{readiness.externalWorkerInstalled ?
          "Yes" : "No"}</strong>.
        Autonomous dispatch ready:
        {" "}<strong>{readiness.automationReady ?
          "Yes" : "No"}</strong>.</p>
      <h4>Schedule assessments</h4>
      {readiness.manualDispatchCandidates.map(item =>
        <article key={item.scheduleId} style={{
          border: "1px solid #8885", borderRadius: 8,
          padding: 12, marginBlock: 8,
        }}>
          <strong>{item.name}</strong>
          <p>Due: {item.due ? "Yes" : "No"}.
            Reviewable: {item.eligibleForManualReview ? "Yes" : "No"}.
            Next due: {timestamp(item.nextDueAt)}.</p>
          {item.blockingReasons.length > 0 &&
            <ul>{item.blockingReasons.map((reason, index) =>
              <li key={index}>{reason}</li>)}</ul>}
        </article>)}
      <details>
        <summary>Proposed least-privilege service identity</summary>
        <p>These are proposed authorization requirements only;
          no executable worker credential exists.</p>
        <ul>{readiness.proposedWorkerContract.permittedActions.map(value =>
          <li key={value}>{value}</li>)}</ul>
        <p>Maximum claims per poll:
          {" "}{readiness.proposedWorkerContract.maximumClaimsPerPoll}.
          Maximum simultaneous claims per tenant:
          {" "}{readiness.proposedWorkerContract.maximumParallelClaimsPerTenant}.</p>
        <p>It must not override quotas, change findings or CyberScore,
          and must use authenticated, signed and auditable dispatch.</p>
        <ul>{readiness.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
      </details>
    </section>}
    {preview && <section>
      <h3>Unsettled schedule claims</h3>
      <p>{preview.totalClaimed} claimed slots, of which
        {" "}{preview.eligible} are eligible for UNKNOWN
        classification in the displayed page.</p>
      {preview.truncated && <p role="alert">
        Additional claims exist beyond the bounded incident page.
      </p>}
      <label>Investigate a claimed slot
        <select value={selected} onChange={event => {
          setSelected(event.target.value); clearConfirmation();
        }}>
          <option value="">Select claim</option>
          {preview.candidates.map(item =>
            <option value={item.runId} key={item.runId}>
              {item.runId} · {item.expiredMinutes} min past expiry ·
              {" "}{item.eligible ? "ELIGIBLE" : "NOT ELIGIBLE"}
            </option>)}
        </select>
      </label>
      {current && <article>
        <h4>Selected schedule incident</h4>
        <p>Run: <code>{current.runId}</code>.
          Schedule: <code>{current.scheduleId}</code>.</p>
        <p>Slot: {timestamp(current.slotAt)}.
          Claimed: {timestamp(current.claimedAt)}.
          Expiration: {timestamp(current.claimExpiresAt)}.</p>
        <p>Quota state: {current.associatedQuotaState ?? "Unknown"}.
          Reserved provider requests:
          {" "}{current.associatedQuotaRequests ?? "Unknown"}.</p>
        <p>Associated persisted inspection:
          {" "}{current.associatedInspectionId ?? "Not confirmed"}.</p>
        <p>{current.reason}</p>
        <details>
          <summary>Provider and run idempotency fingerprints</summary>
          <p>Provider request key:
            {" "}<code style={{ overflowWrap: "anywhere" }}>
              {current.sourceRequestKey}</code></p>
          <p>Command digest:
            {" "}<code style={{ overflowWrap: "anywhere" }}>
              {current.commandDigest}</code></p>
        </details>
        <fieldset disabled={busy || !current.eligible}>
          <legend>Confirm irreversible incident classification</legend>
          <label>Re-enter exact run ID
            <input value={confirmRunId}
              maxLength={150}
              onChange={event => setConfirmRunId(event.target.value)}/>
          </label>
          <label>Investigation reason (minimum 20 characters)
            <textarea rows={3} value={reason} maxLength={500}
              onChange={event => setReason(event.target.value)}/>
          </label>
          <label>
            <input type="checkbox" checked={consent}
              onChange={event => setConsent(event.target.checked)}/>
            I acknowledge that the provider may have received
            requests and no quota, slot or retry will be restored.
          </label>
          <button type="button" disabled={
            confirmRunId !== current.runId ||
            reason.trim().length < 20 || !consent || busy}
            onClick={() => void classifyUnknown()}>
            Mark UNKNOWN with a transactional audit record
          </button>
        </fieldset>
      </article>}
      <details>
        <summary>Incident review limitations</summary>
        <p>Preview digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {preview.digest}</code></p>
        <ul>{preview.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
      </details>
    </section>}
    {recovered && <section role="status">
      <h3>Incident classified</h3>
      <p>Run {recovered.runId}: {recovered.state}.
        Audit event recorded: {recovered.auditRecorded ? "Yes" : "No"}.
        Provider retried: {recovered.providerRetried ? "Yes" : "No"}.
        Slot released: {recovered.slotReleased ? "Yes" : "No"}.
        Quota refunded: {recovered.quotaRefunded ? "Yes" : "No"}.</p>
      <p>Recovery fingerprint:
        {" "}<code style={{ overflowWrap: "anywhere" }}>
          {recovered.digest}</code></p>
      <ul>{recovered.warnings.map((warning, index) =>
        <li key={index}>{warning}</li>)}</ul>
    </section>}
  </section>;
}
