"use client";

import { useEffect, useMemo, useState } from "react";

type Inventory = {
  id: string; sourceLabel: string; state: string; importedCount: number;
};
type Inspection = {
  id: string; inventoryImportId: string;
  status: string; completedAt: string;
};
type Schedule = {
  id: string; name: string; inventoryImportId: string;
  sourceInspectionId: string; cadenceMinutes: number;
  enabled: boolean; outboundConsent: boolean;
  revision: number; consentDigest: string; nextDueAt: string;
  lastAttemptAt: string | null; lastSucceededAt: string | null;
  lastRunId: string | null; runCount: number;
};
type SchedulePage = { total: number; schedules: Schedule[]; warnings: string[] };
type DuePreview = {
  schema: string; scheduleId: string; revision: number;
  enabled: boolean; due: boolean; dueAt: string;
  nextDueIfClaimed: string; checkedAt: string;
  claimable: boolean; checks: string[];
  renewal: {
    selectedPackages: number; eligiblePackages: number;
    deferredPackages: number; maximumHttpPages: number;
    validForExecution: boolean; blockingReasons: string[];
    quotaRequestsRemaining: number;
  } | null;
  warnings: string[];
};
type Run = {
  id: string; slotAt: string; state: string;
  claimedAt: string; completedAt: string | null;
  inspectionId: string | null; errorCode: string | null;
  commandDigest: string;
};
type RunsPage = { total: number; runs: Run[] };
type DispatchResult = {
  runId: string; scheduleId: string; slotAt: string;
  nextDueAt: string; state: string; errorCode: string | null;
  inspectionId: string | null; warnings: string[];
};
type Status = "IDLE" | "READING" | "SAVING" | "DISPATCHING";
const sampleBindings = JSON.stringify([{
  inventoryProduct: "Example Package",
  ecosystem: "npm", packageName: "example-package",
}], null, 2);
function formatted(value: string | null) {
  if (!value) return "None recorded";
  const time = new Date(value);
  return Number.isFinite(time.getTime()) ? time.toLocaleString() :
    "Unparseable date";
}
async function call<T>(url: string, method: "GET" | "POST" | "PATCH" | "PUT",
  payload?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "GET" ? {} : { body: JSON.stringify(payload) }),
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const error = data as { error?: string };
    throw new Error(error.error ?? "OSV schedule request failed: " +
      response.status);
  }
  return data as T;
}
function message(error: unknown) {
  return error instanceof Error ? error.message :
    "Unable to perform OSV schedule operation.";
}
function Metric({ label, number }: { label: string; number: number }) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}>
    <strong>{number}</strong><div>{label}</div>
  </div>;
}
export function AssetOsvScheduleWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const api = base + "/osv-schedules";
  const [imports, setImports] = useState<Inventory[]>([]);
  const [inspections, setInspections] = useState<Inspection[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [selected, setSelected] = useState("");
  const [sourceInspectionId, setSourceInspectionId] = useState("");
  const [importId, setImportId] = useState("");
  const [name, setName] = useState("OSV weekly package refresh");
  const [cadence, setCadence] = useState(10080);
  const [bindings, setBindings] = useState("");
  const [freshness, setFreshness] = useState(1440);
  const [retry, setRetry] = useState(60);
  const [packageLimit, setPackageLimit] = useState(5);
  const [newPackages, setNewPackages] = useState(false);
  const [partialCoverage, setPartialCoverage] = useState(false);
  const [confirmEnable, setConfirmEnable] = useState(false);
  const [confirmDispatch, setConfirmDispatch] = useState(false);
  const [preview, setPreview] = useState<DuePreview | null>(null);
  const [history, setHistory] = useState<RunsPage | null>(null);
  const [lastRun, setLastRun] = useState<DispatchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<Status>("IDLE");
  const [revision, setRevision] = useState(0);
  const eligibleInspections = useMemo(() =>
    inspections.filter(row => row.inventoryImportId === importId),
  [inspections, importId]);
  const current = schedules.find(row => row.id === selected);
  const url = (view: "list" | "preview" | "history", scheduleId?: string) =>
    api + "?" + new URLSearchParams({
      view, ...(scheduleId ? { scheduleId } : {}),
    });
  useEffect(() => {
    if (!canManage) return;
    let canceled = false;
    void Promise.all([
      call<{ imports: Inventory[] }>(base + "/imports?limit=100", "GET"),
      call<{ inspections: Inspection[] }>(base +
        "/osv-inspections?limit=100", "GET"),
      call<SchedulePage>(url("list"), "GET"),
    ]).then(([a, b, c]) => {
      if (!canceled) {
        setImports(a.imports);
        setInspections(b.inspections);
        setSchedules(c.schedules);
        setError(null);
      }
    }).catch(cause => {
      if (!canceled) setError(message(cause));
    });
    return () => { canceled = true; };
  }, [base, api, canManage, revision]);
  function resetReview() {
    setPreview(null); setHistory(null); setLastRun(null);
    setConfirmEnable(false); setConfirmDispatch(false);
  }
  function config(): unknown {
    const packageBindings: unknown = JSON.parse(bindings);
    return {
      name, inventoryImportId: importId, sourceInspectionId,
      cadenceMinutes: cadence,
      inspection: {
        importId, packageBindings,
        dryRun: true, limitPackages: packageLimit,
        maxPagesPerPackage: 2, maxRecordsPerPackage: 50,
        maxAgeMinutes: 60,
      },
      policy: {
        freshnessMinutes: freshness,
        minimumRetryMinutes: retry,
        maximumQueriesPerDay: 200,
        maximumInspectionsPerDay: 20,
        maximumPackagesPerRun: packageLimit,
        historyWindowDays: 90, includeIncomplete: true,
      },
      allowNewPackages: newPackages,
      allowIncompleteInventory: partialCoverage,
    };
  }
  async function create() {
    if (status !== "IDLE" || !importId || !sourceInspectionId ||
        !bindings.trim()) return;
    setStatus("SAVING"); setError(null); resetReview();
    try {
      const created = await call<Schedule>(api, "POST", config());
      setSelected(created.id);
      setRevision(n => n + 1);
    } catch (cause) {
      setError(message(cause));
    } finally { setStatus("IDLE"); }
  }
  async function change(operation: "ENABLE" | "DISABLE") {
    if (status !== "IDLE" || !current) return;
    if (operation === "ENABLE" && !confirmEnable) return;
    setStatus("SAVING"); setError(null); resetReview();
    try {
      const updated = await call<Schedule>(api, "PATCH", {
        scheduleId: current.id, expectedRevision: current.revision,
        operation, confirmOutbound: operation === "ENABLE",
        consentDigest: operation === "ENABLE" ? current.consentDigest : null,
      });
      setSchedules(rows => rows.map(row =>
        row.id === updated.id ? updated : row));
      setRevision(n => n + 1);
    } catch (cause) {
      setError(message(cause));
    } finally { setStatus("IDLE"); }
  }
  async function review() {
    if (status !== "IDLE" || !current) return;
    setStatus("READING"); setError(null); resetReview();
    try {
      const data = await call<DuePreview>(
        url("preview", current.id), "GET");
      setPreview(data);
    } catch (cause) {
      setError(message(cause));
    } finally { setStatus("IDLE"); }
  }
  async function loadHistory() {
    if (status !== "IDLE" || !current) return;
    setStatus("READING"); setError(null);
    try {
      setHistory(await call<RunsPage>(
        url("history", current.id), "GET"));
    } catch (cause) {
      setError(message(cause));
    } finally { setStatus("IDLE"); }
  }
  async function dispatch() {
    if (status !== "IDLE" || !current || !preview?.claimable ||
        preview.revision !== current.revision || !confirmDispatch)
      return;
    setStatus("DISPATCHING"); setError(null);
    try {
      const data = await call<DispatchResult>(api, "PUT", {
        scheduleId: current.id, expectedRevision: current.revision,
        confirmDispatch: true,
      });
      setLastRun(data); setPreview(null); setConfirmDispatch(false);
      setRevision(n => n + 1);
    } catch (cause) {
      setError(message(cause));
    } finally { setStatus("IDLE"); }
  }
  if (!canManage) return null;
  return <section aria-label="Opt-in OSV recurring renewal"
    style={{ border: "1px solid #8885", padding: 16,
      borderRadius: 12, marginBlock: 20 }}>
    <h2>OSV recurring renewal policies</h2>
    <p>Schedules are created disabled. Enabling one records
      explicit organization consent. No background timer or cron
      is installed here: an administrator must separately dispatch
      each due interval, which obtains a unique PostgreSQL claim.
      All provider calls still require atomic daily quota.</p>
    {error && <p role="alert">{error}</p>}
    {status !== "IDLE" && <p role="status">
      {status === "DISPATCHING" ?
        "Claiming the due interval and checking the provider…" :
        status === "SAVING" ?
        "Recording schedule and consent…" :
        "Inspecting saved schedule data…"}
    </p>}
    <fieldset disabled={status !== "IDLE"}>
      <legend>Create a disabled recurring policy</legend>
      <label>Policy name
        <input value={name} maxLength={120}
          onChange={event => setName(event.target.value)}/>
      </label>
      <label>Active inventory
        <select value={importId} onChange={event => {
          setImportId(event.target.value); setSourceInspectionId("");
        }}>
          <option value="">Choose active snapshot</option>
          {imports.filter(row => row.state === "COMMITTED")
            .map(row => <option value={row.id} key={row.id}>
              {row.sourceLabel} · {row.importedCount} rows
            </option>)}
        </select>
      </label>
      <label>Saved source inspection
        <select value={sourceInspectionId}
          onChange={event => setSourceInspectionId(event.target.value)}>
          <option value="">Choose prior inspection</option>
          {eligibleInspections.map(row =>
            <option value={row.id} key={row.id}>
              {formatted(row.completedAt)} · {row.status} · {row.id}
            </option>)}
        </select>
      </label>
      <label>Reviewed product/package bindings JSON
        <textarea value={bindings} rows={6}
          maxLength={50000}
          placeholder={sampleBindings}
          onChange={event => setBindings(event.target.value)}/>
      </label>
      <button type="button" onClick={() => setBindings(sampleBindings)}>
        Insert synthetic mapping example
      </button>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <label>Cadence (minutes)
          <select value={cadence}
            onChange={event => setCadence(Number(event.target.value))}>
            {[60, 360, 1440, 10080, 20160, 43200]
              .map(n => <option value={n} key={n}>{n}</option>)}
          </select>
        </label>
        <label>Freshness threshold
          <select value={freshness}
            onChange={event => setFreshness(Number(event.target.value))}>
            {[60, 360, 1440, 10080, 43200]
              .map(n => <option value={n} key={n}>{n} minutes</option>)}
          </select>
        </label>
        <label>Failed query cooldown
          <select value={retry}
            onChange={event => setRetry(Number(event.target.value))}>
            {[15, 60, 360, 1440]
              .map(n => <option value={n} key={n}>{n} minutes</option>)}
          </select>
        </label>
        <label>Packages per inspection
          <select value={packageLimit}
            onChange={event => setPackageLimit(Number(event.target.value))}>
            {[1, 3, 5, 10, 20]
              .map(n => <option value={n} key={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={newPackages}
          onChange={event => setNewPackages(event.target.checked)}/>
        Approve new package identities beyond the previous inspection
      </label>
      <label>
        <input type="checkbox" checked={partialCoverage}
          onChange={event => setPartialCoverage(event.target.checked)}/>
        Acknowledge that unmapped inventory remains UNKNOWN
      </label>
      <button type="button" disabled={!sourceInspectionId ||
        !importId || !bindings.trim() || name.trim().length < 3}
        onClick={() => void create()}>
        Save disabled policy
      </button>
    </fieldset>
    <fieldset disabled={status !== "IDLE"}>
      <legend>Existing organizational schedules</legend>
      <button type="button" onClick={() => setRevision(n => n + 1)}>
        Refresh schedules
      </button>
      <label>Schedule
        <select value={selected} onChange={event => {
          setSelected(event.target.value); resetReview();
        }}>
          <option value="">Choose schedule</option>
          {schedules.map(row => <option value={row.id} key={row.id}>
            {row.name} · {row.enabled ? "ENABLED" : "DISABLED"} ·
            {" "}revision {row.revision}
          </option>)}
        </select>
      </label>
    </fieldset>
    {current && <section>
      <h3>{current.name}</h3>
      <p>Status: <strong>{current.enabled ? "ENABLED" : "DISABLED"}</strong>.
        Next due interval: {formatted(current.nextDueAt)}.
        Revision: {current.revision}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
      }}>
        <Metric label="Cadence minutes" number={current.cadenceMinutes}/>
        <Metric label="Recorded intervals" number={current.runCount}/>
      </div>
      <p>Last attempt: {formatted(current.lastAttemptAt)}.
        Last successful renewal: {formatted(current.lastSucceededAt)}.</p>
      {!current.enabled && <fieldset disabled={status !== "IDLE"}>
        <legend>Explicit activation</legend>
        <p>Enabling this schedule authorizes its stored package/version
          mappings to be sent to OSV.dev, but does not itself
          perform a query or start a background timer.</p>
        <label>
          <input type="checkbox" checked={confirmEnable}
            onChange={event => setConfirmEnable(event.target.checked)}/>
          I authorize the exact schedule configuration to be enabled.
        </label>
        <button type="button" disabled={!confirmEnable}
          onClick={() => void change("ENABLE")}>
          Enable authorized schedule
        </button>
      </fieldset>}
      {current.enabled && <button type="button"
        disabled={status !== "IDLE"}
        onClick={() => void change("DISABLE")}>
        Disable and revoke future schedule consent
      </button>}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <button type="button" disabled={status !== "IDLE"}
          onClick={() => void review()}>
          Preview next due slot (no network)
        </button>
        <button type="button" disabled={status !== "IDLE"}
          onClick={() => void loadHistory()}>
          View durable run history
        </button>
      </div>
    </section>}
    {preview && <section>
      <h3>Due interval assessment</h3>
      <p>Slot: {formatted(preview.dueAt)}.
        Next scheduled slot after claim:
        {" "}{formatted(preview.nextDueIfClaimed)}.</p>
      <p>Dispatch status: <strong>{preview.claimable ?
        "ELIGIBLE" : "BLOCKED"}</strong>.</p>
      {preview.renewal && <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Mapped packages"
          number={preview.renewal.selectedPackages}/>
        <Metric label="Due for update"
          number={preview.renewal.eligiblePackages}/>
        <Metric label="Deferred"
          number={preview.renewal.deferredPackages}/>
        <Metric label="Reserved HTTP pages"
          number={preview.renewal.maximumHttpPages}/>
      </div>}
      {preview.checks.length > 0 && <div role="alert">
        <p>Reasons execution is blocked:</p>
        <ul>{preview.checks.map((reason, i) =>
          <li key={i}>{reason}</li>)}</ul>
      </div>}
      <details>
        <summary>Preview limitations</summary>
        <ul>{preview.warnings.map((warning, i) =>
          <li key={i}>{warning}</li>)}</ul>
      </details>
      {preview.claimable && <fieldset disabled={status !== "IDLE"}>
        <legend>Dispatch due slot</legend>
        <label>
          <input type="checkbox" checked={confirmDispatch}
            onChange={event => setConfirmDispatch(event.target.checked)}/>
          I authorize the due slot to be claimed now, consuming the
          quota required for a provider request if still eligible.
        </label>
        <button type="button" disabled={!confirmDispatch ||
          preview.revision !== current?.revision}
          onClick={() => void dispatch()}>
          Dispatch one authorized due interval
        </button>
      </fieldset>}
    </section>}
    {lastRun && <section role="status">
      <h3>Schedule execution result</h3>
      <p>State: {lastRun.state}. Run ID: {lastRun.runId}.
        Resulting inspection: {lastRun.inspectionId ?? "None"}.
        Error: {lastRun.errorCode ?? "None"}.</p>
      <p>Next slot: {formatted(lastRun.nextDueAt)}.</p>
      <ul>{lastRun.warnings.map((warning, i) =>
        <li key={i}>{warning}</li>)}</ul>
    </section>}
    {history && <section>
      <h3>Durable schedule runs</h3>
      <p>{history.total} recorded slots;
        {" "}{history.runs.length} shown.</p>
      {history.runs.map(row => <article key={row.id}
        style={{ border: "1px solid #8885", padding: 12,
          borderRadius: 8, marginBlock: 8 }}>
        <strong>{row.state}</strong>
        <p>Slot: {formatted(row.slotAt)}.
          Claimed: {formatted(row.claimedAt)}.
          Completed: {formatted(row.completedAt)}.</p>
        <p>Inspection: {row.inspectionId ?? "No persisted inspection"}.
          Error: {row.errorCode ?? "None"}.</p>
      </article>)}
    </section>}
  </section>;
}
