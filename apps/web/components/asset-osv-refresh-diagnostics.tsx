"use client";

import { useEffect, useMemo, useState } from "react";

type Import = {
  id: string; sourceLabel: string; state: string; importedCount: number;
};
type Inspection = {
  id: string; inventoryImportId: string; status: string;
  completedAt: string; queryCount: number;
};
type PackageDecision = {
  key: string; ecosystem: string; packageName: string;
  version: string; state: string; shouldRefresh: boolean;
  dueAt: string | null; lastCheckedAt: string | null;
  lastInspectionId: string | null; ageMinutes: number | null;
  possibleIds: string[]; providerOnlyIds: string[];
  unresolvedIds: string[]; withdrawnIds: string[];
  reasons: string[];
};
type RefreshReport = {
  schema: string; organizationId: string; generatedAt: string;
  totalHistoricalPackages: number; dueCount: number;
  freshCount: number; incompleteCount: number; deferredCount: number;
  selectedCount: number; excludedDueToBudget: number;
  offset: number; limit: number; hasMore: boolean;
  budget: {
    inspectionCountToday: number; queryCountToday: number;
    inspectionBudgetRemaining: number; queryBudgetRemaining: number;
    allowedPackageQueries: number; blockedByInspectionBudget: boolean;
  };
  selected: PackageDecision[]; candidates: PackageDecision[];
  digest: string; warnings: string[];
};
type DeltaRow = {
  key: string; ecosystem: string; packageName: string;
  version: string; kind: string; advisoryId: string | null;
  previous: string | null; current: string | null;
  confidence: string; explanation: string; fingerprint: string;
};
type Delta = {
  schema: string; completeComparison: boolean;
  previousInspectionId: string; currentInspectionId: string;
  summary: {
    total: number; changed: number; unchanged: number;
    possibleAdded: number; possibleNoLongerListed: number;
    providerOnlyAdded: number; withdrawnAdded: number;
    statusChanged: number; comparedPackages: number;
    excludedPackages: number;
  };
  totalChanges: number; offset: number; limit: number;
  hasMore: boolean; digest: string; rows: DeltaRow[];
  warnings: string[];
};
type InspectionPage = { inspections: Inspection[] };
type ImportPage = { imports: Import[] };
function url(base: string, pairs: Record<string, string>) {
  return base + "?" + new URLSearchParams(pairs);
}
async function load<T>(target: string): Promise<T> {
  const response = await fetch(target, {
    method: "GET", cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const failure = data as { error?: string };
    throw new Error(failure.error ?? "OSV history HTTP " + response.status);
  }
  return data as T;
}
function errorMessage(error: unknown) {
  return error instanceof Error ? error.message :
    "Unable to load OSV diagnostics.";
}
function DateLabel({ value }: { value: string | null }) {
  if (!value) return <>Not observed</>;
  const date = new Date(value);
  return <>{Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid provider date"}</>;
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    border: "1px solid #8885", padding: 10, borderRadius: 8,
  }}>
    <strong>{value}</strong><div>{label}</div>
  </div>;
}
function DecisionRow({ decision }: { decision: PackageDecision }) {
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{decision.ecosystem}/{decision.packageName}
      {" · "}{decision.version}</strong>
    <p>Classification: <strong>{decision.state}</strong>.
      Recommended refresh: {decision.shouldRefresh ? "Yes" : "No"}.</p>
    <p>Last checked: <DateLabel value={decision.lastCheckedAt}/>.
      {" "}Age: {decision.ageMinutes ?? "Unknown"} minutes.</p>
    {decision.dueAt && <p>Next eligible checkpoint:
      {" "}<DateLabel value={decision.dueAt}/></p>}
    <p>{decision.reasons.join(" ")}</p>
    <details>
      <summary>Historical associations (not endpoint findings)</summary>
      <p>Literal: {decision.possibleIds.join(", ") || "None listed"}</p>
      <p>Provider-only: {decision.providerOnlyIds.join(", ") || "None listed"}</p>
      <p>Unevaluated: {decision.unresolvedIds.join(", ") || "None listed"}</p>
      <p>Withdrawn: {decision.withdrawnIds.join(", ") || "None listed"}</p>
    </details>
  </article>;
}
function DeltaRowView({ row }: { row: DeltaRow }) {
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{row.ecosystem}/{row.packageName} · {row.version}</strong>
    <p>{row.kind} {row.advisoryId ?? ""}</p>
    <p>{row.explanation}</p>
    <p>Previous: {row.previous ?? "Not listed"}
      {" · "}Current: {row.current ?? "Not listed"}</p>
    <details>
      <summary>Change fingerprint</summary>
      <code style={{ overflowWrap: "anywhere" }}>
        {row.fingerprint}</code>
    </details>
  </article>;
}
export function AssetOsvRefreshDiagnostics({ slug }: { slug: string }) {
  const base = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [imports, setImports] = useState<Import[]>([]);
  const [inspections, setInspections] = useState<Inspection[]>([]);
  const [importId, setImportId] = useState("");
  const [freshness, setFreshness] = useState(1440);
  const [retry, setRetry] = useState(60);
  const [dailyQueries, setDailyQueries] = useState(200);
  const [dailyInspections, setDailyInspections] = useState(20);
  const [perRun, setPerRun] = useState(10);
  const [includeIncomplete, setIncludeIncomplete] = useState(true);
  const [refreshOffset, setRefreshOffset] = useState(0);
  const [deltaOffset, setDeltaOffset] = useState(0);
  const [previousId, setPreviousId] = useState("");
  const [currentId, setCurrentId] = useState("");
  const [refresh, setRefresh] = useState<RefreshReport | null>(null);
  const [delta, setDelta] = useState<Delta | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const refreshUrl = useMemo(() => url(base + "/refresh-readiness", {
    importId, freshnessMinutes: String(freshness),
    minimumRetryMinutes: String(retry),
    maximumQueriesPerDay: String(dailyQueries),
    maximumInspectionsPerDay: String(dailyInspections),
    maximumPackagesPerRun: String(perRun),
    historyWindowDays: "90",
    includeIncomplete: String(includeIncomplete),
    offset: String(refreshOffset), limit: "25",
  }), [base, importId, freshness, retry, dailyQueries,
    dailyInspections, perRun, includeIncomplete, refreshOffset]);
  const deltaUrl = useMemo(() => url(base + "/osv-history-delta", {
    previousInspectionId: previousId, currentInspectionId: currentId,
    offset: String(deltaOffset), limit: "25",
  }), [base, previousId, currentId, deltaOffset]);
  useEffect(() => {
    let cancelled = false;
    void Promise.all([
      load<ImportPage>(base + "/imports?includeRetired=true&limit=100"),
      load<InspectionPage>(base + "/osv-inspections?limit=100"),
    ]).then(([a, b]) => {
      if (cancelled) return;
      setImports(a.imports);
      setInspections(b.inspections);
    }).catch(cause => {
      if (!cancelled) setError(errorMessage(cause));
    });
    return () => { cancelled = true; };
  }, [base, reload]);
  function invalidateRefresh() {
    setRefresh(null);
    setRefreshOffset(0);
    setError(null);
  }
  function invalidateDelta() {
    setDelta(null);
    setDeltaOffset(0);
    setError(null);
  }
  async function inspectRefresh(target = refreshUrl) {
    if (busy || !importId) return;
    setBusy(true); setError(null);
    try { setRefresh(await load<RefreshReport>(target)); }
    catch (cause) { setRefresh(null); setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }
  async function compare(target = deltaUrl) {
    if (busy || !previousId || !currentId ||
        previousId === currentId) return;
    setBusy(true); setError(null);
    try { setDelta(await load<Delta>(target)); }
    catch (cause) { setDelta(null); setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }
  return <section aria-label="OSV freshness and longitudinal diagnostics"
    style={{
      padding: 16, borderRadius: 12, marginBlock: 20,
      border: "1px solid #8885",
    }}>
    <h2>OSV freshness, advisory quotas and change history</h2>
    <p>This is a read-only analytical planner. Daily limits below
      are recommendations derived from historical records, not
      atomic reservations or a guarantee against concurrent requests.
      No scheduled background execution is enabled.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Reviewing historical OSV records…</p>}
    <fieldset disabled={busy}>
      <legend>Provider refresh readiness</legend>
      <label>Inventory snapshot
        <select value={importId} onChange={event => {
          setImportId(event.target.value); invalidateRefresh();
        }}>
          <option value="">Choose snapshot</option>
          {imports.map(row => <option key={row.id} value={row.id}>
            {row.sourceLabel} · {row.state} · {row.importedCount} rows
          </option>)}
        </select>
      </label>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        <label>Freshness threshold (minutes)
          <select value={freshness} onChange={event => {
            setFreshness(Number(event.target.value)); invalidateRefresh();
          }}>
            {[60, 360, 720, 1440, 10080, 43200].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Retry cooldown (minutes)
          <select value={retry} onChange={event => {
            setRetry(Number(event.target.value)); invalidateRefresh();
          }}>
            {[5, 15, 60, 180, 720, 1440].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Daily advisory query budget
          <select value={dailyQueries} onChange={event => {
            setDailyQueries(Number(event.target.value)); invalidateRefresh();
          }}>
            {[20, 50, 100, 200, 500, 1000].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Daily inspection budget
          <select value={dailyInspections} onChange={event => {
            setDailyInspections(Number(event.target.value)); invalidateRefresh();
          }}>
            {[1, 5, 10, 20, 50].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum package queries per run
          <select value={perRun} onChange={event => {
            setPerRun(Number(event.target.value)); invalidateRefresh();
          }}>
            {[1, 3, 5, 10, 20].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={includeIncomplete}
          onChange={event => {
            setIncludeIncomplete(event.target.checked); invalidateRefresh();
          }} />
        Include incomplete queries after cooldown
      </label>
      <button type="button" disabled={!importId || busy}
        onClick={() => void inspectRefresh()}>
        Analyze refresh readiness (no provider calls)
      </button>
      <button type="button" disabled={busy}
        onClick={() => setReload(x => x + 1)}>
        Reload saved inspections
      </button>
    </fieldset>
    {refresh && <section>
      <h3>Refresh readiness</h3>
      <p>Historical package identities: {refresh.totalHistoricalPackages}.
        Due: {refresh.dueCount}. Selected under advisory budget:
        {" "}{refresh.selectedCount}. Excluded:
        {" "}{refresh.excludedDueToBudget}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Fresh" value={refresh.freshCount}/>
        <Metric label="Incomplete" value={refresh.incompleteCount}/>
        <Metric label="Cooldown deferred" value={refresh.deferredCount}/>
        <Metric label="Queries today" value={refresh.budget.queryCountToday}/>
        <Metric label="Advisory query capacity"
          value={refresh.budget.queryBudgetRemaining}/>
        <Metric label="Inspection capacity"
          value={refresh.budget.inspectionBudgetRemaining}/>
      </div>
      {refresh.budget.blockedByInspectionBudget &&
        <p>Daily inspection advisory allowance exhausted.</p>}
      <h4>Queries recommended for manual review</h4>
      {refresh.selected.map(row =>
        <DecisionRow key={row.key} decision={row}/>)}
      <h4>Historical package decisions</h4>
      {refresh.candidates.map(row =>
        <DecisionRow key={row.key} decision={row}/>)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={busy || refreshOffset === 0}
          onClick={() => {
            const value = Math.max(0, refreshOffset - 25);
            setRefreshOffset(value); setRefresh(null);
          }}>Previous page</button>
        <button type="button" disabled={busy || !refresh.hasMore}
          onClick={() => {
            setRefreshOffset(n => n + 25); setRefresh(null);
          }}>Next page</button>
      </div>
      <details>
        <summary>Budget and freshness caveats</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>
          {refresh.digest}</code></p>
        <ul>{refresh.warnings.map(text =>
          <li key={text}>{text}</li>)}</ul>
      </details>
    </section>}
    <fieldset disabled={busy}>
      <legend>Compare two recorded OSV inspections</legend>
      <label>Previous inspection
        <select value={previousId} onChange={event => {
          setPreviousId(event.target.value); invalidateDelta();
        }}>
          <option value="">Select earlier inspection</option>
          {inspections.map(item =>
            <option value={item.id} key={item.id}>
              {item.completedAt} · {item.status} · {item.id}
            </option>)}
        </select>
      </label>
      <label>Current inspection
        <select value={currentId} onChange={event => {
          setCurrentId(event.target.value); invalidateDelta();
        }}>
          <option value="">Select later inspection</option>
          {inspections.map(item =>
            <option value={item.id} key={item.id}>
              {item.completedAt} · {item.status} · {item.id}
            </option>)}
        </select>
      </label>
      <button type="button" disabled={!previousId || !currentId ||
        previousId === currentId || busy}
        onClick={() => void compare()}>
        Compare recorded provider associations
      </button>
    </fieldset>
    {delta && <section>
      <h3>Historical provider changes</h3>
      <p>Completeness: {delta.completeComparison ?
        "Comparable package sets with complete provider plans" :
        "Partial or incomplete comparison"}.
        {" "}{delta.summary.comparedPackages} packages compared;
        {" "}{delta.summary.excludedPackages} incomparable identities.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Recorded changes" value={delta.summary.changed}/>
        <Metric label="New literal associations"
          value={delta.summary.possibleAdded}/>
        <Metric label="No longer listed"
          value={delta.summary.possibleNoLongerListed}/>
        <Metric label="New provider-only IDs"
          value={delta.summary.providerOnlyAdded}/>
        <Metric label="New withdrawals"
          value={delta.summary.withdrawnAdded}/>
        <Metric label="Provider status changes"
          value={delta.summary.statusChanged}/>
      </div>
      {delta.rows.map((row, i) =>
        <DeltaRowView row={row} key={row.fingerprint + i}/>)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={busy || deltaOffset === 0}
          onClick={() => { setDeltaOffset(n => Math.max(0, n - 25)); setDelta(null); }}>
          Previous changes
        </button>
        <button type="button" disabled={busy || !delta.hasMore}
          onClick={() => { setDeltaOffset(n => n + 25); setDelta(null); }}>
          Next changes
        </button>
      </div>
      <details>
        <summary>Comparison confidence and fingerprint</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>{delta.digest}</code></p>
        <ul>{delta.warnings.map(text => <li key={text}>{text}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
