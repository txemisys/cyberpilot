"use client";

import { useEffect, useMemo, useState } from "react";

type Import = {
  id: string;
  sourceLabel: string;
  state: string;
  payloadDigest: string;
  importedCount: number;
  createdAt: string;
  retiredAt: string | null;
};
type ImportsResponse = { imports: Import[]; total: number; hasMore: boolean };
type Diff = {
  key: string;
  externalId: string;
  productKey: string;
  category: string;
  significant: boolean;
  previousValue: string | null;
  currentValue: string | null;
  previousObservedAt: string | null;
  currentObservedAt: string | null;
  explanations: string[];
  fingerprint: string;
};
type Comparison = {
  schema: string;
  previousImport: Import;
  currentImport: Import;
  coverage: string;
  totalDifferences: number;
  hasMore: boolean;
  digest: string;
  summary: {
    inspectedPrevious: number;
    inspectedCurrent: number;
    uniqueAssetsPrevious: number;
    uniqueAssetsCurrent: number;
    changed: number;
    unchanged: number;
    newAssets: number;
    missingFromExport: number;
    newProducts: number;
    productsNotInExport: number;
    osChanges: number;
    versionChanges: number;
    platformChanges: number;
    advisoryChanges: number;
  };
  warnings: string[];
  rows: Diff[];
};
type RetentionCandidate = {
  importId: string;
  state: string;
  sourceLabel: string;
  importedCount: number;
  ageDays: number;
  daysSinceRetirement: number | null;
  eligible: boolean;
  reason: string;
  fingerprint: string;
};
type Retention = {
  total: number;
  hasMore: boolean;
  candidates: RetentionCandidate[];
  eligibleOnPage: number;
  blockedOnPage: number;
  digest: string;
  warnings: string[];
};
type PurgeResult = {
  importId: string;
  dryRun: boolean;
  replayed: boolean;
  status: string;
  devicesAffected: number;
  confirmationDigest: string;
  warnings: string[];
};
const CATEGORIES = [
  "ALL", "NEW_ASSET", "MISSING_FROM_EXPORT", "NEW_PRODUCT",
  "PRODUCT_NOT_IN_EXPORT", "OS_CHANGED", "VERSION_CHANGED",
  "PLATFORM_CHANGED", "ADVISORY_CHANGED", "OBSERVATION_UPDATED",
  "UNCHANGED",
];
async function call<T>(url: string, method: "GET" | "POST", value?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ? { Accept: "application/json" } :
      { "Content-Type": "application/json", Accept: "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(value) } : {}),
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const message = data as { error?: string };
    throw new Error(message.error || "Asset request failed (" + response.status + ").");
  }
  return data as T;
}
function message(error: unknown) {
  return error instanceof Error ? error.message : "Unknown asset request error.";
}
function Digest({ value }: { value: string }) {
  return <details>
    <summary>Record digest (SHA-256)</summary>
    <code style={{ overflowWrap: "anywhere" }}>{value}</code>
  </details>;
}
function Metric({ name, value }: { name: string; value: number }) {
  return <div style={{
    padding: 10, border: "1px solid #8885", borderRadius: 8,
  }}>
    <strong>{value}</strong>
    <div>{name}</div>
  </div>;
}
function DifferenceCard({ row }: { row: Diff }) {
  return <article style={{
    border: "1px solid #8885", padding: 12, borderRadius: 8, marginBlock: 8,
  }}>
    <strong>{row.category}: {row.externalId}</strong>
    {row.productKey && <p>Product: {row.productKey}</p>}
    <p>{row.explanations.join(" ")}</p>
    <p>Before: {row.previousValue ?? "Absent from export"}</p>
    <p>After: {row.currentValue ?? "Absent from export"}</p>
    <p>Observed before: {row.previousObservedAt ?? "No observation"}
      {" · "}after: {row.currentObservedAt ?? "No observation"}</p>
    <details>
      <summary>Change fingerprint</summary>
      <code style={{ overflowWrap: "anywhere" }}>{row.fingerprint}</code>
    </details>
  </article>;
}
export function AssetInventoryLongitudinal({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const api = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [imports, setImports] = useState<Import[]>([]);
  const [previousId, setPreviousId] = useState("");
  const [currentId, setCurrentId] = useState("");
  const [category, setCategory] = useState("ALL");
  const [includeUnchanged, setIncludeUnchanged] = useState(false);
  const [diffOffset, setDiffOffset] = useState(0);
  const [report, setReport] = useState<Comparison | null>(null);
  const [retention, setRetention] = useState<Retention | null>(null);
  const [retentionOffset, setRetentionOffset] = useState(0);
  const [minimumDays, setMinimumDays] = useState("30");
  const [minimumAge, setMinimumAge] = useState("365");
  const [candidateId, setCandidateId] = useState("");
  const [reason, setReason] = useState("");
  const [key, setKey] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [enteredId, setEnteredId] = useState("");
  const [preview, setPreview] = useState<PurgeResult | null>(null);
  const [purged, setPurged] = useState<PurgeResult | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const comparisonUrl = useMemo(() => {
    const parameters = new URLSearchParams({
      previousImportId: previousId, currentImportId: currentId,
      offset: String(diffOffset), limit: "50",
      includeUnchanged: String(includeUnchanged),
    });
    if (category !== "ALL") parameters.set("category", category);
    return api + "/comparison?" + parameters.toString();
  }, [api, previousId, currentId, diffOffset, includeUnchanged, category]);
  const retentionUrl = useMemo(() => {
    const parameters = new URLSearchParams({
      minimumRetiredDays: minimumDays,
      maximumCandidateAgeDays: minimumAge,
      offset: String(retentionOffset), limit: "25",
    });
    return api + "/retention?" + parameters.toString();
  }, [api, minimumDays, minimumAge, retentionOffset]);
  useEffect(() => {
    let canceled = false;
    void call<ImportsResponse>(api + "/imports?limit=100&includeRetired=true", "GET")
      .then(data => { if (!canceled) setImports(data.imports); })
      .catch(e => { if (!canceled) setError(message(e)); });
    return () => { canceled = true; };
  }, [api, refresh]);
  function resetComparison() {
    setDiffOffset(0);
    setReport(null);
    setError(null);
  }
  async function loadComparison() {
    if (!previousId || !currentId || previousId === currentId || busy) return;
    setBusy(true); setError(null);
    try {
      setReport(await call<Comparison>(comparisonUrl, "GET"));
    } catch (cause) {
      setReport(null); setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  async function loadRetention() {
    if (!canManage || busy) return;
    setBusy(true); setError(null);
    try {
      setRetention(await call<Retention>(retentionUrl, "GET"));
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  function selectCandidate(id: string) {
    setCandidateId(id);
    setEnteredId("");
    setReason("");
    setConfirmed(false);
    setKey("");
    setPreview(null);
    setPurged(null);
  }
  async function runPurge(dryRun: boolean) {
    if (!canManage || busy || !candidateId || !confirmed ||
        enteredId !== candidateId || reason.trim().length < 20) return;
    const imported = imports.find(item => item.id === candidateId);
    if (!imported || imported.state !== "RETIRED") {
      setError("Only retired snapshots can be purged.");
      return;
    }
    const nonce = key || crypto.randomUUID();
    setKey(nonce);
    setBusy(true); setError(null);
    const command = {
      importId: candidateId,
      expectedDigest: imported.payloadDigest,
      confirmImportId: enteredId,
      confirmPurge: true,
      minimumRetiredDays: Number(minimumDays),
      reason: reason.trim(),
      dryRun,
      idempotencyKey: nonce,
    };
    try {
      const result = await call<PurgeResult>(api + "/retention", "POST", command);
      if (dryRun) {
        setPreview(result);
      } else {
        setPurged(result);
        setPreview(null);
        setRefresh(value => value + 1);
        setRetention(null);
        setReport(null);
      }
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  return <section aria-label="Asset inventory longitudinal comparisons"
    style={{ border: "1px solid #8885", padding: 16,
      borderRadius: 12, marginBlock: 20 }}>
    <h2>Longitudinal asset evidence</h2>
    <p>Compare two declared CSV snapshots. Changes indicate a difference
      between exports; they do not verify live device deployment, software
      installation, patch level or security.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Inspecting inventory…</p>}
    <fieldset disabled={busy}>
      <legend>Compare inventory snapshots</legend>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        <label>Previous snapshot
          <select value={previousId} onChange={event => {
            setPreviousId(event.target.value); resetComparison();
          }}>
            <option value="">Choose source snapshot</option>
            {imports.map(item => <option value={item.id} key={item.id}>
              {item.sourceLabel} · {item.createdAt.slice(0, 10)} · {item.id}
            </option>)}
          </select>
        </label>
        <label>Current snapshot
          <select value={currentId} onChange={event => {
            setCurrentId(event.target.value); resetComparison();
          }}>
            <option value="">Choose destination snapshot</option>
            {imports.map(item => <option value={item.id} key={item.id}>
              {item.sourceLabel} · {item.createdAt.slice(0, 10)} · {item.id}
            </option>)}
          </select>
        </label>
        <label>Change category
          <select value={category} onChange={event => {
            setCategory(event.target.value); resetComparison();
          }}>
            {CATEGORIES.map(item => <option key={item} value={item}>
              {item}</option>)}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={includeUnchanged}
            onChange={event => {
              setIncludeUnchanged(event.target.checked); resetComparison();
            }} />
          Include unchanged observations
        </label>
      </div>
      <button type="button" disabled={busy || !previousId || !currentId ||
        previousId === currentId}
        onClick={() => void loadComparison()}>Compare snapshots</button>
    </fieldset>
    {report && <div>
      <h3>Comparison result</h3>
      <p>Declared scope: {report.coverage}.
        Total matching differences: {report.totalDifferences}.
        The summary includes both selected full snapshots.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))",
      }}>
        <Metric name="Previous rows" value={report.summary.inspectedPrevious}/>
        <Metric name="Current rows" value={report.summary.inspectedCurrent}/>
        <Metric name="New identifiers" value={report.summary.newAssets}/>
        <Metric name="Missing from export" value={report.summary.missingFromExport}/>
        <Metric name="Added products" value={report.summary.newProducts}/>
        <Metric name="Omitted products" value={report.summary.productsNotInExport}/>
        <Metric name="OS changes" value={report.summary.osChanges}/>
        <Metric name="Version changes" value={report.summary.versionChanges}/>
        <Metric name="Advisory associations changed" value={report.summary.advisoryChanges}/>
      </div>
      <Digest value={report.digest}/>
      {report.rows.map(row =>
        <DifferenceCard row={row} key={row.key}/>)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={busy || diffOffset === 0}
          onClick={() => { setDiffOffset(x => Math.max(0, x - 50)); setReport(null); }}>
          Previous comparison page
        </button>
        <button type="button" disabled={busy || !report.hasMore}
          onClick={() => { setDiffOffset(x => x + 50); setReport(null); }}>
          Next comparison page
        </button>
        <button type="button" disabled={busy}
          onClick={() => void loadComparison()}>Refresh selected page</button>
      </div>
      <details>
        <summary>Scope and interpretation limitations</summary>
        <ul>{report.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
    </div>}
    {canManage && <section>
      <h2>Retention and permanent purge</h2>
      <p>Administrators can inspect old snapshots and explicitly remove
        previously retired records. Purge is irreversible for the active
        database. Backups require their own retention lifecycle.</p>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <label>Minimum retired days
          <select value={minimumDays} onChange={event => {
            setMinimumDays(event.target.value); setRetention(null);
          }}>
            {[1, 7, 30, 90, 180, 365].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Candidate age in days
          <select value={minimumAge} onChange={event => {
            setMinimumAge(event.target.value); setRetention(null);
          }}>
            {[30, 90, 180, 365, 730, 1095].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <button type="button" disabled={busy}
          onClick={() => void loadRetention()}>Inspect retention</button>
      </div>
      {retention && <div>
        <p>{retention.eligibleOnPage} eligible on this page,
          {" "}{retention.blockedOnPage} blocked.
          There are {retention.total} snapshots in the organization.</p>
        <Digest value={retention.digest}/>
        {retention.candidates.map(candidate => <article key={candidate.importId}
          style={{
            border: "1px solid #8885", padding: 12,
            borderRadius: 8, marginBlock: 8,
          }}>
          <strong>{candidate.sourceLabel}</strong>
          <p>{candidate.importId} · {candidate.state}
            {" · "}{candidate.importedCount} observations</p>
          <p>Age {candidate.ageDays} days;
            retired {candidate.daysSinceRetirement ?? "not retired"} days ago.</p>
          <p>{candidate.reason}</p>
          {candidate.eligible && <button type="button" disabled={busy}
            onClick={() => selectCandidate(candidate.importId)}>
            Prepare permanent purge
          </button>}
        </article>)}
        <div style={{ display: "flex", gap: 12 }}>
          <button type="button" disabled={busy || retentionOffset === 0}
            onClick={() => {
              setRetentionOffset(x => Math.max(0, x - 25));
              setRetention(null);
            }}>Previous retention page</button>
          <button type="button" disabled={busy || !retention.hasMore}
            onClick={() => {
              setRetentionOffset(x => x + 25);
              setRetention(null);
            }}>Next retention page</button>
        </div>
        <details>
          <summary>Retention warnings</summary>
          <ul>{retention.warnings.map(warning =>
            <li key={warning}>{warning}</li>)}</ul>
        </details>
      </div>}
      {candidateId && <fieldset disabled={busy}>
        <legend>Irreversible purge confirmation</legend>
        <p>Target snapshot: <code>{candidateId}</code></p>
        <p>Retired data and related observations will be deleted from
          the active database. Audit metadata remains.</p>
        <label>Reason (at least 20 characters)
          <textarea rows={3} value={reason} onChange={event => {
            setReason(event.target.value); setPreview(null);
          }} />
        </label>
        <label>Type the exact import ID
          <input value={enteredId} onChange={event => {
            setEnteredId(event.target.value); setPreview(null);
          }} />
        </label>
        <label>
          <input type="checkbox" checked={confirmed}
            onChange={event => { setConfirmed(event.target.checked); setPreview(null); }}/>
          I understand this operation permanently deletes the active snapshot.
        </label>
        <button type="button" disabled={!confirmed ||
          enteredId !== candidateId || reason.trim().length < 20}
          onClick={() => void runPurge(true)}>Preview irreversible purge</button>
        {preview && <div>
          <h4>Preview complete — no rows deleted</h4>
          <p>{preview.devicesAffected} observations affected.</p>
          <Digest value={preview.confirmationDigest}/>
          <ul>{preview.warnings.map(warning =>
            <li key={warning}>{warning}</li>)}</ul>
          <button type="button" disabled={busy}
            onClick={() => void runPurge(false)}>
            Execute permanent purge
          </button>
        </div>}
        {purged && <p role="status">{purged.status}:
          {" "}{purged.devicesAffected} observations removed.</p>}
        <button type="button" onClick={() => selectCandidate("")}>
          Cancel purge preparation
        </button>
      </fieldset>}
    </section>}
  </section>;
}
