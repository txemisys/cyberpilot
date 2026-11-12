"use client";

import { useEffect, useMemo, useState } from "react";

type InspectionSummary = {
  id: string;
  inventoryImportId: string;
  requestKey: string;
  status: string;
  provider: string;
  coverage: string;
  requestDigest: string;
  reportDigest: string;
  queryCount: number;
  completedCount: number;
  possibleCount: number;
  providerOnlyCount: number;
  completedAt: string;
  createdAt: string;
};
type QueryRecord = {
  id: string;
  queryKey: string;
  ecosystem: string;
  packageName: string;
  version: string;
  providerStatus: string;
  providerDigest: string | null;
  checkedAt: string | null;
  possibleIds: string[];
  providerOnlyIds: string[];
  withdrawnIds: string[];
  unresolvedIds: string[];
  observationCount: number;
  pageCount: number;
};
type InspectionPage = {
  schema: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  inspections: InspectionSummary[];
  warnings: string[];
};
type InspectionDetail = {
  schema: string;
  inspection: InspectionSummary;
  recordedQueries: QueryRecord[];
  report: {
    status: string;
    reportDigest: string;
    warnings: string[];
    plan: {
      inventoryRows: number;
      mappedRows: number;
      unmappedRows: number;
      invalidVersionRows: number;
      skippedPackages: number;
    };
  };
  checkedAt: string;
  persistedReportDigest: string;
  warnings: string[];
};
type Import = {
  id: string;
  sourceLabel: string;
  state: string;
  importedCount: number;
};
type ImportPage = { imports: Import[] };
type OsvCommit = {
  inspectionId: string;
  replayed: boolean;
  reportDigest: string;
  status: string;
  queryCount: number;
  warnings: string[];
};
type Busy = "NONE" | "LIST" | "DETAIL" | "PREVIEW" | "COMMIT";
const DEFAULT_BINDINGS = JSON.stringify([
  {
    inventoryProduct: "Example Package",
    ecosystem: "npm",
    packageName: "example-package",
  },
], null, 2);
async function request<T>(url: string, method: "GET" | "POST",
  value?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(value) } : {}),
  });
  const parsed: unknown = await response.json();
  if (!response.ok) {
    const err = parsed as { error?: string };
    throw new Error(err.error ?? "Request rejected (" + response.status + ")");
  }
  return parsed as T;
}
function errorText(error: unknown) {
  return error instanceof Error ? error.message : "OSV inspection is unavailable.";
}
function date(value: string | null) {
  if (!value) return "Not available";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Invalid date" : parsed.toLocaleString();
}
function Stat({ value, label }: { value: number; label: string }) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}>
    <strong>{value}</strong><div>{label}</div>
  </div>;
}
function QueryRow({ row }: { row: QueryRecord }) {
  return <article style={{
    border: "1px solid #8885", padding: 12,
    borderRadius: 8, marginBlock: 8,
  }}>
    <strong>{row.ecosystem}/{row.packageName} · {row.version}</strong>
    <p>Result: {row.providerStatus}. Queried {date(row.checkedAt)}.
      {" "}{row.observationCount} associated declared observations.</p>
    <p>Literal matches: {row.possibleIds.join(", ") || "None reported"}</p>
    <p>Provider-only IDs: {row.providerOnlyIds.join(", ") || "None reported"}</p>
    <p>Unevaluated ranges: {row.unresolvedIds.join(", ") || "None reported"}</p>
    <p>Withdrawn records: {row.withdrawnIds.join(", ") || "None reported"}</p>
    <details>
      <summary>Query digest and reference</summary>
      <p><code style={{ overflowWrap: "anywhere" }}>
        {row.providerDigest ?? "No provider response digest"}</code></p>
      <p><code style={{ overflowWrap: "anywhere" }}>
        {row.queryKey}</code></p>
    </details>
  </article>;
}
export function AssetOsvInspectionLedger({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const ledgerUrl = base + "/osv-inspections";
  const [imports, setImports] = useState<Import[]>([]);
  const [filterImport, setFilterImport] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<InspectionPage | null>(null);
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<InspectionDetail | null>(null);
  const [busy, setBusy] = useState<Busy>("NONE");
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [runImportId, setRunImportId] = useState("");
  const [bindings, setBindings] = useState("");
  const [requestKey, setRequestKey] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [maxPackages, setMaxPackages] = useState(5);
  const [preview, setPreview] = useState<{
    plan: {
      selectedPackages: number;
      unmappedRows: number;
      invalidVersionRows: number;
      skippedPackages: number;
      work: Array<{
        key: string; ecosystem: string;
        name: string; version: string;
      }>;
    };
  } | null>(null);
  const [committed, setCommitted] = useState<OsvCommit | null>(null);
  const historyUrl = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(offset), limit: "25",
    });
    if (filterImport) params.set("importId", filterImport);
    if (statusFilter) params.set("status", statusFilter);
    return ledgerUrl + "?" + params;
  }, [filterImport, statusFilter, offset, ledgerUrl]);
  useEffect(() => {
    let cancelled = false;
    void request<ImportPage>(base + "/imports?limit=100&includeRetired=true", "GET")
      .then(data => { if (!cancelled) setImports(data.imports); })
      .catch(cause => { if (!cancelled) setError(errorText(cause)); });
    return () => { cancelled = true; };
  }, [base, reload]);
  useEffect(() => {
    let cancelled = false;
    void request<InspectionPage>(historyUrl, "GET")
      .then(data => { if (!cancelled) setPage(data); })
      .catch(cause => { if (!cancelled) setError(errorText(cause)); });
    return () => { cancelled = true; };
  }, [historyUrl, reload]);
  function resetPreparation() {
    setPreview(null);
    setCommitted(null);
    setConfirmed(false);
    setRequestKey("");
    setError(null);
  }
  async function showDetail(id: string) {
    if (busy !== "NONE") return;
    setBusy("DETAIL"); setError(null); setSelected(id);
    try {
      const parameters = new URLSearchParams({ inspectionId: id });
      setDetail(await request<InspectionDetail>(
        ledgerUrl + "?" + parameters, "GET"));
    } catch (cause) {
      setDetail(null); setError(errorText(cause));
    } finally {
      setBusy("NONE");
    }
  }
  function payload(dryRun: boolean, packageBindings: unknown) {
    return {
      importId: runImportId, packageBindings,
      limitPackages: maxPackages, maxPagesPerPackage: 2,
      maxRecordsPerPackage: 50, maxAgeMinutes: 60, dryRun,
    };
  }
  async function makePreview() {
    if (!runImportId || busy !== "NONE") return;
    let parsed: unknown;
    try { parsed = JSON.parse(bindings); }
    catch {
      setError("Explicit bindings must be valid JSON.");
      return;
    }
    setBusy("PREVIEW"); setError(null);
    setPreview(null); setCommitted(null); setConfirmed(false);
    try {
      const response = await request<{
        plan: {
          selectedPackages: number;
          unmappedRows: number;
          invalidVersionRows: number;
          skippedPackages: number;
          work: Array<{
            key: string; ecosystem: string; name: string; version: string;
          }>;
        };
      }>(base + "/osv-official", "POST", payload(true, parsed));
      setPreview(response);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("NONE");
    }
  }
  async function persist() {
    if (!canManage || !preview || !confirmed ||
        preview.plan.selectedPackages < 1 ||
        !runImportId || busy !== "NONE") return;
    let parsed: unknown;
    try { parsed = JSON.parse(bindings); }
    catch {
      setError("Explicit bindings must be valid JSON.");
      return;
    }
    const key = requestKey || crypto.randomUUID();
    setRequestKey(key);
    setBusy("COMMIT"); setError(null);
    try {
      const response = await request<OsvCommit>(ledgerUrl, "POST", {
        requestKey: key,
        inspection: payload(false, parsed),
      });
      setCommitted(response);
      setReload(value => value + 1);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("NONE");
    }
  }
  return <section aria-label="OSV inspection ledger"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>OSV provider inspection history</h2>
    <p>Records from prior provider queries remain available for authorized
      reviews. A historical result is not a current vulnerability
      verification, and even a COMPLETE provider response does not verify
      the endpoint or software inventory.</p>
    {error && <p role="alert">{error}</p>}
    {busy !== "NONE" && <p role="status">
      {busy === "COMMIT" ? "Executing and recording provider inspection…" :
        "Inspecting OSV records…"}
    </p>}
    <fieldset disabled={busy !== "NONE"}>
      <legend>Recorded inspection filters</legend>
      <label>Inventory snapshot
        <select value={filterImport} onChange={event => {
          setFilterImport(event.target.value);
          setOffset(0); setPage(null);
        }}>
          <option value="">All organizational imports</option>
          {imports.map(row => <option key={row.id} value={row.id}>
            {row.sourceLabel} · {row.id}
          </option>)}
        </select>
      </label>
      <label>Inspection status
        <select value={statusFilter} onChange={event => {
          setStatusFilter(event.target.value);
          setOffset(0); setPage(null);
        }}>
          <option value="">All statuses</option>
          {["COMPLETE", "PARTIAL", "INCOMPLETE", "ERROR"].map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button type="button" onClick={() => setReload(value => value + 1)}>
        Refresh recorded inspections
      </button>
    </fieldset>
    {page && <div>
      <p>{page.total} recorded inspections.
        {" "}{page.inspections.length} on this page.</p>
      {page.inspections.map(row => <article key={row.id}
        style={{
          padding: 12, marginBlock: 8,
          borderRadius: 8, border: "1px solid #8885",
        }}>
        <strong>{row.provider} · {row.status}</strong>
        <p>{date(row.createdAt)} · {row.queryCount} package queries
          {" · "}{row.possibleCount} literal possible matches.</p>
        <p>Inventory <code>{row.inventoryImportId}</code></p>
        <button type="button" disabled={busy !== "NONE"}
          onClick={() => void showDetail(row.id)}>
          Inspect historical result
        </button>
      </article>)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={offset === 0 || busy !== "NONE"}
          onClick={() => { setOffset(n => Math.max(0, n - 25)); setPage(null); }}>
          Previous page
        </button>
        <button type="button" disabled={!page.hasMore || busy !== "NONE"}
          onClick={() => { setOffset(n => n + 25); setPage(null); }}>
          Next page
        </button>
      </div>
      <details>
        <summary>History limitations</summary>
        <ul>{page.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
    </div>}
    {detail && detail.inspection.id === selected && <section>
      <h3>Inspection detail</h3>
      <p>Recorded {date(detail.checkedAt)}.
        Status {detail.inspection.status}.
        Coverage {detail.inspection.coverage}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Stat value={detail.inspection.queryCount} label="Queries"/>
        <Stat value={detail.inspection.completedCount} label="Complete queries"/>
        <Stat value={detail.inspection.possibleCount} label="Literal associations"/>
        <Stat value={detail.inspection.providerOnlyCount}
          label="Provider-only associations"/>
      </div>
      <details>
        <summary>Immutable report and request digests</summary>
        <p>Report: <code style={{ overflowWrap: "anywhere" }}>
          {detail.persistedReportDigest}</code></p>
        <p>Request: <code style={{ overflowWrap: "anywhere" }}>
          {detail.inspection.requestDigest}</code></p>
      </details>
      {detail.recordedQueries.map(row =>
        <QueryRow row={row} key={row.id}/>)}
      <details>
        <summary>Historical record caveats</summary>
        <ul>{detail.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
    </section>}
    {canManage && <section>
      <h2>Record new official OSV inspection</h2>
      <p>A preview does not contact OSV.dev. Saving a new inspection
        sends explicitly mapped package names and versions to the
        provider, then stores a versioned history record. The record
        is not a confirmation of active exploitation.</p>
      <fieldset disabled={busy !== "NONE"}>
        <legend>Provider inspection command</legend>
        <label>Active inventory
          <select value={runImportId} onChange={event => {
            setRunImportId(event.target.value); resetPreparation();
          }}>
            <option value="">Select a snapshot</option>
            {imports.filter(row => row.state === "COMMITTED")
              .map(row => <option key={row.id} value={row.id}>
                {row.sourceLabel} · {row.importedCount} rows
              </option>)}
          </select>
        </label>
        <label>Explicit package bindings JSON
          <textarea value={bindings} rows={7} maxLength={50000}
            onChange={event => {
              setBindings(event.target.value); resetPreparation();
            }} placeholder={DEFAULT_BINDINGS} />
        </label>
        <button type="button" onClick={() => {
          setBindings(DEFAULT_BINDINGS); resetPreparation();
        }}>Insert synthetic binding example</button>
        <label>Maximum different packages to query
          <select value={maxPackages} onChange={event => {
            setMaxPackages(Number(event.target.value)); resetPreparation();
          }}>
            {[1, 3, 5, 10, 20].map(value =>
              <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
        <button type="button" disabled={!runImportId || !bindings.trim()}
          onClick={() => void makePreview()}>
          Preview provider inspection
        </button>
      </fieldset>
      {preview && <div>
        <h3>Queries planned without network access</h3>
        <p>{preview.plan.selectedPackages} distinct package queries.
          {" "}{preview.plan.unmappedRows} unmapped observations;
          {" "}{preview.plan.invalidVersionRows} uncertain versions;
          {" "}{preview.plan.skippedPackages} queries excluded by budget.</p>
        {preview.plan.work.map(work => <p key={work.key}>
          {work.ecosystem}/{work.name} · {work.version}
        </p>)}
        <label>
          <input type="checkbox" checked={confirmed}
            onChange={event => setConfirmed(event.target.checked)}/>
          I authorize the OSV.dev request and storage of
          its query results in the organization audit history.
        </label>
        <button type="button" disabled={!confirmed ||
          preview.plan.selectedPackages < 1 || busy !== "NONE" ||
          committed !== null}
          onClick={() => void persist()}>
          Query official OSV and persist inspection
        </button>
      </div>}
      {committed && <p role="status">
        Inspection recorded: {committed.inspectionId}.
        Result {committed.status}.
        {" "}{committed.replayed ?
          "Existing record reused without a new provider call." :
          "New provider inspection persisted."}
        {" "}{committed.queryCount} package records.
      </p>}
    </section>}
  </section>;
}
