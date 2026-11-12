"use client";

import { useEffect, useMemo, useState } from "react";

type Import = {
  id: string;
  sourceLabel: string;
  state: string;
  importedCount: number;
  createdAt: string;
};
type ImportPage = { imports: Import[]; total: number; hasMore: boolean };
type OsvCandidate = {
  externalId: string;
  softwareName: string;
  version: string | null;
  ecosystem: string | null;
  packageName: string | null;
  category: string;
  possibleAdvisoryIds: string[];
  withdrawnIds: string[];
  unresolvedRangeIds: string[];
  certainty: string;
  reason: string;
  fingerprint: string;
};
type OsvReport = {
  schema: string;
  organizationId: string;
  importId: string;
  source: string;
  generatedAt: string;
  feed: {
    sourceLabel: string;
    sourceVersion: string;
    retrievedAt: string;
    recordCount: number;
    withdrawnCount: number;
    digest: string;
  };
  bindingCount: number;
  totalRows: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  summary: {
    totalRows: number;
    mappedRows: number;
    unmappedRows: number;
    unknownVersions: number;
    possibleAssociations: number;
    unresolvedRanges: number;
    withdrawnRecords: number;
    noExactMatches: number;
    byClassification: Record<string, number>;
  };
  candidates: OsvCandidate[];
  digest: string;
  warnings: string[];
};
type OsvResponse = {
  importId: string;
  importState: string;
  importCreatedAt: string;
  inventoryObservations: number;
  importSource: string;
  feedProvenance: string;
  report: OsvReport;
};
const sampleRecords = {
  sourceLabel: "Example OSV export (synthetic, not an official feed)",
  sourceVersion: "synthetic-v1",
  retrievedAt: "2026-11-05T12:00:00.000Z",
  records: [{
    id: "CVE-2026-12345",
    modified: "2026-11-04T12:00:00Z",
    affected: [{
      package: { ecosystem: "npm", name: "example-package" },
      versions: ["1.0.0"],
    }],
  }],
};
const sampleBindings = [{
  inventoryProduct: "Example Package",
  ecosystem: "npm",
  packageName: "example-package",
}];
const explanation: Record<string, string> = {
  EXACT_AFFECTED_VERSION:
    "An explicitly mapped package has an exact enumerated affected version. This is not verified endpoint exposure.",
  NO_EXACT_VERSION_MATCH:
    "No exact match was listed in this supplied export; do not infer security.",
  UNKNOWN_VERSION:
    "Declared inventory version is missing or not specific enough.",
  UNMAPPED_PRODUCT:
    "A package mapping has not been explicitly approved.",
  RANGES_UNEVALUATED:
    "Affects-version ranges exist, but this engine does not evaluate them.",
  WITHDRAWN_RECORD:
    "Only withdrawn matching advisory records were present.",
};
async function request<T>(
  url: string, method: "GET" | "POST", data?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(data) } : {}),
  });
  const raw: unknown = await response.json();
  if (!response.ok) {
    const failure = raw as { error?: string };
    throw new Error(failure.error ?? "HTTP " + response.status);
  }
  return raw as T;
}
function failure(cause: unknown) {
  return cause instanceof Error ? cause.message : "OSV inspection unavailable.";
}
function timestamp(raw: string) {
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}
function DataMetric({ title, count }: { title: string; count: number }) {
  return <div style={{
    padding: 12, border: "1px solid #8885", borderRadius: 8,
  }}>
    <strong>{count}</strong>
    <div>{title}</div>
  </div>;
}
function CandidateRow({ row }: { row: OsvCandidate }) {
  return <article style={{
    padding: 12, border: "1px solid #8885", borderRadius: 8, marginBlock: 8,
  }}>
    <h4>{row.externalId} · {row.softwareName}</h4>
    <p>{row.ecosystem ?? "Unmapped ecosystem"} /
      {" "}{row.packageName ?? "Unmapped package"}
      {" · "}{row.version ?? "Unknown version"}</p>
    <p><strong>{row.category}</strong> — {row.reason}</p>
    <p>{explanation[row.category] ?? "Review this classification manually."}</p>
    {row.possibleAdvisoryIds.length > 0 && <p>
      Possible exact associations: {row.possibleAdvisoryIds.join(", ")}
    </p>}
    {row.unresolvedRangeIds.length > 0 && <p>
      Unevaluated ranges: {row.unresolvedRangeIds.join(", ")}
    </p>}
    {row.withdrawnIds.length > 0 && <p>
      Withdrawn records: {row.withdrawnIds.join(", ")}
    </p>}
    <details>
      <summary>Row fingerprint</summary>
      <code style={{ overflowWrap: "anywhere" }}>{row.fingerprint}</code>
    </details>
  </article>;
}
export function AssetOsvCorrelationWorkspace({ slug }: { slug: string }) {
  const api = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [imports, setImports] = useState<Import[]>([]);
  const [selectedImport, setSelectedImport] = useState("");
  const [feedText, setFeedText] = useState("");
  const [bindingsText, setBindingsText] = useState("");
  const [offset, setOffset] = useState(0);
  const [report, setReport] = useState<OsvResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [acknowledge, setAcknowledge] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState("ALL");
  const [refresh, setRefresh] = useState(0);
  const endpoint = useMemo(() => api + "/osv-candidates", [api]);
  useEffect(() => {
    let canceled = false;
    void request<ImportPage>(api + "/imports?includeRetired=true&limit=100", "GET")
      .then(result => {
        if (!canceled) setImports(result.imports);
      }).catch(cause => {
        if (!canceled) setError(failure(cause));
      });
    return () => { canceled = true; };
  }, [api, refresh]);
  function invalidate() {
    setReport(null);
    setOffset(0);
    setAcknowledge(false);
    setError(null);
  }
  function useExample() {
    setFeedText(JSON.stringify(sampleRecords, null, 2));
    setBindingsText(JSON.stringify(sampleBindings, null, 2));
    invalidate();
  }
  async function loadJsonFile(file: File | undefined,
    update: (value: string) => void) {
    if (!file) return;
    if (file.size > 900000) {
      setError("Source file exceeds the 900 KiB browser import limit.");
      return;
    }
    try {
      const text = await file.text();
      update(text);
      invalidate();
    } catch (cause) {
      setError(failure(cause));
    }
  }
  async function inspect(pageOffset = offset) {
    if (!selectedImport || !acknowledge || busy) return;
    let feed: unknown, packageBindings: unknown;
    try {
      feed = JSON.parse(feedText);
      packageBindings = JSON.parse(bindingsText);
    } catch {
      setError("Both the feed export and the mapping must be valid JSON.");
      return;
    }
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const result = await request<OsvResponse>(endpoint, "POST", {
        importId: selectedImport,
        feed, packageBindings,
        offset: pageOffset, limit: 50,
      });
      setOffset(pageOffset);
      setReport(result);
    } catch (cause) {
      setError(failure(cause));
    } finally {
      setBusy(false);
    }
  }
  const visible = report?.report.candidates.filter(row =>
    selectedCategory === "ALL" || row.category === selectedCategory) ?? [];
  const available = report ? Object.keys(
    report.report.summary.byClassification) : [];
  return <section aria-label="OSV asset candidate inspection"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>OSV advisory correlation — declared sources</h2>
    <p>Evaluate customer-supplied OSV records against a declared asset
      inventory. Only explicitly mapped packages and enumerated affected
      versions can produce a possible match. No live vulnerability queries,
      endpoint agents or scanners are used.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Evaluating declared OSV records…</p>}
    <fieldset disabled={busy}>
      <legend>Read-only evaluation inputs</legend>
      <label>Asset inventory snapshot
        <select value={selectedImport} onChange={event => {
          setSelectedImport(event.target.value);
          invalidate();
        }}>
          <option value="">Select an inventory</option>
          {imports.map(item => <option key={item.id} value={item.id}>
            {item.sourceLabel} · {item.importedCount} observations
            {" · "}{item.state} · {item.id}
          </option>)}
        </select>
      </label>
      <button type="button" onClick={() => setRefresh(x => x + 1)}>
        Refresh snapshot list
      </button>
      <p>Provide a JSON object containing sourceLabel, sourceVersion,
        retrievedAt and records in OSV format. A file that resembles the
        OSV schema is not independently authenticated by this feature.</p>
      <label>OSV export JSON file
        <input type="file" accept=".json,application/json"
          onChange={event => void loadJsonFile(
            event.target.files?.[0], setFeedText)} />
      </label>
      <label>OSV export JSON
        <textarea value={feedText} rows={9} maxLength={900000}
          onChange={event => {
            setFeedText(event.target.value);
            invalidate();
          }}
          placeholder="Paste an OSV-shaped export" />
      </label>
      <p>Provide an array of explicit product bindings with inventoryProduct,
        ecosystem, packageName and optional expectedPurl. Names cannot be
        inferred from ambiguous matches.</p>
      <label>Explicit package binding JSON file
        <input type="file" accept=".json,application/json"
          onChange={event => void loadJsonFile(
            event.target.files?.[0], setBindingsText)} />
      </label>
      <label>Explicit package bindings JSON
        <textarea value={bindingsText} rows={7} maxLength={900000}
          onChange={event => {
            setBindingsText(event.target.value);
            invalidate();
          }}
          placeholder="Paste reviewed package mappings" />
      </label>
      <button type="button" onClick={useExample}>Load synthetic example</button>
      <label>
        <input type="checkbox" checked={acknowledge}
          onChange={event => setAcknowledge(event.target.checked)} />
        I understand the source and mappings are provided by the operator.
        Results cannot certify device vulnerability or safety.
      </label>
      <button type="button" disabled={!selectedImport || !feedText.trim() ||
        !bindingsText.trim() || !acknowledge}
        onClick={() => void inspect(0)}>
        Evaluate candidates (no writes)
      </button>
    </fieldset>
    {report && <section>
      <h3>Evaluation — {report.importSource}</h3>
      <p>Import: <code>{report.importId}</code>,
        state {report.importState}, created {timestamp(report.importCreatedAt)}.</p>
      <p>Feed provenance: <strong>{report.feedProvenance}</strong>.
        Source: {report.report.feed.sourceLabel},
        version: {report.report.feed.sourceVersion},
        retrieved {timestamp(report.report.feed.retrievedAt)}.
      </p>
      <p>Rows: {report.report.totalRows}
        {" · "}OSV records: {report.report.feed.recordCount}
        {" · "}Explicit bindings: {report.report.bindingCount}
        {" · "}Report complete on this page: {report.report.complete ? "Yes" : "No"}
      </p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))",
      }}>
        <DataMetric title="Exact possible associations"
          count={report.report.summary.possibleAssociations}/>
        <DataMetric title="Unmapped product rows"
          count={report.report.summary.unmappedRows}/>
        <DataMetric title="Unknown version rows"
          count={report.report.summary.unknownVersions}/>
        <DataMetric title="Rows with unevaluated ranges"
          count={report.report.summary.unresolvedRanges}/>
        <DataMetric title="Rows with withdrawn records"
          count={report.report.summary.withdrawnRecords}/>
        <DataMetric title="No exact enumerated match"
          count={report.report.summary.noExactMatches}/>
      </div>
      <details>
        <summary>Report and feed digests</summary>
        <p>Report: <code style={{ overflowWrap: "anywhere" }}>
          {report.report.digest}</code></p>
        <p>Feed: <code style={{ overflowWrap: "anywhere" }}>
          {report.report.feed.digest}</code></p>
      </details>
      <label>Filter displayed classification
        <select value={selectedCategory}
          onChange={event => setSelectedCategory(event.target.value)}>
          <option value="ALL">All results on current page</option>
          {available.map(category => <option key={category} value={category}>
            {category}
          </option>)}
        </select>
      </label>
      <p>{visible.length} visible rows on this page. Summary counters
        cover all observations in the selected inventory.</p>
      {visible.map(row => <CandidateRow
        key={row.externalId + ":" + row.softwareName} row={row}/>)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={busy || offset === 0}
          onClick={() => void inspect(Math.max(0, offset - 50))}>
          Previous results</button>
        <button type="button" disabled={busy || !report.report.hasMore}
          onClick={() => void inspect(offset + 50)}>Next results</button>
      </div>
      <details>
        <summary>Interpretation and source limits</summary>
        <ul>{report.report.warnings.map(text =>
          <li key={text}>{text}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
