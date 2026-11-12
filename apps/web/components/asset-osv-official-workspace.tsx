"use client";

import { useEffect, useMemo, useState } from "react";

type ImportRow = {
  id: string;
  state: string;
  sourceLabel: string;
  importedCount: number;
  createdAt: string;
};
type ImportPage = { imports: ImportRow[]; total: number };
type Work = {
  key: string;
  ecosystem: string;
  name: string;
  version: string;
  expectedPurl: string | null;
  observationCount: number;
  identifiers: string[];
};
type Plan = {
  inventoryRows: number;
  mappedRows: number;
  unmappedRows: number;
  invalidVersionRows: number;
  actionablePackages: number;
  selectedPackages: number;
  skippedPackages: number;
  allRowsAccountedFor: boolean;
  work: Work[];
  warnings: string[];
};
type QueryRow = {
  key: string;
  ecosystem: string;
  name: string;
  version: string;
  observationCount: number;
  status: string;
  checkedAt: string | null;
  digest: string | null;
  possibleIds: string[];
  providerOnlyIds: string[];
  withdrawnIds: string[];
  unresolvedIds: string[];
  queriedPages: number;
  warnings: string[];
};
type Inspection = {
  schema: string;
  generatedAt: string;
  importId: string;
  providerOrigin: string;
  inventoryOrigin: string;
  status: string;
  coverage: string;
  dryRun: boolean;
  plan: Plan;
  results: QueryRow[];
  queriesAttempted: number;
  queriesCompleted: number;
  totalPossibleAssociations: number;
  totalProviderOnlyAssociations: number;
  totalUnresolved: number;
  totalWithdrawn: number;
  reportDigest: string;
  warnings: string[];
};
type State = "IDLE" | "PREVIEW" | "FETCH";
const sampleMappings = JSON.stringify([
  {
    inventoryProduct: "Example Package",
    ecosystem: "npm",
    packageName: "example-package",
  },
], null, 2);
function failure(value: unknown) {
  return value instanceof Error ? value.message : "Unknown provider error.";
}
async function request<T>(
  url: string, method: "GET" | "POST", body?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ? { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(body) } : {}),
  });
  const json: unknown = await response.json();
  if (!response.ok) {
    const data = json as { error?: string };
    throw new Error(data.error ?? "HTTP " + response.status);
  }
  return json as T;
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    padding: 10, border: "1px solid #8885", borderRadius: 8,
  }}>
    <strong>{value}</strong><div>{label}</div>
  </div>;
}
function PackageResult({ result }: { result: QueryRow }) {
  return <article style={{
    padding: 12, border: "1px solid #8885", borderRadius: 8,
    marginBlock: 8,
  }}>
    <h4>{result.ecosystem}/{result.name} · {result.version}</h4>
    <p>Provider result: <strong>{result.status}</strong>.
      {" "}{result.observationCount} declared observations associated
      with this package-version query.</p>
    <p>{result.queriedPages} OSV API response pages examined.</p>
    {result.possibleIds.length > 0 && <p>
      Literal affected-version associations:
      {" "}{result.possibleIds.join(", ")}
    </p>}
    {result.providerOnlyIds.length > 0 && <p>
      OSV-reported, not literally enumerated:
      {" "}{result.providerOnlyIds.join(", ")}
    </p>}
    {result.unresolvedIds.length > 0 && <p>
      Vulnerability ranges not interpreted locally:
      {" "}{result.unresolvedIds.join(", ")}
    </p>}
    {result.withdrawnIds.length > 0 && <p>
      Withdrawn records:
      {" "}{result.withdrawnIds.join(", ")}
    </p>}
    <details>
      <summary>Response digest and caveats</summary>
      <p><code style={{ overflowWrap: "anywhere" }}>
        {result.digest ?? "No response digest"}</code></p>
      <ul>{result.warnings.map((warning, i) =>
        <li key={i}>{warning}</li>)}</ul>
    </details>
  </article>;
}
export function AssetOfficialOsvWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const api = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [imports, setImports] = useState<ImportRow[]>([]);
  const [importId, setImportId] = useState("");
  const [bindingsText, setBindingsText] = useState("");
  const [maxPackages, setMaxPackages] = useState(10);
  const [pages, setPages] = useState(2);
  const [records, setRecords] = useState(50);
  const [maxAge, setMaxAge] = useState(60);
  const [approved, setApproved] = useState(false);
  const [preview, setPreview] = useState<Inspection | null>(null);
  const [completed, setCompleted] = useState<Inspection | null>(null);
  const [state, setState] = useState<State>("IDLE");
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const hasPreview = preview !== null &&
    preview.importId === importId && preview.dryRun === true;
  const basePayload = useMemo(() => ({
    importId, limitPackages: maxPackages,
    maxPagesPerPackage: pages, maxRecordsPerPackage: records,
    maxAgeMinutes: maxAge,
  }), [importId, maxPackages, pages, records, maxAge]);
  useEffect(() => {
    if (!canManage) return;
    let canceled = false;
    void request<ImportPage>(api + "/imports?limit=100", "GET")
      .then(data => { if (!canceled) setImports(data.imports); })
      .catch(cause => { if (!canceled) setError(failure(cause)); });
    return () => { canceled = true; };
  }, [api, canManage, reload]);
  function invalidate() {
    setPreview(null);
    setCompleted(null);
    setApproved(false);
    setError(null);
  }
  async function readFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 50000) {
      setError("Package binding JSON must be under 50 KiB.");
      return;
    }
    try {
      const content = await file.text();
      setBindingsText(content);
      invalidate();
    } catch (cause) {
      setError(failure(cause));
    }
  }
  async function execute(dryRun: boolean) {
    if (!canManage || state !== "IDLE" || !importId || !bindingsText.trim())
      return;
    if (!dryRun && (!approved || !hasPreview || preview.plan.selectedPackages < 1))
      return;
    let packageBindings: unknown;
    try {
      packageBindings = JSON.parse(bindingsText);
    } catch {
      setError("Package bindings must be valid JSON.");
      return;
    }
    setState(dryRun ? "PREVIEW" : "FETCH");
    setError(null);
    if (dryRun) {
      setPreview(null);
      setCompleted(null);
      setApproved(false);
    }
    try {
      const result = await request<Inspection>(api + "/osv-official", "POST", {
        ...basePayload, packageBindings, dryRun,
      });
      if (dryRun) {
        setPreview(result);
      } else {
        setCompleted(result);
        setApproved(false);
      }
    } catch (cause) {
      setError(failure(cause));
    } finally {
      setState("IDLE");
    }
  }
  if (!canManage) return null;
  return <section aria-label="OSV official source inspection"
    style={{
      border: "1px solid #8885", padding: 16, borderRadius: 12,
      marginBlock: 20,
    }}>
    <h2>OSV.dev — official API inspection</h2>
    <p>Administrator-only, read-only HTTPS request to
      {" "}https://api.osv.dev/v1/query. This is an actual provider
      lookup when authorized, not a simulated feed. Only reviewed
      ecosystem, package and version fields are transmitted.</p>
    <p>The provider may perform approximate version matching.
      CyberPilot separates literal affected-version entries from
      other OSV-reported vulnerabilities, and does not assert
      device compromise or confirmed remediation.</p>
    {error && <p role="alert">{error}</p>}
    {state !== "IDLE" && <p role="status">
      {state === "PREVIEW" ? "Planning without network requests…" :
        "Requesting bounded OSV API responses…"}
    </p>}
    <fieldset disabled={state !== "IDLE"}>
      <legend>Official OSV query setup</legend>
      <label>Active asset snapshot
        <select value={importId}
          onChange={event => {
            setImportId(event.target.value); invalidate();
          }}>
          <option value="">Select inventory snapshot</option>
          {imports.filter(item => item.state === "COMMITTED")
            .map(item => <option key={item.id} value={item.id}>
              {item.sourceLabel} · {item.importedCount} observations
              {" · "}{item.id}
            </option>)}
        </select>
      </label>
      <button type="button" onClick={() => setReload(x => x + 1)}>
        Refresh imports
      </button>
      <label>Explicit product-to-package bindings (JSON)
        <textarea value={bindingsText} rows={7} maxLength={50000}
          onChange={event => {
            setBindingsText(event.target.value); invalidate();
          }}
          placeholder={sampleMappings} />
      </label>
      <label>Load reviewed JSON bindings file
        <input type="file" accept=".json,application/json"
          onChange={event => void readFile(event.target.files?.[0])} />
      </label>
      <button type="button" onClick={() => {
        setBindingsText(sampleMappings); invalidate();
      }}>Insert synthetic mapping example</button>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        <label>Maximum distinct package queries
          <select value={maxPackages} onChange={event => {
            setMaxPackages(Number(event.target.value)); invalidate();
          }}>
            {[1, 3, 5, 10, 20].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum pages per query
          <select value={pages} onChange={event => {
            setPages(Number(event.target.value)); invalidate();
          }}>
            {[1, 2, 3].map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum records per query
          <select value={records} onChange={event => {
            setRecords(Number(event.target.value)); invalidate();
          }}>
            {[10, 25, 50, 100].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Freshness threshold in minutes
          <select value={maxAge} onChange={event => {
            setMaxAge(Number(event.target.value)); invalidate();
          }}>
            {[15, 30, 60, 120, 1440].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <button type="button" onClick={() => void execute(true)}
        disabled={!importId || !bindingsText.trim()}>
        Plan queries without contacting OSV
      </button>
    </fieldset>
    {preview && <section>
      <h3>Network-free query preview</h3>
      <p>{preview.plan.inventoryRows} observations inspected,
        {" "}{preview.plan.selectedPackages} distinct queries planned,
        {" "}{preview.plan.skippedPackages} omitted due to budget.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
      }}>
        <Metric label="Mapped rows" value={preview.plan.mappedRows}/>
        <Metric label="Unmapped rows" value={preview.plan.unmappedRows}/>
        <Metric label="Unknown version rows"
          value={preview.plan.invalidVersionRows}/>
        <Metric label="Planned queries"
          value={preview.plan.selectedPackages}/>
        <Metric label="Skipped distinct packages"
          value={preview.plan.skippedPackages}/>
      </div>
      <ol>{preview.plan.work.map(work =>
        <li key={work.key}>{work.ecosystem}/{work.name}
          {" "}{work.version} — {work.observationCount} observations
        </li>)}</ol>
      <details>
        <summary>Planning caveats</summary>
        <ul>{preview.plan.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
      <label>
        <input type="checkbox" checked={approved}
          onChange={event => setApproved(event.target.checked)} />
        I authorize transmitting the planned package names,
        ecosystem identities and versions to the OSV.dev API.
      </label>
      <button type="button" disabled={state !== "IDLE" ||
        !approved || preview.plan.selectedPackages === 0 || completed !== null}
        onClick={() => void execute(false)}>
        Fetch official OSV results
      </button>
    </section>}
    {completed && <section>
      <h3>Official OSV query results</h3>
      <p>Inspection: <strong>{completed.status}</strong>.
        {" "}{completed.queriesCompleted} complete responses of
        {" "}{completed.queriesAttempted} attempted.
        Origin: {completed.providerOrigin}.
        Coverage: {completed.coverage}.</p>
      <p>These are provider-reported associations, not
        verified endpoint exploitability or remediation status.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
      }}>
        <Metric label="Literal associations"
          value={completed.totalPossibleAssociations}/>
        <Metric label="Provider-only associations"
          value={completed.totalProviderOnlyAssociations}/>
        <Metric label="Unevaluated range associations"
          value={completed.totalUnresolved}/>
        <Metric label="Withdrawn records"
          value={completed.totalWithdrawn}/>
      </div>
      {completed.results.map(result =>
        <PackageResult key={result.key} result={result}/>)}
      <details>
        <summary>Report digest and limitations</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>
          {completed.reportDigest}</code></p>
        <ul>{completed.warnings.map(text =>
          <li key={text}>{text}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
