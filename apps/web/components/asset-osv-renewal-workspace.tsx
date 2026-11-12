"use client";

import { useEffect, useMemo, useState } from "react";

type ImportRow = { id: string; state: string; sourceLabel: string; importedCount: number };
type InspectionRow = {
  id: string; inventoryImportId: string; completedAt: string;
  status: string; queryCount: number;
};
type RenewalDecision = {
  packageKey: string; ecosystem: string; packageName: string;
  version: string; classification: string; eligible: boolean;
  lastCheckedAt: string | null; lastProviderStatus: string | null;
  reason: string;
};
type RenewalPlan = {
  schema: string; organizationId: string; importId: string;
  sourceInspectionId: string; generatedAt: string;
  sourceCompletedAt: string; sourceStatus: string;
  selectedPackages: number; eligiblePackages: number;
  deferredPackages: number; missingPreviousPackages: number;
  unreviewedPackages: number; inventoryRows: number;
  unboundRows: number; invalidVersionRows: number;
  maximumHttpPages: number; capacityAvailable: boolean;
  quotaInspectionsRemaining: number; quotaRequestsRemaining: number;
  decisions: RenewalDecision[]; validForExecution: boolean;
  blockingReasons: string[];
  newPackagesApproved: boolean;
  partialInventoryApproved: boolean;
  planDigest: string; warnings: string[];
};
type RenewalDelta = {
  summary: {
    changed: number; unchanged: number; possibleAdded: number;
    possibleNoLongerListed: number; excludedPackages: number;
  };
  completeComparison: boolean;
  warnings: string[];
};
type RenewalOutcome = {
  schema: string; previousInspectionId: string;
  currentInspectionId: string; status: string;
  replayed: boolean; newReportDigest: string;
  previousReportDigest: string; comparison: RenewalDelta | null;
  completeComparison: boolean; warnings: string[];
};
type ImportPage = { imports: ImportRow[] };
type InspectionPage = { inspections: InspectionRow[] };
type Busy = "IDLE" | "PREVIEW" | "EXECUTING";
const exampleBindings = JSON.stringify([
  {
    inventoryProduct: "Example Package",
    ecosystem: "npm",
    packageName: "example-package",
  },
], null, 2);
async function request<T>(
  url: string, method: "GET" | "POST", payload?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, credentials: "same-origin", cache: "no-store",
    headers: method === "POST" ? {
      "Content-Type": "application/json",
      Accept: "application/json",
    } : { Accept: "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(payload) } : {}),
  });
  const value: unknown = await response.json();
  if (!response.ok) {
    const error = value as { error?: string };
    throw new Error(error.error ?? "OSV renewal HTTP " + response.status);
  }
  return value as T;
}
function errorText(value: unknown) {
  return value instanceof Error ? value.message : "OSV renewal unavailable.";
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 10,
  }}>
    <strong>{value}</strong><p>{label}</p>
  </div>;
}
function Decision({ value }: { value: RenewalDecision }) {
  return <article style={{
    marginBlock: 8, border: "1px solid #8885",
    borderRadius: 8, padding: 10,
  }}>
    <strong>{value.ecosystem}/{value.packageName} · {value.version}</strong>
    <p>{value.classification} · {value.eligible ?
      "Renewal eligible" : "Deferred (no provider query)"}</p>
    <p>{value.reason}</p>
    <p>Last provider status: {value.lastProviderStatus ?? "Not available"}.</p>
  </article>;
}
export function AssetOsvRenewalWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [imports, setImports] = useState<ImportRow[]>([]);
  const [inspections, setInspections] = useState<InspectionRow[]>([]);
  const [importId, setImportId] = useState("");
  const [sourceInspectionId, setSourceInspectionId] = useState("");
  const [bindings, setBindings] = useState("");
  const [freshnessMinutes, setFreshnessMinutes] = useState(1440);
  const [retryMinutes, setRetryMinutes] = useState(60);
  const [limitPackages, setLimitPackages] = useState(5);
  const [includeIncomplete, setIncludeIncomplete] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [allowNewPackages, setAllowNewPackages] = useState(false);
  const [allowIncompleteInventory, setAllowIncompleteInventory] = useState(false);
  const [preview, setPreview] = useState<RenewalPlan | null>(null);
  const [outcome, setOutcome] = useState<RenewalOutcome | null>(null);
  const [requestKey, setRequestKey] = useState("");
  const [busy, setBusy] = useState<Busy>("IDLE");
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const eligibleInspections = useMemo(() =>
    inspections.filter(item => item.inventoryImportId === importId),
  [inspections, importId]);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    void Promise.all([
      request<ImportPage>(base + "/imports?limit=100", "GET"),
      request<InspectionPage>(base + "/osv-inspections?limit=100", "GET"),
    ]).then(([a, b]) => {
      if (!cancelled) {
        setImports(a.imports);
        setInspections(b.inspections);
        setError(null);
      }
    }).catch(cause => {
      if (!cancelled) setError(errorText(cause));
    });
    return () => { cancelled = true; };
  }, [base, canManage, revision]);
  function reset() {
    setPreview(null);
    setOutcome(null);
    setConfirmed(false);
    setRequestKey("");
    setError(null);
  }
  function command(dryRun: boolean, packageBindings: unknown,
    key: string, planDigest: string | null) {
    return {
      sourceInspectionId,
      requestKey: key,
      inspection: {
        importId, packageBindings,
        limitPackages, maxPagesPerPackage: 2,
        maxRecordsPerPackage: 50, maxAgeMinutes: 60,
        dryRun,
      },
      policy: {
        freshnessMinutes, minimumRetryMinutes: retryMinutes,
        maximumQueriesPerDay: 200, maximumInspectionsPerDay: 20,
        maximumPackagesPerRun: limitPackages,
        historyWindowDays: 90, includeIncomplete,
      },
      dryRun, confirmOutbound: !dryRun,
      allowNewPackages, allowIncompleteInventory,
      expectedPlanDigest: planDigest,
    };
  }
  /**
   * Reviewed package mappings can be loaded from a local JSON file. The
   * browser does not upload the file itself; only validated mappings are
   * included in the eventual explicit preview request.
   */
  async function importBindingsFile(file: File | undefined) {
    if (!file || busy !== "IDLE") return;
    if (file.size > 50000) {
      setError("OSV renewal package mappings must be under 50 KiB.");
      return;
    }
    try {
      const source = await file.text();
      const decoded: unknown = JSON.parse(source);
      if (!Array.isArray(decoded) || decoded.length > 100) {
        setError("Mapping JSON must be an array of at most 100 entries.");
        return;
      }
      for (const item of decoded) {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          setError("Each mapping must be an object.");
          return;
        }
        const row = item as Record<string, unknown>;
        if (typeof row.inventoryProduct !== "string" ||
            typeof row.ecosystem !== "string" ||
            typeof row.packageName !== "string") {
          setError("Every mapping requires product, ecosystem and package name.");
          return;
        }
      }
      setBindings(JSON.stringify(decoded, null, 2));
      reset();
    } catch (cause) {
      setError(errorText(cause));
    }
  }
  async function plan() {
    if (busy !== "IDLE" || !importId || !sourceInspectionId ||
        !bindings.trim()) return;
    let parsed: unknown;
    try { parsed = JSON.parse(bindings); }
    catch {
      setError("Explicit package bindings must be valid JSON.");
      return;
    }
    const key = crypto.randomUUID();
    setRequestKey(key);
    setBusy("PREVIEW"); resetVisible();
    try {
      const result = await request<RenewalPlan>(
        base + "/osv-renewal", "POST",
        command(true, parsed, key, null));
      setPreview(result);
    } catch (cause) {
      setError(errorText(cause));
    } finally { setBusy("IDLE"); }
  }
  function resetVisible() {
    setError(null);
    setPreview(null);
    setOutcome(null);
    setConfirmed(false);
  }
  async function execute() {
    if (busy !== "IDLE" || !preview?.validForExecution ||
        !confirmed || !requestKey) return;
    let parsed: unknown;
    try { parsed = JSON.parse(bindings); }
    catch { setError("Invalid package bindings JSON."); return; }
    setBusy("EXECUTING"); setError(null);
    try {
      const result = await request<RenewalOutcome>(
        base + "/osv-renewal", "POST",
        command(false, parsed, requestKey, preview.planDigest));
      setOutcome(result);
      setConfirmed(false);
      setRevision(value => value + 1);
    } catch (cause) {
      setError(errorText(cause));
    } finally { setBusy("IDLE"); }
  }
  if (!canManage) return null;
  return <section aria-label="Controlled OSV inspection renewal"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>Controlled OSV inspection renewal</h2>
    <p>Re-check a prior OSV inspection only when the source package
      identities are explicitly mapped and due for review. This
      is a manually authorized operation, not a recurring schedule.
      An unchanged advisory does not establish endpoint security.</p>
    {error && <p role="alert">{error}</p>}
    {busy !== "IDLE" && <p role="status">
      {busy === "PREVIEW" ?
        "Checking inventory, freshness and budget without OSV calls…" :
        "Retrieving OSV advisories and recording the new inspection…"}
    </p>}
    <fieldset disabled={busy !== "IDLE"}>
      <legend>Renewal source and explicit package mappings</legend>
      <label>Active inventory
        <select value={importId} onChange={event => {
          setImportId(event.target.value);
          setSourceInspectionId(""); reset();
        }}>
          <option value="">Select source snapshot</option>
          {imports.filter(item => item.state === "COMMITTED")
            .map(item => <option key={item.id} value={item.id}>
              {item.sourceLabel} · {item.importedCount} rows
            </option>)}
        </select>
      </label>
      <label>Previous inspection
        <select value={sourceInspectionId} onChange={event => {
          setSourceInspectionId(event.target.value); reset();
        }}>
          <option value="">Select previous saved OSV inspection</option>
          {eligibleInspections.map(item =>
            <option key={item.id} value={item.id}>
              {item.completedAt} · {item.status} · {item.id}
            </option>)}
        </select>
      </label>
      <label>Approved product-to-package bindings JSON
        <textarea value={bindings} onChange={event => {
          setBindings(event.target.value); reset();
        }} rows={6} maxLength={50000} placeholder={exampleBindings}/>
      </label>
      <button type="button" onClick={() => {
        setBindings(exampleBindings); reset();
      }}>Insert synthetic mapping example</button>
      <label>Load reviewed JSON mapping file
        <input type="file" accept="application/json,.json"
          onChange={event => {
            void importBindingsFile(event.target.files?.[0]);
            event.target.value = "";
          }}/>
      </label>
      <p>The file is parsed locally; package mappings are transmitted
        only when requesting a preview or explicitly authorized renewal.</p>

      <div style={{
        display: "flex", flexWrap: "wrap", gap: 12,
      }}>
        <label>Freshness threshold
          <select value={freshnessMinutes} onChange={event => {
            setFreshnessMinutes(Number(event.target.value)); reset();
          }}>
            {[60, 360, 1440, 10080, 43200].map(n =>
              <option key={n} value={n}>{n} minutes</option>)}
          </select>
        </label>
        <label>Incomplete retry cooldown
          <select value={retryMinutes} onChange={event => {
            setRetryMinutes(Number(event.target.value)); reset();
          }}>
            {[15, 60, 180, 720, 1440].map(n =>
              <option key={n} value={n}>{n} minutes</option>)}
          </select>
        </label>
        <label>Maximum distinct packages
          <select value={limitPackages} onChange={event => {
            setLimitPackages(Number(event.target.value)); reset();
          }}>
            {[1, 3, 5, 10, 20].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={includeIncomplete}
          onChange={event => {
            setIncludeIncomplete(event.target.checked); reset();
          }}/>
        Permit retry of incomplete provider responses after cooldown
      </label>
      <label>
        <input type="checkbox" checked={allowNewPackages}
          onChange={event => {
            setAllowNewPackages(event.target.checked); reset();
          }}/>
        I explicitly approve querying new package/version identities not
        present in the historical OSV inspection.
      </label>
      <label>
        <input type="checkbox" checked={allowIncompleteInventory}
          onChange={event => {
            setAllowIncompleteInventory(event.target.checked); reset();
          }}/>
        I acknowledge that unmapped or ambiguous inventory rows will
        remain UNKNOWN rather than being considered vulnerability-free.
      </label>
      <button type="button" disabled={!importId ||
        !sourceInspectionId || !bindings.trim()}
        onClick={() => void plan()}>
        Preview renewal without contacting OSV
      </button>
      <button type="button" onClick={() => setRevision(n => n + 1)}>
        Reload saved inspections
      </button>
    </fieldset>
    {preview && <section>
      <h3>Renewal preview</h3>
      <p>Authorization status: <strong>{preview.validForExecution ?
        "ELIGIBLE" : "BLOCKED"}</strong>. Previous source:
        {" "}{preview.sourceStatus}. Quota inspected at
        {" "}{preview.generatedAt}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Selected packages" value={preview.selectedPackages}/>
        <Metric label="Due for refresh" value={preview.eligiblePackages}/>
        <Metric label="Deferred" value={preview.deferredPackages}/>
        <Metric label="Absent from source" value={preview.missingPreviousPackages}/>
        <Metric label="Unmapped inventory rows" value={preview.unboundRows}/>
        <Metric label="Max reserved HTTP pages" value={preview.maximumHttpPages}/>
        <Metric label="Available daily request pages"
          value={preview.quotaRequestsRemaining}/>
      </div>
      {(preview.missingPreviousPackages > 0 && !preview.newPackagesApproved) &&
        <p role="alert">New package identities require explicit opt-in above,
          followed by a fresh preview.</p>}
      {(preview.unboundRows + preview.invalidVersionRows > 0 &&
        !preview.partialInventoryApproved) &&
        <p role="alert">Incomplete inventory mapping requires explicit
          acknowledgment above before renewal.</p>}
      {preview.blockingReasons.length > 0 && <section role="alert">
        <h4>Execution is blocked for these reasons</h4>
        <ul>{preview.blockingReasons.map((reason, index) =>
          <li key={index}>{reason}</li>)}</ul>
      </section>}
      {preview.decisions.map(item =>
        <Decision key={item.packageKey} value={item}/>)}
      <details>
        <summary>Approval digest, warnings and completeness</summary>
        <p><code style={{ overflowWrap: "anywhere" }}>
          {preview.planDigest}</code></p>
        <ul>{preview.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
      <label>
        <input type="checkbox" checked={confirmed}
          disabled={!preview.validForExecution || busy !== "IDLE"}
          onChange={event => setConfirmed(event.target.checked)}/>
        I authorize the selected package/version metadata to be
        sent to OSV.dev, consuming reserved daily quota and saving
        the historical result for this organization.
      </label>
      <button type="button" disabled={!confirmed ||
        !preview.validForExecution || busy !== "IDLE" || outcome !== null}
        onClick={() => void execute()}>
        Run authorized OSV renewal
      </button>
    </section>}
    {outcome && <section role="status">
      <h3>Renewal recorded</h3>
      <p>New inspection: <code>{outcome.currentInspectionId}</code>.
        {" "}Status: <strong>{outcome.status}</strong>.
        {" "}Replayed: {outcome.replayed ? "Yes" : "No"}.</p>
      <p>Comparison complete: {outcome.completeComparison ? "Yes" : "No"}.</p>
      {outcome.comparison && <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Provider changes"
          value={outcome.comparison.summary.changed}/>
        <Metric label="New literal associations"
          value={outcome.comparison.summary.possibleAdded}/>
        <Metric label="No longer listed (not remediated)"
          value={outcome.comparison.summary.possibleNoLongerListed}/>
        <Metric label="Incomparable packages"
          value={outcome.comparison.summary.excludedPackages}/>
      </div>}
      <details>
        <summary>Report digests and limitations</summary>
        <p>New report digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {outcome.newReportDigest}</code></p>
        <p>Prior report digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {outcome.previousReportDigest}</code></p>
        <ul>{outcome.warnings.map(warning =>
          <li key={warning}>{warning}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
