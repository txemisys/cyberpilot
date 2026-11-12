"use client";

import { useEffect, useMemo, useState } from "react";

type PreviewRow = {
  assetId: string;
  hostname: string | null;
  platform: string;
  osName: string;
  osVersion: string | null;
  softwareName: string;
  softwareVersion: string | null;
  observedAt: string;
  versionStatus: string;
  freshnessStatus: string;
  advisoryStatus: string;
  advisoryIds: string[];
  confidence: string;
};
type ImportReport = {
  schema: string;
  source: string;
  sourceLabel: string;
  declaredCount: number;
  importedCount: number;
  duplicateCount: number;
  unknownVersionCount: number;
  staleCount: number;
  futureCount: number;
  possibleAdvisoryCount: number;
  rows: PreviewRow[];
  digest: string;
  warnings: string[];
};
type ImportResponse = {
  dryRun: boolean;
  replayed: boolean;
  importId: string | null;
  state: string;
  report: ImportReport;
  limitations: string[];
};
type ImportSummary = {
  id: string;
  sourceLabel: string;
  state: string;
  declaredCount: number;
  importedCount: number;
  duplicateCount: number;
  unknownVersionCount: number;
  createdAt: string;
  retiredAt: string | null;
};
type ImportsPage = {
  total: number;
  hasMore: boolean;
  imports: ImportSummary[];
  limitations: string[];
};
type DeviceRow = {
  id: string;
  importId: string;
  externalId: string;
  hostname: string | null;
  platform: string;
  osName: string;
  osVersion: string | null;
  softwareName: string;
  softwareVersion: string | null;
  observedAt: string;
  versionStatus: string;
  freshnessStatus: string;
  advisoryStatus: string;
  advisoryIds: string[];
  confidence: string;
};
type DevicesPage = {
  total: number;
  hasMore: boolean;
  devices: DeviceRow[];
  limitations: string[];
};
type Mode = "IDLE" | "PREVIEW" | "COMMIT" | "READ" | "RETIRE";
const COLUMNS = [
  "asset_id", "hostname", "owner", "platform", "os_name", "os_version",
  "software_name", "software_version", "observed_at",
];
const SAMPLE = COLUMNS.join(",") + "\n" +
  "device-001,workstation-001,,WINDOWS,Windows 11,23H2,Example Editor,2.4.1,2026-11-01T12:00:00.000Z\n";
function outcome(error: unknown) {
  return error instanceof Error ? error.message : "Asset operation unavailable.";
}
async function request<T>(url: string, method: "GET" | "POST" | "PATCH",
  payload?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, credentials: "same-origin", cache: "no-store",
    headers: method === "GET" ? { Accept: "application/json" } :
      { "Content-Type": "application/json", Accept: "application/json" },
    ...(method === "GET" ? {} : { body: JSON.stringify(payload) }),
  });
  const parsed: unknown = await response.json();
  if (!response.ok) {
    const data = parsed as { error?: string };
    throw new Error(data.error ?? "HTTP " + response.status);
  }
  return parsed as T;
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown timestamp" : date.toLocaleString();
}
function Metric({ name, value }: { name: string; value: number }) {
  return <div style={{ padding: 12, border: "1px solid #8885", borderRadius: 8 }}>
    <strong>{value}</strong><div>{name}</div>
  </div>;
}
export function AssetInventoryWorkspace({ slug, canManage }: {
  slug: string;
  canManage: boolean;
}) {
  const api = "/api/organizations/" + encodeURIComponent(slug) + "/assets";
  const [sourceLabel, setSourceLabel] = useState("Managed device export");
  const [csv, setCsv] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [state, setState] = useState<Mode>("IDLE");
  const [preview, setPreview] = useState<ImportResponse | null>(null);
  const [committed, setCommitted] = useState<ImportResponse | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [imports, setImports] = useState<ImportsPage | null>(null);
  const [devices, setDevices] = useState<DevicesPage | null>(null);
  const [importOffset, setImportOffset] = useState(0);
  const [deviceOffset, setDeviceOffset] = useState(0);
  const [selectedImport, setSelectedImport] = useState("");
  const [showRetired, setShowRetired] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [retireId, setRetireId] = useState("");
  const [retireReason, setRetireReason] = useState("");
  const [retireConfirmed, setRetireConfirmed] = useState(false);
  const importUrl = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(importOffset), limit: "20",
      includeRetired: String(showRetired),
    });
    return api + "/imports?" + params.toString();
  }, [api, importOffset, showRetired]);
  const deviceUrl = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(deviceOffset), limit: "50",
      includeRetired: String(showRetired),
    });
    if (selectedImport) params.set("importId", selectedImport);
    return api + "/devices?" + params.toString();
  }, [api, deviceOffset, showRetired, selectedImport]);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [nextImports, nextDevices] = await Promise.all([
          request<ImportsPage>(importUrl, "GET"),
          request<DevicesPage>(deviceUrl, "GET"),
        ]);
        if (!cancelled) {
          setImports(nextImports);
          setDevices(nextDevices);
        }
      } catch (cause) {
        if (!cancelled) setError(outcome(cause));
      }
    };
    void load();
    return () => { cancelled = true; };
  }, [importUrl, deviceUrl, refresh]);
  function invalidatePreview() {
    setPreview(null); setCommitted(null); setConfirmed(false);
    setIdempotencyKey("");
    setError(null);
  }
  function changeCsv(value: string) {
    setCsv(value);
    invalidatePreview();
  }
  async function loadFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 262144) {
      setError("CSV exceeds 256 KiB.");
      return;
    }
    const content = await file.text();
    changeCsv(content);
  }
  async function previewImport() {
    if (!canManage || state !== "IDLE") return;
    setError(null); setPreview(null); setCommitted(null); setConfirmed(false);
    const key = idempotencyKey || crypto.randomUUID();
    setIdempotencyKey(key);
    setState("PREVIEW");
    try {
      const result = await request<ImportResponse>(
        api + "/imports", "POST", {
          sourceLabel, idempotencyKey: key, csv, dryRun: true,
        });
      setPreview(result);
    } catch (cause) {
      setError(outcome(cause));
    } finally {
      setState("IDLE");
    }
  }
  async function commitImport() {
    if (!preview || !confirmed || state !== "IDLE" || !canManage) return;
    setError(null);
    setState("COMMIT");
    try {
      const result = await request<ImportResponse>(api + "/imports", "POST", {
        sourceLabel, idempotencyKey, csv, dryRun: false,
      });
      if (result.report.digest !== preview.report.digest)
        setError("Committed digest differs from preview. Inspect imported data.");
      setCommitted(result);
      setSelectedImport(result.importId ?? "");
      setImportOffset(0); setDeviceOffset(0);
      setRefresh(x => x + 1);
    } catch (cause) {
      setError(outcome(cause));
    } finally {
      setState("IDLE");
    }
  }
  async function retireImport() {
    if (!retireId || !retireConfirmed || state !== "IDLE" ||
        retireReason.trim().length < 12 || !canManage) return;
    setError(null);
    setState("RETIRE");
    try {
      await request(api + "/imports", "PATCH", {
        importId: retireId,
        reason: retireReason.trim(),
        expectedState: "COMMITTED",
      });
      setRetireId(""); setRetireReason(""); setRetireConfirmed(false);
      setRefresh(x => x + 1);
    } catch (cause) {
      setError(outcome(cause));
    } finally {
      setState("IDLE");
    }
  }
  const disabled = state !== "IDLE";
  return <section aria-label="Passive asset inventory"
    style={{ border: "1px solid #8885", padding: 16, borderRadius: 12 }}>
    <header>
      <h2>Assets — passive CSV inventory</h2>
      <p>Customer-declared inventory, without agents or network scanning.
        This does not prove a device is safe, patched or reachable.</p>
    </header>
    {error && <p role="alert">{error}</p>}
    {disabled && <p role="status">Processing {state.toLowerCase()}…</p>}
    {canManage && <section>
      <h3>Import asset observations</h3>
      <p>CSV header: <code>{COLUMNS.join(",")}</code></p>
      <div style={{ display: "grid", gap: 10 }}>
        <label>Import source label
          <input value={sourceLabel} maxLength={120}
            onChange={event => {
              setSourceLabel(event.target.value); invalidatePreview();
            }} disabled={disabled} />
        </label>
        <label>Import a local CSV file
          <input type="file" accept=".csv,text/csv"
            disabled={disabled}
            onChange={event =>
              void loadFile(event.target.files?.[0])} />
        </label>
        <label>CSV content (maximum 256 KiB)
          <textarea rows={6} value={csv} disabled={disabled}
            onChange={event => changeCsv(event.target.value)}
            placeholder={SAMPLE} />
        </label>
        <button type="button" disabled={disabled || !csv.trim()}
          onClick={() => void previewImport()}>Validate and preview</button>
      </div>
      {preview && <section>
        <h4>Preview — no data persisted</h4>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))",
          gap: 10,
        }}>
          <Metric name="Declared rows" value={preview.report.declaredCount} />
          <Metric name="Importable" value={preview.report.importedCount} />
          <Metric name="Duplicates" value={preview.report.duplicateCount} />
          <Metric name="Unknown versions" value={preview.report.unknownVersionCount} />
          <Metric name="Stale observations" value={preview.report.staleCount} />
          <Metric name="Possible CVE matches" value={preview.report.possibleAdvisoryCount} />
        </div>
        <p>Data origin: {preview.report.source}</p>
        <details>
          <summary>Preview digest and limitations</summary>
          <code style={{ overflowWrap: "anywhere" }}>{preview.report.digest}</code>
          <ul>{preview.report.warnings.map(w =>
            <li key={w}>{w}</li>)}</ul>
        </details>
        <ol>{preview.report.rows.slice(0, 25).map(row =>
          <li key={row.assetId + ":" + row.softwareName}>
            {row.assetId} · {row.osName} {row.osVersion ?? "unknown"}
            {" · "}{row.softwareName || "No software entry"}
            {" "}{row.softwareVersion ?? "unknown"}
            {" · "}{row.freshnessStatus}
          </li>)}</ol>
        {preview.report.rows.length > 25 &&
          <p>Only the first 25 preview rows are displayed.</p>}
        <label>
          <input type="checkbox" checked={confirmed}
            onChange={event => setConfirmed(event.target.checked)}
            disabled={disabled || committed !== null} />
          I confirm this inventory is declared data and authorize its storage.
        </label>
        <button type="button"
          disabled={disabled || !confirmed || committed !== null}
          onClick={() => void commitImport()}>Commit inventory snapshot</button>
      </section>}
      {committed && <p role="status">
        {committed.replayed ? "Existing import reused" : "Import persisted"}:
        {" "}{committed.importId} · {committed.report.importedCount} observations
      </p>}
    </section>}
    <section>
      <h3>Stored import snapshots</h3>
      <label>
        <input type="checkbox" checked={showRetired}
          onChange={event => {
            setShowRetired(event.target.checked);
            setImportOffset(0); setDeviceOffset(0);
          }} />
        Include retired snapshots
      </label>
      <button type="button" disabled={disabled}
        onClick={() => setRefresh(x => x + 1)}>Refresh inventory</button>
      <p>{imports?.total ?? 0} imported snapshots</p>
      <div style={{ display: "grid", gap: 10 }}>
        {imports?.imports.map(item => <article key={item.id}
          style={{ border: "1px solid #8885", borderRadius: 8, padding: 12 }}>
          <strong>{item.sourceLabel}</strong>
          <p>{item.state} · {formatDate(item.createdAt)}
            {" · "}{item.importedCount} rows
            {" · "}Duplicates: {item.duplicateCount}</p>
          <p><code>{item.id}</code></p>
          <button type="button" disabled={disabled}
            onClick={() => { setSelectedImport(item.id); setDeviceOffset(0); }}>
            View devices
          </button>
          {canManage && item.state === "COMMITTED" &&
            <button type="button" disabled={disabled}
              onClick={() => {
                setRetireId(item.id); setRetireReason("");
                setRetireConfirmed(false);
              }}>Retire snapshot</button>}
        </article>)}
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        <button type="button" disabled={disabled || importOffset === 0}
          onClick={() => setImportOffset(x => Math.max(0, x - 20))}>
          Previous imports</button>
        <button type="button" disabled={disabled || !imports?.hasMore}
          onClick={() => setImportOffset(x => x + 20)}>Next imports</button>
      </div>
      {retireId && canManage && <section>
        <h4>Retire snapshot {retireId}</h4>
        <p>Retirement hides a snapshot from ordinary queries but retains
          its audit history. This action does not erase personal data.</p>
        <label>Reason
          <textarea value={retireReason} rows={2}
            onChange={event => {
              setRetireReason(event.target.value);
              setRetireConfirmed(false);
            }} />
        </label>
        <label>
          <input type="checkbox" checked={retireConfirmed}
            onChange={event => setRetireConfirmed(event.target.checked)} />
          Confirm this snapshot should be retired.
        </label>
        <button type="button" disabled={disabled || !retireConfirmed ||
          retireReason.trim().length < 12}
          onClick={() => void retireImport()}>Retire snapshot</button>
      </section>}
    </section>
    <section>
      <h3>Stored asset observations</h3>
      {selectedImport && <p>Filtered import: {selectedImport}
        {" "}<button type="button" onClick={() => {
          setSelectedImport(""); setDeviceOffset(0);
        }}>Show all</button></p>}
      <p>{devices?.total ?? 0} matching observations</p>
      {devices?.devices.map(device => <article key={device.id}
        style={{ padding: 12, border: "1px solid #8885", marginBlock: 8,
          borderRadius: 8 }}>
        <strong>{device.hostname ?? device.externalId}</strong>
        <p>{device.platform} · {device.osName}
          {" "}{device.osVersion ?? "Unknown OS version"}</p>
        <p>{device.softwareName || "No software declared"}
          {" "}{device.softwareVersion ?? "Unknown software version"}</p>
        <p>Declared {formatDate(device.observedAt)}
          {" · "}{device.freshnessStatus}
          {" · "}{device.versionStatus}
          {" · "}Advisory: {device.advisoryStatus}</p>
        {device.advisoryIds.length > 0 &&
          <p>Possible associations: {device.advisoryIds.join(", ")}</p>}
        <small>{device.externalId} · {device.confidence}</small>
      </article>)}
      <div style={{ display: "flex", gap: 10 }}>
        <button type="button" disabled={disabled || deviceOffset === 0}
          onClick={() => setDeviceOffset(x => Math.max(0, x - 50))}>
          Previous devices</button>
        <button type="button" disabled={disabled || !devices?.hasMore}
          onClick={() => setDeviceOffset(x => x + 50)}>Next devices</button>
      </div>
      <ul>{devices?.limitations.map(note => <li key={note}>{note}</li>)}</ul>
    </section>
  </section>;
}
