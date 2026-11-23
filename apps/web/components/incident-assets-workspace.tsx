"use client";
import { useEffect, useState } from "react";
type AssetRef = { id: string; importId: string; externalId: string;
  osName: string; osVersion: string | null; softwareName: string;
  softwareVersion: string | null; advisoryStatus: string;
  observedAt: string; confidence: string };
type ImportRef = { id: string; sourceLabel: string; state: string;
  importedCount: number };
type Inventory = { devices: AssetRef[]; imports: ImportRef[];
  nextOffset: number | null; total: number };
type Impact = { affectedDevices: Array<{ id: string; externalId: string;
  osName: string; outcome: string; advisoryStatus: string;
  matchBasis: string; warnings: string[] }>;
  reviewGate: string; coverage: string; findings: string[];
  missingDeviceIds: string[]; missingImportIds: string[];
  unknownVersionIds: string[]; staleDeviceIds: string[];
  highPriorityDeviceIds: string[];
  groups: Array<{ productKey: string; count: number;
    advisoryPossible: number; unknownCount: number }>;
  remoteDeviceIsolationVerified: false; riskReductionProven: false };
export function IncidentAssetsWorkspace({ slug, incidentId }: {
  slug: string; incidentId: string;
}) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/assets";
  const [inventory, setInventory] = useState<Inventory>({
    devices: [], imports: [], nextOffset: null, total: 0,
  });
  const [deviceIds, setDeviceIds] = useState<string[]>([]);
  const [importIds, setImportIds] = useState<string[]>([]);
  const [externalIds, setExternalIds] = useState<string[]>([]);
  const [hours, setHours] = useState(72);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [exposure, setExposure] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function load(offset = 0) {
    const params = new URLSearchParams({ limit: "30", offset: String(offset) });
    const response = await fetch(endpoint + "?" + params, { cache: "no-store" });
    const body = await response.json();
    if (!response.ok) throw Error(body.code ?? "ASSET_INVENTORY_UNAVAILABLE");
    const next = body.data as Inventory;
    setInventory(previous => offset ? {
      ...next, devices: [...previous.devices,
        ...next.devices.filter(x => !previous.devices.some(y => y.id === x.id))],
    } : next);
  }
  useEffect(() => { void load().catch(e => setMessage(String(e))); }, [endpoint]);
  function toggle(value: string, selected: string[], update: (x: string[]) => void) {
    update(selected.includes(value) ? selected.filter(x => x !== value) :
      [...selected, value]);
    setImpact(null);
  }
  async function review(exposureOnly = false) {
    setBusy(true);
    try {
      const response = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incidentId, deviceIds,
          importIds: exposureOnly ? [] : importIds,
          externalIds: exposureOnly ? [] : externalIds,
          freshnessHours: hours, ...(exposureOnly ? { exposure: true } : {}),
        }),
      });
      const body = await response.json();
      if (!response.ok) throw Error(body.code ?? "ASSET_IMPACT_READ_FAILED");
      if (exposureOnly) setExposure(body.data);
      else setImpact(body.data.impact as Impact);
      setMessage("Se inspeccionó el inventario almacenado; no se aisló ningún dispositivo.");
    } catch (e) { setMessage(String(e)); }
    finally { setBusy(false); }
  }
  return <section aria-label="Impacto de activos del incidente">
    <p role="note">Selección expresa de dispositivos e importaciones.
      El inventario no permite atribuir un dispositivo físico, una persona
      o un ataque únicamente por coincidencia de identificadores o nombres.</p>
    <h3>Activos inventariados</h3>
    <p>Filas totales del inventario: {inventory.total}.
      La selección no inicia una sincronización.</p>
    <ul>{inventory.devices.map(device => <li key={device.id}>
      <label><input type="checkbox" checked={deviceIds.includes(device.id)}
        onChange={() => toggle(device.id, deviceIds, setDeviceIds)}/>
        {device.externalId} — {device.osName} {device.osVersion ?? "version UNKNOWN"}
        {" "}({device.advisoryStatus})
      </label>
    </li>)}</ul>
    {inventory.nextOffset !== null && <button type="button"
      disabled={busy} onClick={() => void load(inventory.nextOffset!)
        .catch(e => setMessage(String(e)))}>Más dispositivos</button>}
    <h3>Importaciones disponibles</h3>
    <ul>{inventory.imports.map(item => <li key={item.id}>
      <label><input type="checkbox" checked={importIds.includes(item.id)}
        onChange={() => toggle(item.id, importIds, setImportIds)}/>
        {item.sourceLabel}: {item.state} ({item.importedCount} dispositivos)
      </label>
    </li>)}</ul>
    <label>Identificadores externos explícitos, separados por comas
      <textarea value={externalIds.join(", ")} onChange={e =>
        setExternalIds(e.target.value.split(",").map(x => x.trim())
          .filter(Boolean).slice(0, 150))} rows={2}/>
    </label>
    <label>Máxima edad en horas
      <input type="number" min={1} max={8760} value={hours}
        onChange={e => setHours(Number(e.target.value))}/>
    </label>
    <p>Dispositivos elegidos: {deviceIds.length}.
      Importaciones elegidas: {importIds.length}.
      Identificadores externos: {externalIds.length}.</p>
    <button disabled={busy} type="button" onClick={() => void review()}>
      Revisar impacto sobre inventario y OSV
    </button>
    <button disabled={busy || deviceIds.length === 0} type="button"
      onClick={() => void review(true)}>
      Analizar exposición de dispositivos seleccionados
    </button>
    {impact && <section aria-label="Resultado del impacto">
      <h3>Estado: {impact.reviewGate}</h3>
      <p>Cobertura: {impact.coverage}.
        Aislamiento remoto confirmado: NO.</p>
      <p>Activos afectados explícitamente: {impact.affectedDevices.length}.
        Versiones desconocidas: {impact.unknownVersionIds.length}.
        Observaciones caducadas: {impact.staleDeviceIds.length}.
        Revisiones prioritarias: {impact.highPriorityDeviceIds.length}.</p>
      <ul>{impact.findings.map(x => <li key={x}>{x}</li>)}</ul>
      <h4>Dispositivos correlacionados</h4>
      <ul>{impact.affectedDevices.map(device => <li key={device.id}>
        {device.externalId}: {device.outcome} — {device.matchBasis}
        <p>{device.warnings.join("; ") || "Sin avisos adicionales"}.</p>
      </li>)}</ul>
      <h4>Productos y avisos</h4>
      <ul>{impact.groups.map(group => <li key={group.productKey}>
        {group.productKey}: {group.count} registros;
        {group.advisoryPossible} con avisos pendientes.
      </li>)}</ul>
    </section>}
    {exposure && <details open><summary>Exposición conservadora</summary>
      <pre>{JSON.stringify(exposure, null, 2)}</pre>
    </details>}
    <p role="status">{message}</p>
  </section>;
}
