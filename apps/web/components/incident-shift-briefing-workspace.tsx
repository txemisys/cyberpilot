"use client";

import { useState } from "react";
import type { ShiftBriefing, ShiftWorkItem } from
  "../lib/incident-shift-briefing-domain";
type Response = {
  briefing: ShiftBriefing;
  workload: Array<{ role: string; openWork: number; urgentWork: number;
    evidenceRequirements: number }>;
  proofMatrix: Array<{ source: string; observedRecords: number;
    interpretation: string; providerReceipts: number }>;
  priorityQueue: ShiftWorkItem[];
  limitations: string[];
  persistedAcceptance: false;
  providerWrites: 0;
};
function isResponse(value: unknown): value is Response {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<Response>;
  return v.briefing?.schema === "cyberpilot.incident.shift.briefing.v1" &&
    Array.isArray(v.workload) && Array.isArray(v.proofMatrix) &&
    Array.isArray(v.priorityQueue) && v.persistedAcceptance === false &&
    v.providerWrites === 0;
}
export function IncidentShiftBriefingWorkspace({ slug }: { slug: string }) {
  const [incidentId, setIncidentId] = useState("");
  const [starts, setStarts] = useState("");
  const [ends, setEnds] = useState("");
  const [incomingRole, setIncomingRole] = useState(
    "OWNER" as "OWNER" | "ADMIN" | "AUDITOR");
  const [result, setResult] = useState<Response | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedTask, setExpandedTask] = useState<string | null>(null);
  const valid = /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(incidentId) &&
    !!starts && !!ends && Number.isFinite(Date.parse(starts)) &&
    Number.isFinite(Date.parse(ends)) && ends > starts &&
    Date.parse(ends) - Date.parse(starts) <= 7 * 86400000;
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/shift-briefing";
  function buildQuery(format?: "csv" | "json" | "md") {
    const q = new URLSearchParams();
    const from = new Date(starts).toISOString();
    const to = new Date(ends).toISOString();
    q.set("incidentId", incidentId.trim());
    q.set("shiftId", "shift-" + from.replace(/\D/g, "").slice(0, 14));
    q.set("startsAt", from);
    q.set("endsAt", to);
    q.set("incomingRole", incomingRole);
    if (format) {
      q.set("format", format);
      q.set("download", "1");
    }
    return base + "?" + q.toString();
  }
  async function load() {
    if (!valid || pending) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch(buildQuery(), {
        cache: "no-store", headers: { Accept: "application/json" },
      });
      const value: unknown = await response.json();
      if (!response.ok) {
        const code = value && typeof value === "object" &&
          "code" in value ? String(value.code) : "SHIFT_FETCH_FAILED";
        throw Error(code);
      }
      if (!isResponse(value)) throw Error("SHIFT_RESPONSE_INVALID");
      if (value.briefing.incidentId !== incidentId.trim())
        throw Error("SHIFT_RESPONSE_SCOPE_MISMATCH");
      setResult(value);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "SHIFT_UNAVAILABLE");
    } finally {
      setPending(false);
    }
  }
  function exportReport(format: "csv" | "json" | "md") {
    if (!valid || pending) return;
    window.location.assign(buildQuery(format));
  }
  return <section aria-label="Briefing de relevo interno">
    <h2>Definir ventana operativa</h2>
    <p>El briefing se genera para un caso y un turno concreto.
      No asigna usuarios, no confirma recepción ni ejecuta operaciones externas.</p>
    <div className="form-grid">
      <label>Identificador de incidente
        <input value={incidentId} maxLength={128}
          onChange={e => { setIncidentId(e.target.value); setResult(null); }}
          placeholder="ID del caso" />
      </label>
      <label>Inicio del turno
        <input type="datetime-local" value={starts}
          onChange={e => { setStarts(e.target.value); setResult(null); }} />
      </label>
      <label>Fin del turno
        <input type="datetime-local" value={ends}
          onChange={e => { setEnds(e.target.value); setResult(null); }} />
      </label>
      <label>Rol entrante propuesto
        <select value={incomingRole} onChange={e => {
          setIncomingRole(e.target.value as typeof incomingRole);
          setResult(null);
        }}>
          <option value="OWNER">Propietario</option>
          <option value="ADMIN">Administrador</option>
          <option value="AUDITOR">Auditor</option>
        </select>
      </label>
    </div>
    <button type="button" disabled={!valid || pending}
      onClick={() => void load()}>
      {pending ? "Conciliando fuentes..." : "Generar briefing"}
    </button>
    {!valid && <p role="status">Se requiere un identificador y una
      ventana válida de hasta siete días.</p>}
    {error && <p role="alert">{error}</p>}
    {result && <section aria-label="Relevo propuesto">
      <h2>Estado al relevo</h2>
      <p role="status">{result.briefing.activity.length} eventos en
        la ventana, {result.briefing.workItems.length} tareas propuestas y
        {result.briefing.watchpoints.length} avisos de revisión.</p>
      <p><strong>Confianza:</strong>
        {result.briefing.operationalConfidence}.
        <strong> Cobertura:</strong> {result.briefing.completeness}.</p>
      <p>Digest: <code>{result.briefing.digest}</code></p>
      <p>La aceptación NO está registrada.
        Ninguna acción de proveedor se ha ejecutado.</p>
      {(result.briefing.activityTruncated ||
        result.briefing.workTruncated ||
        result.briefing.watchpointsTruncated) && <p role="alert">
        Los resultados se han truncado; la vista no es exhaustiva.</p>}
      <div className="actions">
        <button type="button" onClick={() => exportReport("json")}>
          Exportar JSON</button>
        <button type="button" onClick={() => exportReport("csv")}>
          Exportar tareas CSV</button>
        <button type="button" onClick={() => exportReport("md")}>
          Exportar Markdown</button>
      </div>
      <h3>Alertas de turno</h3>
      <ol>{result.briefing.watchpoints.map(point =>
        <li key={point.id}><strong>{point.priority} · {point.category}</strong>
          <p>{point.explanation}</p>
          <p>Revisión sugerida: {point.recommendedRole}</p></li>)}</ol>
      <h3>Trabajo por rol</h3>
      <table><thead><tr><th>Rol</th><th>Pendientes</th>
        <th>Urgentes</th><th>Evidencias solicitadas</th>
      </tr></thead><tbody>
        {result.workload.map(role => <tr key={role.role}>
          <td>{role.role}</td><td>{role.openWork}</td>
          <td>{role.urgentWork}</td>
          <td>{role.evidenceRequirements}</td>
        </tr>)}
      </tbody></table>
      <h3>Tareas propuestas</h3>
      <ol>{result.priorityQueue.map(task =>
        <li key={task.id}><strong>{task.priority} · {task.category}</strong>
          <p>{task.explanation}</p>
          <p>Rol: {task.assignedRole} · Plazo interno propuesto:
            {task.dueAt}</p>
          <button type="button" aria-expanded={expandedTask === task.id}
            onClick={() => setExpandedTask(old =>
              old === task.id ? null : task.id)}>
            {expandedTask === task.id ? "Ocultar evidencia" :
              "Ver evidencia requerida"}
          </button>
          {expandedTask === task.id && <ul>
            {task.evidenceNeeded.map((e, i) =>
              <li key={i}>{e}</li>)}
          </ul>}
        </li>)}</ol>
      <h3>Fuentes de la lectura</h3>
      <table><thead><tr><th>Fuente</th><th>Eventos</th>
        <th>Última actividad</th><th>Cobertura</th>
      </tr></thead><tbody>{result.briefing.sourceInventory.map(x =>
        <tr key={x.source}><td>{x.source}</td>
          <td>{x.eventCount}</td><td>{x.latestAt ?? "No disponible"}</td>
          <td>{x.completeness}</td></tr>)}</tbody></table>
      <details><summary>Límites de evidencia y ejecución</summary>
        <ul>{[...result.briefing.limitations, ...result.limitations].map(
          (value, i) => <li key={i}>{value}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
