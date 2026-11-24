"use client";

import { useCallback, useMemo, useState } from "react";
import type { TimelinePage, TimelineEvent, TimelineSource,
  TimelineIntegrity } from "../lib/incident-operational-timeline-domain";

import type { ForensicCaseReport } from "../lib/incident-timeline-forensics-domain";

type TimelineResponse = {
  page: TimelinePage;
  summary: { matchingTotal: number; displayed: number;
    categories: Array<{ source: TimelineSource; entries: number;
      uniqueInternalActors: number; lastAt: string | null;
      operations: Array<{ operation: string; count: number }> }> };
  warnings: string[];
  forensics: ForensicCaseReport;
  integrityLimitations: string[];
  providerWrites: 0;
};
const sources: TimelineSource[] = ["INCIDENT", "SITUATION_REVIEW",
  "TABLETOP_SESSION", "ASSURANCE_HANDOFF"];
const integrity: TimelineIntegrity[] = ["VERIFIED", "INCOMPLETE", "CONFLICT"];
const sourceLabels: Record<TimelineSource, string> = {
  INCIDENT: "Caso", SITUATION_REVIEW: "Revisión de situación",
  TABLETOP_SESSION: "Ejercicio tabletop",
  ASSURANCE_HANDOFF: "Asignación y escalado",
};
const statusLabels: Record<TimelineIntegrity, string> = {
  VERIFIED: "Verificado localmente",
  INCOMPLETE: "Evidencia insuficiente",
  CONFLICT: "Conflicto de integridad",
};
function formatTime(x: string | null) {
  if (!x) return "Sin eventos";
  const d = new Date(x);
  return Number.isNaN(d.getTime()) ? "Fecha no disponible" :
    d.toLocaleString("es-ES", { dateStyle: "short", timeStyle: "medium" });
}
function isPage(value: unknown): value is TimelineResponse {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<TimelineResponse>;
  return result.page?.schema === "cyberpilot.incident.timeline.page.v1" &&
    Array.isArray(result.page.entries) &&
    result.providerWrites === 0 && Array.isArray(result.warnings) &&
    result.forensics?.schema === "cyberpilot.incident.timeline.forensic-report.v1";
}
function eventLabel(e: TimelineEvent) {
  const state = e.priorState === null ? e.nextState :
    e.priorState + " → " + (e.nextState ?? "desconocido");
  return e.operation + (state ? " · " + state : "");
}
export function IncidentOperationalTimelineWorkspace({ slug }: {
  slug: string;
}) {
  const [incidentId, setIncidentId] = useState("");
  const [filterActor, setFilterActor] = useState("");
  const [filterOperation, setFilterOperation] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [selectedSources, setSources] = useState<TimelineSource[]>(sources);
  const [selectedIntegrity, setIntegrity] = useState<TimelineIntegrity[]>(integrity);
  const [limit, setLimit] = useState(25);
  const [page, setPage] = useState<TimelineResponse | null>(null);
  const [history, setHistory] = useState<TimelineEvent[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastQuery, setLastQuery] = useState<string | null>(null);
  const [activeRow, setActiveRow] = useState<string | null>(null);
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/operational-timeline";
  const buildQuery = useCallback((cursor?: string) => {
    const params = new URLSearchParams();
    params.set("incidentId", incidentId.trim());
    params.set("limit", String(limit));
    for (const source of selectedSources) params.append("source", source);
    for (const state of selectedIntegrity) params.append("integrity", state);
    if (filterActor.trim()) params.set("actorUserId", filterActor.trim());
    if (filterOperation.trim()) {
      params.set("operation", filterOperation.trim().toUpperCase());
    }
    if (from) params.set("from", new Date(from).toISOString());
    if (to) params.set("to", new Date(to).toISOString());
    if (cursor) params.set("cursor", cursor);
    return params;
  }, [incidentId, limit, selectedSources, selectedIntegrity,
    filterActor, filterOperation, from, to]);
  const queryValid = incidentId.trim().length >= 4 &&
    selectedSources.length > 0 && selectedIntegrity.length > 0 &&
    (!from || Number.isFinite(Date.parse(from))) &&
    (!to || Number.isFinite(Date.parse(to))) &&
    (!from || !to || from <= to);
  const load = useCallback(async (more = false) => {
    if (!queryValid || pending) return;
    setPending(true);
    setError(null);
    try {
      const params = buildQuery(more ? page?.page.nextCursor ?? undefined : undefined);
      const uri = base + "?" + params.toString();
      const response = await fetch(uri, { cache: "no-store",
        headers: { Accept: "application/json" } });
      const data: unknown = await response.json();
      if (!response.ok) {
        const code = data && typeof data === "object" &&
          "code" in data ? String(data.code) : "TIMELINE_FETCH_FAILED";
        throw Error(code);
      }
      if (!isPage(data)) throw Error("TIMELINE_RESPONSE_INVALID");
      if (data.page.organizationId !== page?.page.organizationId &&
          more && page !== null)
        throw Error("TIMELINE_TENANT_CHANGED");
      if (more && page && data.page.queryDigest !== page.page.queryDigest)
        throw Error("TIMELINE_CURSOR_SOURCE_CHANGED");
      setHistory(old => more ? [...old, ...data.page.entries] :
        data.page.entries);
      setPage(data);
      setLastQuery(params.toString());
    } catch (e) {
      setError(e instanceof Error ? e.message : "TIMELINE_UNAVAILABLE");
    } finally { setPending(false); }
  }, [base, buildQuery, page, pending, queryValid]);
  const allRows = useMemo(() => {
    const seen = new Set<string>();
    return history.filter(row => {
      const key = [row.source, row.sourceId, row.sourceRevision].join("/");
      if (seen.has(key)) return false;
      seen.add(key); return true;
    });
  }, [history]);
  const filtersChanged = page !== null && lastQuery !== null &&
    lastQuery !== buildQuery().toString() &&
    !lastQuery.startsWith(buildQuery().toString() + "&cursor=");
  const exportPage = (format: "json" | "csv") => {
    if (!queryValid) return;
    try {
      const params = buildQuery();
      params.set("format", format);
      params.set("download", "1");
      window.location.assign(base + "?" + params.toString());
    } catch { setError("TIMELINE_EXPORT_QUERY_INVALID"); }
  };
  return <section aria-label="Visor de línea temporal">
    <h2>Consultar incidente</h2>
    <p>Introduzca el identificador de un caso al que tenga acceso.
      Se excluyen las sesiones tabletop sin vinculación explícita.</p>
    <div className="form-grid">
      <label>Identificador del incidente
        <input value={incidentId} onChange={e => {
          setIncidentId(e.target.value); setPage(null); setHistory([]);
        }} maxLength={128} placeholder="ID del incidente" />
      </label>
      <label>Actor interno (opcional)
        <input value={filterActor} onChange={e =>
          setFilterActor(e.target.value)} maxLength={128}
          placeholder="ID de usuario" />
      </label>
      <label>Operación (opcional)
        <input value={filterOperation} onChange={e =>
          setFilterOperation(e.target.value)} maxLength={48}
          placeholder="ASSIGN, CREATE, ..." />
      </label>
      <label>Desde
        <input type="datetime-local" value={from} onChange={e =>
          setFrom(e.target.value)} />
      </label>
      <label>Hasta
        <input type="datetime-local" value={to} onChange={e =>
          setTo(e.target.value)} />
      </label>
      <label>Entradas por página
        <select value={limit} onChange={e => setLimit(Number(e.target.value))}>
          <option value={10}>10</option>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </label>
    </div>
    <fieldset>
      <legend>Fuentes registradas</legend>
      {sources.map(source =>
        <label key={source} style={{ marginRight: 16 }}>
          <input type="checkbox" checked={selectedSources.includes(source)}
            onChange={e => setSources(old => e.target.checked ?
              [...old, source] : old.filter(x => x !== source))} />
          {sourceLabels[source]}
        </label>)}
    </fieldset>
    <fieldset>
      <legend>Integridad</legend>
      {integrity.map(state =>
        <label key={state} style={{ marginRight: 16 }}>
          <input type="checkbox" checked={selectedIntegrity.includes(state)}
            onChange={e => setIntegrity(old => e.target.checked ?
              [...old, state] : old.filter(x => x !== state))} />
          {statusLabels[state]}
        </label>)}
    </fieldset>
    <div className="actions">
      <button type="button" onClick={() => void load(false)}
        disabled={!queryValid || pending}>{pending ? "Consultando..." :
          "Reconciliar eventos"}</button>
      <button type="button" onClick={() => exportPage("csv")}
        disabled={!queryValid || pending}>Exportar página CSV</button>
      <button type="button" onClick={() => exportPage("json")}
        disabled={!queryValid || pending}>Exportar página JSON</button>
    </div>
    {filtersChanged && <p role="status">Filtros modificados.
      Actualice la consulta antes de interpretar resultados.</p>}
    {error && <p role="alert">No fue posible consultar: {error}</p>}
    {page && <section aria-label="Resultado de conciliación">
      <h2>Integridad y cobertura</h2>
      <p role="status">{page.page.total} eventos coincidentes.
        Se muestran {allRows.length} registros internos.</p>
      <p><strong>Estado de la lectura:</strong> {page.page.completeness}.
        <strong> Integridad:</strong> {statusLabels[page.page.integrity]}.</p>
      <p>Digest de página: <code>{page.page.pageDigest}</code></p>
      {page.warnings.length > 0 && <details open>
        <summary>Advertencias ({page.warnings.length})</summary>
        <ul>{page.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
      </details>}
      <details>
        <summary>Auditoría forense del historial ({page.forensics.findings.length}
          {page.forensics.findingsTruncated ? "+": ""} hallazgos)</summary>
        <p><strong>Integridad local:</strong> {statusLabels[page.forensics.integrity]}.
          <strong> Registros aceptados:</strong> {page.forensics.acceptedEvents}.
          <strong> Registros rechazados:</strong> {page.forensics.rejectedEvents}.
          <strong> Expedientes:</strong> {page.forensics.ledgerCount}.</p>
        <p>La verificación local no acredita ejecución de acciones externas
          ni resultados independientes de proveedores.</p>
        <p>Huella del análisis: <code>{page.forensics.digest}</code></p>
        {page.forensics.findingsTruncated && <p role="alert">
          La lista de hallazgos se ha truncado. No interprete la tabla
          como una revisión completa.</p>}
        <table><thead><tr><th>Hallazgo</th><th>Fuente</th>
          <th>Revisión</th><th>Severidad</th><th>Detalle</th>
        </tr></thead><tbody>
          {page.forensics.findings.map((x, i) =>
            <tr key={x.code + "/" + x.sourceId + "/" + i}>
              <td>{x.code}</td><td>{x.source ?? "Inventario"}</td>
              <td>{x.revision ?? "—"}</td><td>{x.severity}</td>
              <td>{x.explanation}</td>
            </tr>)}
        </tbody></table>
        <h4>Conciliación de expedientes</h4>
        <table><thead><tr><th>Fuente</th><th>Expediente</th>
          <th>Revisiones observadas</th><th>Revisión esperada</th>
          <th>Estado</th></tr></thead><tbody>
          {page.forensics.ledgers.map(x =>
            <tr key={x.source + "/" + x.sourceId}>
              <td>{x.source}</td><td>{x.sourceId}</td>
              <td>{x.observedEvents}</td><td>{x.expectedRevision ?? "—"}</td>
              <td>{statusLabels[x.status]}</td>
            </tr>)}
        </tbody></table>
      </details>
      <h3>Fuentes incluidas</h3>
      <table><thead><tr><th>Fuente</th><th>Registros</th>
        <th>Incompletos</th><th>Conflictos</th><th>Último evento</th>
      </tr></thead><tbody>
        {page.page.sourceStatus.map(s => <tr key={s.source}>
          <td>{sourceLabels[s.source]}</td><td>{s.entries}</td>
          <td>{s.incomplete}</td><td>{s.conflicts}</td>
          <td>{formatTime(s.lastActivityAt)}</td>
        </tr>)}
      </tbody></table>
      <h3>Historial operativo</h3>
      <ol>{allRows.map(event => {
        const key = [event.source, event.sourceId,
          event.sourceRevision].join("/");
        const expanded = activeRow === key;
        return <li key={key}>
          <article>
            <h4>{sourceLabels[event.source]} · {formatTime(event.occurredAt)}</h4>
            <p>{eventLabel(event)}</p>
            <p><strong>Actor:</strong> {event.actorUserId}.
              <strong> Integridad:</strong> {statusLabels[event.sourceIntegrity]}.</p>
            <button type="button" onClick={() => setActiveRow(
              expanded ? null : key)} aria-expanded={expanded}>
              {expanded ? "Ocultar procedencia" : "Inspeccionar procedencia"}
            </button>
            {expanded && <dl>
              <dt>Fuente</dt><dd>{event.source}</dd>
              <dt>ID del registro</dt><dd>{event.sourceId}</dd>
              <dt>Revisión</dt><dd>{event.sourceRevision}</dd>
              <dt>ID del evento</dt><dd>{event.eventId}</dd>
              <dt>Digest anterior</dt><dd>{event.priorDigest ?? "No consta"}</dd>
              <dt>Digest posterior</dt><dd>{event.nextDigest}</dd>
              <dt>Digest del evento</dt><dd>{event.sourceEventDigest ??
                "No disponible"}</dd>
              <dt>Escrituras externas</dt><dd>0</dd>
            </dl>}
          </article>
        </li>;
      })}</ol>
      {allRows.length === 0 && <p>No hay eventos coincidentes con
        los filtros seleccionados. No implica ausencia de incidente.</p>}
      {page.page.nextCursor && <button type="button" disabled={pending}
        onClick={() => void load(true)}>Cargar más eventos</button>}
      <details>
        <summary>Límites de evidencia</summary>
        <ul>{page.integrityLimitations.map(x =>
          <li key={x}>{x}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
