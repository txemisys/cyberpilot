"use client";

import { useMemo, useState } from "react";
import type {
  CorrelationReport, CorrelationGraph,
  CorrelationReviewRequest,
} from "../lib/incident-crosscase-correlation-domain";

type Response = {
  report: CorrelationReport;
  graph: CorrelationGraph;
  reviews: CorrelationReviewRequest[];
  limitations: string[];
  providerWrites: 0;
};
function valid(value: unknown): value is Response {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<Response>;
  return v.report?.schema === "cyberpilot.incident.correlation.report.v1" &&
    v.graph?.schema === "cyberpilot.incident.correlation.graph.v1" &&
    Array.isArray(v.reviews) && Array.isArray(v.limitations) &&
    v.providerWrites === 0;
}
const categories: Record<string, string> = {
  SHARED_ACTOR: "Actor interno compartido",
  REPEATED_OPERATION: "Operación repetida",
  COMMON_SOURCE_KEY: "Clave de fuente coincidente",
  NEARBY_ACTIVITY: "Proximidad temporal",
  REPEATED_FORENSIC_FINDING: "Anomalía forense común",
  JOINT_COVERAGE_GAP: "Cobertura insuficiente",
  SOURCE_CONFLICT_CLUSTER: "Conflictos de origen",
};
export function IncidentCrosscaseCorrelationWorkspace({ slug }: {
  slug: string;
}) {
  const [ids, setIds] = useState(["", ""]);
  const [result, setResult] = useState<Response | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showReview, setShowReview] = useState<string | null>(null);
  const selected = useMemo(() =>
    ids.map(x => x.trim()).filter(x => x !== ""), [ids]);
  const validSelection = selected.length >= 2 && selected.length <= 12 &&
    selected.every(x => /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x)) &&
    new Set(selected).size === selected.length;
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/crosscase-correlation";
  function url(format?: "json" | "csv") {
    const q = new URLSearchParams();
    for (const id of selected) q.append("incidentId", id);
    if (format) {
      q.set("format", format);
      q.set("download", "1");
    }
    return base + "?" + q.toString();
  }
  async function reconcile() {
    if (!validSelection || pending) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch(url(), {
        cache: "no-store", headers: { Accept: "application/json" },
      });
      const value: unknown = await response.json();
      if (!response.ok) {
        const code = value && typeof value === "object" &&
          "code" in value ? String(value.code) : "CORRELATION_FETCH_FAILED";
        throw Error(code);
      }
      if (!valid(value)) throw Error("CORRELATION_RESPONSE_INVALID");
      if (value.report.selectedIncidentIds.join("\0") !==
          [...selected].sort().join("\0"))
        throw Error("CORRELATION_RESPONSE_SELECTION_CHANGED");
      setResult(value);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "CORRELATION_UNAVAILABLE");
    } finally {
      setPending(false);
    }
  }
  function exportReport(format: "csv" | "json") {
    if (!validSelection || pending) return;
    window.location.assign(url(format));
  }
  return <section aria-label="Correlación explícita de incidentes">
    <h2>Selección de casos</h2>
    <p>Solo se consultarán los incidentes escritos aquí. Añada un mínimo
      de dos identificadores; no hay búsqueda del tenant completo.</p>
    <div className="form-grid">
      {ids.map((value, index) =>
        <label key={index}>Incidente {index + 1}
          <input value={value} maxLength={128}
            placeholder="Identificador de caso"
            onChange={e => {
              setIds(old => old.map((v, i) => i === index ?
                e.target.value : v));
              setResult(null);
            }} />
        </label>)}
    </div>
    <div className="actions">
      <button type="button" disabled={ids.length >= 12}
        onClick={() => { setIds(old => [...old, ""]); setResult(null); }}>
        Añadir incidente
      </button>
      <button type="button" disabled={ids.length <= 2}
        onClick={() => { setIds(old => old.slice(0, -1)); setResult(null); }}>
        Quitar último
      </button>
      <button type="button" disabled={!validSelection || pending}
        onClick={() => void reconcile()}>
        {pending ? "Reconciliando..." : "Examinar coincidencias"}
      </button>
    </div>
    {!validSelection && <p role="status">Introduzca entre 2 y 12 casos
      distintos y válidos, sin campos vacíos intermedios.</p>}
    {error && <p role="alert">{error}</p>}
    {result && <section aria-label="Resultado correlación">
      <h2>Candidatos de relación</h2>
      <p role="status">{result.report.findings.length} coincidencias visibles
        en {result.report.selectedIncidentIds.length} incidentes.
        No representan compromisos confirmados.</p>
      <p><strong>Cobertura:</strong> {result.report.completeness}.
        <strong> Huella:</strong> <code>{result.report.digest}</code></p>
      {result.report.resultsTruncated && <p role="alert">
        La selección ha superado la capacidad de resultados.
        El informe no ofrece cobertura exhaustiva.</p>}
      <div className="actions">
        <button type="button" onClick={() => exportReport("csv")}>
          Exportar CSV
        </button>
        <button type="button" onClick={() => exportReport("json")}>
          Exportar JSON
        </button>
      </div>
      <h3>Casos seleccionados</h3>
      <table><thead><tr><th>Caso</th><th>Eventos</th>
        <th>Integridad</th><th>Inventario completo</th>
        <th>Coincidencias</th></tr></thead><tbody>
        {result.report.cases.map(c => <tr key={c.incidentId}>
          <td>{c.incidentId}</td><td>{c.sourceEvents}</td>
          <td>{c.forensicIntegrity}</td>
          <td>{c.inventoryComplete ? "Sí" : "No confirmado"}</td>
          <td>{c.findingsLinked}</td>
        </tr>)}
      </tbody></table>
      <h3>Relaciones candidatas</h3>
      <table><thead><tr><th>Prioridad</th><th>Clase</th>
        <th>Incidentes</th><th>Explicación</th><th>Revisión</th>
      </tr></thead><tbody>
        {result.report.findings.map(f => {
          const review = result.reviews.find(r => r.findingId === f.id);
          return <tr key={f.id}>
            <td>{f.priority}</td><td>{categories[f.kind] ?? f.kind}</td>
            <td>{f.leftIncidentId} / {f.rightIncidentId}</td>
            <td>{f.explanation}</td>
            <td><button type="button" onClick={() =>
              setShowReview(old => old === f.id ? null : f.id)}
              aria-expanded={showReview === f.id}>
              {showReview === f.id ? "Ocultar" : "Examinar"}
            </button>
            {showReview === f.id && review && <div>
              <p><strong>Revisor sugerido:</strong>
                {review.suggestedReviewerRole}</p>
              <p>{review.question}</p>
              <ul>{review.requiredChecks.map((check, i) =>
                <li key={i}>{check}</li>)}</ul>
              <p>Sin confirmación de identidad ni ejecución externa.</p>
            </div>}</td>
          </tr>;
        })}
      </tbody></table>
      {!result.report.findings.length && <p>
        No hay coincidencias según estas reglas y esta selección.
        Esto no demuestra ausencia de una campaña relacionada.</p>}
      <h3>Agrupaciones de candidatos</h3>
      <ol>{result.graph.components.map(component =>
        <li key={component.index}>{component.incidentIds.join(", ")} ·
          {component.links} relaciones candidatas</li>)}</ol>
      <details><summary>Restricciones de interpretación</summary>
        <ul>{[...result.report.warnings, ...result.limitations].map(
          (value, i) => <li key={i}>{value}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
