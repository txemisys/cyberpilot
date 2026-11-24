"use client";

import { useState } from "react";
import type { OperationalSlaPolicy,
  OperationalSlaSnapshot, SlaActorWorkload, SlaDailyBucket,
  SlaIncidentHealth, SlaForecast } from "../lib/incident-operational-sla-domain";

type Report = {
  schema: "cyberpilot.incident.operational-sla.report.v1";
  snapshot: OperationalSlaSnapshot;
  trends: SlaDailyBucket[];
  actors: SlaActorWorkload[];
  forecast: SlaForecast[];
  health: SlaIncidentHealth;
  internalQueue: Array<{ metricId: string; subjectId: string;
    disposition: string; outcome: string; action: string; dueAt: string | null }>;
  sourceWarnings: string[];
  sampledEvents: number;
  eventCollectionTruncated: boolean;
  providerWrites: 0;
};
const baseTargets = {
  firstReviewTargetMinutes: 60,
  firstAssignmentTargetMinutes: 120,
  firstEscalationTargetMinutes: 240,
  followupWarningMinutes: 60,
  priorityTargetsMinutes: { P0: 60, P1: 240, P2: 1440 },
};
const displayDate = (x: string | null) =>
  x ? new Date(x).toLocaleString("es-ES") : "Sin dato observado";
function validReport(x: unknown): x is Report {
  if (!x || typeof x !== "object") return false;
  const r = x as Partial<Report>;
  return r.schema === "cyberpilot.incident.operational-sla.report.v1" &&
    r.snapshot?.schema === "cyberpilot.incident.operational-sla.v1" &&
    r.providerWrites === 0 && Array.isArray(r.trends);
}
function numeric(value: string) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 && n <= 525600 ? n : null;
}
export function IncidentOperationalSlaWorkspace({ slug }: { slug: string }) {
  const [incidentId, setIncidentId] = useState("");
  const [policyId, setPolicyId] = useState("internal-review-policy-01");
  const [targets, setTargets] = useState(baseTargets);
  const [report, setReport] = useState<Report | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [auditJson, setAuditJson] = useState<string | null>(null);
  const route = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/operational-sla";
  const policy = (): OperationalSlaPolicy => ({
    schema: "cyberpilot.incident.internal-sla.policy.v1",
    policyId, effectiveAt: "2026-01-01T00:00:00.000Z",
    ...targets, businessCalendar: "ELAPSED_UTC",
    externalServiceGuarantee: false,
  });
  const send = async (mode: "report" | "audit") => {
    if (!incidentId.trim() || !policyId.trim() || pending) return;
    setPending(true); setError(null);
    try {
      const response = await fetch(route, {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId: incidentId.trim(),
          policy: policy(), mode }),
      });
      const body = await response.text();
      let value: unknown;
      try { value = JSON.parse(body); }
      catch { throw Error("SLA_RESPONSE_JSON_INVALID"); }
      if (!response.ok) {
        const err = value && typeof value === "object" &&
          "code" in value ? String(value.code) : "SLA_FETCH_FAILED";
        throw Error(err);
      }
      if (mode === "audit") {
        setAuditJson(body); return;
      }
      if (!validReport(value)) throw Error("SLA_RESPONSE_UNEXPECTED");
      setReport(value); setAuditJson(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "SLA_UNKNOWN_FAILURE");
    } finally { setPending(false); }
  };
  function targetInput(label: string, value: number,
    onChange: (v: number) => void) {
    return <label>{label} (minutos)
      <input type="number" min={1} max={525600} value={value}
        onChange={e => {
          const parsed = numeric(e.target.value);
          if (parsed !== null) onChange(parsed);
        }} />
    </label>;
  }
  return <section aria-label="Análisis de SLA interno">
    <h2>Objetivos operativos configurables</h2>
    <p>Valores iniciales ilustrativos, no son acuerdos contractuales ni
      plazos reales del proveedor. Modifique y documente la política antes
      de evaluar resultados internos.</p>
    <div className="form-grid">
      <label>ID del incidente
        <input value={incidentId} onChange={e => setIncidentId(e.target.value)}
          maxLength={128} placeholder="ID del caso" />
      </label>
      <label>Identificador de política
        <input value={policyId} onChange={e => setPolicyId(e.target.value)}
          maxLength={128} />
      </label>
      {targetInput("Primera revisión", targets.firstReviewTargetMinutes,
        v => setTargets(old => ({ ...old, firstReviewTargetMinutes: v })))}
      {targetInput("Primera asignación", targets.firstAssignmentTargetMinutes,
        v => setTargets(old => ({ ...old, firstAssignmentTargetMinutes: v })))}
      {targetInput("Primer escalado", targets.firstEscalationTargetMinutes,
        v => setTargets(old => ({ ...old, firstEscalationTargetMinutes: v })))}
      {targetInput("Aviso próximo vencimiento", targets.followupWarningMinutes,
        v => setTargets(old => ({ ...old, followupWarningMinutes: v })))}
      {(["P0", "P1", "P2"] as const).map(priority =>
        <div key={priority}>{targetInput("Asignación " + priority,
          targets.priorityTargetsMinutes[priority], v =>
          setTargets(old => ({ ...old,
            priorityTargetsMinutes: { ...old.priorityTargetsMinutes,
              [priority]: v } })))}</div>)}
    </div>
    <div className="actions">
      <button type="button" disabled={!incidentId.trim() || pending}
        onClick={() => void send("report")}>
        {pending ? "Calculando..." : "Calcular observabilidad interna"}</button>
      <button type="button" disabled={!incidentId.trim() || pending}
        onClick={() => void send("audit")}>
        Exportar evidencia de cálculo</button>
    </div>
    {error && <p role="alert">{error}</p>}
    {auditJson && <details open><summary>Envoltorio de auditoría</summary>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {auditJson}</pre></details>}
    {report && <section aria-label="Resultado SLA">
      <h2>Estado de atención interna</h2>
      <p role="status"><strong>{report.snapshot.signal}</strong> ·
        cobertura {report.snapshot.completeness} · integridad
        {report.snapshot.sourceIntegrity}</p>
      <p>Digest del análisis: <code>{report.snapshot.digest}</code></p>
      <p>{report.sampledEvents} eventos contabilizados.
        {report.eventCollectionTruncated ?
          " Inventario truncado: resultado incompleto." : ""}</p>
      <p><strong>Resultado de contención externa:</strong> desconocido.
        No se ha ejecutado ninguna acción sobre proveedores.</p>
      <h3>Indicadores de seguimiento</h3>
      <table><thead><tr><th>Indicador</th><th>Valor</th>
      </tr></thead><tbody>
        <tr><td>Vencidos</td><td>{report.snapshot.totals.overdue}</td></tr>
        <tr><td>Próximos a vencer</td>
          <td>{report.snapshot.totals.dueSoon}</td></tr>
        <tr><td>Desconocidos</td>
          <td>{report.snapshot.totals.unknown}</td></tr>
        <tr><td>Parciales</td><td>{report.snapshot.totals.partial}</td></tr>
        <tr><td>Handoffs sin asignar</td>
          <td>{report.snapshot.handoffSummary.unassigned}</td></tr>
        <tr><td>Handoffs sin aceptación</td>
          <td>{report.snapshot.handoffSummary.unacknowledged}</td></tr>
        <tr><td>Handoffs fuera del vencimiento explícito</td>
          <td>{report.snapshot.handoffSummary.pastExplicitDueAt}</td></tr>
        <tr><td>Escalados internos registrados</td>
          <td>{report.snapshot.handoffSummary.escalatedInternal}</td></tr>
      </tbody></table>
      <h3>Acciones de atención sugeridas</h3>
      {report.health.operatorAdvice.length ?
        <ul>{report.health.operatorAdvice.map(x =>
          <li key={x}>{x}</li>)}</ul> :
        <p>No hay avisos internos adicionales en esta muestra.</p>}
      <h3>Prioridades operativas</h3>
      <table><thead><tr><th>Asunto</th><th>Estado</th>
        <th>Vencimiento</th><th>Tratamiento propuesto</th>
      </tr></thead><tbody>
        {report.internalQueue.slice(0, 25).map(x =>
          <tr key={x.metricId + x.subjectId}>
            <td>{x.metricId}</td><td>{x.disposition} / {x.outcome}</td>
            <td>{displayDate(x.dueAt)}</td><td>{x.action}</td>
          </tr>)}
      </tbody></table>
      <h3>Ventanas de vencimiento</h3>
      <table><thead><tr><th>Horizonte</th><th>Próximos</th>
        <th>Vencidos</th><th>Siguiente fecha</th>
      </tr></thead><tbody>
        {report.forecast.map(f => <tr key={f.horizonMinutes}>
          <td>{f.horizonMinutes} min</td><td>{f.dueHandoffs}</td>
          <td>{f.alreadyOverdue}</td>
          <td>{displayDate(f.nextDeadlineAt)}</td>
        </tr>)}
      </tbody></table>
      <button type="button" onClick={() => setExpanded(x => !x)}
        aria-expanded={expanded}>
        {expanded ? "Ocultar detalle" : "Mostrar fuentes y tendencias"}
      </button>
      {expanded && <>
        <h3>Estado por fuente</h3>
        <table><thead><tr><th>Fuente</th><th>Eventos</th>
          <th>Incompletos</th><th>Conflictos</th>
        </tr></thead><tbody>{report.snapshot.sourceCoverage.map(s =>
          <tr key={s.source}><td>{s.source}</td>
            <td>{s.availableEntries}</td><td>{s.incompleteEntries}</td>
            <td>{s.conflicts}</td></tr>)}
        </tbody></table>
        <h3>Actividad diaria</h3>
        <table><thead><tr><th>Día</th><th>Fuente</th>
          <th>Eventos</th><th>Actores</th>
        </tr></thead><tbody>{report.trends.slice(-100).map(s =>
          <tr key={s.day + s.source}><td>{s.day}</td>
            <td>{s.source}</td><td>{s.events}</td>
            <td>{s.distinctActors}</td></tr>)}</tbody></table>
        <h3>Actores observados</h3>
        <table><thead><tr><th>Usuario</th><th>Acciones</th>
          <th>Fuentes</th><th>Incidencias de integridad</th>
        </tr></thead><tbody>{report.actors.slice(0, 30).map(a =>
          <tr key={a.userId}><td>{a.userId}</td>
            <td>{a.totalEvents}</td><td>{a.distinctSources}</td>
            <td>{a.uncertainEvidenceEvents}</td></tr>)}
        </tbody></table>
      </>}
      {report.sourceWarnings.length > 0 && <details>
        <summary>Limitaciones ({report.sourceWarnings.length})</summary>
        <ul>{report.sourceWarnings.map((x, i) =>
          <li key={i}>{x}</li>)}</ul>
      </details>}
    </section>}
  </section>;
}
