"use client";

import { useMemo, useState } from "react";
import type {
  EscalationPolicy, EscalationPlan, EscalationRule,
  EscalationDispatch,
} from "../lib/incident-escalation-dispatch-domain";

type ReadResult = {
  plan: EscalationPlan;
  incidentRevision: number;
  incidentStatus: string;
  summary: { actionable: number; saturated: boolean; deferred: number };
  ownerWorkload: Array<{ owner: string; count: number; highPriority: number;
    overdue: number }>;
  assignments: Array<{ handoffId: string; boardId: string;
    eligibility: string; independentReviewNeeded: boolean }>;
  jobsAdmitted: 0;
  providerWrites: 0;
};
const stateOptions: EscalationRule["status"][] = [
  "UNASSIGNED", "ASSIGNED", "ACCEPTED", "NEEDS_EVIDENCE",
  "ESCALATED_INTERNAL", "REOPENED",
];
const triggerOptions: EscalationRule["trigger"][] = [
  "PAST_DUE", "DUE_SOON", "UNASSIGNED_AGE", "UNACCEPTED_AGE",
  "STALE_REVIEW", "MISSING_EVIDENCE",
];
const defaultRules: EscalationRule[] = [
  { id: "rule-p0-unassigned", priority: "P0", status: "UNASSIGNED",
    trigger: "UNASSIGNED_AGE", minimumAgeMinutes: 30,
    warningMinutes: 60, maximumFrequencyMinutes: 240,
    escalationLevel: 3, recommendedRole: "OWNER",
    requireIndependentReview: true },
  { id: "rule-p1-due", priority: "P1", status: "ASSIGNED",
    trigger: "PAST_DUE", minimumAgeMinutes: 60,
    warningMinutes: 60, maximumFrequencyMinutes: 240,
    escalationLevel: 2, recommendedRole: "ADMIN",
    requireIndependentReview: true },
  { id: "rule-p2-evidence", priority: "P2", status: "NEEDS_EVIDENCE",
    trigger: "MISSING_EVIDENCE", minimumAgeMinutes: 120,
    warningMinutes: 60, maximumFrequencyMinutes: 480,
    escalationLevel: 1, recommendedRole: "SECURITY_REVIEWER",
    requireIndependentReview: true },
];
function isResult(x: unknown): x is ReadResult {
  if (x === null || typeof x !== "object") return false;
  const v = x as Partial<ReadResult>;
  return v.plan?.schema === "cyberpilot.incident.escalation.plan.v1" &&
    Array.isArray(v.plan.dispatches) && v.providerWrites === 0 &&
    Number.isSafeInteger(v.incidentRevision);
}
function displayTime(x: string) {
  return new Date(x).toLocaleString("es-ES");
}
export function IncidentOperationalEscalationsWorkspace(props: {
  slug: string; canWrite: boolean;
}) {
  const { slug, canWrite } = props;
  const [incidentId, setIncidentId] = useState("");
  const [policyId, setPolicyId] = useState("internal-escalation-policy-01");
  const [rules, setRules] = useState<EscalationRule[]>(defaultRules);
  const [result, setResult] = useState<ReadResult | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const url = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/operational-escalations";
  const policy = useMemo<EscalationPolicy>(() => ({
    schema: "cyberpilot.incident.escalation.policy.v1",
    id: policyId, effectiveAt: "2026-01-01T00:00:00.000Z",
    rules, concurrencyPerTenant: 2, maxDispatchesPerCycle: 20,
    minReevaluationMinutes: 30, schedulingHorizonMinutes: 1440,
    riskAcceptedForInternalReadOnly: true,
    externalNotificationsAllowed: false, providerWritesAllowed: false,
  }), [rules, policyId]);
  const call = async (mode: "PLAN" | "ADMIT" | "EXPORT",
    dispatch?: EscalationDispatch) => {
    if (!incidentId.trim() || pending) return;
    setPending(true); setError(null); setSuccess(null);
    try {
      const response = await fetch(url, {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId: incidentId.trim(), policy,
          mode, format: "json",
          ...(dispatch && result ? {
            idempotencyKey: dispatch.idempotencyKey,
            boardDigest: dispatch.payload.boardDigest,
            expectedIncidentRevision: result.incidentRevision,
          } : {}) }),
      });
      const data: unknown = await response.json();
      if (!response.ok) {
        const code = data && typeof data === "object" &&
          "code" in data ? String(data.code) : "ESCALATION_FETCH_FAILED";
        throw Error(code);
      }
      if (mode === "EXPORT") {
        setExported(JSON.stringify(data, null, 2)); return;
      }
      if (mode === "ADMIT") {
        const receipt = data as { job?: { id?: string }; created?: boolean };
        setSuccess("Trabajo interno " +
          (receipt.created ? "admitido" : "ya registrado") +
          " · " + (receipt.job?.id ?? "ID no disponible"));
        setSelected(null); return;
      }
      if (!isResult(data)) throw Error("ESCALATION_RESPONSE_INVALID");
      setResult(data); setSelected(null); setExported(null);
    } catch (e) { setError(e instanceof Error ?
      e.message : "ESCALATION_REQUEST_FAILED");
    } finally { setPending(false); }
  };
  function updateRule(index: number, patch: Partial<EscalationRule>) {
    setRules(previous => previous.map((rule, i) =>
      i === index ? { ...rule, ...patch } : rule));
    setResult(null); setSelected(null);
  }
  return <section aria-label="Escalados internos">
    <h2>Política interna de evaluación</h2>
    <p>Las reglas iniciales son ejemplos editables, no compromisos
      contractuales. El despacho solo encola una evaluación de PostgreSQL;
      no envía correo, no revoca tokens y no altera controles de un proveedor.</p>
    <div className="form-grid">
      <label>Incidente
        <input maxLength={128} value={incidentId}
          onChange={e => { setIncidentId(e.target.value);
            setResult(null); }} placeholder="Identificador del caso" />
      </label>
      <label>ID de política
        <input maxLength={128} value={policyId}
          onChange={e => { setPolicyId(e.target.value);
            setResult(null); }} />
      </label>
    </div>
    <h3>Condiciones que generan una revisión</h3>
    {rules.map((rule, index) => <fieldset key={rule.id}>
      <legend>{rule.id}</legend>
      <div className="form-grid">
        <label>Prioridad
          <select value={rule.priority} onChange={e => updateRule(index,
            { priority: e.target.value as EscalationRule["priority"] })}>
            {(["P0", "P1", "P2"] as const).map(x =>
              <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <label>Estado
          <select value={rule.status} onChange={e => updateRule(index,
            { status: e.target.value as EscalationRule["status"] })}>
            {stateOptions.map(x => <option key={x}>{x}</option>)}
          </select>
        </label>
        <label>Condición
          <select value={rule.trigger} onChange={e => updateRule(index,
            { trigger: e.target.value as EscalationRule["trigger"] })}>
            {triggerOptions.map(x => <option key={x}>{x}</option>)}
          </select>
        </label>
        <label>Edad mínima (min)
          <input type="number" min={0} max={525600}
            value={rule.minimumAgeMinutes} onChange={e => {
              const n = Number(e.target.value);
              if (Number.isSafeInteger(n) && n >= 0 && n <= 525600)
                updateRule(index, { minimumAgeMinutes: n });
            }} />
        </label>
        <label>Ventana de aviso (min)
          <input type="number" min={0} max={525600}
            value={rule.warningMinutes} onChange={e => {
              const n = Number(e.target.value);
              if (Number.isSafeInteger(n) && n >= 0 && n <= 525600)
                updateRule(index, { warningMinutes: n });
            }} />
        </label>
      </div>
    </fieldset>)}
    <div className="actions">
      <button type="button" disabled={!incidentId.trim() || pending}
        onClick={() => void call("PLAN")}>
        {pending ? "Consultando..." : "Previsualizar escalados"}</button>
      <button type="button" disabled={!incidentId.trim() || pending}
        onClick={() => void call("EXPORT")}>
        Exportar propuesta JSON</button>
    </div>
    {error && <p role="alert">Error: {error}</p>}
    {success && <p role="status">{success}</p>}
    {exported && <details open><summary>Propuesta exportada</summary>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {exported}</pre></details>}
    {result && <section aria-label="Plan calculado">
      <h2>Plan propuesto · solo interno</h2>
      <p>{result.plan.eligible} candidatos elegibles,
        {result.plan.dispatches.length} evaluaciones planificadas,
        {result.plan.delayed} demoradas. Saturación:
        {result.plan.saturated ? "sí" : "no"}.</p>
      <p>Estado interno del incidente: {result.incidentStatus}.
        Revisión actual: {result.incidentRevision}.</p>
      <p>Digest: <code>{result.plan.planDigest}</code></p>
      <h3>Trabajos que puede admitir la cola</h3>
      <table><thead><tr><th>Tablero</th><th>Asignación</th>
        <th>Regla</th><th>Programado</th><th>Acción</th>
      </tr></thead><tbody>
        {result.plan.dispatches.map(dispatch => <tr
          key={dispatch.idempotencyKey}>
          <td>{dispatch.boardId}</td><td>{dispatch.handoffId}</td>
          <td>{dispatch.ruleId}</td>
          <td>{displayTime(dispatch.scheduledAt)}</td>
          <td><button type="button" disabled={!canWrite || pending}
            onClick={() => setSelected(dispatch.idempotencyKey)}>
            Seleccionar</button></td>
        </tr>)}
      </tbody></table>
      {result.plan.dispatches.length === 0 &&
        <p>La política no ha seleccionado trabajos con la evidencia actual.
          No equivale a ausencia de riesgos.</p>}
      {selected && (() => {
        const dispatch = result.plan.dispatches.find(x =>
          x.idempotencyKey === selected);
        return dispatch ? <section aria-label="Confirmar admisión">
          <h3>Confirmar evaluación interna</h3>
          <p>Se creará un trabajo duradero de solo lectura
            para {dispatch.handoffId} bajo la regla {dispatch.ruleId}.
            No se notificará a terceros.</p>
          <button type="button" disabled={pending || !canWrite}
            onClick={() => void call("ADMIT", dispatch)}>
            Admitir evaluación en la cola</button>
          <button type="button" onClick={() => setSelected(null)}>
            Cancelar</button>
        </section> : null;
      })()}
      <h3>Distribución por responsable</h3>
      <table><thead><tr><th>Usuario</th><th>Acciones</th>
        <th>P0</th><th>Vencidas</th>
      </tr></thead><tbody>
        {result.ownerWorkload.map(x => <tr key={x.owner}>
          <td>{x.owner}</td><td>{x.count}</td>
          <td>{x.highPriority}</td><td>{x.overdue}</td></tr>)}
      </tbody></table>
      <details><summary>Verificación de pertenencia</summary>
        <ul>{result.assignments.map(x =>
          <li key={x.boardId + x.handoffId}>
            {x.handoffId} · {x.eligibility} ·
            {x.independentReviewNeeded ?
              "requiere revisión independiente" :
              "sin conflicto de separación observado"}
          </li>)}</ul>
      </details>
    </section>}
  </section>;
}
