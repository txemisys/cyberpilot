"use client";
import { useState } from "react";
import type { CoordinationEnvelope, CoordinationReceipt } from
  "../lib/incident-coordination-ledger-domain";
import type {
  CorrelationBoardPayload, CorrelationBoardAction,
} from "../lib/incident-persisted-correlation-domain";
type Detail = {
  snapshot: CoordinationEnvelope<CorrelationBoardPayload>;
  events: CoordinationReceipt[];
  summary: { candidates: number; supportedInternally: number;
    rejectedInternally: number; inconclusive: number;
    pendingReview: number; sourceTruncated: boolean };
  integrity: Array<{ hypothesisId: string; evidenceCount: number;
    scopeUnchecked: number; alternateExplanations: number }>;
  providerWrites: 0;
};
type Index = {
  data: Array<CoordinationEnvelope<CorrelationBoardPayload>>;
  total: number; nextOffset: number | null;
};
const newId = () => "corr-" + crypto.randomUUID();
export function IncidentPersistedCorrelationWorkspace({ slug }: {
  slug: string;
}) {
  const [ids, setIds] = useState(["", ""]);
  const [lookup, setLookup] = useState("");
  const [index, setIndex] = useState<Index | null>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [assigneeId, setAssigneeId] = useState("");
  const [evidenceReference, setEvidenceReference] = useState("");
  const [evidenceIncident, setEvidenceIncident] = useState("");
  const [scopeChecked, setScopeChecked] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/persisted-correlations";
  const validIds = ids.length >= 2 && ids.length <= 12 &&
    ids.every(id => /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(id)) &&
    new Set(ids).size === ids.length;
  async function request(q: string, init?: RequestInit) {
    const response = await fetch(endpoint + q, {
      cache: "no-store", ...init,
    });
    const body: unknown = await response.json();
    if (!response.ok) {
      const code = body && typeof body === "object" &&
        "code" in body ? String(body.code) : "CORRELATION_REVIEW_UNAVAILABLE";
      throw Error(code);
    }
    return body;
  }
  async function execute(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(null); setNotice(null);
    try { await fn(); }
    catch (e) { setError(e instanceof Error ? e.message :
      "CORRELATION_REVIEW_UNAVAILABLE"); }
    finally { setBusy(false); }
  }
  async function read(recordId: string) {
    const q = "?" + new URLSearchParams({ recordId });
    const data = await request(q) as Detail;
    if (data.snapshot?.kind !== "CORRELATION" ||
        !Array.isArray(data.events) || data.providerWrites !== 0)
      throw Error("CORRELATION_REVIEW_RESPONSE_INVALID");
    setDetail(data);
  }
  async function list() {
    const q = "?" + new URLSearchParams({ incidentId: lookup });
    const data = await request(q) as Index;
    if (!Array.isArray(data.data))
      throw Error("CORRELATION_REVIEW_INDEX_INVALID");
    setIndex(data);
  }
  async function create() {
    if (!validIds) return;
    await execute(async () => {
      const created = await request("", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "CREATE", recordId: newId(),
          commandId: newId(), selectedIncidentIds: ids,
        }),
      }) as { snapshot: CoordinationEnvelope<CorrelationBoardPayload> };
      setLookup([...ids].sort()[0]!);
      await read(created.snapshot.id);
      setNotice("Tablero creado sin confirmar identidades externas.");
    });
  }
  async function mutate(action: CorrelationBoardAction) {
    if (!detail) return;
    const current = detail.snapshot;
    await execute(async () => {
      await request("", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "MUTATE", recordId: current.id,
          expectedRevision: current.revision, commandId: newId(), action,
        }),
      });
      await read(current.id);
      setNotice("Decisión registrada con CAS y evento de auditoría.");
    });
  }
  const validReason = reason.trim().length >= 15 && reason.length <= 2000;
  return <section aria-label="Correlaciones persistentes">
    <h2>Casos incluidos explícitamente</h2>
    <p>Una coincidencia no significa que dos identidades o equipos
      sean los mismos ni que exista una campaña demostrada.</p>
    <div className="form-grid">
      {ids.map((x, i) => <label key={i}>Incidente {i + 1}
        <input value={x} maxLength={128} onChange={e => {
          setIds(old => old.map((v, j) => i === j ? e.target.value : v));
          setDetail(null);
        }} />
      </label>)}
    </div>
    <div className="actions">
      <button type="button" disabled={ids.length >= 12}
        onClick={() => setIds(old => [...old, ""])}>Añadir caso</button>
      <button type="button" disabled={ids.length <= 2}
        onClick={() => setIds(old => old.slice(0, -1))}>
        Eliminar último
      </button>
      <button type="button" disabled={!validIds || busy}
        onClick={() => void create()}>Crear tablero revisable</button>
    </div>
    <label>Incidente principal de tableros existentes
      <input value={lookup} maxLength={128}
        onChange={e => setLookup(e.target.value)} />
    </label>
    <button type="button" disabled={lookup.length < 4 || busy}
      onClick={() => void execute(list)}>Consultar tableros</button>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {index && <section><h3>Tableros ({index.total})</h3>
      <ul>{index.data.map(x => <li key={x.id}>
        <button type="button" disabled={busy}
          onClick={() => void execute(() => read(x.id))}>
          {x.id} · {x.state} · rev. {x.revision}</button>
      </li>)}</ul>
    </section>}
    {detail && <section aria-label="Hipótesis en revisión">
      <h2>Tablero {detail.snapshot.id}</h2>
      <p role="status">{detail.summary.candidates} candidatos,
        {detail.summary.pendingReview} esperando revisión,
        {detail.summary.supportedInternally} sustentados internamente,
        {detail.summary.rejectedInternally} descartados internamente.</p>
      <p>Revisión {detail.snapshot.revision}.
        La verificación de proveedor es desconocida.</p>
      {detail.summary.sourceTruncated && <p role="alert">
        La fuente está truncada y no permite un cierre completo.</p>}
      <div className="actions">
        <button type="button" disabled={busy}
          onClick={() => void execute(() => read(detail.snapshot.id))}>
          Actualizar
        </button>
        <button type="button" onClick={() => {
          const q = new URLSearchParams({ recordId: detail.snapshot.id,
            audit: "1" });
          window.location.assign(endpoint + "?" + q);
        }}>Exportar auditoría</button>
        <button type="button" disabled={!validReason || busy}
          onClick={() => void mutate({ kind: "CLOSE", reason })}>
          Cerrar internamente
        </button>
      </div>
      <label>Justificación y explicación alternativa
        <textarea value={reason} maxLength={2000}
          onChange={e => setReason(e.target.value)} />
      </label>
      <label>Usuario asignado
        <input value={assigneeId} maxLength={128}
          onChange={e => setAssigneeId(e.target.value)} />
      </label>
      <label>Referencia de evidencia (sin secretos)
        <input value={evidenceReference} maxLength={300}
          onChange={e => setEvidenceReference(e.target.value)} />
      </label>
      <label>Incidente de procedencia
        <select value={evidenceIncident} onChange={e =>
          setEvidenceIncident(e.target.value)}>
          <option value="">Seleccione incidente</option>
          {detail.snapshot.payload.selectedIncidentIds.map(id =>
            <option key={id} value={id}>{id}</option>)}
        </select>
      </label>
      <label><input type="checkbox" checked={scopeChecked}
        onChange={e => setScopeChecked(e.target.checked)} />
        Se revisó el ámbito interno de la referencia</label>
      <ol>{detail.snapshot.payload.hypotheses.map(h => {
        const open = expanded === h.id;
        const matrix = detail.integrity.find(x => x.hypothesisId === h.id);
        return <li key={h.id}>
          <article>
            <h3>{h.priority} · {h.kind} · {h.state}</h3>
            <p>{h.originalExplanation}</p>
            <p>Casos: {h.incidentIds.join(" / ")}.
              Responsable: {h.assignedUserId ?? "Sin asignar"}.
              Evidencias: {matrix?.evidenceCount ?? 0}.
              Alternativas: {matrix?.alternateExplanations ?? 0}.</p>
            <p>La relación con proveedor no está confirmada.</p>
            <button type="button" aria-expanded={open}
              onClick={() => setExpanded(old => old === h.id ?
                null : h.id)}> {open ? "Ocultar" : "Revisar hipótesis"}</button>
            {open && <div className="actions">
              <button disabled={!validReason || busy || assigneeId.length < 4}
                onClick={() => void mutate({ kind: "ASSIGN",
                  hypothesisId: h.id, assigneeId, reason })}>Asignar</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "START",
                  hypothesisId: h.id, reason })}>Iniciar</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "ALTERNATIVE",
                  hypothesisId: h.id, reason })}>
                Registrar explicación alternativa</button>
              <button disabled={!validReason || busy ||
                  !evidenceReference.trim() || !evidenceIncident}
                onClick={() => void mutate({ kind: "ADD_EVIDENCE",
                  hypothesisId: h.id, evidenceId: newId(),
                  incidentId: evidenceIncident,
                  reference: evidenceReference.trim(),
                  sourceCategory: "LOCAL_AUDIT", scopeChecked, reason })}>
                Adjuntar evidencia interna</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "SUBMIT",
                  hypothesisId: h.id, reason })}>
                Solicitar segunda revisión</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "DECIDE",
                  hypothesisId: h.id, conclusion: "SUPPORTED_INTERNAL",
                  reason })}>Sustentada internamente</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "DECIDE",
                  hypothesisId: h.id, conclusion: "REJECTED_INTERNAL",
                  reason })}>Descartar internamente</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "DECIDE",
                  hypothesisId: h.id, conclusion: "INCONCLUSIVE",
                  reason })}>Inconclusa</button>
              <button disabled={!validReason || busy}
                onClick={() => void mutate({ kind: "REOPEN",
                  hypothesisId: h.id, reason })}>Reabrir</button>
            </div>}
          </article>
        </li>;
      })}</ol>
      <details><summary>Historial ({detail.events.length})</summary>
        <ol>{detail.events.map(e =>
          <li key={e.eventDigest}>{e.operation} · {e.actorId} ·
            {e.at} · rev. {e.revision}</li>)}</ol>
      </details>
    </section>}
  </section>;
}
