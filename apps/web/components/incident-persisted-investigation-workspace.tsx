"use client";
import { useCallback, useEffect, useState } from "react";
import type { CoordinationEnvelope, CoordinationReceipt } from
  "../lib/incident-coordination-ledger-domain";
import type {
  InvestigationReviewPayload, InvestigationReviewCommandAction,
} from "../lib/incident-persisted-investigation-domain";
type Read = {
  snapshot: CoordinationEnvelope<InvestigationReviewPayload>;
  events: CoordinationReceipt[];
  summary: { workTotal: number; reviewedInternally: number;
    waitingEvidence: number; readyForReview: number; sourceComplete: boolean };
  evidenceGaps: Array<{ workId: string; uncoveredRequestIds: string[] }>;
  providerWrites: 0;
};
type Index = { data: Array<CoordinationEnvelope<InvestigationReviewPayload>>;
  total: number; nextOffset: number | null };
const id = () => "work-" + crypto.randomUUID();
export function IncidentPersistedInvestigationWorkspace({
  slug,
}: { slug: string }) {
  const [incidentId, setIncidentId] = useState("");
  const [records, setRecords] = useState<Index | null>(null);
  const [active, setActive] = useState<Read | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [assignee, setAssignee] = useState("");
  const [reference, setReference] = useState("");
  const [description, setDescription] = useState("");
  const [note, setNote] = useState("");
  const [workId, setWorkId] = useState("");
  const [requestId, setRequestId] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/persisted-investigations";
  const fetchJSON = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    const body: unknown = await response.json();
    if (!response.ok) {
      const code = body && typeof body === "object" &&
        "code" in body ? String(body.code) : "INVESTIGATION_FETCH_FAILED";
      throw Error(code);
    }
    return body;
  }, []);
  const loadList = useCallback(async (caseId: string) => {
    const q = new URLSearchParams({ incidentId: caseId, limit: "50" });
    const body = await fetchJSON(endpoint + "?" + q) as Index;
    if (!Array.isArray(body.data)) throw Error("INVESTIGATION_INDEX_INVALID");
    setRecords(body);
  }, [endpoint, fetchJSON]);
  const loadRecord = useCallback(async (recordId: string) => {
    const q = new URLSearchParams({ recordId });
    const body = await fetchJSON(endpoint + "?" + q) as Read;
    if (body.snapshot?.kind !== "INVESTIGATION" ||
        !Array.isArray(body.events) || body.providerWrites !== 0)
      throw Error("INVESTIGATION_RESPONSE_INVALID");
    setActive(body);
  }, [endpoint, fetchJSON]);
  async function execute(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(null); setNotice(null);
    try { await action(); }
    catch (e) { setError(e instanceof Error ? e.message :
      "INVESTIGATION_UNAVAILABLE"); }
    finally { setBusy(false); }
  }
  async function create() {
    if (!incidentId.trim()) return;
    await execute(async () => {
      const body = await fetchJSON(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "CREATE", recordId: id(),
          incidentId: incidentId.trim(), commandId: id(),
        }),
      }) as { snapshot: CoordinationEnvelope<InvestigationReviewPayload> };
      await loadList(incidentId.trim());
      await loadRecord(body.snapshot.id);
      setNotice("Investigación interna creada. Sin acciones externas.");
    });
  }
  async function mutate(action: InvestigationReviewCommandAction) {
    if (!active) return;
    const snapshot = active.snapshot;
    await execute(async () => {
      await fetchJSON(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "MUTATE", recordId: snapshot.id,
          commandId: id(), expectedRevision: snapshot.revision,
          action,
        }),
      });
      await loadRecord(snapshot.id);
      await loadList(snapshot.incidentId);
      setNotice("Cambio confirmado con auditoría interna.");
    });
  }
  const reason = note.trim();
  const validReason = reason.length >= 12 && reason.length <= 2000;
  const current = active?.snapshot;
  return <section aria-label="Investigaciones persistentes">
    <h2>Expedientes de investigación</h2>
    <p>Los estados son internos. Un expediente revisado no certifica
      acciones realizadas en proveedores externos.</p>
    <label>ID del incidente
      <input value={incidentId} maxLength={128}
        onChange={e => { setIncidentId(e.target.value);
          setRecords(null); setActive(null); }} />
    </label>
    <div className="actions">
      <button type="button" disabled={busy || incidentId.length < 4}
        onClick={() => void execute(() => loadList(incidentId.trim()))}>
        Consultar expedientes
      </button>
      <button type="button" disabled={busy || incidentId.length < 4}
        onClick={() => void create()}>
        Crear investigación desde el estado actual
      </button>
    </div>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {records && <section aria-label="Listado de investigaciones">
      <h3>Historial ({records.total})</h3>
      <ul>{records.data.map(x => <li key={x.id}>
        <button type="button" disabled={busy}
          onClick={() => void execute(() => loadRecord(x.id))}>
          {x.id} · {x.state} · rev. {x.revision}
        </button>
      </li>)}</ul>
      {records.nextOffset !== null && <p>Hay más expedientes.
        El listado está paginado por el servidor.</p>}
    </section>}
    {active && current && <section aria-label="Expediente activo">
      <h3>Investigación {current.id}</h3>
      <p role="status">Estado: {current.state}. Revisión {current.revision}.
        Pendientes de evidencia: {active.summary.waitingEvidence}.
        Revisados internamente: {active.summary.reviewedInternally}.</p>
      <p><strong>Fuente completa:</strong>
        {active.summary.sourceComplete ? "Sí, inventario local" :
          "No acreditada"}.</p>
      <p><strong>Integridad de origen:</strong>
        <code>{current.sourceDigest}</code></p>
      <p>El cierre interno no acredita contención o remediación.</p>
      <div className="actions">
        <button type="button" onClick={() => void loadRecord(current.id)}
          disabled={busy}>Actualizar estado</button>
        <button type="button" onClick={() => {
          const q = new URLSearchParams({
            recordId: current.id, format: "audit",
          });
          window.location.assign(endpoint + "?" + q);
        }}>Exportar auditoría</button>
        <button type="button" disabled={busy || !validReason ||
            current.state === "CLOSED_INTERNAL"}
          onClick={() => void mutate({ kind: "CLOSE", reason })}>
          Cerrar expediente internamente
        </button>
      </div>
      <h4>Introducir justificación</h4>
      <label>Motivo de la acción
        <textarea value={note} maxLength={2000}
          onChange={e => setNote(e.target.value)}
          placeholder="Explicar la necesidad, prueba o decisión" />
      </label>
      <label>ID del usuario asignado
        <input value={assignee} maxLength={128}
          onChange={e => setAssignee(e.target.value)} />
      </label>
      <h4>Trabajos de investigación</h4>
      {current.payload.work.map(w => {
        const selected = workId === w.id;
        const gaps = active.evidenceGaps.find(x => x.workId === w.id);
        return <article key={w.id}>
          <h5>{w.priority} · {w.status} · {w.sourceTaskId}</h5>
          <p>Rol requerido: {w.assignedRole}.
            Responsable: {w.assignedUserId ?? "Sin asignar"}.
            Revisor: {w.reviewedBy ?? "Pendiente"}.</p>
          <p>Referencias recopiladas: {w.attachedEvidenceIds.length}.
            Pruebas pendientes: {gaps?.uncoveredRequestIds.length ?? 0}.</p>
          <button type="button" aria-expanded={expanded === w.id}
            onClick={() => setExpanded(old =>
              old === w.id ? null : w.id)}>
            {expanded === w.id ? "Ocultar operaciones" :
              "Gestionar trabajo"}
          </button>
          {expanded === w.id && <section>
            <div className="actions">
              <button disabled={busy || !validReason || assignee.length < 4}
                onClick={() => void mutate({ kind: "ASSIGN",
                  workId: w.id, assigneeId: assignee.trim(), reason })}>
                Asignar
              </button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "START",
                  workId: w.id, reason })}>Iniciar</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "REQUEST_EVIDENCE",
                  workId: w.id, reason })}>Pedir evidencia</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "SUBMIT_REVIEW",
                  workId: w.id, reason })}>Solicitar revisión</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "REVIEW",
                  workId: w.id, disposition: "SUFFICIENT_INTERNAL",
                  reason })}>Revisar (internamente)</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "REVIEW",
                  workId: w.id, disposition: "NEEDS_EVIDENCE",
                  reason })}>Devolver por evidencias</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "REOPEN",
                  workId: w.id, reason })}>Reabrir</button>
              <button disabled={busy || !validReason}
                onClick={() => void mutate({ kind: "ADD_NOTE",
                  workId: w.id, noteId: id(), reason })}>
                Registrar nota
              </button>
            </div>
            <p>El servidor exige una segunda persona para revisar.</p>
            <label>Solicitud de evidencia
              <select value={selected ? requestId : ""}
                onChange={e => { setWorkId(w.id);
                  setRequestId(e.target.value); }}>
                <option value="">Seleccione solicitud</option>
                {w.evidenceRequestIds.map(id => <option key={id}
                  value={id}>{id}</option>)}
              </select>
            </label>
            <label>Referencia (sin secretos)
              <input value={selected ? reference : ""}
                onChange={e => { setWorkId(w.id);
                  setReference(e.target.value); }} maxLength={300} />
            </label>
            <label>Descripción de evidencia
              <textarea value={selected ? description : ""}
                onChange={e => { setWorkId(w.id);
                  setDescription(e.target.value); }} maxLength={2000} />
            </label>
            <button disabled={busy || !validReason ||
                !selected || !requestId || !reference.trim() ||
                !description.trim()}
              onClick={() => void mutate({
                kind: "ADD_EVIDENCE", workId: w.id,
                evidenceId: id(), requestId,
                evidenceKind: "OPERATOR_CONFIRMATION",
                reference: reference.trim(), description: description.trim(),
                provenance: "INTERNAL", reason,
              })}>Adjuntar referencia interna</button>
          </section>}
        </article>;
      })}
      <details><summary>Eventos de auditoría ({active.events.length})</summary>
        <ol>{active.events.map(e => <li key={e.eventDigest}>
          {e.operation} · rev. {e.revision} · {e.actorId} · {e.at}
        </li>)}</ol>
      </details>
    </section>}
  </section>;
}
