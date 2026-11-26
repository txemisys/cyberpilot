"use client";
import { useState } from "react";
import type { CoordinationEnvelope, CoordinationReceipt } from
  "../lib/incident-coordination-ledger-domain";
import type {
  ShiftHandoffPayload, ShiftHandoffAction,
} from "../lib/incident-persisted-shift-handoff-domain";
type Detail = {
  snapshot: CoordinationEnvelope<ShiftHandoffPayload>;
  events: CoordinationReceipt[];
  summary: { status: string; workTotal: number; acknowledgedWork: number;
    outstandingConcerns: number; acceptedInternally: boolean;
    submissionCount: number; returnedCount: number };
  pendingWork: Array<{ id: string; priority: string; dueAt: string }>;
  continuity: Array<{ workId: string;
    reviewedByOutgoing: boolean; incomingAcknowledged: boolean }>;
  responsibility: { outgoing: { userId: string; submitted: boolean };
    incoming: { userId: string; accepted: boolean; canRespond: boolean } };
  sourceIncidentRevisionDrift: boolean;
  providerWrites: 0;
};
type Index = {
  data: Array<CoordinationEnvelope<ShiftHandoffPayload>>;
  total: number;
};
const uniqueId = () => "shift-" + crypto.randomUUID();
export function IncidentPersistedShiftHandoffWorkspace({ slug }: {
  slug: string;
}) {
  const [incidentId, setIncidentId] = useState("");
  const [incomingUserId, setIncomingUserId] = useState("");
  const [startsAt, setStartsAt] = useState("");
  const [endsAt, setEndsAt] = useState("");
  const [index, setIndex] = useState<Index | null>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [noteCategory, setNoteCategory] = useState<
    "RISK" | "MISSING_EVIDENCE" | "SOURCE_DRIFT" |
      "OWNERSHIP" | "SHIFT_CONTINUITY">("SHIFT_CONTINUITY");
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/persisted-shift-handoffs";
  async function request(q = "", init?: RequestInit) {
    const response = await fetch(endpoint + q, {
      cache: "no-store", ...init,
    });
    const body: unknown = await response.json();
    if (!response.ok) {
      const code = body && typeof body === "object" &&
        "code" in body ? String(body.code) : "SHIFT_HANDOFF_UNAVAILABLE";
      throw Error(code);
    }
    return body;
  }
  async function execute(work: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(null); setNotice(null);
    try { await work(); }
    catch (e) { setError(e instanceof Error ? e.message :
      "SHIFT_HANDOFF_UNAVAILABLE"); }
    finally { setBusy(false); }
  }
  async function read(id: string) {
    const data = await request("?" + new URLSearchParams({
      recordId: id,
    })) as Detail;
    if (data.snapshot?.kind !== "SHIFT" ||
        !Array.isArray(data.events) || data.providerWrites !== 0)
      throw Error("SHIFT_HANDOFF_RESPONSE_INVALID");
    setDetail(data);
  }
  async function loadList() {
    const data = await request("?" + new URLSearchParams({
      incidentId,
    })) as Index;
    if (!Array.isArray(data.data))
      throw Error("SHIFT_HANDOFF_INDEX_INVALID");
    setIndex(data);
  }
  async function create() {
    if (!incidentId || !incomingUserId || !startsAt || !endsAt) return;
    await execute(async () => {
      const created = await request("", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "CREATE", recordId: uniqueId(),
          commandId: uniqueId(), incidentId,
          shiftId: "turn-" + new Date(startsAt).toISOString()
            .replace(/\D/g, "").slice(0, 14),
          incomingUserId,
          startsAt: new Date(startsAt).toISOString(),
          endsAt: new Date(endsAt).toISOString(),
        }),
      }) as { snapshot: CoordinationEnvelope<ShiftHandoffPayload> };
      await read(created.snapshot.id);
      setNotice("Propuesta creada. El responsable entrante no ha aceptado.");
    });
  }
  async function mutate(action: ShiftHandoffAction) {
    if (!detail) return;
    const current = detail.snapshot;
    await execute(async () => {
      await request("", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "MUTATE", recordId: current.id,
          expectedRevision: current.revision,
          commandId: uniqueId(), action,
        }),
      });
      await read(current.id);
      setNotice("Operación interna persistida en el registro de auditoría.");
    });
  }
  const validReason = reason.trim().length >= 15 && reason.length <= 2000;
  const validWindow = !!startsAt && !!endsAt &&
    Number.isFinite(Date.parse(startsAt)) &&
    Number.isFinite(Date.parse(endsAt)) &&
    endsAt > startsAt &&
    Date.parse(endsAt) - Date.parse(startsAt) <= 7 * 86400000;
  return <section aria-label="Relevo persistente de incidentes">
    <h2>Preparar transferencia</h2>
    <p>Se requiere un usuario entrante distinto del saliente.
      Solo la aceptación autenticada del entrante acredita recepción interna.</p>
    <div className="form-grid">
      <label>Incidente
        <input value={incidentId} maxLength={128}
          onChange={e => { setIncidentId(e.target.value);
            setDetail(null); setIndex(null); }} />
      </label>
      <label>Usuario entrante
        <input value={incomingUserId} maxLength={128}
          onChange={e => setIncomingUserId(e.target.value)} />
      </label>
      <label>Inicio
        <input type="datetime-local" value={startsAt}
          onChange={e => setStartsAt(e.target.value)} />
      </label>
      <label>Fin
        <input type="datetime-local" value={endsAt}
          onChange={e => setEndsAt(e.target.value)} />
      </label>
    </div>
    <div className="actions">
      <button disabled={busy || incidentId.length < 4 ||
          incomingUserId.length < 4 || !validWindow}
        onClick={() => void create()}>Preparar relevo interno</button>
      <button disabled={busy || incidentId.length < 4}
        onClick={() => void execute(loadList)}>
        Consultar relevos
      </button>
    </div>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {index && <section><h3>Relevos ({index.total})</h3>
      <ul>{index.data.map(item => <li key={item.id}>
        <button disabled={busy}
          onClick={() => void execute(() => read(item.id))}>
          {item.id} · {item.state} · rev. {item.revision}
        </button>
      </li>)}</ul>
    </section>}
    {detail && <section aria-label="Relevo en curso">
      <h2>Transferencia {detail.snapshot.id}</h2>
      <p role="status">Estado: {detail.summary.status}.
        Revisados: {detail.summary.acknowledgedWork} de
        {detail.summary.workTotal}.
        Preocupaciones: {detail.summary.outstandingConcerns}.</p>
      <p>Entrega: {detail.responsibility.outgoing.userId}.
        Recepción: {detail.responsibility.incoming.userId}.</p>
      <p>Recibido internamente:
        {detail.summary.acceptedInternally ? "Sí" : "No"}.</p>
      <p>Acciones de proveedor ejecutadas: 0.</p>
      {detail.sourceIncidentRevisionDrift && <p role="alert">
        La revisión del incidente cambió desde la preparación.
        No se puede aceptar el briefing sin reconciliarlo.</p>}
      <p>Digest de propuesta:
        <code>{detail.snapshot.sourceDigest}</code></p>
      <label>Justificación de la operación
        <textarea value={reason} maxLength={2000}
          onChange={e => setReason(e.target.value)} />
      </label>
      <label>Categoría de la nota
        <select value={noteCategory}
          onChange={e => setNoteCategory(
            e.target.value as typeof noteCategory)}>
          <option value="SHIFT_CONTINUITY">Continuidad</option>
          <option value="RISK">Riesgo</option>
          <option value="MISSING_EVIDENCE">Evidencia ausente</option>
          <option value="SOURCE_DRIFT">Cambio de fuente</option>
          <option value="OWNERSHIP">Responsables</option>
        </select>
      </label>
      <div className="actions">
        <button disabled={busy}
          onClick={() => void execute(() => read(detail.snapshot.id))}>
          Actualizar</button>
        <button type="button" onClick={() => {
          const q = new URLSearchParams({
            recordId: detail.snapshot.id, audit: "1",
          });
          window.location.assign(endpoint + "?" + q);
        }}>Descargar auditoría</button>
        <button disabled={busy || !validReason}
          onClick={() => void mutate({ kind: "SUBMIT", reason })}>
          Enviar al entrante</button>
        <button disabled={busy || !validReason ||
            detail.sourceIncidentRevisionDrift}
          onClick={() => void mutate({ kind: "ACCEPT",
            expectedSubmittedDigest: coordinationHash(detail.snapshot),
            reason })}>Aceptar recepción interna</button>
        <button disabled={busy || !validReason}
          onClick={() => void mutate({ kind: "RETURN",
            category: "OPERATIONAL_DISAGREEMENT",
            expectedSubmittedDigest: coordinationHash(detail.snapshot),
            reason })}>Devolver con observaciones</button>
        <button disabled={busy || !validReason}
          onClick={() => void mutate({ kind: "REOPEN", reason })}>
          Reabrir entrega</button>
        <button disabled={busy || !validReason}
          onClick={() => void mutate({ kind: "CLOSE", reason })}>
          Cerrar transferencia internamente</button>
      </div>
      <h3>Trabajos del turno</h3>
      <ol>{detail.snapshot.payload.workItems.map(work => {
        const open = expanded === work.id;
        const reviewed = detail.snapshot.payload.acknowledgedWorkIds
          .includes(work.id);
        return <li key={work.id}>
          <p><strong>{work.priority} · {work.category}</strong> ·
            {reviewed ? "Revisado por saliente" : "Pendiente"}
            · Plazo {work.dueAt}</p>
          <button disabled={busy || !validReason || reviewed}
            onClick={() => void mutate({ kind: "MARK_REVIEWED",
              workId: work.id, reason })}>Marcar trabajo revisado</button>
          <button aria-expanded={open} onClick={() =>
            setExpanded(old => old === work.id ? null : work.id)}>
            {open ? "Ocultar" : "Notas del trabajo"}</button>
          {open && <button disabled={busy || !validReason}
            onClick={() => void mutate({ kind: "ADD_NOTE",
              noteId: uniqueId(), workId: work.id,
              category: noteCategory, reason })}>
            Registrar observación</button>}
        </li>;
      })}</ol>
      <h3>Alertas de cobertura</h3>
      <ol>{detail.snapshot.payload.watchpoints.map(point => {
        const open = detail.snapshot.payload.outstandingConcernIds
          .includes(point.id);
        return <li key={point.id}>{point.priority} · {point.trigger}
          <button disabled={busy || !validReason || open}
            onClick={() => void mutate({ kind: "RAISE_CONCERN",
              concernId: point.id, reason })}>Marcar pendiente</button>
          <button disabled={busy || !validReason || !open}
            onClick={() => void mutate({ kind: "CLEAR_CONCERN",
              concernId: point.id, reason })}>Resolver alerta interna</button>
        </li>;
      })}</ol>
      <details><summary>Eventos auditables ({detail.events.length})</summary>
        <ol>{detail.events.map(e => <li key={e.eventDigest}>
          {e.operation} · {e.actorId} · {e.at} · rev. {e.revision}
        </li>)}</ol></details>
    </section>}
  </section>;
}
// A receipt refers to the exact snapshot seen by the receiving operator.
// The server verifies this digest again and commits under CAS.
function coordinationHash(value: CoordinationEnvelope<ShiftHandoffPayload>) {
  return value.__digestFallbackNever ?? "";
}
