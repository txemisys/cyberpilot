"use client";

import { useMemo, useState } from "react";

type Status = "OPEN" | "IN_PROGRESS" | "BLOCKED" |
  "COMPLETED_REPORTED" | "REOPENED";
type Item = {
  id: string; questionId: string; revision: number;
  severity: string; status: Status;
  title: string; nextAction: string; evidenceNeeded: string;
  evidenceReference: string | null;
  ownerUserId: string | null; dueAt: string | null;
  completedAt: string | null; sourceDraftRevision: number;
  independentlyVerified: false; securityCertified: false;
};
type Event = {
  revision: number; action: string;
  previousStatus: string; nextStatus: string;
  ownerUserId: string | null; evidenceReference: string | null;
  at: string; independentlyVerified: false;
};
type Props = { slug: string; canEdit: boolean };
const statuses: Array<{ value: Status; title: string }> = [
  { value: "OPEN", title: "Pendiente" },
  { value: "IN_PROGRESS", title: "En curso" },
  { value: "BLOCKED", title: "Bloqueada" },
  { value: "COMPLETED_REPORTED", title: "Completada según responsable" },
  { value: "REOPENED", title: "Reabierta" },
];
export function BaselineFollowUpsWorkspace({ slug,
  canEdit }: Props) {
  const [items, setItems] = useState<Item[]>([]);
  const [selected, setSelected] = useState<Item | null>(null);
  const [history, setHistory] = useState<Event[]>([]);
  const [owner, setOwner] = useState("");
  const [due, setDue] = useState("");
  const [reference, setReference] = useState("");
  const [status, setStatus] = useState<Status>("OPEN");
  const [filter, setFilter] = useState("ALL");
  const [sort, setSort] = useState("priority");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [summary, setSummary] = useState<{
    total: number; overdue: number;
    withoutOwner: number; highPriority: number;
    technicallyVerifiedCompleted: 0;
  } | null>(null);
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/baseline-followups";
  const request = async (operation: string,
    fields: Record<string, unknown> = {}) => {
    const response = await fetch(endpoint, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, ...fields }),
    });
    const raw = await response.json() as Record<string, unknown>;
    if (!response.ok) {
      if (raw.code === "REVISION_CONFLICT")
        throw Error("Conflicto de versión. Recarga el seguimiento.");
      throw Error(String(raw.code ?? "Seguimiento no disponible."));
    }
    if (raw.externalActionsExecuted !== 0 ||
        raw.independentRemediationVerified !== false ||
        raw.customerSecurityCertified !== false ||
        raw.legacyCyberScoreChanged !== false)
      throw Error("El seguimiento no puede certificar una remediación.");
    return raw.data as Record<string, unknown>;
  };
  const execute = (task: () => Promise<void>) =>
    async () => {
      if (busy) return;
      setBusy(true); setError(""); setMessage("");
      try { await task(); }
      catch (cause) {
        setError(cause instanceof Error ? cause.message :
          "Error desconocido.");
      } finally { setBusy(false); }
    };
  const load = execute(async () => {
    const [list, metrics] = await Promise.all([
      request("LIST", { limit: 100 }),
      request("SUMMARY"),
    ]);
    setItems(list.items as Item[]);
    setSummary(metrics as typeof summary);
    setMessage("Acciones declarativas recuperadas; sin verificación independiente.");
  });
  const initialize = execute(async () => {
    const result = await request("INITIALIZE");
    setMessage("Acciones propuestas desde el último diagnóstico presentado: " +
      result.created + " nuevas; " + result.preserved + " conservadas.");
    const list = await request("LIST", { limit: 100 });
    setItems(list.items as Item[]);
  });
  const select = (item: Item) => {
    setSelected(item);
    setStatus(item.status);
    setOwner(item.ownerUserId ?? "");
    setDue(item.dueAt ? item.dueAt.slice(0, 16) : "");
    setReference(item.evidenceReference ?? "");
    setHistory([]);
  };
  const save = execute(async () => {
    if (!selected) throw Error("Selecciona una acción.");
    const result = await request("UPDATE", {
      questionId: selected.questionId,
      expectedRevision: selected.revision,
      status, ownerUserId: owner.trim() || null,
      dueAt: due ? new Date(due).toISOString() : null,
      evidenceReference: reference.trim() || null,
    });
    const updated = (result.item as Item);
    setSelected(updated);
    setItems(prev => prev.map(item =>
      item.id === updated.id ? updated : item));
    setMessage(status === "COMPLETED_REPORTED" ?
      "Completada según declaración; pendiente de prueba técnica." :
      "Seguimiento actualizado con auditoría y control de versiones.");
  });
  const loadHistory = execute(async () => {
    if (!selected) throw Error("Selecciona una acción.");
    const data = await request("HISTORY", {
      questionId: selected.questionId, limit: 100,
    });
    setHistory(data.events as Event[]);
    setMessage("Eventos inmutables de la acción recuperados.");
  });
  const visible = useMemo(() => {
    const filtered = items.filter(item =>
      filter === "ALL" || item.status === filter);
    const priority = (value: string) =>
      ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN","NOT_APPLICABLE"]
        .indexOf(value);
    return [...filtered].sort((a, b) => sort === "priority" ?
      priority(a.severity) - priority(b.severity) ||
        a.questionId.localeCompare(b.questionId) :
      sort === "due" ?
        (a.dueAt ?? "9999").localeCompare(b.dueAt ?? "9999") :
        a.questionId.localeCompare(b.questionId));
  }, [items, filter, sort]);
  const button: React.CSSProperties = {
    padding: "8px 12px", borderRadius: 8,
    border: "1px solid #64748b88",
    color: "inherit", background: "transparent", cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #64748b66",
    borderRadius: 12, padding: 16, marginBottom: 15,
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center",
  };
  return <div>
    <section style={card}>
      <h2>Seguimiento de mejoras del diagnóstico Baseline</h2>
      <p>Inicializa propuestas a partir de un diagnóstico presentado;
        asigna responsables, plazos y evidencia local. Una
        tarea marcada como completada es una <strong>declaración
        de progreso, no una comprobación técnica</strong>.</p>
      <div style={row}>
        <button style={button} disabled={busy}
          onClick={load}>Consultar acciones</button>
        <button style={button} disabled={busy || !canEdit}
          onClick={initialize}>Crear acciones desde diagnóstico presentado</button>
      </div>
      {error && <p role="alert" style={{ color: "#b33" }}>{error}</p>}
      {message && <p role="status">{message}</p>}
      {busy && <p aria-live="polite">Procesando…</p>}
      {summary && <div style={row}>
        <p>Total: <strong>{summary.total}</strong></p>
        <p>Con retraso: <strong>{summary.overdue}</strong></p>
        <p>Sin responsable: <strong>{summary.withoutOwner}</strong></p>
        <p>Alta prioridad: <strong>{summary.highPriority}</strong></p>
        <p>Completadas con prueba técnica:{" "}
          <strong>{summary.technicallyVerifiedCompleted}</strong></p>
      </div>}
    </section>
    <section style={card}>
      <div style={row}>
        <label>Estado{" "}
          <select value={filter} onChange={e => setFilter(e.target.value)}>
            <option value="ALL">Todos</option>
            {statuses.map(item =>
              <option key={item.value} value={item.value}>
                {item.title}
              </option>)}
          </select>
        </label>
        <label>Ordenar{" "}
          <select value={sort} onChange={e => setSort(e.target.value)}>
            <option value="priority">Prioridad</option>
            <option value="due">Plazo</option>
            <option value="question">Control</option>
          </select>
        </label>
      </div>
      {visible.length === 0 && <p>No hay acciones cargadas para este filtro.</p>}
      <ul>{visible.map(item => <li key={item.id}
        style={{ padding: "9px 0" }}>
        <button style={button} disabled={busy}
          onClick={() => select(item)}>
          {item.severity} · {item.questionId} · {item.status}
        </button>
        <p>{item.title}</p>
        <small>Revisión v{item.revision} ·
          {item.ownerUserId ? " Asignada" : " Sin responsable"}
        </small>
      </li>)}</ul>
    </section>
    {selected && <section style={card}>
      <h3>{selected.title}</h3>
      <p>Origen: Baseline revisión {selected.sourceDraftRevision}</p>
      <p>Guía: {selected.nextAction}</p>
      <p>Evidencia sugerida: {selected.evidenceNeeded}</p>
      <p>Remediación verificada: <strong>NO</strong></p>
      <div style={row}>
        <label>Estado{" "}
          <select value={status}
            disabled={!canEdit}
            onChange={e => setStatus(e.target.value as Status)}>
            {statuses.map(item => <option key={item.value}
              value={item.value}>{item.title}</option>)}
          </select>
        </label>
        <label>Responsable (ID de miembro){" "}
          <input value={owner} disabled={!canEdit}
            onChange={e => setOwner(e.target.value)}
            placeholder="ID de usuario autorizado" />
        </label>
        <label>Fecha objetivo{" "}
          <input type="datetime-local" value={due}
            disabled={!canEdit}
            onChange={e => setDue(e.target.value)} />
        </label>
        <label>Referencia opaca de evidencia{" "}
          <input value={reference} disabled={!canEdit}
            onChange={e => setReference(e.target.value)}
            maxLength={96} placeholder="documento-12345" />
        </label>
      </div>
      <div style={{ ...row, marginTop: 15 }}>
        <button style={button} disabled={busy || !canEdit}
          onClick={save}>Guardar seguimiento</button>
        <button style={button} disabled={busy}
          onClick={loadHistory}>Ver auditoría</button>
      </div>
      {history.length > 0 && <ol>{history.map(event =>
        <li key={event.revision}>
          {event.at} · {event.action} ·
          {" "}{event.previousStatus} → {event.nextStatus}
          {" "}(v{event.revision})
        </li>)}</ol>}
    </section>}
  </div>;
}
