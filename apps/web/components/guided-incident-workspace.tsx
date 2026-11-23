"use client";
import { useEffect, useState } from "react";
import { getIncidentPlaybook, catalogIncidentPlaybooks,
  type IncidentType } from "../lib/incident-playbook-catalog";
import type { IncidentSnapshot } from "../lib/incident-case-domain";
import { evaluateIncidentReadiness } from "../lib/incident-operations-domain";
type Page = { cases: IncidentSnapshot[]; total: number; nextOffset: number | null };
const catalog = catalogIncidentPlaybooks();
export function GuidedIncidentWorkspace({ slug, mayWrite }: {
  slug: string; mayWrite: boolean;
}) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) + "/guided-incidents";
  const [items, setItems] = useState<IncidentSnapshot[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [type, setType] = useState<IncidentType>("COMPROMISED_ACCOUNT");
  const [title, setTitle] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [offset, setOffset] = useState(0);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [exported, setExported] = useState("");
  const active = items.find(x => x.id === selected) ?? null;
  async function load(start = 0) {
    const response = await fetch(endpoint + "?offset=" + start + "&limit=30",
      { cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw Error(payload.code ?? "INCIDENT_READ_FAILED");
    const page = payload.data as Page;
    setItems(previous => start === 0 ? page.cases :
      [...previous, ...page.cases.filter(x => !previous.some(p => p.id === x.id))]);
    setOffset(start); setNextOffset(page.nextOffset);
  }
  useEffect(() => { void load().catch(e => setMessage(String(e))); }, [endpoint]);
  async function send(command: Record<string, unknown>) {
    setBusy(true); setMessage("");
    try {
      const res = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(command),
      });
      const body = await res.json();
      if (!res.ok) throw Error(body.code ?? "INCIDENT_WRITE_FAILED");
      const updated = body.data?.case as IncidentSnapshot | undefined;
      await load();
      if (updated) setSelected(updated.id);
      setMessage("Cambio persistido; no se ejecutó ninguna acción en el proveedor.");
    } catch (e) { setMessage(String(e)); }
    finally { setBusy(false); }
  }
  async function download(format: "JSON" | "CSV" | "MARKDOWN") {
    if (!active) return;
    setBusy(true);
    try {
      const response = await fetch(endpoint + "?incidentId=" +
        encodeURIComponent(active.id) + "&format=" + format, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw Error(body.code ?? "INCIDENT_EXPORT_FAILED");
      const artifact = body.data?.artifact;
      if (typeof artifact?.content !== "string") throw Error("INCIDENT_ARTIFACT_INVALID");
      setExported(artifact.content);
      setMessage("Expediente generado; copiar o revisar antes de distribuir.");
    } catch (e) { setMessage(String(e)); } finally { setBusy(false); }
  }
  const book = active ? getIncidentPlaybook(active.type) : null;
  const readiness = active ? evaluateIncidentReadiness(active) : null;
  return <section aria-label="Incidentes guiados">
    <p role="note">Solo flujos guiados, sin revocación, purga, aislamiento, borrado
      ni comunicaciones reales. Todo resultado del proveedor requiere evidencia independiente.</p>
    {mayWrite && <form onSubmit={e => { e.preventDefault();
      void send({ operation: "CREATE", type, title,
        subjectReference: subject, ownerUserId: null, relatedDecisionCaseId: null });
    }}>
      <h2>Nuevo incidente</h2>
      <label>Playbook <select value={type} onChange={e =>
        setType(e.target.value as IncidentType)}>
        {catalog.map(x => <option key={x.id} value={x.id}>{x.title}</option>)}
      </select></label>
      <label>Título <input value={title} maxLength={180} required
        onChange={e => setTitle(e.target.value)}/></label>
      <label>Referencia de afectación (sin secretos)
        <input value={subject} maxLength={220} required
          onChange={e => setSubject(e.target.value)}/></label>
      <button disabled={busy} type="submit">Crear caso offline</button>
    </form>}
    <h2>Registro de incidentes</h2>
    <button type="button" disabled={busy} onClick={() =>
      void load().catch(e => setMessage(String(e)))}>Actualizar</button>
    <ul>{items.map(item => <li key={item.id}>
      <button type="button" onClick={() => {
        setSelected(item.id); setExported("");
      }}>{item.title} — {item.type} — {item.status} — rev. {item.revision}</button>
    </li>)}</ul>
    {nextOffset !== null && <button type="button" disabled={busy}
      onClick={() => void load(nextOffset).catch(e => setMessage(String(e)))}>
      Cargar más
    </button>}
    <p>Registros cargados: {items.length}. Página de inicio: {offset}.</p>
    {active && book && readiness && <section aria-label="Detalle de incidente">
      <h2>{active.title}</h2>
      <p>Estado: {active.status}. Revisión: {active.revision}. Gravedad: {active.severity}.</p>
      <p>Evaluación: {readiness.gate}. Contención técnica demostrada: NO.</p>
      <p>{book.description}</p>
      <h3>Prioridades inmediatas</h3>
      <ul>{book.immediateSafety.map(s => <li key={s}>{s}</li>)}</ul>
      <h3>Pasos guiados</h3>
      <ol>{book.steps.map(spec => {
        const progress = active.steps.find(x => x.stepId === spec.id)!;
        const evaluation = readiness.steps.find(x => x.id === spec.id)!;
        return <li key={spec.id}>
          <h4>{spec.title} — {progress.status}</h4>
          <p>{spec.objective}</p>
          <ol>{spec.instructions.map(x => <li key={x}>{x}</li>)}</ol>
          <p>Evidencia requerida: {spec.proofRequired.join("; ")}.</p>
          <p>Capacidad: {spec.providerCapability}. Riesgo: {spec.risk}.
            Aprobación: {spec.requiresApproval ? "necesaria" : "no"}.</p>
          <p>Pruebas independientes: {evaluation.independentObservedCount};
            fuentes pendientes: {evaluation.missingRequiredSources.join(", ") || "ninguna"}.</p>
          <p>Si no está disponible: {spec.fallback}</p>
          {mayWrite && <>
            {progress.status === "PENDING" &&
              <button disabled={busy || active.status === "CLOSED"} onClick={() =>
                void send({ operation: "UPDATE", incidentId: active.id,
                  expectedRevision: active.revision, kind: "STEP_START", stepId: spec.id })}>
                Iniciar paso
              </button>}
            {progress.status === "IN_PROGRESS" &&
              <button disabled={busy} onClick={() =>
                void send({ operation: "UPDATE", incidentId: active.id,
                  expectedRevision: active.revision, kind: "STEP_BLOCK",
                  stepId: spec.id, reason: reason || "Evidencia insuficiente para continuar" })}>
                Marcar bloqueado
              </button>}
          </>}
        </li>;
      })}</ol>
      {mayWrite && <section>
        <h3>Avance y revisión</h3>
        <label>Motivo del cambio
          <textarea value={reason} maxLength={4000}
            onChange={e => setReason(e.target.value)}/>
        </label>
        {([
          ["OPEN", "START_TRIAGE", "Iniciar triage"],
          ["TRIAGE", "START_CONTAINMENT", "Iniciar contención guiada"],
          ["CONTAINMENT", "START_RECOVERY", "Iniciar recuperación guiada"],
          ["RECOVERY", "REQUEST_REVIEW", "Solicitar revisión"],
          ["REVIEW", "CLOSE", "Cerrar expediente (solo workflow)"],
          ["CLOSED", "REOPEN", "Reabrir"],
        ] as const).filter(([status]) => active.status === status)
          .map(([, kind, label]) => <button type="button" key={kind}
            disabled={busy} onClick={() => void send({ operation: "UPDATE",
              incidentId: active.id, expectedRevision: active.revision,
              kind, reason })}>{label}</button>)}
      </section>}
      <h3>Exportación revisable</h3>
      {(["JSON", "CSV", "MARKDOWN"] as const).map(f =>
        <button key={f} type="button" disabled={busy} onClick={() =>
          void download(f)}>Preparar {f}</button>)}
      {exported && <textarea aria-label="Expediente exportado" rows={12}
        value={exported} readOnly />}
      <h3>Limitaciones</h3>
      <ul>{book.scopeLimitations.map(x => <li key={x}>{x}</li>)}</ul>
      <ul>{readiness.warnings.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </section>}
    <p role="status">{message}</p>
  </section>;
}
