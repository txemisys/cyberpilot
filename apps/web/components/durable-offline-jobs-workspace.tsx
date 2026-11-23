"use client";
import { useEffect, useState } from "react";
import type { OfflineJobSnapshot, OfflineJobType } from "../lib/durable-offline-job-domain";
type JobPage = { items: OfflineJobSnapshot[]; total: number;
  nextOffset: number | null };
type Audit = { audit: { valid: boolean; issues: string[] }; events: Array<{
  revision: number; kind: string; occurredAt: string; next: string;
}> };
const jobTypes = [
  { id: "CAPTURE_TIMELINE_AUDIT", name: "Audit stored capture timeline" },
  { id: "RECOVERY_FAULT_MATRIX", name: "Read-only recovery fault matrix" },
] as const;
export function OfflineJobWorkspace({ slug, mayManage }: {
  slug: string; mayManage: boolean;
}) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) + "/offline-jobs";
  const [items, setItems] = useState<OfflineJobSnapshot[]>([]);
  const [total, setTotal] = useState(0);
  const [next, setNext] = useState<number | null>(null);
  const [kind, setKind] = useState<OfflineJobType>("CAPTURE_TIMELINE_AUDIT");
  const [key, setKey] = useState("");
  const [delay, setDelay] = useState(0);
  const [selected, setSelected] = useState("");
  const [audit, setAudit] = useState<Audit | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const current = items.find(x => x.id === selected) ?? null;
  async function load(offset = 0) {
    const response = await fetch(endpoint + "?limit=40&offset=" + offset,
      { cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw Error(payload.code ?? "JOB_READ_FAILED");
    const page = payload.data as JobPage;
    setItems(prev => offset ? [...prev, ...page.items.filter(
      x => !prev.some(item => item.id === x.id))] : page.items);
    setTotal(page.total); setNext(page.nextOffset);
  }
  async function loadAudit(id: string) {
    const response = await fetch(endpoint + "?jobId=" +
      encodeURIComponent(id), { cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw Error(payload.code ?? "JOB_AUDIT_FAILED");
    setAudit(payload.data as Audit);
  }
  async function loadMetrics() {
    const response = await fetch(endpoint + "?metrics=true", { cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw Error(payload.code ?? "JOB_METRICS_FAILED");
    setMetrics(payload.data as Record<string, unknown>);
  }
  useEffect(() => {
    void Promise.all([load(), loadMetrics()]).catch(e => setMessage(String(e)));
  }, [endpoint]);
  async function send(body: Record<string, unknown>) {
    setBusy(true); setMessage("");
    try {
      const response = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      if (!response.ok) throw Error(result.code ?? "OFFLINE_JOB_COMMAND_FAILED");
      const job = result.data?.job as OfflineJobSnapshot | undefined;
      await Promise.all([load(), loadMetrics()]);
      if (job) {
        setSelected(job.id);
        await loadAudit(job.id);
      }
      setMessage("Persistido. Sin escritura al proveedor ni sincronización automática.");
    } catch (e) { setMessage(String(e)); }
    finally { setBusy(false); }
  }
  return <section aria-label="Cola offline durable">
    <p role="note">Solo trabajos locales sobre evidencia persistida.
      El despacho es manual, requiere membresía activa y no usa credenciales M365.</p>
    {mayManage && <form onSubmit={e => {
      e.preventDefault();
      void send({ operation: "ENQUEUE", type: kind,
        idempotencyKey: key, payload: {}, delaySeconds: delay });
    }}>
      <h2>Planificar inspección offline</h2>
      <label>Tipo <select value={kind} onChange={e =>
        setKind(e.target.value as OfflineJobType)}>
        {jobTypes.map(type => <option key={type.id}
          value={type.id}>{type.name}</option>)}
      </select></label>
      <label>Clave de idempotencia <input required minLength={8} maxLength={128}
        value={key} onChange={e => setKey(e.target.value)}
        placeholder="audit-revision-20261123"/></label>
      <label>Retardo (segundos) <input type="number" min={0} max={86400}
        value={delay} onChange={e => setDelay(Number(e.target.value))}/></label>
      <button disabled={busy} type="submit">Registrar trabajo</button>
    </form>}
    <h2>Cola e inspección</h2>
    <button type="button" disabled={busy} onClick={() =>
      void Promise.all([load(), loadMetrics()]).catch(e =>
        setMessage(String(e)))}>Actualizar</button>
    <p>Trabajos registrados: {total}. Visibles: {items.length}.</p>
    <ul>{items.map(job => <li key={job.id}>
      <button type="button" onClick={() => {
        setSelected(job.id);
        void loadAudit(job.id).catch(e => setMessage(String(e)));
      }}>{job.type} · {job.status} · intento {job.attempts}/{job.maxAttempts}
        · rev. {job.revision}</button>
    </li>)}</ul>
    {next !== null && <button disabled={busy} type="button" onClick={() =>
      void load(next).catch(e => setMessage(String(e)))}>Más trabajos</button>}
    {current && <section aria-label="Detalle de trabajo">
      <h3>{current.type} — {current.status}</h3>
      <p>Revisión: {current.revision}; programado: {current.scheduledAt};
        caduca: {current.expiresAt}.</p>
      <p>Último fallo: {current.lastFailure ?? "ninguno"}.
        Clase: {current.failureClass ?? "no aplica"}.</p>
      <p>Resultado: {current.result ?
        JSON.stringify(current.result, null, 2) : "sin resultado verificado"}.</p>
      <p>Checksum del resultado: {current.resultDigest ?? "pendiente"}.</p>
      <p>El trabajo no demuestra restauración de base de datos gestionada.</p>
      {mayManage && <>
        {["QUEUED", "RETRY_WAIT"].includes(current.status) && <>
          <button disabled={busy} onClick={() => void send({
            operation: "CLAIM", jobId: current.id,
            expectedRevision: current.revision })}>Adquirir lease</button>
          <button disabled={busy} onClick={() => void send({
            operation: "CANCEL", jobId: current.id,
            expectedRevision: current.revision })}>Cancelar pendiente</button>
        </>}
        {current.status === "LEASED" && <>
          <button disabled={busy} onClick={() => void send({
            operation: "EXECUTE", jobId: current.id,
            expectedRevision: current.revision,
            leaseToken: current.leaseToken })}>
            Ejecutar lectura offline bajo lease</button>
          <button disabled={busy} onClick={() => void send({
            operation: "HEARTBEAT", jobId: current.id,
            expectedRevision: current.revision,
            leaseToken: current.leaseToken })}>Renovar lease</button>
          <button disabled={busy} onClick={() => void send({
            operation: "RECOVER", jobId: current.id,
            expectedRevision: current.revision })}>Recuperar lease caducado</button>
        </>}
      </>}
      {audit && <section>
        <h4>Auditoría</h4>
        <p>Integridad: {audit.audit.valid ? "PASS" : "REQUIERE REVISIÓN"}</p>
        <ul>{audit.audit.issues.map(x => <li key={x}>{x}</li>)}</ul>
        <ol>{audit.events.map(event => <li key={event.revision}>
          {event.revision}: {event.kind} → {event.next}
          {" "}{event.occurredAt}
        </li>)}</ol>
      </section>}
    </section>}
    {metrics && <section aria-label="Métricas offline">
      <h3>Observabilidad de cola</h3>
      <pre>{JSON.stringify(metrics, null, 2)}</pre>
    </section>}
    <p role="status">{message}</p>
  </section>;
}
