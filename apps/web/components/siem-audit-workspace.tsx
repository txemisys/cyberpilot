"use client";
import { useEffect, useState } from "react";
import type { PortableAuditEvent, SiemFormat } from "../lib/siem-audit-interchange-domain";
type AuditPage = { events: PortableAuditEvent[]; hasMore: boolean;
  nextCursor: string | null; pageDigest: string; integrity: {
    valid: boolean; issues: string[] }; selection: {
    since: string; until: string; limit: number }; };
type Payload = { page: AuditPage;
  artifact: { content: string; filename: string; artifactDigest: string } | null;
  quality: Record<string, unknown>; readiness: Record<string, unknown> };
const formats: SiemFormat[] = ["JSONL", "ECS", "CEF", "CSV"];
export function SiemAuditWorkspace({ slug, mayExport }: {
  slug: string; mayExport: boolean;
}) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) + "/siem-audit";
  const [page, setPage] = useState<AuditPage | null>(null);
  const [events, setEvents] = useState<PortableAuditEvent[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [format, setFormat] = useState<SiemFormat>("JSONL");
  const [showActor, setShowActor] = useState(false);
  const [showResource, setShowResource] = useState(false);
  const [payload, setPayload] = useState<Payload | null>(null);
  const [artifact, setArtifact] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [histogram, setHistogram] = useState<Record<string, unknown> | null>(null);
  const [facets, setFacets] = useState<Record<string, unknown> | null>(null);
  const [capabilities, setCapabilities] = useState<Record<string, unknown> | null>(null);
  async function get(mode: string) {
    const res = await fetch(endpoint + "?mode=" + mode, { cache: "no-store" });
    const data = await res.json();
    if (!res.ok) throw Error(data.code ?? "SIEM_META_UNAVAILABLE");
    return data.data as Record<string, unknown>;
  }
  async function load(cursor: string | null = null, requestedFormat?: SiemFormat) {
    setBusy(true);
    try {
      const q = new URLSearchParams({ mode: "page", limit: "50" });
      if (since) q.set("since", since);
      if (until) q.set("until", until);
      if (action) q.set("action", action);
      if (resourceType) q.set("resourceType", resourceType);
      if (cursor) q.set("cursor", cursor);
      if (requestedFormat) q.set("format", requestedFormat);
      if (showActor) q.set("actorRefs", "true");
      if (showResource) q.set("resourceRefs", "true");
      const response = await fetch(endpoint + "?" + q.toString(),
        { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw Error(data.code ?? "SIEM_PAGE_UNAVAILABLE");
      const result = data.data as Payload;
      setPayload(result); setPage(result.page);
      setEvents(old => cursor ? [...old, ...result.page.events.filter(e =>
        !old.some(x => x.eventId === e.eventId))] : result.page.events);
      setNext(result.page.nextCursor);
      if (requestedFormat) {
        if (!result.artifact) throw Error("SIEM_EXPORT_EMPTY");
        setArtifact(result.artifact.content);
      }
      setMessage("Registros leídos de PostgreSQL; ningún evento se envió a un SIEM.");
    } catch (e) { setMessage(String(e)); }
    finally { setBusy(false); }
  }
  useEffect(() => {
    void Promise.all([get("facets"), get("histogram"), get("capabilities")])
      .then(([f, h, c]) => {
        setFacets(f); setHistogram(h); setCapabilities(c);
      }).catch(e => setMessage(String(e)));
    void load();
  }, [endpoint]);
  function refresh() { setArtifact(""); void load(); }
  return <section aria-label="Intercambio de auditoría SIEM">
    <p role="note">Solo exportación manual de auditoría existente. Los formatos
      JSONL, ECS, CEF y CSV no significan que exista una integración conectada
      a Splunk, Sentinel o Datadog.</p>
    <h2>Consulta con límites</h2>
    <form onSubmit={e => { e.preventDefault(); refresh(); }}>
      <label>Desde UTC (ISO 8601)
        <input value={since} placeholder="2026-11-01T00:00:00.000Z"
          onChange={e => setSince(e.target.value)}/></label>
      <label>Hasta UTC (ISO 8601)
        <input value={until} placeholder="2026-11-23T00:00:00.000Z"
          onChange={e => setUntil(e.target.value)}/></label>
      <label>Acción
        <input value={action} maxLength={150} onChange={e =>
          setAction(e.target.value)}/></label>
      <label>Tipo de recurso
        <input value={resourceType} maxLength={100} onChange={e =>
          setResourceType(e.target.value)}/></label>
      {mayExport && <>
        <label>Referencia del actor (pseudonimizada)
          <input type="checkbox" checked={showActor}
            onChange={e => setShowActor(e.target.checked)}/></label>
        <label>Referencia del recurso (pseudonimizada)
          <input type="checkbox" checked={showResource}
            onChange={e => setShowResource(e.target.checked)}/></label>
      </>}
      <button type="submit" disabled={busy}>Consultar auditoría</button>
    </form>
    {page && <section aria-label="Página de auditoría">
      <h3>Registros: {events.length}</h3>
      <p>Integridad: {page.integrity.valid ? "PASS" : "REQUIERE REVISIÓN"}.
        Digest de página: {page.pageDigest}.</p>
      <p>Página incompleta: {page.hasMore ? "sí" : "no"}.
        Cobertura histórica total: no inferida.</p>
      <ol>{events.map(event => <li key={event.eventId}>
        <strong>{event.action}</strong> — {event.occurredAt}
        {" "}({event.category}, {event.severity})
        <p>Recurso: {event.resourceType};
          metadatos omitidos: {event.redactedFields};
          confianza: {event.confidence}.</p>
      </li>)}</ol>
      {next && <button type="button" disabled={busy} onClick={() =>
        void load(next)}>Siguiente página</button>}
    </section>}
    {mayExport && <section aria-label="Preparar exportación">
      <h3>Generar archivo para revisión</h3>
      <label>Formato
        <select value={format} onChange={e =>
          setFormat(e.target.value as SiemFormat)}>
          {formats.map(x => <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <button disabled={busy} type="button" onClick={() =>
        void load(null, format)}>Preparar exportación manual</button>
      {artifact && <>
        <p>Archivo preparado localmente; no se ha transmitido a ningún destinatario.</p>
        <textarea rows={12} aria-label="Archivo SIEM exportable"
          readOnly value={artifact}/>
      </>}
    </section>}
    {payload && <section aria-label="Calidad de exportación">
      <h3>Verificación y limitaciones</h3>
      <pre>{JSON.stringify({
        quality: payload.quality, readiness: payload.readiness,
      }, null, 2)}</pre>
    </section>}
    {facets && <details><summary>Acciones y recursos observados</summary>
      <pre>{JSON.stringify(facets, null, 2)}</pre></details>}
    {histogram && <details><summary>Frecuencia de auditoría</summary>
      <pre>{JSON.stringify(histogram, null, 2)}</pre></details>}
    {capabilities && <details><summary>Capacidades sin conexión externa</summary>
      <pre>{JSON.stringify(capabilities, null, 2)}</pre></details>}
    <p role="status">{message}</p>
  </section>;
}
