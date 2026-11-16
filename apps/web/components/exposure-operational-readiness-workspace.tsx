"use client";

import { useMemo, useState } from "react";
import type {
  ExposureCloseoutReport,
  ExposureCloseoutDomain,
} from "../lib/exposure-operational-closeout";

type Envelope = {
  report: ExposureCloseoutReport;
  verification: { valid: boolean; errors: string[] };
  externallyAuthorizedCollection: false;
  independentConsentCertified: false;
  providerNetworkCalls: 0;
  writeOperations: 0;
};
type ExportEnvelope = {
  filename: string; mime: string; content: string; digest: string;
  containsCredentials: false;
  legalApprovalSigned: false;
  liveNetworkAuthorized: false;
  claimsRemediation: false;
};
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}
function validEnvelope(value: unknown): value is Envelope {
  if (!object(value) || !object(value.report) ||
      !object(value.verification)) return false;
  return value.report.schema ===
    "cyberpilot.exposure.operational.readiness.v1" &&
    typeof value.report.organizationId === "string" &&
    typeof value.report.digest === "string" &&
    Array.isArray(value.report.domains) &&
    Array.isArray(value.report.gates) &&
    value.verification.valid === true &&
    value.externallyAuthorizedCollection === false &&
    value.independentConsentCertified === false &&
    value.providerNetworkCalls === 0 &&
    value.writeOperations === 0 &&
    value.report.legalCustomerConsentSigned === false &&
    value.report.providerTrafficPermitted === false &&
    value.report.externalInfrastructureEvaluated === false &&
    value.report.priorCyberScoreChanged === false;
}
function saveFile(payload: ExportEnvelope) {
  if (payload.legalApprovalSigned !== false ||
      payload.liveNetworkAuthorized !== false ||
      payload.claimsRemediation !== false ||
      payload.containsCredentials !== false)
    throw Error("La exportación incluye afirmaciones de seguridad inválidas.");
  if (!/^[a-z0-9.-]{1,120}$/.test(payload.filename))
    throw Error("Nombre de archivo de exportación no permitido.");
  const blob = new Blob([payload.content], { type: payload.mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = payload.filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
function quotaLabel(row: ExposureCloseoutDomain) {
  const expected = row.quotaAttempted;
  const reported = row.quotaReportedActual;
  return "DNS " + reported.dns + "/" + expected.dns +
    " · TLS " + reported.tls + "/" + expected.tls +
    " · HEAD " + reported.http + "/" + expected.http;
}
function badgeStyle(state: "BLOCK" | "ADVISORY" | "PASS") {
  return {
    fontWeight: 700,
    color: state === "PASS" ? "#0f766e" :
      state === "BLOCK" ? "#b91c1c" : "#a16207",
  };
}
export function ExposureOperationalReadinessWorkspace({
  slug, organizationId,
}: { slug: string; organizationId: string }) {
  const [report, setReport] = useState<ExposureCloseoutReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [showOnlyBlocked, setShowOnlyBlocked] = useState(false);
  const [chosenDomain, setChosenDomain] = useState("");
  const [showGates, setShowGates] = useState(true);
  const [gateFilter, setGateFilter] = useState("ALL");
  const [showLimits, setShowLimits] = useState(true);
  const [sourceLimit, setSourceLimit] = useState(25);
  const [selectedGate, setSelectedGate] = useState("");
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/exposure-operational-readiness";
  const load = async () => {
    if (loading) return;
    setLoading(true); setError(""); setNotice("");
    try {
      const response = await fetch(endpoint, {
        method: "GET", cache: "no-store",
      });
      const value: unknown = await response.json();
      if (!response.ok)
        throw Error(object(value) && typeof value.code === "string" ?
          value.code : "No se pudo consultar la preparación Exposure.");
      if (!validEnvelope(value))
        throw Error("Faltan garantías de origen en el expediente.");
      if (value.report.organizationId !== organizationId)
        throw Error("Se ha recibido información de otra organización.");
      setReport(value.report);
      setChosenDomain("");
      setSelectedGate("");
      setNotice("Evidencia operativa consultada sin realizar solicitudes LIVE.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "No se pudo verificar la lectura del expediente.");
      setReport(null);
    } finally { setLoading(false); }
  };
  const exportFile = async (format: "JSON" | "CSV" | "MARKDOWN") => {
    if (!report || loading) return;
    setLoading(true); setError(""); setNotice("");
    try {
      const response = await fetch(endpoint + "?format=" + format, {
        method: "GET", cache: "no-store",
      });
      const data = await response.json() as Partial<ExportEnvelope> & {
        code?: string;
      };
      if (!response.ok)
        throw Error(data.code ?? "Formato de exportación rechazado.");
      if (data.digest !== report.digest)
        throw Error("Los registros han cambiado. Recarga el informe.");
      if (typeof data.filename !== "string" ||
          typeof data.content !== "string" ||
          typeof data.mime !== "string")
        throw Error("La respuesta de exportación es incompleta.");
      saveFile(data as ExportEnvelope);
      setNotice("Expediente exportado con integridad local SHA-256.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "No se pudo exportar el informe.");
    } finally { setLoading(false); }
  };
  const visibleDomains = useMemo(() => (report?.domains ?? [])
    .filter(item => (!showOnlyBlocked || item.blockers.length > 0) &&
      (!query.trim() ||
        [item.domain, item.technicalOwnershipState,
          item.scheduleState ?? "", ...item.blockers,
          ...item.nextActions].join(" ").toLowerCase()
          .includes(query.toLowerCase()))),
  [report, query, showOnlyBlocked]);
  const selected = useMemo(() =>
    report?.domains.find(item => item.domain === chosenDomain) ?? null,
  [report, chosenDomain]);
  const gates = useMemo(() =>
    (report?.gates ?? []).filter(item =>
      gateFilter === "ALL" || item.severity === gateFilter),
  [report, gateFilter]);
  const gateDetail = useMemo(() =>
    report?.gates.find(item => item.id === selectedGate) ?? null,
  [report, selectedGate]);
  const button: React.CSSProperties = {
    border: "1px solid #64748b88",
    borderRadius: 8, background: "transparent",
    color: "inherit", padding: "8px 13px",
    cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #94a3b866",
    borderRadius: 12, padding: 18,
    marginBottom: 16,
  };
  const row: React.CSSProperties = {
    display: "flex", gap: 12,
    alignItems: "center", flexWrap: "wrap",
  };
  return <div>
    <section style={card}>
      <h2>Preparación de Exposure · autorización y cuotas</h2>
      <p>Conciliación local de autorizaciones de dominio, agendas
        persistidas, reservas y auditorías. No activa evaluaciones
        externas ni crea una autorización legal en nombre del cliente.</p>
      <p><strong>LIVE permanece bloqueado.</strong> Una prueba DNS
        demuestra control técnico limitado; el consentimiento empresarial
        independiente debe verificarse por otro servicio autorizado.</p>
      <div style={row}>
        <button style={button} disabled={loading}
          onClick={load}>Evaluar preparación offline</button>
        <button style={button} disabled={loading || !report}
          onClick={() => exportFile("JSON")}>Expediente JSON</button>
        <button style={button} disabled={loading || !report}
          onClick={() => exportFile("CSV")}>Dominios CSV</button>
        <button style={button} disabled={loading || !report}
          onClick={() => exportFile("MARKDOWN")}>Informe Markdown</button>
      </div>
      {loading && <p role="status">Leyendo evidencias de la organización…</p>}
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </section>
    {report && <>
      <section style={card}>
        <h3>Resultado: {report.verdict}</h3>
        <p>Organización: {report.organizationId} ·
          análisis: {report.generatedAt}</p>
        <p>SHA-256:
          <code style={{ overflowWrap: "anywhere" }}>{report.digest}</code></p>
        <div style={row}>
          <p>Autorizaciones: <strong>{report.total.authorizations}</strong></p>
          <p>Agendas: <strong>{report.total.schedules}</strong></p>
          <p>Reservas: <strong>{report.total.reservations}</strong></p>
          <p>Denegadas: <strong>{report.total.deniedReservations}</strong></p>
          <p>Anomalías CAS:
            <strong>{report.total.eventSequenceAnomalies}</strong></p>
          <p>Referencias huérfanas:
            <strong>{report.total.orphanedRows}</strong></p>
        </div>
        <p>Lectura acotada: {report.sourceBounded ? "Sí" : "NO"} ·
          Aislamiento: {report.allTenantScoped ? "coherente" : "INCOMPLETO"}</p>
        <p>Solicitudes externas autorizadas por esta vista: <strong>0</strong>.
          Mejoras de CyberScore: <strong>0</strong>.</p>
      </section>
      <section style={card}>
        <h3>Dominios y bloqueantes operativos</h3>
        <div style={row}>
          <label>Buscar dominio o blocker{" "}
            <input value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Dominio, estado, motivo" />
          </label>
          <label><input type="checkbox"
            checked={showOnlyBlocked}
            onChange={e => setShowOnlyBlocked(e.target.checked)} />
            Solo bloqueados</label>
        </div>
        {visibleDomains.length === 0 &&
          <p>No hay dominios para este filtro.</p>}
        <ul>{visibleDomains.slice(0, sourceLimit).map(item =>
          <li key={item.domain} style={{ marginBottom: 14 }}>
            <div style={row}>
              <button style={button}
                onClick={() => setChosenDomain(item.domain)}>
                {item.domain}
              </button>
              <span>{item.technicalOwnershipState}</span>
              <span>{item.scheduleState ?? "SIN AGENDA"}</span>
              <strong style={{ color: "#b91c1c" }}>
                {item.blockers.length} bloqueantes</strong>
            </div>
            <p>Cuotas locales: {quotaLabel(item)}</p>
            <p>Solicitudes denegadas: {item.deniedReservations} ·
              eventos DNS: {item.authorizationHistoryEvents} ·
              eventos de agenda: {item.scheduleHistoryEvents}</p>
          </li>)}</ul>
        {visibleDomains.length > sourceLimit &&
          <button style={button}
            onClick={() => setSourceLimit(x => x + 25)}>
            Mostrar más dominios
          </button>}
        {selected && <section style={card}>
          <h4>Dominio: {selected.domain}</h4>
          <p>Autorización:
            <code>{selected.authorizationId ?? "ausente"}</code></p>
          <p>Agenda:
            <code>{selected.scheduleId ?? "ausente"}</code></p>
          <p>Fuentes previstas: {selected.sources.join(", ") || "ninguna"}</p>
          <p>Consentimiento independiente: <strong>NO VERIFICADO</strong>.</p>
          <p>Tráfico externo permitido: <strong>NO</strong>.</p>
          <h5>Bloqueantes</h5>
          <ul>{selected.blockers.map(value =>
            <li key={value}>{value}</li>)}</ul>
          <h5>Próximas acciones</h5>
          <ol>{selected.nextActions.map(value =>
            <li key={value}>{value}</li>)}</ol>
          {selected.advisories.length > 0 && <>
            <h5>Advertencias</h5>
            <ul>{selected.advisories.map(value =>
              <li key={value}>{value}</li>)}</ul>
          </>}
        </section>}
      </section>
      <section style={card}>
        <div style={row}>
          <h3>Puertas de integridad</h3>
          <button style={button}
            onClick={() => setShowGates(value => !value)}>
            {showGates ? "Contraer" : "Mostrar"}
          </button>
        </div>
        {showGates && <>
          <label>Filtro{" "}
            <select value={gateFilter}
              onChange={e => setGateFilter(e.target.value)}>
              <option value="ALL">Todas</option>
              <option value="PASS">Coherentes</option>
              <option value="BLOCK">Bloqueantes</option>
              <option value="ADVISORY">Advertencias</option>
            </select>
          </label>
          <ul>{gates.map(item => <li key={item.id}
            style={{ marginBottom: 10 }}>
            <button style={button}
              onClick={() => setSelectedGate(item.id)}>
              {item.id}
            </button>
            {" "}<span style={badgeStyle(item.severity)}>
              {item.severity}</span>
            {" "}{item.actual}/{item.expected}
          </li>)}</ul>
          {gateDetail && <section style={card}>
            <h4>{gateDetail.id}</h4>
            <p>{gateDetail.reason}</p>
            <p>Esperado: {gateDetail.expected} ·
              Observado: {gateDetail.actual}</p>
            <ul>{gateDetail.relatedIds.map(value =>
              <li key={value}><code>{value}</code></li>)}</ul>
          </section>}
        </>}
      </section>
      <section style={card}>
        <button style={button}
          onClick={() => setShowLimits(x => !x)}>
          {showLimits ? "Ocultar límites" : "Mostrar límites"}
        </button>
        {showLimits && <ul>{report.limitations.map(value =>
          <li key={value}>{value}</li>)}</ul>}
      </section>
    </>}
  </div>;
}
