"use client";

import { useMemo, useState } from "react";
import type {
  BaselineDossierReport,
  BaselineDossierGate,
  BaselineDossierTimelineEntry,
} from "../lib/baseline-development-dossier";

type DossierEnvelope = {
  report: BaselineDossierReport;
  verification: { valid: boolean; errors: string[] };
  liveProviderQueries: 0;
  writeOperations: 0;
  customerApprovalRecorded: false;
};
type ExportEnvelope = {
  filename: string;
  mime: string;
  text: string;
  digest: string;
  containsCredentials: false;
  includesLegalSignature: false;
  customerApprovalRecorded: false;
  securityCertificationClaimed: false;
};
const stateLabels = {
  PASS: "Coherente",
  BLOCK: "Evidencia bloqueante",
  ADVISORY: "Revisión pendiente",
} as const;
const sourceLabels: Record<BaselineDossierTimelineEntry["kind"], string> = {
  DRAFT_REVISION: "Revisión del cuestionario",
  TECHNICAL_REVIEW: "Revisión técnica",
  REVIEW_EVENT: "Evento de revisión",
  ACTION: "Acción declarativa",
  ACTION_EVENT: "Evento de seguimiento",
};
function statusColor(state: BaselineDossierGate["state"]) {
  if (state === "PASS") return "#0f766e";
  if (state === "BLOCK") return "#b91c1c";
  return "#a16207";
}
function reportDate(value: string): string {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Fecha no verificable";
}
function safeObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}
function isReportEnvelope(value: unknown):
  value is DossierEnvelope {
  if (!safeObject(value)) return false;
  const { report, verification } = value;
  if (!safeObject(report) || !safeObject(verification))
    return false;
  return report.schema === "cyberpilot.baseline.development.dossier.v1" &&
    typeof report.organizationId === "string" &&
    typeof report.digest === "string" &&
    Array.isArray(report.gates) &&
    Array.isArray(report.timeline) &&
    verification.valid === true &&
    value.liveProviderQueries === 0 &&
    value.writeOperations === 0 &&
    value.customerApprovalRecorded === false &&
    report.customerApprovalRecorded === false &&
    report.independentlyValidatedSecurityControls === 0 &&
    report.actualRemediationVerified === false &&
    report.existingCyberScoreModified === false;
}
function download(payload: ExportEnvelope) {
  if (payload.containsCredentials !== false ||
      payload.includesLegalSignature !== false ||
      payload.customerApprovalRecorded !== false ||
      payload.securityCertificationClaimed !== false)
    throw Error("El expediente afirma una autorización no verificada.");
  if (!/^[a-z0-9.-]{1,120}$/.test(payload.filename))
    throw Error("Nombre de exportación no permitido.");
  const blob = new Blob([payload.text], { type: payload.mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = payload.filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
export function BaselineDevelopmentDossierWorkspace({
  slug, organizationId,
}: { slug: string; organizationId: string }) {
  const [report, setReport] = useState<BaselineDossierReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState<"ALL" |
    BaselineDossierGate["state"]>("ALL");
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<"ALL" |
    BaselineDossierTimelineEntry["kind"]>("ALL");
  const [timelineSearch, setTimelineSearch] = useState("");
  const [showTimeline, setShowTimeline] = useState(false);
  const [pageSize, setPageSize] = useState(25);
  const [selectedSourceId, setSelectedSourceId] = useState("");
  const [expandedGates, setExpandedGates] =
    useState<Record<string, boolean>>({});
  const [sortNewest, setSortNewest] = useState(true);
  const [showLimits, setShowLimits] = useState(true);
  const [showSubmissions, setShowSubmissions] = useState(true);
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/baseline-development-dossier";
  const load = async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(endpoint, {
        method: "GET", cache: "no-store",
        headers: { Accept: "application/json" },
      });
      const body: unknown = await response.json();
      if (!response.ok)
        throw Error(safeObject(body) && typeof body.code === "string" ?
          body.code : "No se ha podido recuperar el expediente.");
      if (!isReportEnvelope(body))
        throw Error("El servidor no devolvió un expediente verificable.");
      if (body.report.organizationId !== organizationId)
        throw Error("La respuesta corresponde a otra organización.");
      setReport(body.report);
      setExpandedGates({});
      setSelectedSourceId("");
      setMessage("Evidencia técnica recuperada en modo solo lectura.");
    } catch (cause) {
      setReport(null);
      setError(cause instanceof Error ? cause.message :
        "No se ha podido verificar el expediente.");
    } finally {
      setBusy(false);
    }
  };
  const exportFile = async (format: "JSON" | "CSV" | "MARKDOWN") => {
    if (busy || !report) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(endpoint + "?format=" + format, {
        method: "GET", cache: "no-store",
      });
      const data = await response.json() as Partial<ExportEnvelope> & {
        code?: string;
      };
      if (!response.ok) throw Error(data.code ?? "Exportación rechazada.");
      if (data.digest !== report.digest)
        throw Error("La evidencia cambió desde su última consulta.");
      if (typeof data.filename !== "string" ||
          typeof data.mime !== "string" ||
          typeof data.text !== "string")
        throw Error("Respuesta de exportación incompleta.");
      download(data as ExportEnvelope);
      setMessage("Expediente descargado con su huella de integridad local.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Error exportando el expediente.");
    } finally {
      setBusy(false);
    }
  };
  const visibleGates = useMemo(() => (report?.gates ?? [])
    .filter(g => (filter === "ALL" || g.state === filter) &&
      (search.trim() === "" ||
        [g.id, g.reason, ...g.linkedSourceIds]
          .join(" ").toLowerCase().includes(search.toLowerCase()))),
  [report, filter, search]);
  const visibleTimeline = useMemo(() => {
    const result = (report?.timeline ?? []).filter(e =>
      (kind === "ALL" || e.kind === kind) &&
      (!timelineSearch.trim() ||
        [e.sourceId, e.state, e.relationship, sourceLabels[e.kind]]
          .join(" ").toLowerCase().includes(timelineSearch.toLowerCase())));
    if (sortNewest) return [...result].reverse();
    return result;
  }, [report, kind, timelineSearch, sortNewest]);
  const selectedSource = useMemo(() =>
    report?.timeline.find(x => x.sourceId === selectedSourceId) ?? null,
  [report, selectedSourceId]);
  const totals = useMemo(() => {
    const gates = report?.gates ?? [];
    return {
      passed: gates.filter(x => x.state === "PASS").length,
      blocked: gates.filter(x => x.state === "BLOCK").length,
      advisory: gates.filter(x => x.state === "ADVISORY").length,
      total: gates.length,
    };
  }, [report]);
  const action: React.CSSProperties = {
    padding: "8px 13px", borderRadius: 8,
    border: "1px solid #64748b88",
    background: "transparent", color: "inherit",
    cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #94a3b866",
    padding: 18, borderRadius: 12, marginBottom: 16,
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap",
    alignItems: "center", gap: 12,
  };
  return <div>
    <section style={card}>
      <h2>Conciliación técnica del Baseline persistido</h2>
      <p>Esta vista contrasta evidencias reales guardadas en PostgreSQL:
        cuestionarios, presentaciones, revisiones y acciones humanas.
        Una evidencia íntegra no acredita que un control de seguridad
        haya sido probado por un tercero.</p>
      <p><strong>El expediente nunca registra aprobaciones legales
        de clientes ni certificaciones CIS.</strong> Tampoco cambia
        CyberScore, realiza escaneos ni ejecuta remediaciones.</p>
      <div style={row}>
        <button style={action} disabled={busy}
          onClick={load}>Conciliar evidencias</button>
        <button style={action} disabled={busy || !report}
          onClick={() => exportFile("JSON")}>Exportar JSON</button>
        <button style={action} disabled={busy || !report}
          onClick={() => exportFile("CSV")}>Exportar gates CSV</button>
        <button style={action} disabled={busy || !report}
          onClick={() => exportFile("MARKDOWN")}>Exportar resumen Markdown</button>
      </div>
      {busy && <p role="status">Consultando registros tenant-scoped…</p>}
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
    </section>
    {report && <>
      <section style={card}>
        <h3>Resultado de trazabilidad: {report.verdict}</h3>
        <p>Origen: organización autenticada ·
          {report.latestDraftState ?? "sin borrador"} ·
          revisión {report.latestDraftRevision ?? "desconocida"}</p>
        <p>Generado: {reportDate(report.generatedAt)}</p>
        <p>Huella SHA-256 local:
          <code style={{ overflowWrap: "anywhere" }}>{report.digest}</code></p>
        <div style={row}>
          <p>Puertas: <strong>{totals.total}</strong></p>
          <p>Coherentes: <strong>{totals.passed}</strong></p>
          <p>Bloqueadas: <strong>{totals.blocked}</strong></p>
          <p>Revisar: <strong>{totals.advisory}</strong></p>
        </div>
        <p>Integridad de consultas:
          {report.sourceCompleteness.bounded ? " completa dentro del límite" :
            " INCOMPLETA: límite excedido"}.</p>
        <p>Revisiones del cuestionario: {report.sampleCounts.revisions} ·
          revisiones técnicas: {report.sampleCounts.reviews} ·
          eventos de revisión: {report.sampleCounts.reviewEvents} ·
          acciones: {report.sampleCounts.actions} ·
          eventos de acciones: {report.sampleCounts.actionEvents}.</p>
      </section>
      <section style={card}>
        <h3>Puertas de consistencia</h3>
        <div style={row}>
          <label>Estado{" "}
            <select value={filter}
              onChange={e => setFilter(
                e.target.value as typeof filter)}>
              <option value="ALL">Todos</option>
              <option value="PASS">Coherente</option>
              <option value="BLOCK">Bloqueante</option>
              <option value="ADVISORY">Requiere revisión</option>
            </select>
          </label>
          <label>Buscar gate o referencia{" "}
            <input value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Identificador de evidencia" />
          </label>
        </div>
        {visibleGates.length === 0 && <p>No hay gates para este filtro.</p>}
        <ul>{visibleGates.map(gate => <li key={gate.id}
          style={{ marginBottom: 13 }}>
          <div style={row}>
            <strong>{gate.id}</strong>
            <span style={{ color: statusColor(gate.state) }}>
              {stateLabels[gate.state]}
            </span>
            <span>{gate.observed} / {gate.expected}</span>
            <button style={action}
              onClick={() => setExpandedGates(p => ({
                ...p, [gate.id]: !p[gate.id],
              }))}>
              {expandedGates[gate.id] ?
                "Ocultar fuentes" : "Mostrar fuentes"}
            </button>
          </div>
          <p>{gate.reason}</p>
          {expandedGates[gate.id] &&
            (gate.linkedSourceIds.length ? <ul>
              {gate.linkedSourceIds.map(id => <li key={id}>
                <code>{id}</code>
              </li>)}
            </ul> : <p>Sin referencias individuales asociadas.</p>)}
        </li>)}</ul>
      </section>
      {showSubmissions && <section style={card}>
        <div style={row}>
          <h3>Versiones presentadas y revisiones</h3>
          <button style={action}
            onClick={() => setShowSubmissions(false)}>Contraer</button>
        </div>
        {report.submissions.length === 0 &&
          <p>No consta una presentación persistida.</p>}
        <ol>{report.submissions.map(source =>
          <li key={source.revision} style={{ marginBottom: 10 }}>
            <p>Baseline presentado v{source.revision} ·
              informe {source.sourceValid ? "verificado" : "NO VERIFICADO"}</p>
            <p>Revisión interna:
              {source.internalReviewState ?? "pendiente"} ·
              eventos: {source.reviewEventCount} ·
              bloqueantes: {source.blockingIssueCount}</p>
            <p>Aprobación de cliente: no consta.
              Controles verificados: no consta.</p>
            {source.reportDigest && <small>
              Digest: <code>{source.reportDigest}</code>
            </small>}
          </li>)}</ol>
      </section>}
      {!showSubmissions && <button style={action}
        onClick={() => setShowSubmissions(true)}>
        Mostrar presentaciones y revisiones
      </button>}
      <section style={card}>
        <h3>Acciones de seguimiento</h3>
        <div style={row}>
          {Object.entries(report.actions)
            .filter(([key]) => key !== "independentRemediationsVerified")
            .map(([key, value]) => <p key={key}>
              {key}: <strong>{value}</strong>
            </p>)}
        </div>
        <p>Las acciones COMPLETED_REPORTED son declaraciones humanas;
          no se contabilizan como remediación técnica comprobada.</p>
      </section>
      <section style={card}>
        <div style={row}>
          <h3>Cadena temporal de evidencias</h3>
          <button style={action}
            onClick={() => setShowTimeline(x => !x)}>
            {showTimeline ? "Ocultar" : "Explorar"}
          </button>
        </div>
        {showTimeline && <>
          <div style={row}>
            <label>Fuente{" "}
              <select value={kind}
                onChange={e => setKind(e.target.value as typeof kind)}>
                <option value="ALL">Todas</option>
                {Object.entries(sourceLabels).map(([key, value]) =>
                  <option key={key} value={key}>{value}</option>)}
              </select>
            </label>
            <label>Referencia/estado{" "}
              <input value={timelineSearch}
                onChange={e => setTimelineSearch(e.target.value)}
                placeholder="ID, estado, relación" />
            </label>
            <label><input type="checkbox"
              checked={sortNewest}
              onChange={e => setSortNewest(e.target.checked)} />
              Más recientes primero</label>
            <label>Registros por página{" "}
              <select value={pageSize}
                onChange={e => setPageSize(Number(e.target.value))}>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
              </select>
            </label>
          </div>
          <p>{visibleTimeline.length} eventos coincidentes.</p>
          <ol>{visibleTimeline.slice(0, pageSize).map(entry =>
            <li key={entry.kind + entry.sourceId}
              style={{ marginBottom: 9 }}>
              <button style={action}
                onClick={() => setSelectedSourceId(entry.sourceId)}>
                {sourceLabels[entry.kind]} ·
                {entry.state} · v{entry.sourceRevision}
              </button>
              <small> {reportDate(entry.at)}</small>
            </li>)}</ol>
          {visibleTimeline.length > pageSize &&
            <button style={action}
              onClick={() => setPageSize(
                size => Math.min(2000, size + 100))}>
              Mostrar más
            </button>}
          {selectedSource && <section style={card}>
            <h4>Procedencia del registro</h4>
            <p>Tipo: {sourceLabels[selectedSource.kind]}</p>
            <p>Estado: {selectedSource.state}</p>
            <p>Revisión: {selectedSource.sourceRevision}</p>
            <p>Referencia:
              <code style={{ overflowWrap: "anywhere" }}>
                {selectedSource.sourceId}
              </code></p>
            <p>Relación:
              <code style={{ overflowWrap: "anywhere" }}>
                {selectedSource.relationship}
              </code></p>
            <p>No se incluyen respuestas libres ni credenciales.</p>
          </section>}
        </>}
      </section>
      <section style={card}>
        <button style={action} onClick={() => setShowLimits(x => !x)}>
          {showLimits ? "Ocultar límites" : "Mostrar límites"}
        </button>
        {showLimits && <ul>{report.limits.map(value =>
          <li key={value}>{value}</li>)}</ul>}
      </section>
    </>}
  </div>;
}
