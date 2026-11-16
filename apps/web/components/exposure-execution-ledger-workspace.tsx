"use client";
import { useMemo, useState } from "react";
import type {
  ExecutionLeaseView,
  ExecutionChargeView,
  LedgerReadResult,
} from "../lib/exposure-execution-ledger-service";
type ListEnvelope = {
  schema: "cyberpilot.exposure.execution.ledger.api.v1";
  organizationId: string;
  data: LedgerReadResult;
  consumedQuotas: 0;
  executableLeaseIssued: false;
  startedNetworkCalls: 0;
  legalApprovalSigned: false;
  historicalCyberScoreModified: false;
};
function isObject(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}
function validateEnvelope(
  value: unknown, organizationId: string,
): value is ListEnvelope {
  if (!isObject(value) || !isObject(value.data)) return false;
  const data = value.data;
  return value.schema ===
    "cyberpilot.exposure.execution.ledger.api.v1" &&
    value.organizationId === organizationId &&
    data.schema ===
      "cyberpilot.exposure.execution.ledger.read.v1" &&
    data.organizationId === organizationId &&
    Array.isArray(data.leases) &&
    Array.isArray(data.charges) &&
    value.consumedQuotas === 0 &&
    value.executableLeaseIssued === false &&
    value.startedNetworkCalls === 0 &&
    value.legalApprovalSigned === false &&
    value.historicalCyberScoreModified === false &&
    data.externalNetworkCallsPerformedByReader === 0 &&
    data.legalAuthorizationIssuedByReader === false &&
    data.CyberScoreChanged === false;
}
function quota(lease: ExecutionLeaseView) {
  const value = lease.quota;
  return "DNS " + value.used.DNS + "/" + value.reserved.DNS +
    " · TLS " + value.used.TLS_HANDSHAKE + "/" +
      value.reserved.TLS_HANDSHAKE +
    " · HEAD " + value.used.HTTPS_HEADERS + "/" +
      value.reserved.HTTPS_HEADERS;
}
export function ExposureExecutionLedgerWorkspace({
  slug, organizationId,
}: { slug: string; organizationId: string }) {
  const [data, setData] = useState<LedgerReadResult | null>(null);
  const [selected, setSelected] = useState<ExecutionLeaseView | null>(null);
  const [chargeDetail, setChargeDetail] = useState<ExecutionChargeView | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [onlyIssues, setOnlyIssues] = useState(false);
  const [size, setSize] = useState(100);
  const [page, setPage] = useState(0);
  const [descending, setDescending] = useState(true);
  const [showAllCharges, setShowAllCharges] = useState(false);
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/exposure-execution-ledger";
  const load = async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(endpoint, {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "LIST", limit: size }),
      });
      const value: unknown = await response.json();
      if (!response.ok)
        throw Error(isObject(value) && typeof value.code === "string" ?
          value.code : "No se pudo consultar el ledger.");
      if (!validateEnvelope(value, organizationId))
        throw Error("Respuesta del ledger incoherente o ajena al tenant.");
      setData(value.data);
      setPage(0); setSelected(null); setChargeDetail(null);
      setMessage("Consultas PostgreSQL completadas sin emitir permisos LIVE.");
    } catch (cause) {
      setData(null);
      setError(cause instanceof Error ? cause.message :
        "Fallo consultando el historial operativo.");
    } finally { setBusy(false); }
  };
  const visible = useMemo(() => {
    const items = (data?.leases ?? []).filter(x =>
      (filter === "ALL" || x.state === filter) &&
      (!search || [
        x.domain, x.id, x.requestId, x.authorizationId,
        x.denialCode ?? "",
      ].join(" ").toLowerCase().includes(search.toLowerCase())));
    return descending ? items : [...items].reverse();
  }, [data, filter, search, descending]);
  const linkedCharges = useMemo(() =>
    (data?.charges ?? []).filter(x =>
      (!selected || x.leaseId === selected.id) &&
      (sourceFilter === "ALL" || x.source === sourceFilter)),
  [data, selected, sourceFilter]);
  const counts = useMemo(() => ({
    shown: visible.length,
    denied: visible.filter(x => x.state === "DENIED").length,
    active: visible.filter(x => x.state === "ACTIVE").length,
    completed: visible.filter(x => x.state === "COMPLETED").length,
    failed: visible.filter(x => x.state === "FAILED").length,
    used: visible.reduce((n,x) => n + x.quota.totalUsed,0),
  }),[visible]);
  const button: React.CSSProperties = {
    borderRadius: 8, border: "1px solid #64748b88",
    padding: "8px 12px", background: "transparent",
    color: "inherit", cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #94a3b866", borderRadius: 12,
    padding: 18, marginBottom: 14,
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap",
    alignItems: "center", gap: 12,
  };
  return <div>
    <section style={card}>
      <h2>Reservas ejecutables y cargos duraderos</h2>
      <p>Registro independiente de la planificación simulada.
        Las cuotas se consumirán transaccionalmente antes de cada
        operación externa y requieren una autoridad legal independiente,
        revisión vigente y un worker aislado.</p>
      <p><strong>Esta consola es exclusivamente de lectura.</strong>
        No se pueden emitir leases, cambiar consentimientos,
        reactivar agendas ni conectarse a infraestructura externa.</p>
      <div style={row}>
        <label>Límite de expedientes{" "}
          <select value={size}
            onChange={event => setSize(Number(event.target.value))}>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
          </select>
        </label>
        <button style={button} disabled={busy}
          onClick={load}>Consultar ledger</button>
      </div>
      {busy && <p role="status">Leyendo historial tenant-scoped…</p>}
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
    </section>
    {data && <>
      <section style={card}>
        <h3>Resumen de reservas</h3>
        <div style={row}>
          <p>Consultadas: <strong>{data.totalReservations}</strong></p>
          <p>Denegadas: <strong>{data.denied}</strong></p>
          <p>Terminadas: <strong>{data.terminal}</strong></p>
          <p>Abiertas: <strong>{data.unclosed}</strong></p>
          <p>DNS reservado:
            <strong>{data.sourceConsumption.DNS}</strong></p>
          <p>TLS reservado:
            <strong>{data.sourceConsumption.TLS_HANDSHAKE}</strong></p>
          <p>HEAD reservado:
            <strong>{data.sourceConsumption.HTTPS_HEADERS}</strong></p>
        </div>
        <p>Muestra limitada:
          {data.sampleTruncated ? " SÍ: datos incompletos" : " NO"}.</p>
        {data.auditIntegrityIssues.length > 0 ?
          <div role="alert">
            <p>Inconsistencias de auditoría detectadas:</p>
            <ul>{data.auditIntegrityIssues.map(code =>
              <li key={code}><code>{code}</code></li>)}</ul>
          </div> : <p>No se detectaron anomalías entre las
            filas consultadas. Esto no certifica servicios remotos.</p>}
      </section>
      <section style={card}>
        <h3>Historial de leases</h3>
        <div style={row}>
          <label>Buscar{" "}
            <input value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
              placeholder="Dominio, request ID, motivo" />
          </label>
          <label>Estado{" "}
            <select value={filter}
              onChange={e => { setFilter(e.target.value); setPage(0); }}>
              <option value="ALL">Todos</option>
              {["DENIED","ACTIVE","CANCELLED","EXPIRED","COMPLETED","FAILED"]
                .map(state => <option key={state} value={state}>{state}</option>)}
            </select>
          </label>
          <label><input type="checkbox"
            checked={descending}
            onChange={e => setDescending(e.target.checked)} />
            Más reciente primero</label>
          <label><input type="checkbox"
            checked={onlyIssues}
            onChange={e => setOnlyIssues(e.target.checked)} />
            Mostrar fallos</label>
        </div>
        <p>Coincidencias: {counts.shown} · Denegadas:
          {counts.denied} · Activas: {counts.active} ·
          Cerradas: {counts.completed} · Fallidas: {counts.failed}.</p>
        <ul>{visible
          .filter(item => !onlyIssues ||
            ["DENIED","FAILED","EXPIRED"].includes(item.state))
          .slice(page * 25, page * 25 + 25)
          .map(item => <li key={item.id} style={{ marginBottom: 14 }}>
            <button style={button} onClick={() => {
              setSelected(item); setChargeDetail(null);
            }}>
              {item.domain} · {item.state} · {item.requestId}
            </button>
            <p>Revision CAS {item.revision} · {quota(item)}</p>
            {item.denialCode && <p>Denegación:
              <code>{item.denialCode}</code></p>}
          </li>)}</ul>
        <div style={row}>
          <button style={button} disabled={page === 0}
            onClick={() => setPage(p => Math.max(0, p-1))}>Anterior</button>
          <button style={button}
            disabled={(page + 1) * 25 >= visible.length}
            onClick={() => setPage(p => p+1)}>Siguiente</button>
        </div>
      </section>
      {selected && <section style={card}>
        <h3>Detalle de reserva: {selected.requestId}</h3>
        <p>Estado: <strong>{selected.state}</strong> ·
          revisión {selected.revision}</p>
        <p>Dominio: {selected.domain} ·
          autorización: <code>{selected.authorizationId}</code></p>
        <p>Firma independiente: <code>{selected.consentDigest}</code></p>
        <p>Alcance SHA-256: <code>{selected.scopeDigest}</code></p>
        <p>Caduca: {selected.expiresAt} ·
          finalización: {selected.finishedAt ?? "pendiente"}</p>
        <p>Total consumido: {selected.quota.totalUsed} /
          {selected.quota.maximum}</p>
        <p>Legal customer approval generado aquí: <strong>NO</strong>.</p>
        <p>Seguridad técnica confirmada: <strong>NO</strong>.</p>
      </section>}
      <section style={card}>
        <div style={row}>
          <h3>Cargos de operaciones</h3>
          <button style={button}
            onClick={() => setShowAllCharges(x => !x)}>
            {showAllCharges ? "Limitar a 50" : "Mostrar todos"}
          </button>
          <label>Fuente{" "}
            <select value={sourceFilter}
              onChange={e => setSourceFilter(e.target.value)}>
              <option value="ALL">Todas</option>
              <option value="DNS">DNS</option>
              <option value="TLS_HANDSHAKE">TLS</option>
              <option value="HTTPS_HEADERS">HTTPS HEAD</option>
            </select>
          </label>
        </div>
        <ul>{linkedCharges.slice(0,
          showAllCharges ? linkedCharges.length : 50).map(item =>
          <li key={item.id} style={{ marginBottom: 10 }}>
            <button style={button} onClick={() => setChargeDetail(item)}>
              #{item.sequence} · {item.source} · {item.status}
            </button>
            <p>Operación identificada por digest:
              <code>{item.targetDigest}</code></p>
          </li>)}</ul>
        {chargeDetail && <section style={card}>
          <h4>Cargo #{chargeDetail.sequence}</h4>
          <p>Fuente: {chargeDetail.source} ·
            estado: {chargeDetail.status}</p>
          <p>Iniciado: {chargeDetail.startedAt} ·
            terminado: {chargeDetail.finishedAt ?? "no cerrado"}</p>
          <p>Peer SHA-256: {chargeDetail.peerDigest ?? "no observado"}</p>
          <p>Error: {chargeDetail.errorCode ?? "ninguno"}</p>
          <p>Una fila reservada no acredita que haya habido
            una conexión real ni seguridad verificada.</p>
        </section>}
      </section>
    </>}
  </div>;
}
