"use client";

import { useMemo, useState } from "react";

type PassiveSource = "DNS" | "TLS_HANDSHAKE" | "HTTPS_HEADERS";
type Schedule = {
  organizationId: string;
  scheduleId: string;
  authorizationId: string;
  domain: string;
  revision: number;
  state: "DISABLED" | "PAUSED" | "READY" | "REVOKED";
  sources: PassiveSource[];
  policyDigest: string;
  legalConsentVerified: boolean;
  minimumIntervalMs: number;
  dailyDnsLimit: number;
  dailyTlsLimit: number;
  dailyHttpLimit: number;
  lastAttemptAt: string | null;
  nextEligibleAt: string | null;
  activeNetworkConnections: 0;
};
type Quota = {
  eligibleForNetwork: false;
  reservationPermitted: false;
  proposedCalls: number;
  quotasFit: boolean;
  usage: {
    dns: number; tls: number; http: number;
    reservations: number;
  };
  cost: { dns: number; tls: number; http: number };
  scheduleEnabled: boolean;
  independentlyVerifiedLegalConsent: boolean;
  noNetworkRequests: true;
  reasons: string[];
};
type Event = {
  revision: number; action: string;
  priorState: string; currentState: string;
  at: string; actorUserId: string;
  externalNetworkRequests: 0;
};
type Reservation = {
  requestId: string;
  state: string;
  createdAt: string;
  rejectionCode: string | null;
};
const sources: Array<{ value: PassiveSource; label: string }> = [
  { value: "DNS", label: "DNS SPF/DMARC/MX" },
  { value: "TLS_HANDSHAKE", label: "TLS 443 (futuro)" },
  { value: "HTTPS_HEADERS", label: "Cabeceras HEAD (futuro)" },
];
export function ExposurePassiveScheduleWorkspace({
  slug, canAdmin,
}: { slug: string; canAdmin: boolean }) {
  const [domain, setDomain] = useState("");
  const [selectedSources, setSelectedSources] =
    useState<PassiveSource[]>(["DNS"]);
  const [items, setItems] = useState<Schedule[]>([]);
  const [current, setCurrent] = useState<Schedule | null>(null);
  const [quota, setQuota] = useState<Quota | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [reservations, setReservations] =
    useState<Reservation[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("ALL");
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/exposure-passive-schedules";
  const request = async (operation: string,
    fields: Record<string, unknown> = {}) => {
    const response = await fetch(endpoint, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, ...fields }),
    });
    const result = await response.json() as Record<string, unknown>;
    if (!response.ok) {
      if (result.code === "SCHEDULE_REVISION_CONFLICT")
        throw Error("La planificación ha cambiado; recupera su última versión.");
      throw Error(typeof result.code === "string" ?
        result.code : "No se pudo consultar la planificación.");
    }
    if (result.networkRequestsExecuted !== 0 ||
        result.activeScansPerformed !== 0 ||
        result.legalConsentProven !== false ||
        result.historicalCyberScoreChanged !== false)
      throw Error("La planificación no puede certificar ni iniciar escaneos.");
    return result.data as Record<string, unknown>;
  };
  const execute = (task: () => Promise<void>) => async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await task(); }
    catch (e) {
      setError(e instanceof Error ? e.message : "Error inesperado.");
    } finally { setBusy(false); }
  };
  const load = execute(async () => {
    const result = await request("LIST", { limit: 100 });
    setItems(result.items as Schedule[]);
    setMessage("Se han recuperado planificaciones; no se ha conectado a terceros.");
  });
  const read = execute(async () => {
    const result = await request("READ", {
      domain: domain.toLowerCase().trim(),
    });
    setCurrent(result.schedule as Schedule);
    setSelectedSources((result.schedule as Schedule).sources);
    setQuota(null); setEvents([]); setReservations([]);
    setMessage("Planificación recuperada.");
  });
  const create = execute(async () => {
    if (!canAdmin) throw Error("Se necesita rol administrador.");
    const result = await request("CREATE", {
      domain: domain.toLowerCase().trim(),
      expectedRevision: 0, sources: selectedSources,
    });
    const value = result.schedule as Schedule;
    setCurrent(value); setDomain(value.domain);
    setMessage("Planificación guardada deshabilitada; pendiente de consentimiento.");
  });
  const update = (operation: "UPDATE" | "PAUSE" |
    "REVOKE") => execute(async () => {
    if (!current) throw Error("Selecciona una planificación.");
    const result = await request(operation, {
      domain: current.domain,
      expectedRevision: current.revision,
      ...(operation === "UPDATE" ?
        { sources: selectedSources } : {}),
    });
    setCurrent(result.schedule as Schedule);
    setQuota(null); setEvents([]);
    setMessage("Cambio versionado y auditado; no se han ejecutado peticiones.");
  });
  const simulate = execute(async () => {
    if (!current) throw Error("Selecciona una planificación.");
    const result = await request("SIMULATE", {
      domain: current.domain,
    });
    setQuota((result.decision as Quota));
    setMessage("Simulación de cuota, no escaneo ni reserva de tráfico.");
  });
  const reserve = execute(async () => {
    if (!current) throw Error("Selecciona una planificación.");
    const requestId = "requested-" +
      crypto.randomUUID().replaceAll("-", "");
    const result = await request("RESERVE", {
      domain: current.domain, requestId,
    });
    if (result.state !== "DENIED" ||
        result.networkCallsStarted !== 0)
      throw Error("La reserva no debe activar una red sin consentimiento independiente.");
    setMessage("Solicitud " + requestId + " denegada de forma auditable: " +
      result.rejectionCode);
  });
  const history = execute(async () => {
    if (!current) throw Error("Selecciona una planificación.");
    const result = await request("HISTORY", {
      domain: current.domain, limit: 100,
    });
    setEvents(result.events as Event[]);
    setMessage("Eventos de política recuperados.");
  });
  const historyReservations = execute(async () => {
    if (!current) throw Error("Selecciona una planificación.");
    const result = await request("RESERVATIONS", {
      domain: current.domain, limit: 100,
    });
    setReservations(result.requests as Reservation[]);
    setMessage("Registro persistente de reservas consultado.");
  });
  const filtered = useMemo(() => items.filter(x =>
    filter === "ALL" || x.state === filter), [items, filter]);
  const card: React.CSSProperties = {
    padding: 18, borderRadius: 12,
    border: "1px solid #94a3b866", marginBottom: 14,
  };
  const button: React.CSSProperties = {
    padding: "8px 12px", border: "1px solid #64748b77",
    borderRadius: 8, color: "inherit",
    background: "transparent", cursor: "pointer",
  };
  const row: React.CSSProperties = {
    display: "flex", gap: 12, alignItems: "center",
    flexWrap: "wrap",
  };
  return <div>
    <section style={card}>
      <h2>Planificación pasiva · Exposure</h2>
      <p>Define qué observaciones se podrían solicitar
        tras verificar el dominio y el consentimiento
        independiente. Las planificaciones nuevas
        nacen deshabilitadas; ninguna operación de esta
        pantalla realiza escaneos.</p>
      <p>El desafío DNS no constituye autorización legal
        para recoger datos. Las reservas operativas se
        deniegan hasta incorporar un servicio de
        consentimiento autenticado y un recolector
        técnicamente aislado.</p>
      <div style={row}>
        <label>Dominio{" "}
          <input value={domain}
            placeholder="empresa.example.com"
            onChange={event => {
              setDomain(event.target.value);
              setCurrent(null); setQuota(null);
            }} />
        </label>
        <button style={button} disabled={busy}
          onClick={read}>Consultar</button>
        <button style={button} disabled={busy}
          onClick={load}>Listar</button>
      </div>
      <fieldset style={{ marginTop: 14 }}>
        <legend>Fuentes permitidas</legend>
        <div style={row}>
          {sources.map(source => <label key={source.value}>
            <input type="checkbox"
              checked={selectedSources.includes(source.value)}
              disabled={!canAdmin || busy}
              onChange={event => {
                setSelectedSources(current => event.target.checked ?
                  [...current, source.value] :
                  current.filter(x => x !== source.value));
              }} />
            {source.label}
          </label>)}
        </div>
      </fieldset>
      <div style={{ ...row, marginTop: 14 }}>
        <button style={button}
          disabled={busy || !canAdmin || Boolean(current)}
          onClick={create}>Crear deshabilitada</button>
        <button style={button}
          disabled={busy || !canAdmin || !current}
          onClick={update("UPDATE")}>Guardar fuentes</button>
        <button style={button}
          disabled={busy || !canAdmin || !current}
          onClick={update("PAUSE")}>Pausar</button>
        <button style={button}
          disabled={busy || !canAdmin || !current}
          onClick={update("REVOKE")}>Revocar</button>
        <button style={button}
          disabled={busy || !current}
          onClick={simulate}>Simular cuota</button>
      </div>
      {error && <p role="alert"
        style={{ color: "#b33" }}>{error}</p>}
      {message && <p role="status">{message}</p>}
      {busy && <p aria-live="polite">Procesando…</p>}
    </section>
    {current && <section style={card}>
      <h3>{current.domain}</h3>
      <p>Estado: {current.state} · Revisión: {current.revision}</p>
      <p>Consentimiento verificado independientemente:{" "}
        <strong>{current.legalConsentVerified ? "Sí" : "NO"}</strong></p>
      <p>Conexiones activas: {current.activeNetworkConnections}</p>
      <p>Fuentes: {current.sources.join(", ")}</p>
      <p>Cuotas diarias configuradas:
        DNS {current.dailyDnsLimit},
        TLS {current.dailyTlsLimit},
        HTTP {current.dailyHttpLimit}</p>
      <div style={row}>
        <button style={button} disabled={busy}
          onClick={history}>Historial de cambios</button>
        <button style={button} disabled={busy}
          onClick={historyReservations}>Historial de reservas</button>
        <button style={button} disabled={busy || !canAdmin}
          onClick={reserve}>Solicitar reserva (denegación segura)</button>
      </div>
    </section>}
    {quota && <section style={card}>
      <h3>Simulación de cuota</h3>
      <p>Consultas previstas: {quota.proposedCalls}</p>
      <p>Cuota suficiente: {quota.quotasFit ? "Sí" : "No"}</p>
      <p>Autorización LIVE: <strong>NO</strong></p>
      <p>Consumo registrado: DNS {quota.usage.dns},
        TLS {quota.usage.tls}, HTTP {quota.usage.http}</p>
      <p>Razones de bloqueo:</p>
      <ul>{quota.reasons.map(reason =>
        <li key={reason}>{reason}</li>)}</ul>
    </section>}
    <section style={card}>
      <label>Filtrar por estado{" "}
        <select value={filter}
          onChange={event => setFilter(event.target.value)}>
          <option value="ALL">Todos</option>
          {["DISABLED","PAUSED","READY","REVOKED"].map(x =>
            <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <ul>{filtered.map(item => <li key={item.scheduleId}>
        <button style={button} disabled={busy}
          onClick={() => {
            setCurrent(item); setDomain(item.domain);
            setSelectedSources(item.sources);
            setQuota(null);
            setEvents([]); setReservations([]);
          }}>{item.domain} · {item.state} · v{item.revision}</button>
      </li>)}</ul>
    </section>
    {events.length > 0 && <section style={card}>
      <h3>Auditoría de planificación</h3>
      <ol>{events.map(event =>
        <li key={event.revision}>{event.at} ·
          {event.action}: {event.priorState} → {event.currentState}
        </li>)}</ol>
    </section>}
    {reservations.length > 0 && <section style={card}>
      <h3>Reservas registradas</h3>
      <ul>{reservations.map(item =>
        <li key={item.requestId}>
          {item.createdAt} · {item.requestId} ·
          {item.state} · {item.rejectionCode ?? "Sin motivo"}
        </li>)}</ul>
    </section>}
  </div>;
}
