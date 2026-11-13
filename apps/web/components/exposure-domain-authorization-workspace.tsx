"use client";

import { useState } from "react";

type Authorization = {
  id: string;
  organizationId: string;
  domain: string;
  revision: number;
  state: "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
  method: "DNS_TOKEN" | "HTTP_TOKEN";
  challengeDigest: string;
  challengeExpiresAt: string;
  verifiedAt: string | null;
  revokedAt: string | null;
  mayScanAutomatically: false;
  legalConsentProven: false;
  remoteHostProbed: false;
};
type Challenge = {
  expectedName: string;
  expectedValue: string;
  method: "DNS_TOKEN" | "HTTP_TOKEN";
  expiresAt: string;
  status: "PENDING";
  mayTriggerNetworkScan: false;
};
type Event = {
  revision: number;
  action: string;
  newState: string;
  priorState: string;
  at: string;
  actorUserId: string;
  externalVerificationClaimed: false;
};
type Props = {
  slug: string;
  canManage: boolean;
};
function formatState(state: string) {
  switch (state) {
    case "PENDING": return "Pendiente de prueba independiente";
    case "VERIFIED": return "Verificado";
    case "REVOKED": return "Revocado";
    case "EXPIRED": return "Caducado";
    default: return state;
  }
}
export function ExposureDomainAuthorizationWorkspace({
  slug, canManage,
}: Props) {
  const [domain, setDomain] = useState("");
  const [method, setMethod] = useState<"DNS_TOKEN" | "HTTP_TOKEN">("DNS_TOKEN");
  const [items, setItems] = useState<Authorization[]>([]);
  const [selected, setSelected] = useState<Authorization | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const route = "/api/organizations/" +
    encodeURIComponent(slug) + "/exposure-authorization";
  const request = async (operation: string,
    fields: Record<string, unknown> = {}) => {
    const response = await fetch(route, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, ...fields }),
      cache: "no-store",
    });
    const result = await response.json() as Record<string, unknown>;
    if (!response.ok) {
      if (result.code === "AUTHORIZATION_REVISION_CONFLICT")
        throw Error("El registro cambió en otra sesión; recarga el dominio.");
      throw Error(typeof result.code === "string" ?
        result.code : "No se pudo completar la operación.");
    }
    if (result.httpRequestsMade !== 0 ||
        result.dnsQueriesMade !== 0 ||
        result.portScansMade !== 0 ||
        result.signedCustomerApproval !== false ||
        result.legacyCyberScoreModified !== false)
      throw Error("Una autorización no puede provocar escaneos ni declarar aprobación.");
    return result.data as Record<string, unknown>;
  };
  const execute = (work: () => Promise<void>) => async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await work(); }
    catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Error desconocido en la autorización.");
    } finally { setBusy(false); }
  };
  const reload = execute(async () => {
    const data = await request("LIST", { limit: 50 });
    setItems(data.items as Authorization[]);
    setMessage("Registro de autorizaciones consultado sin verificar dominios externamente.");
  });
  const selectDomain = execute(async () => {
    const name = domain.toLowerCase().trim().replace(/\.$/, "");
    const result = await request("READ", { domain: name });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setEvents([]);
    setDomain(name);
    setMessage("Estado guardado. Una prueba pendiente no autoriza escaneo.");
  });
  const issue = (replacement: boolean) => execute(async () => {
    const name = domain.toLowerCase().trim().replace(/\.$/, "");
    const result = await request(replacement ? "REPLACE" : "ISSUE", {
      domain: name, method,
      expectedRevision: replacement ? selected?.revision ?? 0 : 0,
    });
    const auth = result.authorization as Authorization;
    const proof = result.challenge as Challenge;
    setSelected(auth); setChallenge(proof);
    setDomain(auth.domain);
    setMessage("Desafío temporal emitido. Su presencia todavía no ha sido verificada.");
  });
  const revoke = execute(async () => {
    if (!selected) throw Error("Selecciona un dominio.");
    const result = await request("REVOKE", {
      domain: selected.domain, expectedRevision: selected.revision,
    });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setMessage("Revocación registrada y auditada; no se realizan conexiones.");
  });
  const expire = execute(async () => {
    if (!selected) throw Error("Selecciona un dominio.");
    const result = await request("EXPIRE", {
      domain: selected.domain, expectedRevision: selected.revision,
    });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setMessage("Desafío marcado como caducado.");
  });
  const history = execute(async () => {
    if (!selected) throw Error("Selecciona un dominio.");
    const result = await request("HISTORY", {
      domain: selected.domain, limit: 50,
    });
    setEvents(result.events as Event[]);
    setHistoryOpen(true);
    setMessage("Historial de emisión, rotación y revocación consultado.");
  });
  const button: React.CSSProperties = {
    background: "transparent", color: "inherit",
    border: "1px solid #94a3b888",
    borderRadius: 8, padding: "9px 13px", cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #94a3b84d",
    borderRadius: 12, padding: 18, marginBottom: 16,
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap",
    gap: 10, alignItems: "center",
  };
  return <div>
    <section style={card}>
      <h2>Autorización de dominio · Exposure</h2>
      <p>Genera una prueba de titularidad que pueda comprobar
        posteriormente un recolector autorizado.
        <strong> Esta pantalla no consulta DNS, no descarga
        páginas y no escanea dominios.</strong></p>
      <p>El desafío solo permite planificar una comprobación
        pasiva. Ni emitirlo ni publicarlo demuestra consentimiento
        legal o titularidad hasta que una fuente independiente
        complete la verificación.</p>
      <div style={row}>
        <label>Dominio{" "}
          <input value={domain} placeholder="empresa.example.org"
            onChange={event => {
              setDomain(event.target.value);
              setSelected(null); setChallenge(null);
              setEvents([]);
            }} />
        </label>
        <label>Prueba{" "}
          <select value={method}
            onChange={event => setMethod(
              event.target.value as "DNS_TOKEN" | "HTTP_TOKEN")}>
            <option value="DNS_TOKEN">Registro TXT DNS</option>
            <option value="HTTP_TOKEN">Ruta HTTPS well-known</option>
          </select>
        </label>
        <button style={button} disabled={busy}
          onClick={selectDomain}>Consultar</button>
        <button style={button} disabled={busy}
          onClick={reload}>Ver dominios</button>
      </div>
      <div style={{ ...row, marginTop: 14 }}>
        <button style={button}
          disabled={busy || !canManage || Boolean(selected)}
          onClick={issue(false)}>Emitir desafío</button>
        <button style={button}
          disabled={busy || !canManage || !selected}
          onClick={issue(true)}>Rotar desafío</button>
        <button style={button}
          disabled={busy || !canManage || !selected}
          onClick={revoke}>Revocar</button>
        <button style={button}
          disabled={busy || !canManage || !selected}
          onClick={expire}>Caducar</button>
        <button style={button}
          disabled={busy || !selected}
          onClick={history}>Historial</button>
      </div>
      {error && <p role="alert" style={{ color: "#b33" }}>{error}</p>}
      {message && <p role="status">{message}</p>}
      {busy && <p aria-live="polite">Procesando…</p>}
    </section>
    {selected && <section style={card}>
      <h3>{selected.domain}</h3>
      <p>Estado: <strong>{formatState(selected.state)}</strong></p>
      <p>Revisión: {selected.revision}</p>
      <p>Caduca: {selected.challengeExpiresAt}</p>
      <p>Verificado externamente:{" "}
        {selected.verifiedAt ? selected.verifiedAt : "NO"}</p>
      <p>El escaneo automático no está autorizado por este registro.</p>
      <small>Digest del desafío: {selected.challengeDigest}</small>
    </section>}
    {challenge && <section style={card}>
      <h3>Prueba para publicar</h3>
      <p>Este valor se muestra únicamente durante esta
        operación. La base de datos guarda su huella, no el token.</p>
      <p>Nombre o dirección de comprobación:</p>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {challenge.expectedName}
      </pre>
      <p>Contenido exacto:</p>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {challenge.expectedValue}
      </pre>
      <p>Expiración: {challenge.expiresAt}</p>
      <small>Solo se permite publicar en un dominio que
        esté bajo tu control. No se envía ninguna petición
        de verificación desde esta pantalla.</small>
    </section>}
    {items.length > 0 && <section style={card}>
      <h3>Autorizaciones registradas</h3>
      <ul>{items.map(item => <li key={item.id}>
        <button style={button} disabled={busy}
          onClick={() => {
            setSelected(item); setDomain(item.domain);
            setChallenge(null); setEvents([]);
          }}>
          {item.domain} · {formatState(item.state)} · v{item.revision}
        </button>
      </li>)}</ul>
    </section>}
    {historyOpen && <section style={card}>
      <h3>Eventos de autorización</h3>
      <ol>{events.map(item => <li key={item.revision}>
        {item.at} · v{item.revision} · {item.action}
        {" (" + item.priorState + " → " + item.newState + ")"}
      </li>)}</ol>
      <p>Ningún evento constituye aprobación legal
        o verificación técnica independiente.</p>
    </section>}
  </div>;
}
