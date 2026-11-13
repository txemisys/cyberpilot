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
  const [proofToken, setProofToken] = useState("");
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
        Number(result.dnsQueriesMade) > 1 ||
        (operation !== "VERIFY_DNS" && result.dnsQueriesMade !== 0) ||
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
    setProofToken(proof.expectedValue.replace(
      /^cyberpilot-domain-verification=/, ""));
    setDomain(auth.domain);
    setMessage("Desafío temporal emitido. Su presencia todavía no ha sido verificada.");
  });
  const verifyDns = execute(async () => {
    if (!selected || selected.method !== "DNS_TOKEN")
      throw Error("Selecciona un desafío DNS pendiente.");
    const token = proofToken.trim();
    if (!/^[a-f0-9]{64}$/.test(token))
      throw Error("El desafío actual no contiene un token válido.");
    const result = await request("VERIFY_DNS", {
      domain: selected.domain,
      proofToken: token,
      expectedRevision: selected.revision,
    });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setProofToken("");
    const proof = result.proofResult as {
      state: string; networkQueriesPerformed: number;
    };
    setMessage(proof.state === "MATCH" ?
      "El recolector DNS ha observado el token TXT. No se certifica la seguridad del dominio." :
      "Prueba no confirmada: " + proof.state +
        ". No se ha autorizado escaneo adicional.");
  });
  const revoke = execute(async () => {
    if (!selected) throw Error("Selecciona un dominio.");
    const result = await request("REVOKE", {
      domain: selected.domain, expectedRevision: selected.revision,
    });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setProofToken("");
    setMessage("Revocación registrada y auditada; no se realizan conexiones.");
  });
  const expire = execute(async () => {
    if (!selected) throw Error("Selecciona un dominio.");
    const result = await request("EXPIRE", {
      domain: selected.domain, expectedRevision: selected.revision,
    });
    setSelected(result.authorization as Authorization);
    setChallenge(null);
    setProofToken("");
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
      <p>La consulta TXT DNS solo ocurre cuando un administrador pulsa
        «Verificar TXT DNS» sobre un desafío vigente. Se limita
        al nombre de prueba y nunca ejecuta escaneo de puertos,
        solicitudes HTTP ni enumeración de subdominios.</p>
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
          disabled={busy || !canManage || !selected ||
            selected.method !== "DNS_TOKEN" ||
            !/^[a-f0-9]{64}$/.test(proofToken)}
          onClick={verifyDns}>Verificar TXT DNS (consulta puntual)</button>
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
    {selected && selected.state === "PENDING" &&
      selected.method === "DNS_TOKEN" && <section style={card}>
      <h3>Token de verificación TXT</h3>
      <p>Se muestra al emitir el desafío, pero no se guarda en la
        base de datos. También puedes introducir el token de
        64 caracteres que conservaste al emitirlo. Solo se consulta
        DNS cuando pulsas verificar.</p>
      <label>Token temporal{" "}
        <input type="password" autoComplete="off"
          value={proofToken}
          disabled={!canManage}
          maxLength={64}
          onChange={e => setProofToken(e.target.value)}
          placeholder="64 caracteres hexadecimales" />
      </label>
    </section>}
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
