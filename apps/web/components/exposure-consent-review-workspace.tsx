"use client";
import { useMemo, useState } from "react";
import type {
  DetachedConsentEnvelope,
  IndependentConsentVerification,
} from "../lib/exposure-independent-consent";

type Source = "DNS" | "TLS_HANDSHAKE" | "HTTPS_HEADERS";
type Result = {
  report: IndependentConsentVerification;
  currentTechnicalOwnershipProof: boolean;
  independentAuthorityConnected: boolean;
  operationalAdmissionGranted: false;
  networkWorkerAvailable: false;
  independentlySignedConsentCreatedHere: false;
  executableQuotaReservationCreated: false;
  reasonForNoNetwork: string;
  artifact?: { filename: string; mime: string; content: string };
  containsOriginalSignature?: false;
  containsCustomerCredentials?: false;
  externallySignedCustomerApprovalGenerated?: false;
};
const options: Array<{ value: Source; title: string }> = [
  { value: "DNS", title: "DNS pasivo" },
  { value: "TLS_HANDSHAKE", title: "Certificado y TLS" },
  { value: "HTTPS_HEADERS", title: "Cabeceras HTTPS HEAD" },
];
function object(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}
function validateEnvelopeText(text: string): DetachedConsentEnvelope | null {
  if (!text.trim()) return null;
  if (text.length > 20000)
    throw Error("El sobre de firma supera 20 KB.");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw Error("JSON de autorización malformado."); }
  if (!object(parsed) || !object(parsed.grant) ||
      parsed.schema !== "cyberpilot.exposure.legal.envelope.v1" ||
      parsed.signatureAlgorithm !== "Ed25519" ||
      typeof parsed.signatureBase64Url !== "string")
    throw Error("Se requiere un sobre Ed25519 desprendido válido.");
  return parsed as DetachedConsentEnvelope;
}
function save(content: string, filename: string, mime: string) {
  if (!/^[a-z0-9.-]{1,120}$/.test(filename))
    throw Error("Nombre de fichero inseguro.");
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const link = document.createElement("a");
  link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove();
  URL.revokeObjectURL(url);
}
export function ExposureConsentReviewWorkspace({
  slug,
}: { slug: string }) {
  const [domain, setDomain] = useState("");
  const [revision, setRevision] = useState(1);
  const [sources, setSources] = useState<Source[]>(["DNS"]);
  const [envelopeText, setEnvelopeText] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [requirements, setRequirements] =
    useState<Record<string, unknown> | null>(null);
  const [authorization, setAuthorization] =
    useState<Record<string, unknown> | null>(null);
  const [filter, setFilter] =
    useState<"ALL" | "PASS" | "DENIED">("ALL");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/exposure-consent-review";
  const request = async (operation: string,
    additional: Record<string, unknown> = {}) => {
    const response = await fetch(endpoint, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, domain: domain.trim(),
        ...additional }),
    });
    const body = await response.json() as Record<string, unknown>;
    if (!response.ok)
      throw Error(typeof body.code === "string" ?
        body.code : "Operación de consentimiento rechazada.");
    if (body.networkCollectionStarted !== false ||
        body.executableLeaseIssued !== false ||
        body.legalCustomerApprovalSignedByCyberPilot !== false ||
        body.scoreMutated !== false)
      throw Error("El servicio ha afirmado ejecutar operaciones prohibidas.");
    return body.data;
  };
  const act = (callback: () => Promise<void>) => async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await callback(); }
    catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "No se pudo analizar la autorización.");
    } finally { setBusy(false); }
  };
  const readProof = act(async () => {
    const data = await request("READ_AUTHORIZATION");
    if (!object(data)) throw Error("Respuesta de prueba incompleta.");
    setAuthorization(data);
    if (typeof data.revision === "number")
      setRevision(data.revision);
    setMessage("Estado de prueba técnica recuperado. No es consentimiento legal.");
  });
  const readRequirements = act(async () => {
    const data = await request("GET_CONSENT_REQUIREMENTS");
    if (!object(data)) throw Error("Requisitos incompletos.");
    setRequirements(data);
    setMessage("Requisitos técnicos de firma y revocación cargados.");
  });
  const analyze = (format?: "JSON" | "CSV" | "MARKDOWN") =>
    act(async () => {
      const envelope = validateEnvelopeText(envelopeText);
      const data = await request(format ? "EXPORT_CHECK" : "ANALYZE", {
        authorizationRevision: revision, sources,
        ...(envelope ? { envelope } : {}),
        ...(format ? { format } : {}),
      });
      if (!object(data) || !object(data.report))
        throw Error("El informe de consentimiento no es válido.");
      const review = data as Result;
      if (review.operationalAdmissionGranted !== false ||
          review.networkWorkerAvailable !== false ||
          review.executableQuotaReservationCreated !== false ||
          review.report.allowsExternalNetworkByItself !== false ||
          review.report.legalConsentUnconditionallyProven !== false)
        throw Error("La respuesta indica una autorización LIVE inexistente.");
      setResult(review);
      if (format) {
        if (!review.artifact || typeof review.artifact.content !== "string")
          throw Error("Exportación incompleta.");
        save(review.artifact.content, review.artifact.filename,
          review.artifact.mime);
        setMessage("Exportado resultado de validación, no una firma nueva.");
      } else setMessage(
        "Análisis completado. No se ha emitido permiso ejecutable.");
    });
  const gates = useMemo(() =>
    (result?.report.gates ?? []).filter(item =>
      (filter === "ALL" ||
        (filter === "PASS" ? item.passed : !item.passed)) &&
      (!search.trim() ||
        (item.code + " " + item.reason).toLowerCase()
          .includes(search.toLowerCase()))),
  [filter, search, result]);
  const button: React.CSSProperties = {
    border: "1px solid #64748b88", borderRadius: 8,
    padding: "8px 12px", background: "transparent",
    color: "inherit", cursor: "pointer",
  };
  const card: React.CSSProperties = {
    border: "1px solid #94a3b866",
    padding: 18, borderRadius: 12, marginBottom: 14,
  };
  const row: React.CSSProperties = {
    display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
  };
  return <div>
    <section style={card}>
      <h2>Validación de autorización firmada por tercero</h2>
      <p>Una prueba DNS verifica dominio, pero no autoriza legalmente
        una evaluación externa. La firma Ed25519 debe emitirse y
        custodiarse en una autoridad independiente: esta aplicación
        solo puede verificar un sobre existente.</p>
      <p><strong>El validador no incorpora una autoridad de confianza
        configurada ni realiza una comprobación externa de revocación.</strong>
        Sin ambas dependencias una firma no autoriza ningún tráfico.</p>
      <div style={row}>
        <label>Dominio autorizado{" "}
          <input value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="empresa.example" />
        </label>
        <label>Revisión vigente{" "}
          <input type="number" min={1} value={revision}
            onChange={e => setRevision(Number(e.target.value))} />
        </label>
      </div>
      <fieldset>
        <legend>Fuentes solicitadas</legend>
        <div style={row}>{options.map(option =>
          <label key={option.value}>
            <input type="checkbox"
              checked={sources.includes(option.value)}
              onChange={e => setSources(previous =>
                e.target.checked ?
                  [...previous, option.value] :
                  previous.filter(x => x !== option.value))} />
            {option.title}
          </label>)}</div>
      </fieldset>
      <label>Sobre JSON Ed25519 de autoridad independiente (opcional){" "}
        <textarea rows={5} value={envelopeText}
          maxLength={20000}
          onChange={e => setEnvelopeText(e.target.value)}
          placeholder="Sin sobre firmado el análisis se denegará." />
      </label>
      <p>El navegador no admite claves privadas ni estados de
        revocación suministrados por el cliente.</p>
      <div style={row}>
        <button style={button} disabled={busy || !domain}
          onClick={readProof}>Consultar dominio</button>
        <button style={button} disabled={busy || !domain}
          onClick={readRequirements}>Ver requisitos</button>
        <button style={button}
          disabled={busy || !domain || !sources.length}
          onClick={analyze()}>Analizar firma y alcance</button>
      </div>
      {busy && <p role="status">Comprobando…</p>}
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
    </section>
    {authorization && <section style={card}>
      <h3>Prueba técnica del dominio</h3>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {JSON.stringify(authorization, null, 2)}
      </pre>
    </section>}
    {requirements && <section style={card}>
      <h3>Requisitos independientes</h3>
      <ul>{(requirements.requiredOperationalGates as string[] ?? [])
        .map(value => <li key={value}>{value}</li>)}</ul>
      <p>Recolectores disponibles:
        {String(requirements.availableLIVECollectors)}</p>
    </section>}
    {result && <section style={card}>
      <h3>Decisión: {result.report.decision}</h3>
      <p>Autenticidad criptográfica verificable:
        <strong>{result.report.signatureAuthenticity ? " SÍ" : " NO"}</strong></p>
      <p>Revocación vigente:
        <strong>{result.report.revocationCurrent ? " SÍ" : " NO"}</strong></p>
      <p>Prueba de dominio vigente:
        <strong>{result.currentTechnicalOwnershipProof ? " SÍ" : " NO"}</strong></p>
      <p>Estado operacional: <strong>{result.reasonForNoNetwork}</strong></p>
      <p>Tráfico permitido por este informe: <strong>NO</strong></p>
      <div style={row}>
        <button style={button} disabled={busy}
          onClick={analyze("JSON")}>Exportar JSON</button>
        <button style={button} disabled={busy}
          onClick={analyze("CSV")}>Exportar CSV</button>
        <button style={button} disabled={busy}
          onClick={analyze("MARKDOWN")}>Exportar Markdown</button>
      </div>
      <p>Huella de integridad local:
        <code style={{ overflowWrap: "anywhere" }}>
          {result.report.integrityDigest}
        </code></p>
      <div style={row}>
        <label>Filtrar{" "}
          <select value={filter}
            onChange={e => setFilter(e.target.value as typeof filter)}>
            <option value="ALL">Todas las condiciones</option>
            <option value="PASS">Condiciones válidas</option>
            <option value="DENIED">Condiciones incumplidas</option>
          </select>
        </label>
        <label>Buscar motivo{" "}
          <input value={search}
            onChange={e => setSearch(e.target.value)} />
        </label>
      </div>
      <ul>{gates.map(gate => <li key={gate.code}>
        <strong>{gate.passed ? "PASS" : "DENIED"}: {gate.code}</strong>
        <p>{gate.reason}</p>
      </li>)}</ul>
      <button style={button} onClick={() => setExpanded(x => !x)}>
        {expanded ? "Ocultar límites" : "Mostrar límites"}
      </button>
      {expanded && <ul>{result.report.limitations.map(x =>
        <li key={x}>{x}</li>)}</ul>}
    </section>}
  </div>;
}
