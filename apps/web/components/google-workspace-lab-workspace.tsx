"use client";

import { useCallback, useMemo, useState } from "react";

/**
 * Google Workspace development LAB. Only invokes local fixture endpoints.
 * Never solicits OAuth credentials, Google passwords or service accounts.
 */
type ScenarioCatalogRow = {
  id: string;
  title: string;
  purpose: string;
  expectedRisk: string;
  expectedCoverage: string;
  gates: string[];
  needsRealGoogleTenant: false;
};
type Connection = {
  id: string;
  revision: number;
  state: string;
  stateDigest: string;
  permittedCapabilities: string[];
  expiresAt: string | null;
  realProviderConnected: false;
  administratorConsentVerified: false;
};
type TransitionReceipt = {
  revision: number;
  state: string;
  eventDigest: string;
  connectionDigest: string;
  nextAction: string;
};
type LabResponse = {
  report: {
    operation: string;
    data: unknown;
    boundaries: {
      externalGoogleRequests: 0;
      externalAccountWrites: 0;
      liveProviderValidated: false;
      canonicalCyberScoreModified: false;
    };
  };
};
type CoverageRow = {
  capability: string;
  status: string;
  observed: number;
  unknown: number;
  sourceCount: number;
  verifiedExternally: false;
};
type ScenarioReport = {
  schema: string;
  organizationId: string;
  scenario: string;
  connectionId: string;
  connectionRevision: number;
  checkedAt: string;
  sourceClass: "SYNTHETIC_FIXTURE";
  workflow: {
    collectionPerformed: boolean;
    saved: boolean;
    blockingGateCount: number;
    reviewGateCount: number;
    passedGateCount: number;
    totalGateCount: number;
    localDevelopmentAccepted: boolean;
    customerDeploymentAccepted: false;
    providerAuthenticationVerified: false;
  };
  snapshot: {
    id: string; sourceDigest: string;
    riskCount: number; unknownCount: number;
    expiresAt: string;
  } | null;
  report: {
    digest: string;
    sections: Array<{
      id: string; title: string; state: string;
      summary: string; risks: number; unknown: number;
    }>;
    summary: {
      usersObserved: number;
      adminsObserved: number;
      potentialRisks: number;
      unresolvedUnknowns: number;
      incompleteCapabilities: number;
      previewScore: number | null;
      customerSecurityStatus: "NOT_DETERMINED";
    };
    caveats: string[];
  };
  coverage: CoverageRow[];
  findings: Array<{
    id: string; ruleId: string; status: string;
    severity: string; title: string;
    remediation: string; evidenceDigest: string;
  }>;
  trace: Array<{
    resource: string; page: number;
    status: number; attempt: number; digest: string;
  }>;
  failures: Array<{
    category: string; resource: string;
    requestCount: number; pagesRead: number;
    explanation: string;
  }>;
  operatorActions: Array<{
    rank: number; title: string;
    category: string; description: string;
    requiresLiveValidation: boolean; executed: false;
  }>;
  gates: Array<{
    code: string; passed: boolean;
    severity: string; explanation: string;
  }>;
  sourceDigest: string;
  assessmentDigest: string;
  reportDigest: string;
  neutralDigest: string;
  warnings: string[];
  googleApiRequests: 0;
  googleAccountWrites: 0;
  realAdministratorConsentVerified: false;
  canonicalCyberScoreModified: false;
};
type Props = {
  slug: string;
  canManage: boolean;
};
type Tab = "summary" | "coverage" | "findings" |
  "events" | "gates" | "actions" | "snapshots";
const tabs: Array<{ id: Tab; label: string }> = [
  { id: "summary", label: "Resumen" },
  { id: "coverage", label: "Cobertura" },
  { id: "findings", label: "Hallazgos" },
  { id: "events", label: "Transporte" },
  { id: "gates", label: "Validaciones" },
  { id: "actions", label: "Acciones" },
  { id: "snapshots", label: "Historial" },
];
const defaultCapabilities = [
  "DIRECTORY_USERS", "DIRECTORY_DOMAINS",
  "DIRECTORY_ORGANIZATION_UNITS", "REPORTS_LOGIN",
  "REPORTS_ADMIN", "USER_MFA_ATTRIBUTES",
];
const starterScenarios: ScenarioCatalogRow[] = [
  {
    id: "HEALTHY_REFERENCE",
    title: "Referencia sintética",
    purpose: "Inventario y señales de Directory/Reports sobre datos inventados",
    expectedRisk: "NONE_OBSERVED",
    expectedCoverage: "LOCAL_COMPLETE",
    gates: ["fixture"],
    needsRealGoogleTenant: false,
  },
  {
    id: "MFA_GAPS", title: "Brechas de MFA",
    purpose: "Usuarios con 2SV no observado o no configurado",
    expectedRisk: "POTENTIAL",
    expectedCoverage: "LOCAL_COMPLETE",
    gates: ["2sv"],
    needsRealGoogleTenant: false,
  },
  {
    id: "PERMISSION_DENIED", title: "Permisos denegados",
    purpose: "Simular rechazo de Directory sin declarar una cobertura sana",
    expectedRisk: "UNKNOWN",
    expectedCoverage: "DENIED",
    gates: ["403"],
    needsRealGoogleTenant: false,
  },
];
function formatError(error: unknown) {
  return error instanceof Error ? error.message :
    "Operación de desarrollo no disponible.";
}
function token(bytes = 24) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, byte =>
    byte.toString(16).padStart(2, "0")).join("");
}
function download(data: unknown, filename: string) {
  const text = JSON.stringify(data, null, 2) + "\n";
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
function statusColor(value: string) {
  if (["AVAILABLE", "COMPLETE_LOCAL_ONLY", "OBSERVED",
    "CONNECTED_LAB", "SUCCESS"].includes(value)) return "#16724b";
  if (["UNKNOWN", "PARTIAL", "REQUIRES_PERMISSION",
    "PERMISSION_BLOCKED", "INCOMPLETE"].includes(value))
    return "#97710b";
  if (["ERROR", "DENIED", "REVOKED", "BLOCKED"].includes(value))
    return "#a83939";
  return "#64748b";
}
function Pill({ value }: { value: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "3px 9px",
      borderRadius: 12, fontSize: 12, fontWeight: 700,
      background: "rgba(128,128,128,0.08)",
      color: statusColor(value),
    }}>{value}</span>
  );
}
function InfoRow({ label, value }: {
  label: string; value: string | number;
}) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between",
      gap: 16, borderBottom: "1px solid #94a3b833",
      padding: "9px 0",
    }}>
      <span style={{ opacity: .72 }}>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function Busy({ busy }: { busy: boolean }) {
  return busy ? <span aria-live="polite" style={{
    fontSize: 13, opacity: .8,
  }}>Procesando operación local…</span> : null;
}
export function GoogleWorkspaceLabWorkspace({
  slug, canManage,
}: Props) {
  const [connection, setConnection] =
    useState<Connection | null>(null);
  const [lastEventDigest, setLastEventDigest] = useState<string | null>(null);
  const [challengeNonce, setChallengeNonce] = useState<string | null>(null);
  const [connectionInput, setConnectionInput] = useState("");
  const [catalog, setCatalog] =
    useState<ScenarioCatalogRow[]>(starterScenarios);
  const [scenario, setScenario] = useState("HEALTHY_REFERENCE");
  const [pageSize, setPageSize] = useState("2");
  const [maxRetries, setMaxRetries] = useState("2");
  const [maxPages, setMaxPages] = useState("12");
  const [retentionDays, setRetentionDays] = useState("30");
  const [persist, setPersist] = useState(true);
  const [includeTrace, setIncludeTrace] = useState(true);
  const [requireComplete, setRequireComplete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [run, setRun] = useState<ScenarioReport | null>(null);
  const [snapshotRows, setSnapshotRows] = useState<Array<{
    id: string; sourceDigest: string;
    riskCount: number; unknownCount: number; expiresAt: string;
  }>>([]);
  const [selectedTab, setSelectedTab] = useState<Tab>("summary");
  const [findingFilter, setFindingFilter] = useState("ALL");
  const [coverageFilter, setCoverageFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [showCaveats, setShowCaveats] = useState(false);
  const [showTechnicalDigests, setShowTechnicalDigests] =
    useState(false);
  const [selectedSnapshot, setSelectedSnapshot] = useState("");
  const [compareResult, setCompareResult] = useState<unknown>(null);

  const route = "/api/organizations/" +
    encodeURIComponent(slug) + "/google-workspace";
  const call = useCallback(async (path: string,
    input: unknown, method = "POST") => {
    const response = await fetch(route + path, {
      method,
      headers: method === "POST" ?
        { "Content-Type": "application/json" } : {},
      ...(method === "POST" ?
        { body: JSON.stringify(input) } : {}),
      cache: "no-store",
    });
    const body = await response.json() as Record<string, unknown>;
    if (!response.ok)
      throw new Error(typeof body.error === "string" ?
        body.error : "La operación LAB no se pudo verificar.");
    return body;
  }, [route]);
  const withBusy = useCallback(async (action: () =>
    Promise<void>) => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await action(); }
    catch (cause) { setError(formatError(cause)); }
    finally { setBusy(false); }
  }, [busy]);
  const offline = useCallback(async (operation: string,
    input: unknown) => {
    const body = await call("/offline", { operation, input });
    const data = (body as unknown as LabResponse).report;
    if (!data || data.boundaries.externalGoogleRequests !== 0 ||
        data.boundaries.externalAccountWrites !== 0 ||
        data.boundaries.liveProviderValidated ||
        data.boundaries.canonicalCyberScoreModified)
      throw new Error("Respuesta LAB con declaración no permitida.");
    return data.data;
  }, [call]);

  const loadCatalog = () => withBusy(async () => {
    const body = await call("/scenarios", null, "GET");
    const next = body.scenarios as ScenarioCatalogRow[];
    if (!Array.isArray(next) || next.length === 0)
      throw new Error("El catálogo LAB está vacío.");
    setCatalog(next);
    setMessage("Catálogo sintético actualizado sin contactar Google.");
  });
  const create = () => withBusy(async () => {
    const generatedId = "google-lab-" + token(12);
    const id = connectionInput.trim() || generatedId;
    const data = await offline("CREATE_LAB", {
      connectionId: id, createdAt: new Date().toISOString(),
      requestKey: "create-" + token(12),
    }) as { connection: Connection };
    setConnection(data.connection);
    setLastEventDigest(null); setChallengeNonce(null);
    setRun(null); setSnapshotRows([]);
    setMessage("Conexión LAB creada. No se han solicitado permisos Google.");
  });
  const fetchConnection = () => withBusy(async () => {
    if (!connectionInput.trim() && !connection)
      throw new Error("Escribe el identificador de la conexión LAB.");
    const id = connectionInput.trim() || connection!.id;
    const data = await offline("GET_LAB", {
      connectionId: id,
    }) as { connection: Connection };
    const audit = await offline("AUDIT_LAB", {
      connectionId: id,
    }) as { headEventDigest: string | null; currentRevision: number;
      chainVerified: boolean };
    if (audit.currentRevision !== data.connection.revision ||
        !audit.chainVerified)
      throw new Error("La cadena de auditoría LAB no coincide.");
    setConnection(data.connection);
    setChallengeNonce(null);
    setLastEventDigest(audit.headEventDigest);
    setRun(null);
    setMessage("Estado y cabecera CAS recuperados. Los retos anteriores no se reenvían.");
  });
  const issue = () => withBusy(async () => {
    if (!connection)
      throw new Error("Primero crea o carga una conexión.");
    const nonce = token(24);
    const next = await offline("MUTATE_LAB", {
      connectionId: connection.id,
      expectedRevision: connection.revision,
      type: "ISSUE_CHALLENGE",
      at: new Date().toISOString(),
      reason: "Simulación Directory y Reports de CyberPilot.",
      challengeNonce: nonce,
      requestedCapabilities: defaultCapabilities,
      ...(lastEventDigest ?
        { previousEventDigest: lastEventDigest } : {}),
    }) as {
      connection: Connection; receipt: TransitionReceipt;
    };
    setConnection(next.connection);
    setLastEventDigest(next.receipt.eventDigest);
    setChallengeNonce(nonce);
    setMessage("Desafío local emitido. No equivale a OAuth de Google.");
  });
  const rotate = () => withBusy(async () => {
    if (!connection || connection.state !== "CHALLENGE_ISSUED" ||
        !lastEventDigest)
      throw new Error("No existe un desafío LAB revocable.");
    const nonce = token(24);
    const next = await offline("MUTATE_LAB", {
      connectionId: connection.id,
      expectedRevision: connection.revision,
      type: "ROTATE_CHALLENGE",
      at: new Date().toISOString(),
      reason: "Rotación de un desafío perdido sin OAuth externo.",
      challengeNonce: nonce,
      requestedCapabilities: defaultCapabilities,
      previousEventDigest: lastEventDigest,
    }) as {
      connection: Connection; receipt: TransitionReceipt;
    };
    setConnection(next.connection);
    setLastEventDigest(next.receipt.eventDigest);
    setChallengeNonce(nonce);
    setMessage("Desafío LAB rotado y listo para aceptación local.");
  });
  const accept = () => withBusy(async () => {
    if (!connection || !challengeNonce || !lastEventDigest)
      throw new Error("Emite primero un desafío local válido.");
    const next = await offline("MUTATE_LAB", {
      connectionId: connection.id,
      expectedRevision: connection.revision,
      type: "ACCEPT_LAB",
      at: new Date().toISOString(),
      reason: "Aceptación de simulación offline, no consentimiento Google.",
      challengeNonce,
      previousEventDigest: lastEventDigest,
    }) as {
      connection: Connection; receipt: TransitionReceipt;
    };
    setConnection(next.connection);
    setLastEventDigest(next.receipt.eventDigest);
    setChallengeNonce(null);
    setMessage("LAB activo para fixtures sintéticos. Google LIVE permanece bloqueado.");
  });
  const mutate = (type: string) => withBusy(async () => {
    if (!connection)
      throw new Error("No hay conexión LAB seleccionada.");
    const next = await offline("MUTATE_LAB", {
      connectionId: connection.id,
      expectedRevision: connection.revision,
      type, at: new Date().toISOString(),
      reason: "Cambio local solicitado desde la interfaz LAB.",
      ...(lastEventDigest ?
        { previousEventDigest: lastEventDigest } : {}),
    }) as {
      connection: Connection; receipt: TransitionReceipt;
    };
    setConnection(next.connection);
    setLastEventDigest(next.receipt.eventDigest);
    setChallengeNonce(null);
    setRun(null);
    setMessage("Estado actualizado: " + next.connection.state);
  });
  const runScenario = () => withBusy(async () => {
    if (!connection || connection.state !== "CONNECTED_LAB")
      throw new Error("Activa primero una conexión LAB.");
    const body = await call("/scenarios", {
      connectionId: connection.id,
      expectedConnectionRevision: connection.revision,
      scenario, checkedAt: new Date().toISOString(),
      retentionDays: Number(retentionDays),
      persist: persist && canManage,
      includeAuditTrace: includeTrace,
      pageSize: Number(pageSize),
      maxRetries: Number(maxRetries),
      maxPages: Number(maxPages),
      requireCompleteCoverage: requireComplete,
    });
    const result = body as unknown as ScenarioReport;
    if (result.sourceClass !== "SYNTHETIC_FIXTURE" ||
        result.googleApiRequests !== 0 ||
        result.googleAccountWrites !== 0 ||
        result.realAdministratorConsentVerified ||
        result.canonicalCyberScoreModified)
      throw new Error("Escenario sin las garantías offline requeridas.");
    setRun(result);
    setSelectedTab("summary");
    setMessage(result.workflow.saved ?
      "Simulación ejecutada y evidencia sintética guardada." :
      "Simulación ejecutada sin persistencia.");
  });
  const loadSnapshots = () => withBusy(async () => {
    if (!connection)
      throw new Error("Selecciona una conexión LAB.");
    const data = await offline("LIST_SNAPSHOTS", {
      connectionId: connection.id, offset: 0,
      limit: 50, includeExpired: false,
      onlyWithRisks: false,
    }) as { items: typeof snapshotRows };
    setSnapshotRows(data.items);
    setSelectedTab("snapshots");
    setMessage("Snapshots consultados en esta organización.");
  });
  const compareSnapshots = () => withBusy(async () => {
    if (!run?.snapshot?.id || !selectedSnapshot)
      throw new Error("Selecciona una referencia y ejecuta un snapshot actual.");
    if (selectedSnapshot === run.snapshot.id)
      throw new Error("Debes comparar dos snapshots distintos.");
    const data = await offline("DIFF_SNAPSHOTS", {
      baselineId: selectedSnapshot,
      currentId: run.snapshot.id,
    });
    setCompareResult(data);
    setMessage("Comparación descriptiva, sin afirmar remediación.");
  });
  const filteredFindings = useMemo(() =>
    (run?.findings ?? []).filter(item =>
      (findingFilter === "ALL" ||
       item.severity === findingFilter) &&
      (search.trim() === "" ||
        [item.ruleId, item.title, item.remediation]
          .join(" ").toLowerCase().includes(search.toLowerCase()))
    ), [run, findingFilter, search]);
  const filteredCoverage = useMemo(() =>
    (run?.coverage ?? []).filter(item =>
      coverageFilter === "ALL" ||
      item.status === coverageFilter
    ), [run, coverageFilter]);
  const card: React.CSSProperties = {
    padding: 18, borderRadius: 12,
    border: "1px solid #94a3b83b",
    marginBottom: 16, background: "transparent",
  };
  const row: React.CSSProperties = {
    display: "flex", gap: 10,
    alignItems: "center", flexWrap: "wrap",
  };
  const buttonStyle: React.CSSProperties = {
    padding: "8px 13px", border: "1px solid #64748b80",
    borderRadius: 8, cursor: "pointer",
    background: "transparent", color: "inherit",
  };
  const inputStyle: React.CSSProperties = {
    padding: "8px 10px", border: "1px solid #64748b80",
    borderRadius: 8, minWidth: 100, background: "transparent",
    color: "inherit",
  };
  const button = (label: string, action: () => void,
    disabled = false) =>
    <button type="button" onClick={action}
      style={buttonStyle} disabled={busy || disabled}>{label}</button>;
  return (
    <main>
      <header style={card}>
        <h2>Google Workspace · Laboratorio offline</h2>
        <p>Recorrido para pymes sin Microsoft 365: Directory,
          Reports, identidades, MFA, hallazgos e informe.
          Los datos son <strong>exclusivamente sintéticos</strong>.</p>
        <p><strong>Sin OAuth, llamadas LIVE, cambios en cuentas
          ni modificación del CyberScore histórico.</strong></p>
        <Busy busy={busy} />
        {error && <p role="alert" style={{ color: "#b24545" }}>
          {error}</p>}
        {message && <p role="status">{message}</p>}
      </header>
      <section style={card}>
        <h3>1. Conexión LAB por organización</h3>
        <div style={row}>
          <input aria-label="Identificador de conexión LAB"
            value={connectionInput}
            onChange={event => setConnectionInput(event.target.value)}
            placeholder="ID opcional para recuperar"
            style={{ ...inputStyle, minWidth: 255 }} />
          {button("Crear LAB", create, !canManage)}
          {button("Recuperar estado", fetchConnection)}
          {button("Actualizar catálogo", loadCatalog)}
        </div>
        {connection && <>
          <div style={{ marginTop: 14 }}>
            <InfoRow label="Identificador" value={connection.id} />
            <InfoRow label="Revisión CAS" value={connection.revision} />
            <InfoRow label="Estado" value={connection.state} />
            <InfoRow label="Capacidades LAB concedidas"
              value={connection.permittedCapabilities.length} />
            <InfoRow label="Caducidad" value={
              connection.expiresAt ?? "Sin conexión activa"} />
          </div>
          <div style={{ ...row, marginTop: 12 }}>
            {button("Emitir desafío", issue,
              !canManage || !["NOT_CONFIGURED", "CONSENT_DENIED",
                "REVOKED", "EXPIRED"].includes(connection.state))}
            {button("Rotar desafío", rotate,
              !canManage || connection.state !== "CHALLENGE_ISSUED" ||
              !lastEventDigest)}
            {button("Aceptar solo LAB", accept,
              !canManage || connection.state !== "CHALLENGE_ISSUED" ||
              !challengeNonce)}
            {button("Rechazar", () => mutate("DENY_CONSENT"),
              !canManage || connection.state !== "CHALLENGE_ISSUED")}
            {button("Suspender", () => mutate("SUSPEND"),
              !canManage || connection.state !== "CONNECTED_LAB")}
            {button("Revocar", () => mutate("REVOKE"),
              !canManage || !["CONNECTED_LAB", "SUSPENDED",
                "CHALLENGE_ISSUED"].includes(connection.state))}
          </div>
          {connection.state === "CHALLENGE_ISSUED" &&
            <p>El desafío es efímero. Si se recarga la página,
              habrá que emitir otro desafío desde un estado admisible.</p>}
        </>}
      </section>
      <section style={card}>
        <h3>2. Ejecutar un escenario de Google simulado</h3>
        <div style={{ display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 14 }}>
          <label>Escenario
            <select value={scenario}
              onChange={event => setScenario(event.target.value)}
              style={{ ...inputStyle, width: "100%" }}>
              {catalog.map(item =>
                <option key={item.id} value={item.id}>
                  {item.title}</option>)}
            </select>
          </label>
          <label>Tamaño de página
            <input type="number" min={1} max={500}
              value={pageSize}
              onChange={event => setPageSize(event.target.value)}
              style={{ ...inputStyle, width: "100%" }} />
          </label>
          <label>Máximo de páginas
            <input type="number" min={1} max={30}
              value={maxPages}
              onChange={event => setMaxPages(event.target.value)}
              style={{ ...inputStyle, width: "100%" }} />
          </label>
          <label>Reintentos por página
            <input type="number" min={0} max={6}
              value={maxRetries}
              onChange={event => setMaxRetries(event.target.value)}
              style={{ ...inputStyle, width: "100%" }} />
          </label>
          <label>Retención (días)
            <input type="number" min={1} max={365}
              value={retentionDays}
              onChange={event => setRetentionDays(event.target.value)}
              style={{ ...inputStyle, width: "100%" }} />
          </label>
        </div>
        <div style={{ ...row, marginTop: 15 }}>
          <label><input type="checkbox" checked={persist}
            onChange={event => setPersist(event.target.checked)}
            disabled={!canManage} /> Guardar evidencia sintética</label>
          <label><input type="checkbox" checked={includeTrace}
            onChange={event => setIncludeTrace(event.target.checked)} />
            Incluir traza de transporte</label>
          <label><input type="checkbox" checked={requireComplete}
            onChange={event => setRequireComplete(event.target.checked)} />
            Exigir cobertura completa en LAB</label>
          {button("Ejecutar escenario", runScenario,
            connection?.state !== "CONNECTED_LAB")}
        </div>
        <p style={{ fontSize: 13, opacity: .8 }}>
          Cada ejecución se vincula a la organización y revisión LAB.
          Las respuestas 403, 429 y truncamientos son simulados,
          no observaciones de Google.</p>
      </section>
      {run && <section style={card}>
        <div style={row}>
          <h3 style={{ marginRight: "auto" }}>
            3. Resultado · {run.scenario}</h3>
          <Pill value={run.workflow.localDevelopmentAccepted ?
            "SUCCESS" : "INCOMPLETE"} />
          {button("Exportar JSON sin identidades", () =>
            download(run, "google-fixture-" + run.scenario + ".json"))}
        </div>
        <div style={{ display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
          gap: 14, marginTop: 12 }}>
          {[
            ["Usuarios observados", run.report.summary.usersObserved],
            ["Superadministradores", run.report.summary.adminsObserved],
            ["Riesgos posibles", run.report.summary.potentialRisks],
            ["Señales desconocidas", run.report.summary.unresolvedUnknowns],
            ["Capacidades incompletas",
              run.report.summary.incompleteCapabilities],
            ["Gates superados", run.workflow.passedGateCount +
              "/" + run.workflow.totalGateCount],
          ].map(([label, value]) =>
            <div key={String(label)} style={{
              padding: 12, border: "1px solid #94a3b833",
              borderRadius: 8,
            }}>
              <small>{label}</small>
              <p style={{ fontSize: 24, fontWeight: 700,
                margin: "7px 0" }}>{value}</p>
            </div>)}
        </div>
        <p><strong>Estado de seguridad del cliente:</strong>{" "}
          <Pill value={run.report.summary.customerSecurityStatus} />
          {" "}La simulación no certifica un tenant Google.</p>
        <nav aria-label="Secciones del resultado Google LAB"
          style={{ ...row, margin: "18px 0" }}>
          {tabs.map(tab =>
            <button type="button" key={tab.id}
              aria-current={selectedTab === tab.id ? "page" : undefined}
              onClick={() => setSelectedTab(tab.id)}
              style={{
                ...buttonStyle,
                fontWeight: selectedTab === tab.id ? 700 : 400,
              }}>{tab.label}</button>)}
        </nav>
        {selectedTab === "summary" && <>
          {run.report.sections.map(section =>
            <article key={section.id} style={{
              borderBottom: "1px solid #94a3b833", padding: "9px 0",
            }}>
              <div style={row}>
                <strong>{section.title}</strong>
                <Pill value={section.state} />
                <small>Riesgos: {section.risks},
                  desconocidos: {section.unknown}</small>
              </div>
              <p>{section.summary}</p>
            </article>)}
        </>}
        {selectedTab === "coverage" && <>
          <div style={row}>
            <label>Estado de cobertura
              <select value={coverageFilter}
                style={inputStyle}
                onChange={event =>
                  setCoverageFilter(event.target.value)}>
                {["ALL", ...new Set(run.coverage.map(c => c.status))]
                  .map(status => <option key={status}
                    value={status}>{status}</option>)}
              </select>
            </label>
          </div>
          <table style={{ width: "100%", marginTop: 15 }}>
            <thead><tr><th>Capacidad</th><th>Cobertura</th>
              <th>Observados</th><th>Desconocidos</th></tr></thead>
            <tbody>{filteredCoverage.map(item =>
              <tr key={item.capability}>
                <td>{item.capability}</td>
                <td><Pill value={item.status} /></td>
                <td>{item.observed}</td>
                <td>{item.unknown}</td>
              </tr>)}</tbody>
          </table>
        </>}
        {selectedTab === "findings" && <>
          <div style={row}>
            <label>Filtrar severidad
              <select value={findingFilter}
                style={inputStyle}
                onChange={event =>
                  setFindingFilter(event.target.value)}>
                {["ALL", "CRITICAL", "HIGH", "MEDIUM",
                  "LOW", "INFO", "UNKNOWN"].map(level =>
                  <option key={level} value={level}>{level}</option>)}
              </select>
            </label>
            <input value={search} style={inputStyle}
              aria-label="Buscar hallazgos"
              onChange={event => setSearch(event.target.value)}
              placeholder="Buscar regla o remediación" />
            <span>{filteredFindings.length} hallazgos</span>
          </div>
          {filteredFindings.map(finding =>
            <article key={finding.id} style={{
              marginTop: 12, padding: 12,
              border: "1px solid #94a3b833", borderRadius: 8,
            }}>
              <div style={row}><strong>{finding.title}</strong>
                <Pill value={finding.severity} />
                <Pill value={finding.status} /></div>
              <p>{finding.remediation}</p>
              <small>Regla: {finding.ruleId}. Acción no ejecutada.</small>
            </article>)}
        </>}
        {selectedTab === "events" && <>
          {run.failures.length > 0 && <h4>Errores de API simulados</h4>}
          {run.failures.map((item, index) =>
            <article key={item.resource + index}>
              <strong>{item.category}: {item.resource}</strong>
              <p>{item.explanation}. Páginas: {item.pagesRead};
                solicitudes: {item.requestCount}.</p>
            </article>)}
          <table style={{ width: "100%" }}>
            <thead><tr><th>Recurso</th><th>Página</th>
              <th>HTTP</th><th>Intento</th></tr></thead>
            <tbody>{run.trace.map((item, index) =>
              <tr key={item.digest + index}>
                <td>{item.resource}</td><td>{item.page + 1}</td>
                <td><Pill value={String(item.status)} /></td>
                <td>{item.attempt}</td></tr>)}</tbody>
          </table>
          <p>Las trazas no incluyen Authorization, tokens ni
            respuestas brutas del proveedor.</p>
        </>}
        {selectedTab === "gates" && <>
          {run.gates.map(gate =>
            <article key={gate.code + gate.explanation}
              style={{ padding: "9px 0",
                borderBottom: "1px solid #94a3b833" }}>
              <div style={row}><strong>{gate.code}</strong>
                <Pill value={gate.passed ? "SUCCESS" :
                  gate.severity} /></div>
              <p>{gate.explanation}</p>
            </article>)}
        </>}
        {selectedTab === "actions" && <>
          {run.operatorActions.map(action =>
            <article key={action.rank} style={{
              borderBottom: "1px solid #94a3b833",
              padding: "10px 0",
            }}>
              <strong>{action.rank}. {action.title}</strong>
              <p>{action.description}</p>
              <small>Tipo: {action.category} ·
                Requiere validación LIVE:{" "}
                {action.requiresLiveValidation ? "Sí" : "No"} ·
                Ejecutada: No</small>
            </article>)}
        </>}
        {selectedTab === "snapshots" && <>
          <div style={row}>
            {button("Actualizar historial", loadSnapshots)}
            {run.snapshot &&
              <span>Snapshot actual: {run.snapshot.id}</span>}
          </div>
          <label>Comparar con snapshot anterior
            <select value={selectedSnapshot}
              onChange={event =>
                setSelectedSnapshot(event.target.value)}
              style={{ ...inputStyle, marginLeft: 10 }}>
              <option value="">Seleccionar referencia</option>
              {snapshotRows.map(snapshot =>
                <option value={snapshot.id}
                  key={snapshot.id}>{snapshot.id} ·
                    riesgos {snapshot.riskCount}</option>)}
            </select>
          </label>
          {button("Comparar snapshots", compareSnapshots,
            !run.snapshot || !selectedSnapshot)}
          {compareResult && <pre style={{
            maxHeight: 280, overflow: "auto", fontSize: 12,
          }}>{JSON.stringify(compareResult, null, 2)}</pre>}
          {snapshotRows.map(item =>
            <article key={item.id}>
              <InfoRow label={"Snapshot " + item.id}
                value={"Riesgos " + item.riskCount +
                  " / Unknown " + item.unknownCount} />
            </article>)}
        </>}
        <div style={{ marginTop: 16 }}>
          <label><input type="checkbox" checked={showTechnicalDigests}
            onChange={event =>
              setShowTechnicalDigests(event.target.checked)} />
            Mostrar referencias SHA-256</label>
          {showTechnicalDigests && <>
            <InfoRow label="Fuente" value={run.sourceDigest} />
            <InfoRow label="Evaluación" value={run.assessmentDigest} />
            <InfoRow label="Informe" value={run.reportDigest} />
            <InfoRow label="Neutral" value={run.neutralDigest} />
          </>}
        </div>
        <div style={{ marginTop: 16 }}>
          <label><input type="checkbox" checked={showCaveats}
            onChange={event => setShowCaveats(event.target.checked)} />
            Mostrar limitaciones completas</label>
          {showCaveats && <ul>{run.report.caveats.map(note =>
            <li key={note}>{note}</li>)}</ul>}
        </div>
      </section>}
      <footer style={card}>
        <h3>Límites explícitos de aceptación</h3>
        <p>Este entorno es una herramienta de desarrollo y prueba.
          Las aprobaciones de cliente, el consentimiento OAuth real,
          las verificaciones LIVE, las escrituras en cuentas y
          la certificación de seguridad no están incluidos.
          Una señal UNKNOWN no constituye evidencia de seguridad.</p>
        <p>Las recomendaciones se proponen únicamente para evaluación.
          Ningún botón de este laboratorio remedia una cuenta Google.</p>
      </footer>
    </main>
  );
}
