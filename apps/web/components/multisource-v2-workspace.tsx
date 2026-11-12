"use client";

import { useMemo, useState } from "react";

type Summary = {
  organizationId: string;
  snapshotId: string;
  modelId: string;
  modelRevision: number;
  evaluatedAt: string;
  numericScore: number | null;
  coveragePercent: number;
  status: string;
  riskPoints: number;
  verifiedControls: number;
  totalControls: number;
  manifestDigest: string;
  reportDigest: string;
  sourceClass: string;
  customerApproved: false;
  v1ScoreChanged: false;
};
type Report = {
  schema: string;
  organizationId: string;
  snapshotId: string;
  modelId: "cyberpilot.multisource.v2";
  evaluatedAt: string;
  summary: {
    numericScore: number | null;
    scoreStatus: string;
    coveragePercent: number;
    verifiedControls: number;
    requiredControls: number;
    unknownControls: number;
    riskPoints: number;
    confidence: string;
    noMicrosoft365RequiredToGenerate: true;
    certifiedHealthy: false;
  };
  sources: Array<{
    source: string;
    controlCount: number;
    observed: number;
    unknown: number;
    declared: number;
    scopeAuthenticated: boolean;
  }>;
  sections: Array<{
    id: string;
    title: string;
    status: string;
    narrative: string;
    unknownControls: number;
    evidenceCount: number;
  }>;
  gaps: Array<{
    domain: string;
    controlId: string;
    state: string;
    weight: number;
    explanation: string[];
    nextAction: string;
  }>;
  findings: Array<{
    findingId: string;
    title: string;
    severity: string;
    state: string;
    explanation: string;
    remediation: string;
    source: string;
    scoreEligible: boolean;
  }>;
  priorities: Array<{
    rank: number;
    title: string;
    reason: string;
    recommendation: string;
    source: string;
    automaticallyExecuted: false;
  }>;
  provenance: {
    manifestDigest: string;
    coverageDigest: string;
    scoreDigest: string;
    customerSignatureVerified: false;
  };
  caveats: string[];
  digest: string;
  historicalCyberScoreModified: false;
  customerApprovalAttested: false;
};
type Response = {
  schema: "cyberpilot.multisource.v2.service.v1";
  operation: string;
  organizationId: string;
  mode: "OPT_IN_OFFLINE_PREVIEW";
  data: unknown;
  liveProviderRequests: 0;
  historicalV1ScoresModified: false;
  customerSecurityCertified: false;
};
type Props = { slug: string; canManage: boolean };
type View = "SUMMARY" | "DOMAINS" | "GAPS" |
  "RISKS" | "ACTIONS" | "SOURCES" | "PROVENANCE";
const views: Array<{ code: View; title: string }> = [
  { code: "SUMMARY", title: "Resumen" },
  { code: "DOMAINS", title: "Áreas" },
  { code: "GAPS", title: "Cobertura pendiente" },
  { code: "RISKS", title: "Hallazgos" },
  { code: "ACTIONS", title: "Prioridades" },
  { code: "SOURCES", title: "Fuentes" },
  { code: "PROVENANCE", title: "Procedencia" },
];
function download(content: string,
  filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.download = filename;
  link.href = url;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
function label(status: string) {
  if (status === "ASSESSED_WITH_LIMITATIONS")
    return "Evaluación con limitaciones";
  if (status === "UNASSESSABLE")
    return "Sin datos verificables";
  if (status === "INSUFFICIENT_COVERAGE")
    return "Cobertura insuficiente";
  return status;
}
function Panel({ children }: {
  children: React.ReactNode;
}) {
  return (
    <section style={{
      border: "1px solid #94a3b84d",
      borderRadius: 12, padding: 18, marginBottom: 16,
    }}>{children}</section>
  );
}
function Metric({ title, value, hint }: {
  title: string; value: string | number;
  hint?: string;
}) {
  return (
    <div style={{
      border: "1px solid #94a3b84d",
      borderRadius: 10, padding: 13, minWidth: 140,
    }}>
      <small>{title}</small>
      <p style={{ margin: "8px 0", fontSize: 25,
        fontWeight: 700 }}>{value}</p>
      {hint && <small style={{ opacity: .75 }}>{hint}</small>}
    </div>
  );
}
export function MultiSourceV2Workspace({
  slug, canManage,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [currentId, setCurrentId] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [history, setHistory] = useState<Summary[]>([]);
  const [comparison, setComparison] = useState<unknown>(null);
  const [view, setView] = useState<View>("SUMMARY");
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState("weight");
  const [showLimitations, setShowLimitations] = useState(false);
  const [showDigests, setShowDigests] = useState(false);
  const route = "/api/organizations/" +
    encodeURIComponent(slug) + "/multisource-v2";
  const request = async (operation: string,
    data: Record<string, unknown> = {}) => {
    const response = await fetch(route, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, ...data }),
    });
    const body = await response.json() as Record<string, unknown>;
    if (!response.ok)
      throw new Error(typeof body.error === "string" ?
        body.error : "Servicio v2 no disponible.");
    const scoped = body as unknown as Response;
    if (scoped.organizationId.length === 0 ||
        scoped.liveProviderRequests !== 0 ||
        scoped.historicalV1ScoresModified ||
        scoped.customerSecurityCertified ||
        scoped.mode !== "OPT_IN_OFFLINE_PREVIEW")
      throw new Error("El informe no cumple los límites de seguridad.");
    return scoped.data;
  };
  const execute = (action: () => Promise<void>) =>
    async () => {
      if (busy) return;
      setBusy(true); setError(""); setNotice("");
      try { await action(); }
      catch (cause) {
        setError(cause instanceof Error ? cause.message :
          "Error no identificado de evaluación.");
      } finally { setBusy(false); }
    };
  const preview = execute(async () => {
    const result = await request("PREVIEW") as {
      report: Report;
      snapshotId: string;
      previewOnly: true;
    };
    setReport(result.report);
    setCurrentId(result.snapshotId);
    setView("SUMMARY");
    setNotice("Simulación multifuente generada sin proveedores LIVE.");
  });
  const store = execute(async () => {
    const result = await request("STORE") as {
      summary: Summary; created: boolean;
      legacyV1WriteCount: 0;
    };
    if (result.legacyV1WriteCount !== 0)
      throw new Error("Escritura histórica de CyberScore no permitida.");
    setCurrentId(result.summary.snapshotId);
    setNotice(result.created ?
      "Snapshot de prueba guardado con auditoría." :
      "Snapshot de prueba idéntico ya conservado.");
    const response = await request("READ", {
      snapshotId: result.summary.snapshotId,
    }) as { report: Report };
    setReport(response.report);
  });
  const loadHistory = execute(async () => {
    const result = await request("LIST", {
      limit: 50, offset: 0,
    }) as { items: Summary[] };
    setHistory(result.items);
    setNotice("Historial v2 aislado de las puntuaciones históricas v1.");
  });
  const load = execute(async () => {
    if (!currentId)
      throw new Error("Selecciona un snapshot.");
    const result = await request("READ", {
      snapshotId: currentId,
    }) as { report: Report };
    setReport(result.report);
    setNotice("Expediente v2 recuperado con verificación de integridad.");
  });
  const exportReport = (format: "JSON" | "CSV" |
    "MARKDOWN") => execute(async () => {
    if (!currentId)
      throw new Error("Primero guarda un snapshot v2.");
    const result = await request("EXPORT", {
      snapshotId: currentId, exportFormat: format,
    }) as {
      content: string; filename: string;
      mimeType: string; includesPII: false;
      containsOauthTokens: false;
    };
    if (result.includesPII || result.containsOauthTokens)
      throw new Error("La exportación contiene datos no permitidos.");
    download(result.content, result.filename, result.mimeType);
    setNotice("Informe v2 exportado sin credenciales.");
  });
  const compare = execute(async () => {
    if (!currentId || !baselineId ||
        currentId === baselineId)
      throw new Error("Selecciona dos snapshots v2 distintos.");
    const result = await request("COMPARE", {
      baselineId, currentId,
    });
    setComparison(result);
    setNotice("Comparación descriptiva; no se certifica remediación.");
  });
  const gaps = useMemo(() => {
    const rows = (report?.gaps ?? []).filter(x =>
      !filter || [x.controlId, x.domain,
        x.state, x.nextAction].join(" ").toLowerCase()
        .includes(filter.toLowerCase()));
    return [...rows].sort((a, b) =>
      sortBy === "weight" ? b.weight - a.weight :
        a.controlId.localeCompare(b.controlId));
  }, [report, filter, sortBy]);
  const button: React.CSSProperties = {
    border: "1px solid #64748b88",
    borderRadius: 8, padding: "8px 13px",
    background: "transparent", color: "inherit",
    cursor: "pointer",
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap",
    gap: 10, alignItems: "center",
  };
  return (
    <div>
      <Panel>
        <h2>Motor multifuente · CyberScore v2</h2>
        <p>Evaluación independiente de Microsoft 365,
          preparada para Exposure, Baseline, Assets y Google.
          El v2 es opcional y <strong>no modifica los scores v1</strong>.</p>
        <p><strong>El escenario de esta pantalla utiliza
          únicamente datos ficticios.</strong> Una ausencia de
          hallazgos nunca equivale a seguridad demostrada.</p>
        <div style={row}>
          <button style={button} disabled={busy}
            onClick={preview}>Vista previa offline</button>
          <button style={button}
            disabled={busy || !canManage}
            onClick={store}>Guardar ejemplo auditado</button>
          <button style={button} disabled={busy}
            onClick={loadHistory}>Consultar historial</button>
        </div>
        {error && <p role="alert"
          style={{ color: "#a33" }}>{error}</p>}
        {notice && <p role="status">{notice}</p>}
        {busy && <p aria-live="polite">Evaluando evidencia…</p>}
      </Panel>
      {history.length > 0 && <Panel>
        <h3>Snapshots de desarrollo guardados</h3>
        <div style={row}>
          <label>Snapshot actual{" "}
            <select value={currentId} onChange={event =>
              setCurrentId(event.target.value)}>
              <option value="">Seleccionar</option>
              {history.map(item =>
                <option key={item.snapshotId}
                  value={item.snapshotId}>{item.evaluatedAt}
                  {" — "}{item.status}</option>)}
            </select>
          </label>
          <button style={button} onClick={load}
            disabled={busy || !currentId}>Abrir</button>
        </div>
        <div style={{ ...row, marginTop: 12 }}>
          <label>Referencia para comparar{" "}
            <select value={baselineId}
              onChange={event => setBaselineId(event.target.value)}>
              <option value="">Seleccionar referencia</option>
              {history.map(item =>
                <option key={item.snapshotId}
                  value={item.snapshotId}>{item.evaluatedAt}</option>)}
            </select>
          </label>
          <button style={button} onClick={compare}
            disabled={busy || !currentId ||
              !baselineId || currentId === baselineId}>
            Comparar</button>
        </div>
        {comparison !== null && <pre style={{
          maxHeight: 320, overflow: "auto",
          fontSize: 12,
        }}>{JSON.stringify(comparison, null, 2)}</pre>}
      </Panel>}
      {report && <Panel>
        <div style={{ ...row, justifyContent: "space-between" }}>
          <h3>Informe {report.snapshotId}</h3>
          <div style={row}>
            <button style={button} onClick={exportReport("JSON")}
              disabled={busy || history.length === 0}>JSON</button>
            <button style={button} onClick={exportReport("CSV")}
              disabled={busy || history.length === 0}>CSV</button>
            <button style={button} onClick={exportReport("MARKDOWN")}
              disabled={busy || history.length === 0}>Markdown</button>
          </div>
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(145px, 1fr))",
          gap: 12, marginBottom: 20,
        }}>
          <Metric title="CyberScore v2"
            value={report.summary.numericScore ?? "N/D"}
            hint={label(report.summary.scoreStatus)} />
          <Metric title="Cobertura verificada"
            value={report.summary.coveragePercent + "%"} />
          <Metric title="Controles pendientes"
            value={report.summary.unknownControls} />
          <Metric title="Fuentes del expediente"
            value={report.sources.length} />
        </div>
        <p>El estado de una fuente simulada o autodeclarada
          no se transforma en un control verificado.
          <strong> No hay certificación de cumplimiento.</strong></p>
        <nav aria-label="Navegación del informe"
          style={{ ...row, marginBottom: 18 }}>
          {views.map(item =>
            <button key={item.code} style={{
              ...button,
              fontWeight: view === item.code ? 700 : 400,
            }} onClick={() => setView(item.code)}>
              {item.title}</button>)}
        </nav>
        {view === "SUMMARY" && report.sections.slice(0, 3)
          .map(section => <article key={section.id}>
            <h4>{section.title}</h4>
            <p>{section.narrative}</p>
            <small>Observación limitada ·
              {section.unknownControls} controles desconocidos</small>
          </article>)}
        {view === "DOMAINS" &&
          report.sections.filter(section =>
            ["IDENTITY", "EMAIL", "WEB", "ENDPOINT",
              "BACKUP", "GOVERNANCE",
              "EXPOSURE"].includes(section.id))
            .map(section => <article key={section.id}
              style={{ marginBottom: 16 }}>
              <h4>{section.title}</h4>
              <p>{section.narrative}</p>
              <small>Estado: {section.status}</small>
            </article>)}
        {view === "GAPS" && <>
          <div style={row}>
            <label>Buscar{" "}
              <input value={filter}
                onChange={event => setFilter(event.target.value)}
                placeholder="Dominio, control o estado" />
            </label>
            <label>Orden{" "}
              <select value={sortBy}
                onChange={event => setSortBy(event.target.value)}>
                <option value="weight">Prioridad</option>
                <option value="control">Control</option>
              </select>
            </label>
          </div>
          {gaps.map(gap => <article key={gap.controlId}
            style={{ borderBottom: "1px solid #94a3b855",
              padding: "10px 0" }}>
            <strong>{gap.controlId}</strong> · {gap.domain}
            <p>{gap.explanation.join(" ")}</p>
            <small>Estado: {gap.state} ·
              peso {gap.weight} ·
              acción: {gap.nextAction}</small>
          </article>)}
        </>}
        {view === "RISKS" &&
          report.findings.map(finding =>
            <article key={finding.findingId}>
              <h4>{finding.title}</h4>
              <p>{finding.explanation}</p>
              <p><strong>Recomendación:</strong>{" "}
                {finding.remediation}</p>
              <small>Fuente: {finding.source} ·
                Severidad: {finding.severity} ·
                Ponderado: {finding.scoreEligible ? "sí" : "no"}</small>
            </article>)}
        {view === "ACTIONS" &&
          report.priorities.map(action =>
            <article key={action.rank}>
              <h4>{action.rank}. {action.title}</h4>
              <p>{action.reason}</p>
              <p>{action.recommendation}</p>
              <small>Acción no ejecutada</small>
            </article>)}
        {view === "SOURCES" &&
          report.sources.map(source =>
            <article key={source.source}>
              <h4>{source.source}</h4>
              <p>Controles: {source.controlCount} ·
                Observados: {source.observed} ·
                Desconocidos: {source.unknown} ·
                Declarados: {source.declared}</p>
              <p>Proveedor autenticado:{" "}
                {source.scopeAuthenticated ? "Sí" : "No"}</p>
            </article>)}
        {view === "PROVENANCE" && <>
          <label><input type="checkbox"
            checked={showDigests} onChange={event =>
              setShowDigests(event.target.checked)} />
            Mostrar SHA-256</label>
          {showDigests && <pre style={{
            maxWidth: "100%", overflow: "auto",
          }}>{JSON.stringify(report.provenance, null, 2)}</pre>}
          <p>Versión: {report.modelId} ·
            Historial v1 conservado: sí</p>
          <p>Sin firma externa ni autorización empresarial inferida.</p>
        </>}
        <div style={{ marginTop: 16 }}>
          <label><input type="checkbox" checked={showLimitations}
            onChange={event =>
              setShowLimitations(event.target.checked)} />
            Mostrar todas las limitaciones</label>
          {showLimitations && <ul>{report.caveats.map((text, index) =>
            <li key={index}>{text}</li>)}</ul>}
        </div>
      </Panel>}
    </div>
  );
}
