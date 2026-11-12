"use client";

import { useMemo, useState } from "react";
import type {
  BaselineAnswer, BaselineDomain, BaselineQuestion,
} from "@cyberpilot/risk-engine";

type Answer = BaselineAnswer;
type Report = {
  schema: string;
  organizationId: string; snapshotId: string;
  evaluatedAt: string;
  summary: {
    completionPercent: number; positiveDeclarations: number;
    unknownOrUnanswered: number; negativeDeclarations: number;
    partialDeclarations: number; technicallyVerified: 0;
    securityScore: null; securityStatus: "NOT_DETERMINED";
  };
  evidence: Array<{
    questionId: string; domain: string; answer: string;
    state: string; evidenceReference: string | null;
  }>;
  actions: Array<{
    id: string; title: string; priority: string;
    reason: string; steps: string[];
    evidenceNeeded: string; automaticallyExecuted: false;
  }>;
  limitations: string[]; digest: string;
};
type ActionPlan = {
  prioritized: Array<{
    actionId: string; rank: number; title: string;
    priority: string; guidance: string[];
    evidenceState: "UNVERIFIED"; executed: false;
  }>;
  visibleUnknowns: string[];
  digest: string;
};
type Props = {
  slug: string;
  organizationId: string;
  questions: BaselineQuestion[];
};
const choices: Array<{
  label: string; value: Answer | "UNANSWERED";
}> = [
  { label: "Sin responder", value: "UNANSWERED" },
  { label: "Sí (declarado)", value: "YES" },
  { label: "Parcial", value: "PARTIAL" },
  { label: "No", value: "NO" },
  { label: "Desconocido", value: "UNKNOWN" },
  { label: "No aplica (declarado)", value: "NOT_APPLICABLE" },
];
const groups: Record<string, string> = {
  ASSETS: "Inventario de activos",
  SOFTWARE: "Software",
  DATA: "Datos",
  CONFIGURATION: "Configuración",
  ACCOUNTS: "Cuentas",
  ACCESS: "Accesos y MFA",
  VULNERABILITIES: "Parches y vulnerabilidades",
  LOGGING: "Registro y auditoría",
  EMAIL_WEB: "Correo y web",
  MALWARE: "Protección endpoint",
  RECOVERY: "Copias y restauración",
  NETWORK: "Red",
  AWARENESS: "Formación",
  SERVICE_PROVIDERS: "Proveedores",
  APPLICATIONS: "Aplicaciones",
  INCIDENT_RESPONSE: "Respuesta a incidentes",
  TESTING: "Pruebas y seguimiento",
};
function localDownload(content: string, filename: string,
  mime: string) {
  const blob = new Blob([content], { type: mime });
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);
  link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove();
  URL.revokeObjectURL(url);
}
export function Phase2BaselineWorkspace({
  slug, organizationId, questions,
}: Props) {
  const [answers, setAnswers] = useState<Record<string, Answer>>({});
  const [references, setReferences] = useState<Record<string, string>>({});
  const [domain, setDomain] = useState<BaselineDomain | "ALL">("ALL");
  const [filter, setFilter] = useState("");
  const [onlyUnanswered, setOnlyUnanswered] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [plan, setPlan] = useState<ActionPlan | null>(null);
  const [showLimits, setShowLimits] = useState(false);
  const [showActions, setShowActions] = useState(true);
  const domains = useMemo(() => [...new Set(
    questions.map(x => x.domain))], [questions]);
  const visible = useMemo(() => questions.filter(q =>
    (domain === "ALL" || q.domain === domain) &&
    (!onlyUnanswered || !answers[q.id]) &&
    (!filter || [q.prompt, q.id, q.guidance, q.evidenceHint]
      .join(" ").toLowerCase().includes(filter.toLowerCase()))),
  [questions, domain, onlyUnanswered, filter, answers]);
  const completed = questions.filter(x =>
    Boolean(answers[x.id])).length;
  const percentage = questions.length ?
    Math.round(100 * completed / questions.length) : 0;
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/phase2-offline";
  const request = async (operation: "BASELINE" | "PORTFOLIO",
    format?: "JSON" | "CSV" | "MARKDOWN") => {
    const responses = questions.flatMap(q => {
      const answer = answers[q.id];
      if (!answer) return [];
      const reference = references[q.id]?.trim();
      // Raw names and free-form notes are deliberately excluded.
      return [{
        questionId: q.id, answer,
        evidenceReference: reference || null,
      }];
    });
    const result = await fetch(endpoint, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operation,
        questionnaire: {
          organizationId,
          questionnaireVersion: 1,
          submittedAt: new Date().toISOString(),
          responses,
        },
        ...(operation === "PORTFOLIO" ? { exposure: [] } : {}),
        ...(format ? { exportFormat: format } : {}),
      }),
    });
    const data = await result.json() as Record<string, unknown>;
    if (!result.ok)
      throw Error(typeof data.error === "string" ?
        data.error : "No se pudo evaluar el diagnóstico.");
    if (data.customerComplianceCertified !== false ||
        data.legacyCyberScoreModified !== false ||
        data.providerNetworkRequests !== 0)
      throw Error("La respuesta excede los límites de evaluación offline.");
    return data;
  };
  const execute = (action: () => Promise<void>) =>
    async () => {
      if (busy) return;
      setBusy(true); setError(""); setMessage("");
      try { await action(); }
      catch (cause) {
        setError(cause instanceof Error ? cause.message :
          "Error inesperado en el diagnóstico.");
      } finally { setBusy(false); }
    };
  const evaluate = execute(async () => {
    const data = await request("BASELINE");
    const current = data.report as Report;
    if (current.summary.securityScore !== null ||
        current.summary.technicallyVerified !== 0)
      throw Error("No se puede declarar el cuestionario como verificado.");
    setReport(current); setPlan(data.actionPlan as ActionPlan);
    setMessage("Diagnóstico calculado localmente en el servidor; no se han guardado respuestas.");
  });
  const exportReport = (format: "JSON" | "CSV" |
    "MARKDOWN") => execute(async () => {
    const data = await request("BASELINE", format);
    const exported = data.exported as {
      filename: string; mimeType: string;
      payload: string; containsRawNotes: false;
      securityCertified: false;
    };
    if (exported.containsRawNotes || exported.securityCertified)
      throw Error("La exportación contiene afirmaciones no permitidas.");
    localDownload(exported.payload, exported.filename, exported.mimeType);
    setMessage("Informe declarativo exportado.");
  });
  const card: React.CSSProperties = {
    border: "1px solid #94a3b84a",
    borderRadius: 12, padding: 18, marginBottom: 14,
  };
  const button: React.CSSProperties = {
    border: "1px solid #64748b88", background: "transparent",
    color: "inherit", padding: "8px 14px",
    borderRadius: 8, cursor: "pointer",
  };
  const flex: React.CSSProperties = {
    display: "flex", gap: 10, alignItems: "center",
    flexWrap: "wrap",
  };
  return <div>
    <section style={card}>
      <h2>Baseline · Diagnóstico organizativo</h2>
      <p>Responde a las preguntas de referencia inspiradas
        en áreas CIS Controls IG1. La evaluación no requiere
        Microsoft 365, ni acredita cumplimiento CIS,
        ni solicita acceso a tus cuentas.</p>
      <p><strong>Sin guardado automático:</strong>{" "}
        las respuestas permanecen en esta pantalla hasta
        que salgas. Las evaluaciones se generan bajo demanda
        y las notas libres no se envían.</p>
      <div style={{
        width: "100%", background: "#94a3b83a",
        borderRadius: 8, overflow: "hidden", height: 10,
      }} role="progressbar"
        aria-valuenow={completed} aria-valuemin={0}
        aria-valuemax={questions.length}
        aria-label="Preguntas respondidas">
        <div style={{
          width: percentage + "%", height: 10,
          background: "currentColor",
        }} />
      </div>
      <p>{completed} / {questions.length} preguntas ·
        {percentage}% respondidas</p>
      <div style={flex}>
        <label>Área{" "}
          <select value={domain}
            onChange={e => setDomain(e.target.value as BaselineDomain | "ALL")}>
            <option value="ALL">Todas</option>
            {domains.map(item => <option key={item}
              value={item}>{groups[item] ?? item}</option>)}
          </select>
        </label>
        <label>Buscar{" "}
          <input value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Control o pregunta" />
        </label>
        <label><input type="checkbox"
          checked={onlyUnanswered}
          onChange={e => setOnlyUnanswered(e.target.checked)} />
          Solo sin responder</label>
      </div>
    </section>
    {visible.map(q => <section key={q.id} style={card}>
      <p style={{ opacity: .7 }}>
        {groups[q.domain] ?? q.domain} · {q.id}</p>
      <h3>{q.prompt}</h3>
      <div style={flex}>
        {choices.map(choice => <label key={choice.value}
          style={{ padding: "5px 0" }}>
          <input type="radio" name={"answer-" + q.id}
            checked={(answers[q.id] ?? "UNANSWERED") === choice.value}
            onChange={() => {
              setAnswers(prev => {
                const next = { ...prev };
                if (choice.value === "UNANSWERED") delete next[q.id];
                else next[q.id] = choice.value;
                return next;
              });
              setReport(null); setPlan(null);
            }} />
          {choice.label}{" "}
        </label>)}
      </div>
      <button type="button" style={button}
        aria-expanded={Boolean(expanded[q.id])}
        onClick={() => setExpanded(prev => ({
          ...prev, [q.id]: !prev[q.id],
        }))}>
        {expanded[q.id] ? "Ocultar ayuda" : "Orientación y evidencia"}
      </button>
      {expanded[q.id] && <div>
        <p>{q.guidance}</p>
        <p>Evidencia sugerida: {q.evidenceHint}</p>
        <label>Identificador opaco de evidencia{" "}
          <input value={references[q.id] ?? ""}
            maxLength={95}
            placeholder="doc-interno-1234"
            onChange={e => {
              setReferences(prev => ({
                ...prev, [q.id]: e.target.value,
              }));
              setReport(null); setPlan(null);
            }} />
        </label>
        <small>Evita nombres, correos, URLs, credenciales
          o información personal.</small>
      </div>}
    </section>)}
    <section style={card}>
      <div style={flex}>
        <button style={button} disabled={busy}
          onClick={evaluate}>Evaluar declaraciones</button>
        <button style={button} disabled={busy}
          onClick={exportReport("JSON")}>Exportar JSON</button>
        <button style={button} disabled={busy}
          onClick={exportReport("CSV")}>Exportar CSV</button>
        <button style={button} disabled={busy}
          onClick={exportReport("MARKDOWN")}>Exportar Markdown</button>
      </div>
      {busy && <p role="status">Evaluando…</p>}
      {error && <p role="alert"
        style={{ color: "#b33" }}>{error}</p>}
      {message && <p role="status">{message}</p>}
    </section>
    {report && <section style={card}>
      <h2>Resultado · {report.snapshotId}</h2>
      <div style={flex}>
        <div style={card}>
          <small>Cuestionario completado</small>
          <h3>{report.summary.completionPercent}%</h3>
        </div>
        <div style={card}>
          <small>Controles técnicos verificados</small>
          <h3>{report.summary.technicallyVerified}</h3>
        </div>
        <div style={card}>
          <small>Score de seguridad</small>
          <h3>Indeterminado</h3>
        </div>
        <div style={card}>
          <small>Desconocidos / sin respuesta</small>
          <h3>{report.summary.unknownOrUnanswered}</h3>
        </div>
      </div>
      <p>Las respuestas «sí» representan declaraciones.
        No equivalen a prueba técnica ni certificación.</p>
      {plan && <div>
        <label><input type="checkbox"
          checked={showActions}
          onChange={e => setShowActions(e.target.checked)} />
          Mostrar plan de acciones</label>
        {showActions && <ol>
          {plan.prioritized.map(action =>
            <li key={action.actionId}>
              <strong>{action.title}</strong>
              <span> · {action.priority} · no ejecutada</span>
              <p>{action.guidance.join(" ")}</p>
            </li>)}
        </ol>}
      </div>}
      <label><input type="checkbox"
        checked={showLimits}
        onChange={e => setShowLimits(e.target.checked)} />
        Mostrar limitaciones</label>
      {showLimits && <ul>{report.limitations.map((lim, index) =>
        <li key={index}>{lim}</li>)}</ul>}
    </section>}
  </div>;
}
