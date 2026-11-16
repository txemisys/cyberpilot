"use client";

import { useMemo, useState } from "react";

type Finding = {
  id: string;
  questionId: string | null;
  kind: "MISSING_EVIDENCE" | "SOURCE_INCONSISTENT" |
    "CLARIFICATION_REQUIRED" | "SCOPE_UNCLEAR" |
    "CONTROL_UNANSWERED" | "REPORT_INTEGRITY" | "REVIEW_NOTE";
  severity: "BLOCKING" | "FOLLOW_UP" | "INFORMATIONAL";
  status: "OPEN" | "ADDRESSED" | "ACCEPTED_AS_UNKNOWN";
  observation: string;
  proposedAction: string;
  evidenceReference: string | null;
  reviewerValidatedTechnicalControl: false;
  customerConfirmed: false;
};
type Review = {
  id: string; sourceRevision: number; revision: number;
  reportDigest: string;
  state: "OPEN" | "IN_REVIEW" | "CHANGES_REQUESTED" |
    "TECHNICALLY_REVIEWED" | "REOPENED";
  findings: Finding[]; findingsDigest: string;
  issueCount: number; blockingIssueCount: number;
  reviewerUserId: string | null;
  completedAt: string | null;
  externalCustomerApproval: false;
  securityControlsIndependentlyVerified: 0;
};
type Event = {
  revision: number;
  action: string; previousState: string; newState: string;
  actorUserId: string; at: string; customerApproved: false;
};
const kinds: Finding["kind"][] = [
  "MISSING_EVIDENCE","SOURCE_INCONSISTENT",
  "CLARIFICATION_REQUIRED","SCOPE_UNCLEAR",
  "CONTROL_UNANSWERED","REPORT_INTEGRITY","REVIEW_NOTE",
];
const severities: Finding["severity"][] = [
  "BLOCKING","FOLLOW_UP","INFORMATIONAL",
];
export function BaselineTechnicalReviewWorkspace({
  slug, canReview,
}: { slug: string; canReview: boolean }) {
  const [sourceRevision, setSourceRevision] = useState(1);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [selected, setSelected] = useState<Review | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [findingKind, setFindingKind] =
    useState<Finding["kind"]>("MISSING_EVIDENCE");
  const [findingSeverity, setFindingSeverity] =
    useState<Finding["severity"]>("FOLLOW_UP");
  const [questionId, setQuestionId] = useState("");
  const [observation, setObservation] = useState("");
  const [proposedAction, setProposedAction] = useState("");
  const [reference, setReference] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [olderReviewId, setOlderReviewId] = useState("");
  const [comparison, setComparison] =
    useState<Record<string, unknown> | null>(null);
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/baseline-technical-reviews";
  const request = async (operation: string,
    fields: Record<string, unknown> = {}) => {
    const response = await fetch(endpoint, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, ...fields }),
    });
    const result = await response.json() as Record<string, unknown>;
    if (!response.ok) {
      if (result.code === "REVIEW_REVISION_CONFLICT")
        throw Error("Revisión modificada en otra sesión: recarga antes de guardar.");
      throw Error(typeof result.code === "string" ?
        result.code : "Servicio de revisión no disponible.");
    }
    if (result.legalAcceptanceRecorded !== false ||
        result.independentEvidenceVerified !== false ||
        result.remediationExecuted !== false ||
        result.legacyCyberScoreModified !== false)
      throw Error("La revisión interna no puede generar certificados ni aprobar clientes.");
    return result.data as Record<string, unknown>;
  };
  const execute = (work: () => Promise<void>) => async () => {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await work(); }
    catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Error inesperado en el expediente.");
    } finally { setBusy(false); }
  };
  const apply = (review: Review) => {
    setSelected(review);
    setFindings(review.findings);
    setReviewer(review.reviewerUserId ?? "");
    setEvents([]); setComparison(null);
  };
  const list = execute(async () => {
    const result = await request("LIST", { limit: 100 });
    setReviews(result.reviews as Review[]);
    setMessage("Revisiones de desarrollo recuperadas.");
  });
  const create = execute(async () => {
    if (!canReview) throw Error("No dispones de permisos de revisión.");
    const result = await request("CREATE", { sourceRevision });
    apply(result.review as Review);
    setMessage(result.alreadyExists ?
      "Revisión ya existente; se ha recuperado." :
      "Revisión de desarrollo iniciada y auditada.");
  });
  const read = execute(async () => {
    if (!selected) throw Error("Selecciona la revisión.");
    const data = await request("READ", { reviewId: selected.id });
    apply(data.review as Review);
    setMessage("Se ha cargado el estado actual.");
  });
  const transition = (operation: "START" | "REQUEST_CHANGES" |
    "COMPLETE" | "REOPEN" | "UPDATE") => execute(async () => {
    if (!selected) throw Error("Selecciona la revisión.");
    const result = await request(operation, {
      reviewId: selected.id,
      expectedRevision: selected.revision,
      findings, reviewerUserId: reviewer.trim() || null,
    });
    apply(result.review as Review);
    setMessage(operation === "COMPLETE" ?
      "Aceptación técnica interna registrada. No hay aprobación de cliente." :
      "Estado técnico actualizado y auditado.");
  });
  const addFinding = () => {
    if (!observation.trim() || !proposedAction.trim())
      return setError("La observación y la acción propuesta son obligatorias.");
    if (observation.length > 750 || proposedAction.length > 750)
      return setError("La observación o acción supera el límite.");
    const finding: Finding = {
      id: "reviewfinding-" + crypto.randomUUID().replaceAll("-", ""),
      questionId: questionId.trim() || null,
      kind: findingKind, severity: findingSeverity,
      status: "OPEN",
      observation: observation.trim(),
      proposedAction: proposedAction.trim(),
      evidenceReference: reference.trim() || null,
      reviewerValidatedTechnicalControl: false,
      customerConfirmed: false,
    };
    setFindings(previous => [...previous, finding]);
    setObservation(""); setProposedAction("");
    setQuestionId(""); setReference(""); setError("");
  };
  const changeFinding = (id: string,
    state: Finding["status"]) => {
    setFindings(current => current.map(f =>
      f.id === id ? { ...f, status: state } : f));
  };
  const dropFinding = (id: string) => {
    setFindings(current => current.filter(f => f.id !== id));
  };
  const history = execute(async () => {
    if (!selected) throw Error("Selecciona la revisión.");
    const result = await request("HISTORY", {
      reviewId: selected.id, limit: 100,
    });
    setEvents(result.events as Event[]);
    setMessage("Historial de eventos recuperado.");
  });
  const compare = execute(async () => {
    if (!selected || !olderReviewId)
      throw Error("Selecciona ambas revisiones.");
    const result = await request("COMPARE", {
      reviewId: selected.id, olderReviewId,
    });
    setComparison(result);
    setMessage("Comparación interna; no demuestra reducción de riesgo.");
  });
  const pending = useMemo(() => findings.filter(f =>
    f.status === "OPEN" && f.severity === "BLOCKING").length,
  [findings]);
  const changed = selected ?
    JSON.stringify(findings) !== JSON.stringify(selected.findings) :
    false;
  const button: React.CSSProperties = {
    padding: "9px 13px", borderRadius: 8,
    border: "1px solid #64748b88", color: "inherit",
    background: "transparent", cursor: "pointer",
  };
  const card: React.CSSProperties = {
    padding: 18, border: "1px solid #94a3b866",
    borderRadius: 12, marginBottom: 15,
  };
  const row: React.CSSProperties = {
    display: "flex", flexWrap: "wrap",
    alignItems: "center", gap: 12,
  };
  return <div>
    <section style={card}>
      <h2>Aceptación técnica interna del diagnóstico</h2>
      <p>Inspecciona una versión presentada de Baseline, anota
        incidencias, asígnala y deja constancia de su revisión.
        <strong> No se firma ninguna aceptación legal,
        no se certifica seguridad y no se modifica CyberScore.</strong></p>
      <div style={row}>
        <label>Revisión de Baseline presentada{" "}
          <input type="number" min={1} max={10000000}
            value={sourceRevision}
            onChange={event => setSourceRevision(
              Number(event.target.value))} />
        </label>
        <button style={button} disabled={busy || !canReview}
          onClick={create}>Abrir revisión técnica</button>
        <button style={button} disabled={busy}
          onClick={list}>Listar revisiones</button>
      </div>
      {error && <p role="alert" style={{ color: "#b33" }}>{error}</p>}
      {message && <p role="status">{message}</p>}
      {busy && <p aria-live="polite">Procesando…</p>}
      {reviews.length > 0 && <ul>{reviews.map(item =>
        <li key={item.id}>
          <button style={button} disabled={busy}
            onClick={() => apply(item)}>
            Baseline v{item.sourceRevision} ·
            {item.state} · revisión técnica {item.revision}
          </button>
        </li>)}</ul>}
    </section>
    {selected && <section style={card}>
      <h3>Diagnóstico fuente v{selected.sourceRevision}</h3>
      <p>Revisión interna v{selected.revision} · {selected.state}</p>
      <p>Digest de informe: <code>{selected.reportDigest}</code></p>
      <p>Incidencias: {findings.length} ·
        Bloqueantes sin resolver: <strong>{pending}</strong></p>
      <p>Controles técnicamente validados:{" "}
        {selected.securityControlsIndependentlyVerified}</p>
      <label>Revisor (ID de miembro con rol de revisión){" "}
        <input value={reviewer}
          disabled={!canReview}
          onChange={event => setReviewer(event.target.value)}
          placeholder="ID de miembro autorizado" />
      </label>
      <div style={{ ...row, marginTop: 14 }}>
        <button style={button} disabled={busy}
          onClick={read}>Recargar</button>
        <button style={button} disabled={busy || !canReview}
          onClick={transition("START")}>Empezar</button>
        <button style={button} disabled={busy || !canReview}
          onClick={transition("UPDATE")}>
          Guardar {changed ? "cambios pendientes" : "revisión"}
        </button>
        <button style={button} disabled={busy || !canReview}
          onClick={transition("REQUEST_CHANGES")}>
          Solicitar aclaraciones</button>
        <button style={button}
          disabled={busy || !canReview || pending > 0}
          onClick={transition("COMPLETE")}>Completar revisión interna</button>
        <button style={button} disabled={busy || !canReview}
          onClick={transition("REOPEN")}>Reabrir revisión</button>
        <button style={button} disabled={busy}
          onClick={history}>Historial</button>
      </div>
    </section>}
    {selected && <section style={card}>
      <h3>Incidencias de revisión</h3>
      {findings.length > 0 && <ol>{findings.map(item =>
        <li key={item.id} style={{ marginBottom: 14 }}>
          <strong>{item.severity} · {item.kind}</strong>
          <p>{item.observation}</p>
          <p>Acción: {item.proposedAction}</p>
          <p>Estado: {item.status}</p>
          <div style={row}>
            <select disabled={!canReview}
              value={item.status}
              onChange={event => changeFinding(item.id,
                event.target.value as Finding["status"])}>
              <option value="OPEN">Abierta</option>
              <option value="ADDRESSED">Atendida según revisor</option>
              <option value="ACCEPTED_AS_UNKNOWN">
                Aceptada como desconocida
              </option>
            </select>
            <button style={button} disabled={!canReview}
              onClick={() => dropFinding(item.id)}>
              Quitar de la revisión</button>
          </div>
        </li>)}</ol>}
      <fieldset disabled={!canReview}>
        <legend>Nueva incidencia</legend>
        <div style={row}>
          <label>Tipo{" "}
            <select value={findingKind}
              onChange={event => setFindingKind(
                event.target.value as Finding["kind"])}>
              {kinds.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label>Prioridad{" "}
            <select value={findingSeverity}
              onChange={event => setFindingSeverity(
                event.target.value as Finding["severity"])}>
              {severities.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label>Pregunta (opcional){" "}
            <input value={questionId}
              onChange={event => setQuestionId(event.target.value)} />
          </label>
          <label>Referencia opaca (opcional){" "}
            <input value={reference} maxLength={95}
              onChange={event => setReference(event.target.value)} />
          </label>
        </div>
        <label>Observación{" "}
          <textarea maxLength={750} rows={3}
            value={observation}
            onChange={event => setObservation(event.target.value)} />
        </label>
        <label>Recomendación{" "}
          <textarea maxLength={750} rows={3}
            value={proposedAction}
            onChange={event => setProposedAction(event.target.value)} />
        </label>
        <button style={button}
          type="button" onClick={addFinding}>Añadir incidencia</button>
      </fieldset>
    </section>}
    {selected && <section style={card}>
      <h3>Comparación entre revisiones técnicas</h3>
      <div style={row}>
        <label>Revisión anterior{" "}
          <select value={olderReviewId}
            onChange={event => setOlderReviewId(event.target.value)}>
            <option value="">Seleccionar</option>
            {reviews.filter(x => x.id !== selected.id &&
              x.sourceRevision < selected.sourceRevision)
              .map(x => <option key={x.id} value={x.id}>
                Baseline v{x.sourceRevision}
              </option>)}
          </select>
        </label>
        <button style={button}
          disabled={busy || !olderReviewId}
          onClick={compare}>Comparar</button>
      </div>
      {comparison && <pre style={{
        whiteSpace: "pre-wrap", overflowWrap: "anywhere",
      }}>{JSON.stringify(comparison, null, 2)}</pre>}
      {events.length > 0 && <div>
        <h3>Historial interno</h3>
        <ol>{events.map(event => <li key={event.revision}>
          {event.at} · {event.action}:{" "}
          {event.previousState} → {event.newState}
        </li>)}</ol>
      </div>}
    </section>}
  </div>;
}
