"use client";
import { useEffect, useState } from "react";
type EvidenceSummary = { id: string; source: string; domain: string; controlId: string;
  scope: string; state: string; observedAt: string | null };
type FindingSummary = { id: string; title: string; ruleId: string;
  severity: string; status: string; lastSeenAt: string };
type DecisionSummary = { id: string; domain: string; controlId: string;
  scope: string; status: string; revision: number };
type Inventory = { evidence: EvidenceSummary[]; findings: FindingSummary[];
  decisions: DecisionSummary[]; hasPotentialNextPage: boolean };
type Correlation = { acceptance: string; coverage: string;
  warnings: string[]; missingIds: string[]; foreignTenantIds: string[];
  matchedEvidenceCount: number; matchedFindingCount: number;
  matchedDecisionCount: number; incidentDigest: string;
  sourceRecords: Array<{ id: string; kind: string; verdict: string;
    sourceLabel: string; basis: string; signals: string[] }>;
  steps: Array<{ stepId: string; title: string; capability: string;
    missingSources: string[]; matchedEvidenceIds: string[];
    matchedFindingIds: string[]; independentObservedCount: number;
    humanDeclarationCount: number; completionGate: string }> };
type ReviewResponse = { correlation: Correlation;
  evidenceWasCopiedToCase: false; incidentContainmentVerified: false };
const kinds = ["EVIDENCE", "FINDING", "DECISION"] as const;
export function IncidentEvidenceIntegrationWorkspace({
  slug, incidentId,
}: { slug: string; incidentId: string }) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/evidence";
  const [inventory, setInventory] = useState<Inventory>({
    evidence: [], findings: [], decisions: [], hasPotentialNextPage: false,
  });
  const [kind, setKind] = useState<typeof kinds[number]>("EVIDENCE");
  const [offset, setOffset] = useState(0);
  const [evidenceIds, setEvidenceIds] = useState<string[]>([]);
  const [findingIds, setFindingIds] = useState<string[]>([]);
  const [decisionIds, setDecisionIds] = useState<string[]>([]);
  const [maxAgeHours, setMaxAgeHours] = useState(72);
  const [review, setReview] = useState<ReviewResponse | null>(null);
  const [linked, setLinked] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  async function loadInventory(type: typeof kinds[number], start: number) {
    const params = new URLSearchParams({
      mode: "inventory", kind: type, limit: "30", offset: String(start),
    });
    const response = await fetch(endpoint + "?" + params, { cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw Error(payload.code ?? "INVENTORY_FAILED");
    const next = payload.data as Inventory;
    setInventory(old => start === 0 ? next : {
      evidence: [...old.evidence, ...next.evidence.filter(x =>
        !old.evidence.some(y => y.id === x.id))],
      findings: [...old.findings, ...next.findings.filter(x =>
        !old.findings.some(y => y.id === x.id))],
      decisions: [...old.decisions, ...next.decisions.filter(x =>
        !old.decisions.some(y => y.id === x.id))],
      hasPotentialNextPage: next.hasPotentialNextPage,
    });
    setOffset(start);
  }
  useEffect(() => {
    void loadInventory(kind, 0).catch(e => setNotice(String(e)));
  }, [endpoint, kind]);
  async function loadLinked() {
    setBusy(true);
    try {
      const query = new URLSearchParams({ mode: "decision", incidentId });
      const response = await fetch(endpoint + "?" + query,
        { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw Error(body.code ?? "DECISION_READ_FAILED");
      setLinked(body.data);
      const result = body.data;
      if (result.linked && result.decision) {
        setDecisionIds([result.decision.id]);
        setEvidenceIds(result.evidenceIds ?? []);
        setFindingIds(result.findingIds ?? []);
      }
      setNotice("Relación existente leída; no se ha creado un vínculo implícito.");
    } catch (e) { setNotice(String(e)); } finally { setBusy(false); }
  }
  async function correlate() {
    setBusy(true);
    try {
      const response = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId, evidenceIds, findingIds,
          decisionIds, maxAgeHours }),
      });
      const payload = await response.json();
      if (!response.ok) throw Error(payload.code ?? "CORRELATION_FAILED");
      setReview(payload.data as ReviewResponse);
      setNotice("Comparación de registros persistidos completada; no se ha ejecutado remediación.");
    } catch (e) { setNotice(String(e)); } finally { setBusy(false); }
  }
  const toggle = (value: string, selected: string[],
    update: (ids: string[]) => void) => {
    update(selected.includes(value) ? selected.filter(x => x !== value) :
      [...selected, value]);
    setReview(null);
  };
  const rows = kind === "EVIDENCE" ? inventory.evidence :
    kind === "FINDING" ? inventory.findings : inventory.decisions;
  return <section aria-label="Correlación de evidencias de incidentes">
    <p role="note">Vinculación explícita de identificadores persistidos.
      Las coincidencias de nombre, correo o dispositivo no establecen atribución.
      Ninguna revisión demuestra contención externa.</p>
    <h3>Inventario de CyberPilot</h3>
    <label>Clase de registro
      <select value={kind} onChange={event => setKind(
        event.target.value as typeof kinds[number])}>
        {kinds.map(x => <option key={x} value={x}>{x}</option>)}
      </select>
    </label>
    <button type="button" disabled={busy} onClick={() =>
      void loadInventory(kind, 0).catch(e => setNotice(String(e)))}>
      Actualizar inventario
    </button>
    <ul>{rows.map(item => {
      const selected = kind === "EVIDENCE" ? evidenceIds :
        kind === "FINDING" ? findingIds : decisionIds;
      const update = kind === "EVIDENCE" ? setEvidenceIds :
        kind === "FINDING" ? setFindingIds : setDecisionIds;
      return <li key={item.id}>
        <label><input type="checkbox" checked={selected.includes(item.id)}
          onChange={() => toggle(item.id, selected, update)}/>
          {" "}{kind}: {item.id} — {"title" in item ? item.title :
            "source" in item ? item.source + " / " + item.controlId :
            item.domain + " / " + item.controlId}
        </label>
      </li>;
    })}</ul>
    {inventory.hasPotentialNextPage &&
      <button type="button" disabled={busy} onClick={() =>
        void loadInventory(kind, offset + 30).catch(e => setNotice(String(e)))}>
        Más registros
      </button>}
    <h3>Selección auditada</h3>
    <p>Evidencias: {evidenceIds.length}; hallazgos: {findingIds.length};
      decisiones: {decisionIds.length}.</p>
    <label>Antigüedad máxima de evidencia (horas)
      <input type="number" min={1} max={8760} value={maxAgeHours}
        onChange={e => setMaxAgeHours(Number(e.target.value))}/>
    </label>
    <button type="button" disabled={busy} onClick={() => void loadLinked()}>
      Consultar decisión asociada al incidente
    </button>
    <button type="button" disabled={busy} onClick={() => void correlate()}>
      Correlacionar registros seleccionados
    </button>
    {linked && <details><summary>Relación explícita existente</summary>
      <pre>{JSON.stringify(linked, null, 2)}</pre>
    </details>}
    {review && <section aria-label="Resultado de correlación">
      <h3>Resultado: {review.correlation.acceptance}</h3>
      <p>Cobertura: {review.correlation.coverage}.
        Evidencias coincidentes: {review.correlation.matchedEvidenceCount};
        hallazgos: {review.correlation.matchedFindingCount};
        decisiones: {review.correlation.matchedDecisionCount}.</p>
      <p>Evidencia incorporada automáticamente: NO.
        Contención comprobada: NO.</p>
      <ul>{review.correlation.warnings.map(w => <li key={w}>{w}</li>)}</ul>
      <ul>{review.correlation.missingIds.map(id =>
        <li key={id}>Referencia inexistente: {id}</li>)}</ul>
      <h4>Procedencia de registros</h4>
      <ol>{review.correlation.sourceRecords.map(row =>
        <li key={row.id}>{row.kind}: {row.sourceLabel} —
          {row.verdict} ({row.basis})</li>)}</ol>
      <h4>Impacto en playbook</h4>
      <ol>{review.correlation.steps.map(step => <li key={step.stepId}>
        <strong>{step.title}</strong>
        <p>{step.capability}; pruebas independientes localizadas:
          {step.independentObservedCount}.
          Pendientes: {step.missingSources.join(", ") || "ninguna"}.
          Estado: {step.completionGate}.</p>
      </li>)}</ol>
    </section>}
    <p role="status">{notice}</p>
  </section>;
}
