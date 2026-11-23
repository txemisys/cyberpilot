"use client";
import { useEffect, useState } from "react";
type RemediationRef = { id: string; title: string;
  findingId: string; mode: string; status: string };
type FindingRef = { id: string; title: string; status: string; severity: string };
type WorkRef = { id: string; title: string; status: string;
  remediationId: string; revision: number };
type Inventory = { remediations: RemediationRef[]; findings: FindingRef[];
  works: WorkRef[]; nextOffset: number | null; total: number };
type Review = { readiness: {
  gate: string; blockers: string[]; warnings: string[];
  targetReviews: Array<{ remediationId: string; title: string;
    gate: string; mode: string; risk: string; barriers: string[];
    workItems: Array<{ id: string; status: string; overdue: boolean }> }>;
  stepMappings: Array<{ stepId: string; title: string;
    approvalRequired: boolean; approvalRecorded: boolean;
    associatedRemediationIds: string[]; standaloneManualInstructions: string[];
    providerActionPerformed: false }>;
  actualContainmentVerified: false; unsafeAutomations: number;
  unfinishedWorkItems: number };
  plan: { tickets: Array<{ id: string; urgency: string;
    title: string; ownerRole: string; currentBarriers: string[];
    expectedProof: string[] }> };
  artifact: { content: string } | null; remediationExecutorCalled: false };
export function IncidentRemediationWorkspace({ slug, incidentId }: {
  slug: string; incidentId: string;
}) {
  const endpoint = "/api/organizations/" + encodeURIComponent(slug) +
    "/incident-integrations/remediation";
  const [inventory, setInventory] = useState<Inventory>({
    remediations: [], findings: [], works: [], total: 0, nextOffset: null,
  });
  const [remediationIds, setRemediationIds] = useState<string[]>([]);
  const [findingIds, setFindingIds] = useState<string[]>([]);
  const [workItemIds, setWorkItemIds] = useState<string[]>([]);
  const [revision, setRevision] = useState(1);
  const [hours, setHours] = useState(24);
  const [review, setReview] = useState<Review | null>(null);
  const [checklist, setChecklist] = useState<Record<string, unknown> | null>(null);
  const [format, setFormat] = useState<"JSON" | "CSV" | "MARKDOWN">("JSON");
  const [artifact, setArtifact] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function load(offset = 0) {
    const response = await fetch(endpoint + "?" +
      new URLSearchParams({ offset: String(offset), limit: "30" }),
      { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw Error(data.code ?? "REMEDIATION_INVENTORY_FAILED");
    const next = data.data as Inventory;
    setInventory(previous => offset ? {
      ...next,
      remediations: [...previous.remediations, ...next.remediations.filter(x =>
        !previous.remediations.some(y => y.id === x.id))],
      findings: [...previous.findings, ...next.findings.filter(x =>
        !previous.findings.some(y => y.id === x.id))],
      works: [...previous.works, ...next.works.filter(x =>
        !previous.works.some(y => y.id === x.id))],
    } : next);
  }
  useEffect(() => { void load().catch(e => setMessage(String(e))); }, [endpoint]);
  const toggle = (id: string, list: string[], setList: (value: string[]) => void) => {
    setList(list.includes(id) ? list.filter(x => x !== id) : [...list, id]);
    setReview(null);
  };
  async function loadChecklist() {
    setBusy(true);
    try {
      const query = new URLSearchParams({ mode: "checklist", incidentId });
      const result = await fetch(endpoint + "?" + query, { cache: "no-store" });
      const response = await result.json();
      if (!result.ok) throw Error(response.code ?? "CHECKLIST_UNAVAILABLE");
      setChecklist(response.data);
      if (Number.isSafeInteger(response.data.incidentRevision))
        setRevision(response.data.incidentRevision);
      setMessage("Catálogo supervisado consultado. Ninguna acción enviada.");
    } catch (e) { setMessage(String(e)); } finally { setBusy(false); }
  }
  async function evaluate(exportFormat?: "JSON" | "CSV" | "MARKDOWN") {
    setBusy(true);
    try {
      const response = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId, expectedIncidentRevision: revision,
          remediationIds, findingIds, workItemIds, approvalMaxAgeHours: hours,
          ...(exportFormat ? { format: exportFormat } : {}),
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw Error(payload.code ?? "REVIEW_FAILED");
      const data = payload.data as Review;
      setReview(data);
      if (exportFormat) setArtifact(data.artifact?.content ?? "");
      setMessage("Se calculó una revisión manual sin invocar el executor.");
    } catch (e) { setMessage(String(e)); } finally { setBusy(false); }
  }
  return <section aria-label="Remediación supervisada del incidente">
    <p role="note">Integración exclusivamente de lectura con Remediation,
      RemediationWorkItem y SecurityFinding. Los estados históricos
      SUCCEEDED o VERIFIED no acreditan por sí solos contención actual.</p>
    <button type="button" disabled={busy} onClick={() =>
      void loadChecklist()}>Consultar playbook y revisión del caso</button>
    <label>Revisión actual del incidente
      <input type="number" min={1} value={revision}
        onChange={e => setRevision(Number(e.target.value))}/>
    </label>
    <label>Máxima edad de aprobación (horas)
      <input type="number" min={1} max={8760} value={hours}
        onChange={e => setHours(Number(e.target.value))}/>
    </label>
    <h3>Remediaciones existentes</h3>
    <ul>{inventory.remediations.map(row => <li key={row.id}>
      <label><input type="checkbox" checked={remediationIds.includes(row.id)}
        onChange={() => toggle(row.id, remediationIds, setRemediationIds)}/>
        {row.title} — {row.status} ({row.mode})
      </label>
    </li>)}</ul>
    <h3>Hallazgos del mismo tenant</h3>
    <ul>{inventory.findings.map(row => <li key={row.id}>
      <label><input type="checkbox" checked={findingIds.includes(row.id)}
        onChange={() => toggle(row.id, findingIds, setFindingIds)}/>
        {row.title} — {row.severity} / {row.status}
      </label>
    </li>)}</ul>
    <h3>Tareas de remediación</h3>
    <ul>{inventory.works.map(row => <li key={row.id}>
      <label><input type="checkbox" checked={workItemIds.includes(row.id)}
        onChange={() => toggle(row.id, workItemIds, setWorkItemIds)}/>
        {row.title} — {row.status}, rev. {row.revision}
      </label>
    </li>)}</ul>
    {inventory.nextOffset !== null &&
      <button type="button" disabled={busy} onClick={() =>
        void load(inventory.nextOffset!).catch(e => setMessage(String(e)))}>
        Más registros
      </button>}
    <p>Selección: {remediationIds.length} remediaciones,
      {findingIds.length} hallazgos, {workItemIds.length} tareas.</p>
    <button type="button" disabled={busy} onClick={() => void evaluate()}>
      Evaluar aprobaciones, evidencias y bloqueos
    </button>
    <label>Formato de expediente
      <select value={format} onChange={e =>
        setFormat(e.target.value as typeof format)}>
        <option value="JSON">JSON</option>
        <option value="CSV">CSV</option>
        <option value="MARKDOWN">Markdown</option>
      </select>
    </label>
    <button type="button" disabled={busy} onClick={() => void evaluate(format)}>
      Preparar expediente sin ejecución
    </button>
    {checklist && <details><summary>Guía de trabajo y evidencia requerida</summary>
      <pre>{JSON.stringify(checklist, null, 2)}</pre>
    </details>}
    {review && <section aria-label="Resultado de remediación">
      <h3>Evaluación: {review.readiness.gate}</h3>
      <p>Automatizaciones incompatibles: {review.readiness.unsafeAutomations}.
        Tareas incompletas: {review.readiness.unfinishedWorkItems}.
        Contención acreditada: NO. Executor utilizado: NO.</p>
      <ul>{review.readiness.blockers.map(x => <li key={x}>{x}</li>)}</ul>
      <h4>Remediaciones revisadas</h4>
      <ol>{review.readiness.targetReviews.map(target =>
        <li key={target.remediationId}>
          <strong>{target.title}</strong>: {target.gate}
          {" "}({target.risk} / {target.mode})
          <p>Bloqueos: {target.barriers.join(", ") || "ninguno"}.</p>
        </li>)}</ol>
      <h4>Handoffs para aprobación separada</h4>
      <ol>{review.plan.tickets.map(ticket =>
        <li key={ticket.id}>{ticket.urgency}: {ticket.title}
          <p>Responsable requerido: {ticket.ownerRole}.
            Prueba: {ticket.expectedProof.join("; ")}.</p>
        </li>)}</ol>
      <h4>Correspondencia con pasos del playbook</h4>
      <ul>{review.readiness.stepMappings.map(step => <li key={step.stepId}>
        {step.title}: {step.associatedRemediationIds.length} remediaciones;
        aprobación {step.approvalRecorded ? "registrada" : "no registrada"}.
      </li>)}</ul>
    </section>}
    {artifact && <textarea aria-label="Expediente supervisado"
      readOnly rows={12} value={artifact}/>}
    <p role="status">{message}</p>
  </section>;
}
