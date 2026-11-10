"use client";

import { useEffect, useMemo, useState } from "react";

type Status = "OPEN" | "IN_REVIEW" | "DISMISSED" | "WORK_COMPLETED";
type StepStatus = "TODO" | "IN_PROGRESS" | "BLOCKED" | "DONE";
type Operation = "START_REVIEW" | "DISMISS" | "COMPLETE_WORK" | "REOPEN";
type Step = {
  id: string; actionCode: string; status: StepStatus;
  revision: number; note: string | null;
  completedAt: string | null; completedByUserId: string | null;
};
type Case = {
  id: string; organizationId: string;
  importId: string; inspectionId: string;
  evidenceFingerprint: string; inventoryDigest: string;
  inspectionDigest: string; externalId: string;
  normalizedProductKey: string; softwareVersion: string | null;
  status: Status; category: string; priority: string;
  revision: number; title: string;
  rationale: unknown; actions: unknown; advisoryIds: unknown;
  openedAt: string; lastDecisionAt: string | null;
  lastDecisionReason: string | null; lastDecisionUserId: string | null;
  steps: Step[];
};
type Page = {
  schema: string; total: number; offset: number;
  limit: number; hasMore: boolean; cases: Case[];
  limitations: string[];
};
type Changed = {
  case: Case;
  changed?: boolean; replayed?: boolean;
  auditRecorded?: boolean;
  findingsChanged?: false;
  cyberScoreChanged?: false;
  remediationVerified?: false;
  verifiedRemediation?: false;
  providerQueried?: false;
  warning?: string;
};
function errorText(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Unable to load asset review cases.";
}
function when(iso: string | null) {
  if (!iso) return "Not recorded";
  const parsed = new Date(iso);
  return Number.isFinite(parsed.getTime()) ?
    parsed.toLocaleString() : "Invalid date";
}
async function request<T>(url: string,
  method: "GET" | "POST" | "PATCH" | "PUT",
  payload?: unknown): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "GET" ? {} : {
      body: JSON.stringify(payload),
    }),
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const err = data as { error?: string };
    throw new Error(err.error ?? "Asset review HTTP " + response.status);
  }
  return data as T;
}
function StepEditor({
  step, row, onChange, busy,
}: {
  step: Step; row: Case;
  busy: boolean;
  onChange: (status: StepStatus, reason: string) => Promise<void>;
}) {
  const [next, setNext] = useState<StepStatus>(step.status);
  const [note, setNote] = useState(step.note ?? "");
  const valid = note.trim().length >= 20 && note.length <= 1000 &&
    next !== step.status;
  return <fieldset disabled={busy} style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 9,
  }}>
    <legend>{step.actionCode} · {step.status}</legend>
    <p>Checklist step revision: {step.revision}.
      Last completed: {when(step.completedAt)}.</p>
    <label>Human work status
      <select value={next}
        onChange={event =>
          setNext(event.target.value as StepStatus)}>
        {(["TODO", "IN_PROGRESS", "BLOCKED", "DONE"] as const)
          .map(value =>
            <option value={value} key={value}>{value}</option>)}
      </select>
    </label>
    <label>Activity note or evidence reference
      <textarea rows={3} maxLength={1000} value={note}
        onChange={event => setNote(event.target.value)}
        placeholder="Explain the work performed and evidence still needed"/>
    </label>
    <button type="button" disabled={!valid || busy ||
      row.status !== "IN_REVIEW"}
      onClick={() => void onChange(next, note)}>
      Save audited checklist step
    </button>
    {step.status === "DONE" && <p>
      Work completed, not verified security remediation.
    </p>}
  </fieldset>;
}
function RowDetails({
  row, canManage, busy, onTransition, onStep,
}: {
  row: Case; canManage: boolean; busy: boolean;
  onTransition: (action: Operation, reason: string) => Promise<void>;
  onStep: (step: Step, status: StepStatus,
    reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const allowed: Operation[] = row.status === "OPEN" ?
    ["START_REVIEW", "DISMISS"] :
    row.status === "IN_REVIEW" ?
      ["DISMISS", "COMPLETE_WORK"] :
      ["REOPEN"];
  const allStepsDone = row.steps.length > 0 &&
    row.steps.every(step => step.status === "DONE");
  const completeWorkAllowed = row.status === "IN_REVIEW" &&
    allStepsDone && row.category !==
      "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION";
  const valid = reason.trim().length >= 20 && reason.length <= 1000;
  const notes = row.rationale &&
    typeof row.rationale === "object" && !Array.isArray(row.rationale) ?
      row.rationale as Record<string, unknown> : null;
  return <article style={{
    padding: 14, borderRadius: 10,
    border: "1px solid #8885", marginBlock: 12,
  }}>
    <h4>{row.title}</h4>
    <p><strong>{row.priority} · {row.status}</strong>.
      Category: {row.category}.
      Version: {row.softwareVersion ?? "unknown"}.</p>
    <p>Case revision {row.revision}.
      First opened: {when(row.openedAt)}.
      Last human decision: {when(row.lastDecisionAt)}.</p>
    <p>Declared asset: {row.externalId}.
      Source import: {row.importId}.
      OSV inspection: {row.inspectionId}.</p>
    <p>Checklist:
      {" "}{row.steps.filter(step => step.status === "DONE").length}
      {" "}/ {row.steps.length} steps marked DONE.</p>
    {row.lastDecisionReason && <p>
      Last recorded reason: {row.lastDecisionReason}</p>}
    <button type="button" onClick={() =>
      setExpanded(value => !value)}>
      {expanded ? "Hide" : "Show"} evidence and activity controls
    </button>
    {expanded && <>
      <details>
        <summary>Source provenance and immutable candidate fingerprint</summary>
        <p>Candidate SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {row.evidenceFingerprint}</code></p>
        <p>Inventory SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {row.inventoryDigest}</code></p>
        <p>Inspection SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {row.inspectionDigest}</code></p>
        <pre style={{
          whiteSpace: "pre-wrap", overflowWrap: "anywhere",
          fontSize: "0.82rem",
        }}>{JSON.stringify(notes ?? {}, null, 2)}</pre>
      </details>
      <h5>Human work checklist</h5>
      {row.steps.map(step => <StepEditor
        key={step.id + "-" + step.revision}
        step={step} row={row}
        busy={busy || !canManage}
        onChange={(status, note) =>
          onStep(step, status, note)}/>)}
      {canManage && <fieldset disabled={busy} style={{
        border: "1px solid #8885", padding: 12, borderRadius: 8,
      }}>
        <legend>Review lifecycle decision</legend>
        <p>Completing work does not certify that the endpoint is
          patched, safe or remediated. A dismissal only records
          an operator's decision about this specific candidate.</p>
        <label>Decision rationale (minimum 20 characters)
          <textarea rows={3} maxLength={1000} value={reason}
            onChange={event => setReason(event.target.value)}
            placeholder="Document evidence examined and why this decision is appropriate"/>
        </label>
        <label>
          <input type="checkbox" checked={confirm}
            onChange={event => setConfirm(event.target.checked)}/>
          This decision only updates the review workflow.
          It cannot change findings, CyberScore or provider results.
        </label>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {allowed.map(operation =>
            <button type="button" key={operation}
              disabled={!valid || !confirm || busy ||
                (operation === "COMPLETE_WORK" &&
                  !completeWorkAllowed)}
              onClick={() => void onTransition(operation, reason)}>
              {operation.replaceAll("_", " ")}
            </button>)}
        </div>
      </fieldset>}
    </>}
  </article>;
}
export function AssetActionCaseWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/action-cases";
  const [page, setPage] = useState<Page | null>(null);
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState<Status | "ALL">("ALL");
  const [limit, setLimit] = useState(20);
  const [importFilter, setImportFilter] = useState("");
  const [inspectionFilter, setInspectionFilter] = useState("");
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [evidenceFingerprint, setEvidenceFingerprint] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [openingReason, setOpeningReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const filter = useMemo(() => ({
    offset, limit, status, importFilter, inspectionFilter,
  }), [offset, limit, status, importFilter, inspectionFilter]);
  useEffect(() => {
    let cancelled = false;
    const url = endpoint + "?" + new URLSearchParams({
      offset: String(filter.offset), limit: String(filter.limit),
      ...(filter.status === "ALL" ? {} : {
        status: filter.status,
      }),
      ...(filter.importFilter.trim() ? {
        importId: filter.importFilter.trim(),
      } : {}),
      ...(filter.inspectionFilter.trim() ? {
        inspectionId: filter.inspectionFilter.trim(),
      } : {}),
    });
    void request<Page>(url, "GET").then(result => {
      if (cancelled) return;
      setPage(result); setError(null);
    }).catch(cause => {
      if (!cancelled) setError(errorText(cause));
    });
    return () => { cancelled = true; };
  }, [endpoint, filter, revision]);
  async function openCase() {
    if (busy || !canManage) return;
    let mappings: unknown;
    try {
      mappings = JSON.parse(bindings);
      if (!Array.isArray(mappings))
        throw new Error("Package mappings must be a JSON array.");
    } catch (cause) {
      setError(errorText(cause)); return;
    }
    setBusy(true); setFeedback(null); setError(null);
    try {
      const result = await request<Changed>(endpoint, "POST", {
        importId: importId.trim(),
        inspectionId: inspectionId.trim(),
        evidenceFingerprint: evidenceFingerprint.trim(),
        bindings: mappings, reason: openingReason,
      });
      setFeedback(result.replayed ?
        "Matching case already existed; no duplicate was created." :
        "An evidence-backed human review case was opened and audited.");
      setOpeningReason("");
      setEvidenceFingerprint("");
      setOffset(0); setRevision(x => x + 1);
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  async function transition(row: Case,
    operation: Operation, reason: string) {
    if (busy || !canManage) return;
    setBusy(true); setFeedback(null); setError(null);
    try {
      await request<Changed>(endpoint, "PATCH", {
        caseId: row.id, operation,
        expectedRevision: row.revision,
        expectedEvidenceFingerprint: row.evidenceFingerprint,
        reason,
      });
      setFeedback("Human review decision recorded with an audit event.");
      setRevision(x => x + 1);
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  async function updateStep(row: Case,
    step: Step, status: StepStatus, note: string) {
    if (busy || !canManage) return;
    setBusy(true); setFeedback(null); setError(null);
    try {
      await request<Changed>(endpoint, "PUT", {
        caseId: row.id, actionCode: step.actionCode,
        expectedCaseRevision: row.revision,
        expectedStepRevision: step.revision,
        status, note,
      });
      setFeedback("Checklist activity saved and audited; no remediation verification performed.");
      setRevision(x => x + 1);
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  return <section aria-label="Human asset advisory review cases"
    style={{
      padding: 16, border: "1px solid #8885",
      borderRadius: 12, marginBlock: 22,
    }}>
    <h2>Guided asset investigation and human work</h2>
    <p>Record candidate advisory reviews separately from verified
      findings, security score and remediation state.
      All work and decisions remain tenant-scoped and audited.</p>
    {error && <p role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {busy && <p role="status">Recording a scoped review operation…</p>}
    {canManage && <details>
      <summary>Open a case from verified advice evidence</summary>
      <fieldset disabled={busy}>
        <legend>Explicit evidence and human justification</legend>
        <p>First prepare action guidance above. Copy the exact
          inventory ID, inspection ID, package bindings and
          candidate SHA-256. The server recomputes and verifies
          the candidate from saved data before creating a case.</p>
        <label>Inventory import
          <input value={importId} maxLength={150}
            onChange={event => setImportId(event.target.value)}/>
        </label>
        <label>Saved provider inspection
          <input value={inspectionId} maxLength={150}
            onChange={event => setInspectionId(event.target.value)}/>
        </label>
        <label>Candidate SHA-256
          <input value={evidenceFingerprint} maxLength={64}
            onChange={event =>
              setEvidenceFingerprint(event.target.value)}/>
        </label>
        <label>Explicit package bindings JSON
          <textarea value={bindings} maxLength={60000}
            rows={4} spellCheck={false}
            onChange={event => setBindings(event.target.value)}/>
        </label>
        <label>Reason for opening review
          <textarea value={openingReason} maxLength={1000}
            rows={3} onChange={event =>
              setOpeningReason(event.target.value)}/>
        </label>
        <button type="button" disabled={
          busy || !importId || !inspectionId ||
          evidenceFingerprint.length !== 64 ||
          openingReason.trim().length < 20}
          onClick={() => void openCase()}>
          Open audited review case
        </button>
      </fieldset>
    </details>}
    <fieldset disabled={busy}>
      <legend>Review register filters</legend>
      <label>Case status
        <select value={status} onChange={event => {
          setStatus(event.target.value as Status | "ALL");
          setOffset(0);
        }}>
          {(["ALL", "OPEN", "IN_REVIEW", "DISMISSED",
            "WORK_COMPLETED"] as const).map(x =>
              <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <label>Inventory ID
        <input value={importFilter} maxLength={150}
          onChange={event => {
            setImportFilter(event.target.value); setOffset(0);
          }}/>
      </label>
      <label>Inspection ID
        <input value={inspectionFilter} maxLength={150}
          onChange={event => {
            setInspectionFilter(event.target.value); setOffset(0);
          }}/>
      </label>
      <label>Page size
        <select value={limit} onChange={event => {
          setLimit(Number(event.target.value)); setOffset(0);
        }}>
          {[10, 20, 50, 100].map(x =>
            <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <button type="button" onClick={() =>
        setRevision(x => x + 1)}>
        Refresh review register
      </button>
    </fieldset>
    {page && <section>
      <h3>Stored human review cases</h3>
      <p>{page.total} cases match filters.
        Displaying {page.cases.length} from offset {page.offset}.</p>
      {page.cases.length === 0 &&
        <p>No review cases recorded in this scope.</p>}
      {page.cases.map(row =>
        <RowDetails key={row.id + "-" + row.revision}
          row={row} canManage={canManage} busy={busy}
          onTransition={(operation, reason) =>
            transition(row, operation, reason)}
          onStep={(step, next, reason) =>
            updateStep(row, step, next, reason)}/>)}
      <div style={{ display: "flex", gap: 8 }}>
        <button type="button" disabled={busy || offset === 0}
          onClick={() => setOffset(x =>
            Math.max(0, x - limit))}>
          Previous
        </button>
        <button type="button" disabled={busy || !page.hasMore}
          onClick={() => setOffset(x => x + limit)}>
          Next
        </button>
      </div>
      <details>
        <summary>Workflow guarantees and limitations</summary>
        <ul>{page.limitations.map((value, i) =>
          <li key={i}>{value}</li>)}</ul>
        <p>DONE and WORK_COMPLETED refer to the operator's
          documented activity. Neither status confirms installed
          patches, endpoint exposure, exploitation or the
          remediation of a verified security finding.</p>
      </details>
    </section>}
  </section>;
}
