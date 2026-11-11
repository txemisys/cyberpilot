"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type StepCode =
  "CSV_IMPORT_REVIEW" | "SCOPE_AND_PROVENANCE" |
  "STORED_OSV_REVIEW" | "HUMAN_ADVICE_CASES" |
  "ACCEPTANCE_GATES" | "PRIVACY_AND_PII" |
  "RETENTION_BACKUP_OWNER" | "RELEASE_AUDIT_REVIEW" |
  "FINAL_OPERATOR_WALKTHROUGH";
type Step = {
  code: StepCode;
  status: "TODO" | "BLOCKED" | "EVIDENCE_RECORDED";
  description: string;
  instructions: string;
  evidenceId: string | null;
  evidenceDescription: string | null;
  recordedByUserId: string | null;
  recordedAt: string | null;
  reason: string | null;
  limitations: string[];
};
type Run = {
  id: string;
  importId: string;
  inspectionId: string;
  idempotencyKey: string;
  state: string;
  revision: number;
  dossierDigest: string;
  sourceDigest: string;
  operatorUserId: string;
  openingReason: string;
  steps: Step[];
  limitations: string[];
  humanAcknowledgements: string[];
  completedSteps: number;
  blockedSteps: number;
  startedAt: string;
  updatedAt: string;
  submittedAt: string | null;
  submittedByUserId: string | null;
  submittedReason: string | null;
  verification: {
    valid: boolean;
    issues: string[];
    noApprovalClaim: true;
  };
  readiness: {
    canSubmitForIndependentReview: boolean;
    completed: number;
    blocked: number;
    outstanding: StepCode[];
    externalPrivacySignoffStillRequired: true;
    mergeAuthorizationGranted: false;
  };
  caveats: string[];
};
type ListResult = { total: number; runs: Run[] };
type StatusResult = {
  evaluatedAt: string;
  run: Run;
  manifest: {
    digest: string;
    completed: number; blocked: number;
    externalSignoffVerified: false;
    phaseClosed: false;
  };
  audit: {
    observedCount: number;
    expectedRevision: number;
    completeWithinBound: boolean;
    events: Array<{
      id: string; action: string; occurredAt: string;
      actorUserId: string | null;
    }>;
  };
  readyForExternalSignoff: boolean;
  externalSignoffGranted: false;
  phaseClosed: false;
  warning: string[];
};
type Props = { slug: string; canManage: boolean };
const operations: Array<[string, string]> = [
  ["START", "Start human walkthrough"],
  ["RECORD_EVIDENCE", "Record referenced evidence"],
  ["BLOCK_STEP", "Mark documented blocking issue"],
  ["RESET_STEP", "Reset step for repeat review"],
  ["SUBMIT_FOR_INDEPENDENT_REVIEW", "Submit evidence for independent signoff"],
  ["REOPEN", "Reopen evidence capture"],
];
const acknowledgements = [
  ["OFFLINE_ONLY", "Only persisted data and offline references are reviewed."],
  ["SOURCE_NOT_EXHAUSTIVE", "Customer CSV may omit devices and software."],
  ["NOT_LEGAL_SIGNOFF", "A checklist does not grant privacy or legal authorization."],
  ["BACKUPS_NOT_ERASED", "Backup and export erasure have not been proven."],
  ["NO_VERIFIED_REMEDIATION", "No patch or vulnerability remediation is verified."],
  ["EXTERNAL_PROVIDER_NOT_VALIDATED", "No live provider availability is attested."],
  ["INDEPENDENT_HUMAN_DECISION_REQUIRED", "Responsible human approval remains separate."],
] as const;
function json(value: string, label: string) {
  try { return JSON.parse(value) as unknown; }
  catch { throw new Error(label + " requires valid JSON."); }
}
function message(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Offline operator acceptance request failed.";
}
function save(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json",
  });
  const address = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = address;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(address);
}
function progressColor(status: string) {
  if (status === "BLOCKED") return "#ac3030";
  if (status === "EVIDENCE_RECORDED") return "#147c48";
  return "#64717a";
}
export function AssetOfflineAcceptanceRunWorkspace({
  slug, canManage,
}: Props) {
  const endpoint =
    `/api/organizations/${encodeURIComponent(slug)}/assets/offline-acceptance-runs`;
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [acceptancePolicy, setAcceptancePolicy] = useState("{}");
  const [privacyPolicy, setPrivacyPolicy] = useState("{}");
  const [reason, setReason] = useState("");
  const [limitations, setLimitations] = useState("");
  const [acknowledged, setAcknowledged] = useState<string[]>([]);
  const [operation, setOperation] = useState("START");
  const [stepCode, setStepCode] = useState<StepCode>(
    "CSV_IMPORT_REVIEW");
  const [evidenceId, setEvidenceId] = useState("");
  const [evidenceDescription, setEvidenceDescription] = useState("");
  const [runs, setRuns] = useState<Run[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [stepFilter, setStepFilter] = useState("ALL");
  const [showAudit, setShowAudit] = useState(true);
  const [showLimitations, setShowLimitations] = useState(true);
  const [showManifest, setShowManifest] = useState(false);
  const [showSteps, setShowSteps] = useState(true);
  const [showHistory, setShowHistory] = useState(true);
  const selected = useMemo(() => runs.find(row =>
    row.id === selectedId) ?? status?.run ?? null,
    [runs, selectedId, status]);
  const filteredSteps = useMemo(() => selected?.steps.filter(step =>
    stepFilter === "ALL" || step.status === stepFilter) ?? [],
    [selected, stepFilter]);
  const load = useCallback(async (next: number) => {
    if (!canManage) return;
    const response = await fetch(
      endpoint + `?offset=${next}&limit=20`, { cache: "no-store" });
    const payload = await response.json() as ListResult & {
      error?: string;
    };
    if (!response.ok)
      throw new Error(payload.error ?? "Could not list operator runs.");
    setRuns(payload.runs);
    setTotal(payload.total);
    setOffset(next);
    setSelectedId(current =>
      payload.runs.some(row => row.id === current) ? current : "");
  }, [canManage, endpoint]);
  useEffect(() => {
    if (canManage)
      void load(0).catch(cause => setError(message(cause)));
  }, [canManage, load]);
  function common() {
    return {
      bindings: json(bindings, "Package bindings"),
      acceptancePolicy: json(acceptancePolicy, "Acceptance policy"),
      privacyPolicy: json(privacyPolicy, "Privacy policy"),
      reason,
    };
  }
  async function submit(method: "POST" | "PATCH") {
    if (busy || !canManage) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const shared = common();
      const command = method === "POST" ? {
        ...shared, importId, inspectionId, idempotencyKey,
      } : {
        ...shared, runId: selected?.id,
        expectedRevision: selected?.revision,
        expectedDossierDigest: selected?.dossierDigest,
        operation, stepCode: ["RECORD_EVIDENCE", "BLOCK_STEP",
          "RESET_STEP"].includes(operation) ? stepCode : null,
        evidenceId: operation === "RECORD_EVIDENCE" ? evidenceId : null,
        evidenceDescription: operation === "RECORD_EVIDENCE"
          ? evidenceDescription : null,
        limitations: limitations.split("\n").map(x => x.trim())
          .filter(Boolean),
        acknowledgements: acknowledged,
      };
      if (method === "PATCH" && !selected)
        throw new Error("Choose an existing operator run.");
      const response = await fetch(endpoint, {
        method, cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(command),
      });
      const body = await response.json() as {
        error?: string; run?: Run; replayed?: boolean;
        currentBlockers?: number;
      };
      if (!response.ok)
        throw new Error(body.error ?? "Operator run action rejected.");
      setNotice(body.replayed ?
        "Existing run returned with no duplicate audit." :
        "Operator evidence and audit saved; this does not grant signoff.");
      await load(0);
      if (body.run) setSelectedId(body.run.id);
      setStatus(null);
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  async function inspect() {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        endpoint + "?runId=" + encodeURIComponent(selected.id),
        { method: "PUT", cache: "no-store" });
      const body = await response.json() as StatusResult & {
        error?: string;
      };
      if (!response.ok)
        throw new Error(body.error ?? "Run audit inspection rejected.");
      setStatus(body);
      setNotice("Read-only run and audit status reconstructed.");
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  if (!canManage) return <section aria-label="Operator run access">
    <h2>Human offline acceptance walkthrough</h2>
    <p>Only organization administrators can record acceptance evidence.</p>
  </section>;
  return <section aria-label="Offline operator acceptance runs"
    style={{ marginBlock: "2rem" }}>
    <h2>Witnessed offline walkthrough tracker</h2>
    <p>Record actual operator-observed evidence and its reference IDs, review
      blockers, and submit a completed checklist for independent approval.
      The service cannot itself attest a witness, sign a legal policy or
      authorize a GitHub merge.</p>
    <form onSubmit={event => { event.preventDefault(); void submit("POST"); }}>
      <fieldset disabled={busy}>
        <legend>Start an evidence-bound run</legend>
        <label>Inventory import ID
          <input required minLength={5} maxLength={150}
            value={importId}
            onChange={event => setImportId(event.target.value)} />
        </label>
        <label>Inspection ID
          <input required minLength={5} maxLength={150}
            value={inspectionId}
            onChange={event => setInspectionId(event.target.value)} />
        </label>
        <label>Unique run idempotency key
          <input required minLength={5} maxLength={150}
            value={idempotencyKey}
            onChange={event => setIdempotencyKey(event.target.value)} />
        </label>
        <label>Exact package mappings JSON
          <textarea rows={4} spellCheck={false} value={bindings}
            onChange={event => setBindings(event.target.value)} />
        </label>
        <label>Acceptance policy JSON
          <textarea rows={3} spellCheck={false}
            value={acceptancePolicy}
            onChange={event => setAcceptancePolicy(event.target.value)} />
        </label>
        <label>Privacy policy JSON
          <textarea rows={3} spellCheck={false}
            value={privacyPolicy}
            onChange={event => setPrivacyPolicy(event.target.value)} />
        </label>
        <label>Explicit operator rationale (20–1500 characters)
          <textarea rows={3} required minLength={20} maxLength={1500}
            value={reason}
            onChange={event => setReason(event.target.value)} />
        </label>
        <button type="submit">Create draft witnessed checklist</button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    <h3>Recent operator runs ({total})</h3>
    <button type="button" disabled={busy}
      onClick={() => void load(offset).catch(cause =>
        setError(message(cause)))}>Refresh register</button>
    <ul>{runs.map(row => <li key={row.id}>
      <button type="button" onClick={() => {
        setSelectedId(row.id);
        setStatus(null);
        setImportId(row.importId);
        setInspectionId(row.inspectionId);
      }} aria-pressed={selectedId === row.id}>
        {row.state} · {row.importId} ·
        {row.completedSteps}/{row.steps.length} · revision {row.revision}
      </button>
    </li>)}</ul>
    <button type="button" disabled={busy || offset === 0}
      onClick={() => void load(Math.max(0, offset - 20)).catch(cause =>
        setError(message(cause)))}>Previous</button>
    <span> {Math.min(offset + 1, total)}–
      {Math.min(offset + 20, total)} of {total} </span>
    <button type="button" disabled={busy || offset + 20 >= total}
      onClick={() => void load(offset + 20).catch(cause =>
        setError(message(cause)))}>Next</button>
    {selected && <article>
      <h3>Review run {selected.id}</h3>
      <dl>
        <dt>State</dt><dd>{selected.state}</dd>
        <dt>CAS revision</dt><dd>{selected.revision}</dd>
        <dt>Evidence recorded</dt><dd>{selected.completedSteps}</dd>
        <dt>Open blockers</dt><dd>{selected.blockedSteps}</dd>
        <dt>Independent structural check</dt>
        <dd>{selected.verification.valid ? "Consistent" :
          selected.verification.issues.join("; ")}</dd>
        <dt>Submitted to independent review</dt>
        <dd>{selected.submittedAt ?? "Not submitted"}</dd>
        <dt>Original operator</dt><dd>{selected.operatorUserId}</dd>
      </dl>
      <button type="button" onClick={() =>
        setShowSteps(x => !x)}>
        {showSteps ? "Hide" : "Show"} fixed evidence checklist
      </button>
      {showSteps && <section>
        <label>Filter checklist
          <select value={stepFilter}
            onChange={event => setStepFilter(event.target.value)}>
            <option value="ALL">All steps</option>
            <option value="TODO">To do</option>
            <option value="EVIDENCE_RECORDED">Evidence recorded</option>
            <option value="BLOCKED">Blocked</option>
          </select>
        </label>
        <ol>{filteredSteps.map(step => <li key={step.code}>
          <strong style={{ color: progressColor(step.status) }}>
            {step.status} · {step.description}
          </strong>
          <p>{step.instructions}</p>
          {step.evidenceId && <p>Reference: <code>{step.evidenceId}</code></p>}
          {step.evidenceDescription && <p>{step.evidenceDescription}</p>}
          {step.recordedByUserId && <p>Recorded by:
            {step.recordedByUserId} at {step.recordedAt}</p>}
          {step.reason && <p>Operator reason: {step.reason}</p>}
          {step.limitations.length > 0 &&
            <ul>{step.limitations.map(item =>
              <li key={item}>{item}</li>)}</ul>}
          <button type="button" disabled={busy}
            onClick={() => setStepCode(step.code)}>
            Select this step for next CAS action
          </button>
        </li>)}</ol>
      </section>}
      <fieldset disabled={busy}>
        <legend>Audited human state and evidence update</legend>
        <label>Operation
          <select value={operation}
            onChange={event => setOperation(event.target.value)}>
            {operations.map(([id, label]) =>
              <option value={id} key={id}>{label}</option>)}
          </select>
        </label>
        <label>Selected step
          <select value={stepCode}
            onChange={event => setStepCode(event.target.value as StepCode)}>
            {selected.steps.map(step =>
              <option key={step.code} value={step.code}>
                {step.code}
              </option>)}
          </select>
        </label>
        <label>Evidence reference ID (not file contents)
          <input value={evidenceId} maxLength={800}
            onChange={event => setEvidenceId(event.target.value)} />
        </label>
        <label>What was actually observed?
          <textarea rows={3} maxLength={800}
            value={evidenceDescription}
            onChange={event => setEvidenceDescription(event.target.value)} />
        </label>
        <label>Unresolved limitations, one per line
          <textarea rows={4} value={limitations}
            onChange={event => setLimitations(event.target.value)} />
        </label>
        <fieldset>
          <legend>Scope acknowledgements (nothing is pre-checked)</legend>
          {acknowledgements.map(([id, description]) =>
            <label key={id} style={{ display: "block" }}>
              <input type="checkbox" checked={acknowledged.includes(id)}
                onChange={event => setAcknowledged(previous =>
                  event.target.checked
                    ? [...previous, id]
                    : previous.filter(item => item !== id))} />
              {description}
            </label>)}
        </fieldset>
        <button type="button" onClick={() => void submit("PATCH")}>
          Save CAS transition with operator audit
        </button>
      </fieldset>
      <button type="button" disabled={busy} onClick={() => void inspect()}>
        Inspect stored audit and export manifest
      </button>
      {status && <section aria-label="Operator acceptance audit">
        <h3>Independent local audit status</h3>
        <p>Expected CAS revision: {status.audit.expectedRevision};
          events found: {status.audit.observedCount};
          complete within bound:
          {String(status.audit.completeWithinBound)}</p>
        <p>Ready for independent signoff:
          {String(status.readyForExternalSignoff)}.
          External signoff granted: <strong>No</strong>.
          Phase closed: <strong>No</strong>.</p>
        <button type="button" onClick={() =>
          setShowAudit(x => !x)}>
          {showAudit ? "Hide" : "Show"} audit timeline
        </button>
        {showAudit && <ol>{status.audit.events.map(item =>
          <li key={item.id}>
            <strong>{item.action}</strong> · {item.occurredAt}
            <p>Actor: {item.actorUserId ?? "UNVERIFIED"}</p>
          </li>)}</ol>}
        <button type="button" onClick={() =>
          setShowManifest(x => !x)}>
          {showManifest ? "Hide" : "Show"} acceptance manifest
        </button>
        {showManifest && <p>Digest:
          <code>{status.manifest.digest}</code></p>}
        <button type="button" onClick={() =>
          save(status, `offline-operator-run-${selected.id}.json`)}>
          Export audit and explicitly unsigned manifest
        </button>
        <button type="button" onClick={() =>
          setShowHistory(x => !x)}>
          {showHistory ? "Hide" : "Show"} operational limitations
        </button>
        {showHistory && <ul>{status.warning.map(note =>
          <li key={note}>{note}</li>)}</ul>}
      </section>}
      <button type="button" onClick={() =>
        setShowLimitations(x => !x)}>
        {showLimitations ? "Hide" : "Show"} known limitations
      </button>
      {showLimitations && <ul>{selected.caveats.map(note =>
        <li key={note}>{note}</li>)}</ul>}
    </article>}
  </section>;
}
