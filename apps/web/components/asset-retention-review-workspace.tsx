"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Exception = {
  gateId: string;
  reason: string;
  owner: string;
  reviewBy: string;
  externalTicket: string | null;
};
type RetentionReview = {
  id: string;
  importId: string;
  state: string;
  revision: number;
  sourceDigest: string;
  privacyDigest: string;
  policyDigest: string;
  requestedByUserId: string;
  reviewedByUserId: string | null;
  initialReason: string;
  decisionReason: string | null;
  acknowledgements: string[];
  exceptions: Exception[];
  backupDisposition: string;
  personalDataDisposition: string;
  nextReviewAt: string | null;
  assessmentAt: string;
  decidedAt: string | null;
  verification: { valid: boolean; reasons: string[] };
  snapshot: {
    gates?: Array<{ id: string; severity: string;
      rationale: string; affectedImportIds: string[] }>;
    readiness?: { blocked: number; reviewNeeded: number };
  } | null;
  caveats: string[];
};
type GatePreview = {
  gateId: string;
  severity: string;
  rationale: string;
  status: string;
  addressedBy: Exception | null;
};
type Preview = {
  importId: string;
  privacyDigest: string;
  sourceDigest: string;
  gates: GatePreview[];
  permission: {
    eligible: boolean;
    unresolved: GatePreview[];
    missing: string[];
    exceptionExpired: boolean;
    futureFollowup: boolean;
  };
  privacyReadiness: {
    blocked: number; reviewNeeded: number;
  };
  caveats: string[];
};
type Props = { slug: string; canManage: boolean };
const acknowledgements = [
  ["DATA_MINIMIZATION_REVIEWED", "I reviewed data minimization and retention scope."],
  ["HOSTNAMES_MAY_BE_PERSONAL", "Hostnames may be personal data."],
  ["OWNER_HASH_NOT_ANONYMOUS", "Owner hashes are pseudonymous, not necessarily anonymous."],
  ["HISTORIC_EVIDENCE_RETAINED", "Historic inspections, cases and audit history need handling."],
  ["BACKUPS_NOT_ERASED", "No deletion of backup or exported copies is verified."],
  ["LEGAL_APPROVAL_NOT_INFERRED", "This decision is not independent legal approval."],
  ["CROSS_SYSTEM_EXPORTS_UNVERIFIED", "External copies and transfers are not verified."],
] as const;
const decisions: Array<[string, string]> = [
  ["START_REVIEW", "Begin manual review"],
  ["DOCUMENT_EXCEPTIONS", "Record bounded exceptions, not approval"],
  ["REJECT", "Reject this retention assessment"],
  ["REOPEN", "Reopen documented or rejected review"],
];
function errorText(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Retention review request could not be completed.";
}
function toIso(value: string) {
  if (!value) return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()))
    throw new Error("Review dates must be valid.");
  return date.toISOString();
}
function download(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)],
    { type: "application/json" });
  const address = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = address;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(address);
}
export function AssetRetentionReviewWorkspace({ slug, canManage }: Props) {
  const endpoint =
    `/api/organizations/${encodeURIComponent(slug)}/assets/retention-reviews`;
  const [records, setRecords] = useState<RetentionReview[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [importId, setImportId] = useState("");
  const [policy, setPolicy] = useState("{}");
  const [reason, setReason] = useState("");
  const [selectedAcknowledgements, setSelectedAcknowledgements] =
    useState<string[]>([]);
  const [exceptionsText, setExceptionsText] = useState("[]");
  const [backupDisposition, setBackupDisposition] = useState("UNVERIFIED");
  const [personalDisposition, setPersonalDisposition] =
    useState("REQUIRES_REVIEW");
  const [nextReviewAt, setNextReviewAt] = useState("");
  const [operation, setOperation] = useState("START_REVIEW");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [showDetails, setShowDetails] = useState(true);
  const [showExceptions, setShowExceptions] = useState(true);
  const [showGates, setShowGates] = useState(true);
  const [onlyProblems, setOnlyProblems] = useState(true);
  const selected = useMemo(() =>
    records.find(item => item.id === selectedId) ?? null,
    [records, selectedId]);
  const load = useCallback(async (page: number) => {
    if (!canManage) return;
    const response = await fetch(
      endpoint + `?limit=20&offset=${page}`,
      { cache: "no-store" });
    const body = await response.json() as {
      total?: number; reviews?: RetentionReview[]; error?: string;
    };
    if (!response.ok)
      throw new Error(body.error ?? "Could not list retention reviews.");
    setRecords(body.reviews ?? []);
    setTotal(body.total ?? 0);
    setOffset(page);
    setSelectedId(current => (body.reviews ?? []).some(
      row => row.id === current) ? current : "");
  }, [endpoint, canManage]);
  useEffect(() => {
    if (canManage) void load(0).catch(cause => setError(errorText(cause)));
  }, [canManage, load]);
  function command() {
    let parsed: unknown;
    let retentionPolicy: unknown;
    try { parsed = JSON.parse(exceptionsText); }
    catch { throw new Error("Exception register must be a JSON array."); }
    try { retentionPolicy = JSON.parse(policy); }
    catch { throw new Error("Retention policy must be valid JSON."); }
    return {
      importId, policy: retentionPolicy,
      reason, exceptions: parsed,
      acknowledgements: selectedAcknowledgements,
      backupDisposition,
      personalDataDisposition: personalDisposition,
      nextReviewAt: toIso(nextReviewAt),
    };
  }
  async function submit(method: "POST" | "PATCH" | "PUT") {
    if (busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const common = command();
      const payload = method === "PATCH" ? {
        ...common,
        reviewId: selected?.id,
        expectedRevision: selected?.revision,
        expectedPrivacyDigest: selected?.privacyDigest,
        operation,
      } : common;
      if (method === "PATCH" && !selected)
        throw new Error("Select an existing record before changing its state.");
      const response = await fetch(endpoint, {
        method, cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json() as {
        error?: string; replayed?: boolean;
        review?: RetentionReview; gates?: GatePreview[];
        permission?: Preview["permission"];
      };
      if (!response.ok)
        throw new Error(result.error ?? "Retention operation rejected.");
      if (method === "PUT") {
        setPreview(result as Preview);
        setMessage("Read-only assessment completed; no human decision recorded.");
      } else {
        setMessage(result.replayed
          ? "Existing review returned without another audit entry."
          : "Human retention state and transaction audit saved.");
        setPreview(null);
        await load(0);
        if (result.review)
          setSelectedId(result.review.id);
      }
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }
  const visibleGates = useMemo(() => selected?.snapshot?.gates?.filter(
    gate => !onlyProblems || gate.severity !== "PASS") ?? [],
    [selected, onlyProblems]);
  if (!canManage) return <section aria-label="Retention review access">
    <h2>Administrative privacy and retention register</h2>
    <p>Only organization administrators can inspect or document this process.</p>
  </section>;
  return <section aria-label="Human privacy and retention review"
    style={{ marginBlock: "2rem" }}>
    <h2>Privacy and retention exception register</h2>
    <p>Record explicit human investigation, accountable exceptions and review
      dates for a declared inventory. Even a documented review does not
      establish legal approval, verified erasure or provider availability.</p>
    <form onSubmit={event => { event.preventDefault(); void submit("POST"); }}>
      <fieldset disabled={busy}>
        <legend>Selected tenant inventory</legend>
        <label>Exact inventory import ID
          <input value={importId} required maxLength={150}
            onChange={event => setImportId(event.target.value)} />
        </label>
        <label>Privacy policy (JSON)
          <textarea spellCheck={false} rows={4} value={policy}
            onChange={event => setPolicy(event.target.value)} />
        </label>
        <label>Human explanation (20–1500 characters)
          <textarea required minLength={20} maxLength={1500}
            rows={3} value={reason}
            onChange={event => setReason(event.target.value)} />
        </label>
        <fieldset>
          <legend>Explicit human acknowledgements</legend>
          {acknowledgements.map(([id, description]) =>
            <label key={id} style={{ display: "block" }}>
              <input type="checkbox" checked={
                selectedAcknowledgements.includes(id)}
                onChange={event => setSelectedAcknowledgements(items =>
                  event.target.checked
                    ? [...items, id]
                    : items.filter(item => item !== id))} />
              {description}
            </label>)}
        </fieldset>
        <label>Backup disposition
          <select value={backupDisposition}
            onChange={event => setBackupDisposition(event.target.value)}>
            <option value="UNVERIFIED">Unverified</option>
            <option value="PROCEDURE_DOCUMENTED">Procedure documented, erasure not verified</option>
            <option value="REQUIRES_EXTERNAL_VERIFICATION">Requires external confirmation</option>
          </select>
        </label>
        <label>Personal data disposition
          <select value={personalDisposition}
            onChange={event => setPersonalDisposition(event.target.value)}>
            <option value="REQUIRES_REVIEW">Requires review</option>
            <option value="RETENTION_DOCUMENTED">Retention documented, not legally approved</option>
            <option value="EXTERNAL_APPROVAL_REQUIRED">External responsible-party approval required</option>
          </select>
        </label>
        <label>Next mandatory human review (date/time)
          <input type="datetime-local" value={nextReviewAt}
            onChange={event => setNextReviewAt(event.target.value)} />
        </label>
        <label>Per-gate exceptions with owner, reason, ISO reviewBy and ticket (JSON)
          <textarea spellCheck={false} rows={7}
            value={exceptionsText}
            onChange={event => setExceptionsText(event.target.value)} />
        </label>
        <p>Example exception: gateId, reason, owner, reviewBy and
          optional externalTicket. Every active gate requires its own entry
          before a bounded exception can be documented.</p>
        <button type="button" onClick={() => void submit("PUT")}>
          Preview current evidence and unresolved gates
        </button>
        <button type="submit">Create pending human review</button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {preview && <section aria-label="Retention gate preview">
      <h3>Read-only preview · {preview.importId}</h3>
      <p>Eligible to document exceptions:
        {preview.permission.eligible ? "Yes" : "No"}</p>
      <p>Open privacy gates:
        {preview.privacyReadiness.blocked} blocking,
        {preview.privacyReadiness.reviewNeeded} requiring review.</p>
      <p>Missing acknowledgements:
        {preview.permission.missing.join(", ") || "None"}</p>
      <p>Unresolved gates:
        {preview.permission.unresolved.map(g => g.gateId)
          .join(", ") || "None"}</p>
      <ul>{preview.gates.map(item => <li key={item.gateId}>
        <strong>{item.severity} · {item.gateId}</strong>
        <p>{item.status} · {item.rationale}</p>
        {item.addressedBy && <p>Owner {item.addressedBy.owner} ·
          next review {item.addressedBy.reviewBy}</p>}
      </li>)}</ul>
    </section>}
    <h3>Recorded reviews ({total})</h3>
    <button type="button" disabled={busy}
      onClick={() => void load(offset).catch(cause =>
        setError(errorText(cause)))}>Refresh register</button>
    <ul>{records.map(row => <li key={row.id}>
      <button type="button" onClick={() => {
        setSelectedId(row.id);
        setImportId(row.importId);
      }} aria-pressed={selectedId === row.id}>
        {row.state} · {row.importId} · revision {row.revision}
      </button>
    </li>)}</ul>
    <button type="button" disabled={busy || offset === 0}
      onClick={() => void load(Math.max(0, offset - 20)).catch(cause =>
        setError(errorText(cause)))}>Previous</button>
    <span> {Math.min(offset + 1, total)}–{Math.min(offset + 20, total)} of {total} </span>
    <button type="button" disabled={busy || offset + 20 >= total}
      onClick={() => void load(offset + 20).catch(cause =>
        setError(errorText(cause)))}>Next</button>
    {selected && <section aria-label="Selected retention review">
      <h3>Selected review: {selected.state}</h3>
      <button type="button" onClick={() =>
        setShowDetails(value => !value)}>
        {showDetails ? "Hide" : "Show"} review provenance
      </button>
      {showDetails && <dl>
        <dt>CAS revision</dt><dd>{selected.revision}</dd>
        <dt>Import digest</dt><dd><code>{selected.sourceDigest}</code></dd>
        <dt>Privacy report digest</dt><dd><code>{selected.privacyDigest}</code></dd>
        <dt>Policy digest</dt><dd><code>{selected.policyDigest}</code></dd>
        <dt>Initial operator</dt><dd>{selected.requestedByUserId}</dd>
        <dt>Last reviewer</dt><dd>{selected.reviewedByUserId ?? "Not decided"}</dd>
        <dt>Reason</dt><dd>{selected.decisionReason ??
          selected.initialReason}</dd>
        <dt>Next review</dt><dd>{selected.nextReviewAt ?? "Unscheduled"}</dd>
        <dt>Backup</dt><dd>{selected.backupDisposition}</dd>
        <dt>Personal data</dt><dd>{selected.personalDataDisposition}</dd>
        <dt>Independent verification</dt>
        <dd>{selected.verification.valid ? "Consistent" :
          selected.verification.reasons.join("; ")}</dd>
      </dl>}
      <button type="button" onClick={() => setShowExceptions(x => !x)}>
        {showExceptions ? "Hide" : "Show"} tracked exceptions
      </button>
      {showExceptions && <ul>{selected.exceptions.map(item =>
        <li key={item.gateId}>
          <strong>{item.gateId}</strong>
          <p>{item.reason}</p>
          <p>Owner: {item.owner}; review by {item.reviewBy}</p>
          <p>Ticket: {item.externalTicket ?? "None supplied"}</p>
        </li>)}</ul>}
      <button type="button" onClick={() => setShowGates(x => !x)}>
        {showGates ? "Hide" : "Show"} privacy source gates
      </button>
      {showGates && <section>
        <label><input type="checkbox" checked={onlyProblems}
          onChange={event => setOnlyProblems(event.target.checked)} />
          Show outstanding only</label>
        <ul>{visibleGates.map(item => <li key={item.id}>
          <strong>{item.severity} · {item.id}</strong>
          <p>{item.rationale}</p>
        </li>)}</ul>
      </section>}
      <button type="button" onClick={() =>
        download(selected, `retention-review-${selected.id}.json`)}>
        Export bounded review JSON
      </button>
      <fieldset disabled={busy}>
        <legend>Record a human CAS transition</legend>
        <label>Operation
          <select value={operation}
            onChange={event => setOperation(event.target.value)}>
            {decisions.map(([key, label]) =>
              <option key={key} value={key}>{label}</option>)}
          </select>
        </label>
        <p>Use the form above to update reason, exceptions, policy and
          acknowledgements. The selected revision and privacy digest
          are checked again on the server.</p>
        <button type="button" onClick={() => void submit("PATCH")}>
          Submit explicit human decision
        </button>
      </fieldset>
      <ul>{selected.caveats.map(note =>
        <li key={note}>{note}</li>)}</ul>
    </section>}
  </section>;
}
