"use client";

import { useCallback, useEffect, useState } from "react";

type ReleaseReview = {
  id: string;
  importId: string;
  inspectionId: string;
  state: string;
  revision: number;
  evidenceBundleDigest: string;
  inventoryDigest: string;
  inspectionDigest: string;
  acceptanceDigest: string;
  privacyDigest: string;
  scenarioDigest: string;
  operatorReason: string;
  operatorUserId: string;
  createdAt: string;
  updatedAt: string;
  decidedAt: string | null;
  decisionReason: string | null;
  operatorAcknowledgements: string[];
  exclusions: string[];
  acceptanceSnapshot: {
    acceptanceEligible?: boolean;
    gates?: Array<{ id: string; level: string; explanation: string }>;
    scorecard?: { blocked: number; advisory: number };
  };
  privacySnapshot: {
    readiness?: { blocked: number; reviewNeeded: number;
      eligibleForPrivacySignoff: boolean };
  };
  scenarioSummary: {
    verdict?: string; passed?: number;
    totalExecuted?: number; synthetic?: boolean;
  };
};
type ListResponse = {
  total: number;
  offset: number;
  limit: number;
  reviews: ReleaseReview[];
};
type Props = { slug: string; canManage: boolean };
const acknowledgements = [
  ["OFFLINE_ONLY", "This is not a LIVE OSV or external tenant validation."],
  ["SOURCE_LIMITATIONS", "CSV data and stored inspections have bounded provenance."],
  ["HUMAN_REVIEW", "A human decision is required; a green algorithm is not approval."],
  ["PRIVACY_AND_RETENTION", "I have reviewed privacy and retention obligations."],
  ["NO_VERIFIED_REMEDIATION", "Review work does not prove a patch or remediation."],
  ["BACKUPS_NOT_ERASED", "No backup erasure or legal signoff has been verified."],
] as const;
const operations: Array<[string, string]> = [
  ["START_REVIEW", "Begin independent review"],
  ["ACCEPT_OFFLINE", "Record offline acceptance"],
  ["REJECT", "Reject release"],
  ["REOPEN", "Reopen assessment"],
];
const defaultPolicy = "{}";
function parseJson(value: string, field: string): unknown {
  try { return JSON.parse(value) as unknown; }
  catch { throw new Error(field + " must contain valid JSON."); }
}
function readableError(value: unknown) {
  if (value instanceof Error) return value.message;
  return "The release review operation could not be completed.";
}
function saveJson(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)],
    { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
export function AssetReleaseReviewWorkspace({ slug, canManage }: Props) {
  const [reviews, setReviews] = useState<ReleaseReview[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [acceptancePolicy, setAcceptancePolicy] = useState(defaultPolicy);
  const [privacyPolicy, setPrivacyPolicy] = useState(defaultPolicy);
  const [reason, setReason] = useState("");
  const [exclusions, setExclusions] = useState(
    "LIVE OSV external provider not validated\nBackup erasure not verified");
  const [checked, setChecked] = useState<string[]>([]);
  const [operation, setOperation] = useState("START_REVIEW");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const selected = reviews.find(row => row.id === selectedId) ?? null;
  const endpoint = `/api/organizations/${encodeURIComponent(slug)}/assets/release-reviews`;
  const load = useCallback(async (nextOffset: number) => {
    if (!canManage) return;
    const response = await fetch(endpoint + `?offset=${nextOffset}&limit=20`,
      { cache: "no-store" });
    const payload = await response.json() as ListResponse & { error?: string };
    if (!response.ok)
      throw new Error(payload.error ?? "Could not load release reviews.");
    setReviews(payload.reviews);
    setTotal(payload.total);
    setOffset(nextOffset);
    setSelectedId(current =>
      payload.reviews.some(row => row.id === current) ? current : "");
  }, [endpoint, canManage]);
  useEffect(() => {
    if (!canManage) return;
    void load(0).catch(cause => setError(readableError(cause)));
  }, [canManage, load]);
  async function submit(kind: "create" | "transition") {
    if (!canManage || busy) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const common = {
        bindings: parseJson(bindings, "Package bindings"),
        acceptancePolicy: parseJson(acceptancePolicy, "Acceptance policy"),
        privacyPolicy: parseJson(privacyPolicy, "Privacy policy"),
        reason,
        acknowledgements: checked,
      };
      const request = kind === "create" ? {
        ...common, importId, inspectionId,
        exclusions: exclusions.split("\n").map(x => x.trim()).filter(Boolean),
      } : {
        ...common,
        reviewId: selected?.id,
        expectedRevision: selected?.revision,
        expectedEvidenceBundleDigest: selected?.evidenceBundleDigest,
        operation,
      };
      if (kind === "transition" && !selected)
        throw new Error("Select an existing review before making a decision.");
      const response = await fetch(endpoint, {
        method: kind === "create" ? "POST" : "PATCH",
        headers: { "Content-Type": "application/json" },
        cache: "no-store", body: JSON.stringify(request),
      });
      const result = await response.json() as {
        error?: string; replayed?: boolean; blockers?: string[];
        review?: ReleaseReview;
      };
      if (!response.ok)
        throw new Error(result.error ?? "Release review operation rejected.");
      setMessage(result.replayed
        ? "Existing matching review returned; no decision or duplicate audit recorded."
        : "Release review saved with transactional audit.");
      if (result.blockers?.length)
        setMessage(previous => previous + " Current blockers: " +
          result.blockers?.join(", "));
      await load(0);
      if (result.review)
        setSelectedId(result.review.id);
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setBusy(false);
    }
  }
  if (!canManage)
    return <section aria-label="Release review access">
      <h2>Manual offline release reviews</h2>
      <p>Only organization administrators can read or record release decisions.</p>
    </section>;
  return <section aria-label="Manual asset release review"
    style={{ marginBlock: "2rem" }}>
    <h2>Human offline release decision register</h2>
    <p>Stored CSV and OSV evidence, offline-only. A passing synthetic
      reference matrix does not approve a tenant or attest to live operation.
      No CyberScore, finding, provider quota or endpoint is changed here.</p>
    <form onSubmit={event => { event.preventDefault(); void submit("create"); }}>
      <fieldset disabled={busy}>
        <legend>Start a tenant-scoped evidence review</legend>
        <label>Inventory import ID
          <input value={importId} onChange={e => setImportId(e.target.value)}
            required maxLength={150} />
        </label>
        <label>Stored inspection ID
          <input value={inspectionId}
            onChange={e => setInspectionId(e.target.value)}
            required maxLength={150} />
        </label>
        <label>Exact package bindings (JSON array)
          <textarea value={bindings}
            onChange={e => setBindings(e.target.value)}
            rows={5} spellCheck={false} />
        </label>
        <label>Acceptance policy (JSON object)
          <textarea value={acceptancePolicy}
            onChange={e => setAcceptancePolicy(e.target.value)}
            rows={3} spellCheck={false} />
        </label>
        <label>Privacy policy (JSON object)
          <textarea value={privacyPolicy}
            onChange={e => setPrivacyPolicy(e.target.value)}
            rows={3} spellCheck={false} />
        </label>
        <label>Explicitly excluded or unverified matters, one per line
          <textarea value={exclusions}
            onChange={e => setExclusions(e.target.value)} rows={3} />
        </label>
        <label>Human rationale (20–1500 characters)
          <textarea value={reason} onChange={e => setReason(e.target.value)}
            minLength={20} maxLength={1500} required rows={4} />
        </label>
        <fieldset>
          <legend>Operator acknowledgements (not automatically checked)</legend>
          {acknowledgements.map(([id, description]) =>
            <label key={id} style={{ display: "block" }}>
              <input type="checkbox" checked={checked.includes(id)}
                onChange={event => setChecked(current =>
                  event.target.checked ? [...current, id] :
                    current.filter(item => item !== id))} />
              {description}
            </label>)}
        </fieldset>
        <button type="submit">Create pending review</button>
      </fieldset>
    </form>
    <h3>Existing reviews ({total})</h3>
    <p>Decisions use the selected revision and exact evidence bundle digest.
      If stored evidence changes, a fresh assessment is mandatory.</p>
    <button type="button" disabled={busy}
      onClick={() => void load(offset).catch(cause =>
        setError(readableError(cause)))}>Refresh register</button>
    <ul>
      {reviews.map(row =>
        <li key={row.id}>
          <button type="button" onClick={() => setSelectedId(row.id)}
            aria-pressed={selectedId === row.id}>
            {row.state} · {row.importId} · revision {row.revision}
          </button>
        </li>)}
    </ul>
    <div>
      <button type="button" disabled={busy || offset === 0}
        onClick={() => void load(Math.max(0, offset - 20)).catch(cause =>
          setError(readableError(cause)))}>Previous</button>
      <span> {offset + 1}–{Math.min(offset + 20, total)} of {total} </span>
      <button type="button" disabled={busy || offset + 20 >= total}
        onClick={() => void load(offset + 20).catch(cause =>
          setError(readableError(cause)))}>Next</button>
    </div>
    {selected && <section aria-label="Selected release review">
      <h3>Review {selected.id}</h3>
      <dl>
        <dt>State</dt><dd>{selected.state}</dd>
        <dt>Revision</dt><dd>{selected.revision}</dd>
        <dt>Bundle SHA-256 (local integrity only)</dt>
        <dd><code>{selected.evidenceBundleDigest}</code></dd>
        <dt>Inventory digest</dt><dd><code>{selected.inventoryDigest}</code></dd>
        <dt>Inspection digest</dt><dd><code>{selected.inspectionDigest}</code></dd>
        <dt>Acceptance digest</dt><dd><code>{selected.acceptanceDigest}</code></dd>
        <dt>Privacy digest</dt><dd><code>{selected.privacyDigest}</code></dd>
        <dt>Scenario digest</dt><dd><code>{selected.scenarioDigest}</code></dd>
        <dt>Human reason</dt><dd>{selected.operatorReason}</dd>
        <dt>Latest decision reason</dt>
        <dd>{selected.decisionReason ?? "No decision recorded"}</dd>
        <dt>Decision timestamp</dt>
        <dd>{selected.decidedAt ?? "Not decided"}</dd>
      </dl>
      <p>Offline acceptance eligible:
        {String(selected.acceptanceSnapshot?.acceptanceEligible ?? false)}</p>
      <p>Privacy blocks:
        {selected.privacySnapshot?.readiness?.blocked ?? "Unknown"};
        human reviews:
        {selected.privacySnapshot?.readiness?.reviewNeeded ?? "Unknown"}
      </p>
      <p>Synthetic reference:
        {selected.scenarioSummary?.verdict ?? "UNKNOWN"} —
        {selected.scenarioSummary?.passed ?? 0}/
        {selected.scenarioSummary?.totalExecuted ?? 0}</p>
      <ul>
        {(selected.acceptanceSnapshot?.gates ?? [])
          .filter(gate => gate.level !== "PASS")
          .map(gate => <li key={gate.id}>
            {gate.level} · {gate.id} — {gate.explanation}
          </li>)}
      </ul>
      <button type="button" onClick={() =>
        saveJson(selected, `asset-release-${selected.id}.json`)}>
        Export selected review JSON
      </button>
      <fieldset disabled={busy}>
        <legend>Manual state transition</legend>
        <label>Decision
          <select value={operation} onChange={e => setOperation(e.target.value)}>
            {operations.map(([id, label]) =>
              <option value={id} key={id}>{label}</option>)}
          </select>
        </label>
        <button type="button" onClick={() => void submit("transition")}>
          Record decision using current CAS revision
        </button>
      </fieldset>
    </section>}
    {message && <p role="status">{message}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
