"use client";

import { useMemo, useState } from "react";

type Category =
  "REVIEW_POSSIBLE_ADVISORY" | "REVIEW_PROVIDER_UNCERTAINTY" |
  "REVIEW_SOURCE_INTEGRITY" | "REVIEW_MISSING_MAPPING" |
  "REVIEW_UNKNOWN_VERSION" | "REVIEW_STALE_OBSERVATION" |
  "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION";
type GuidanceAction = {
  code: string; title: string; instruction: string;
  requiresHumanReview: true;
};
type Advice = {
  id: string;
  assetId: string; product: string; version: string | null;
  sourceRow: number; observedAt: string;
  ecosystem: string | null; packageName: string | null;
  status: Category; priority: "URGENT_REVIEW" | "NORMAL_REVIEW" | "INFORMATION";
  confidence: string;
  possibleIds: string[]; providerOnlyIds: string[];
  unresolvedIds: string[]; withdrawnIds: string[];
  reasons: string[]; actions: GuidanceAction[];
  providerStatus: string | null; inspectionStatus: string;
  evidenceFingerprint: string;
  notRemediationProof: true;
};
type Result = {
  schema: string;
  organizationId: string;
  importId: string; inspectionId: string;
  evaluatedAt: string; inventoryDigest: string;
  inspectionDigest: string; totalRows: number;
  offset: number; limit: number; hasMore: boolean;
  rows: Advice[];
  summary: {
    examined: number; possible: number;
    providerUncertain: number; sourceIntegrity: number;
    missingMappings: number; unknownVersions: number;
    staleObservations: number; scopedNoPositiveMatch: number;
    urgentReviews: number; normalReviews: number;
    informative: number; complete: boolean;
  };
  reportDigest: string;
  isReadOnly: true; changesCommitted: false; providerQueried: false;
  implications: string[];
  verification: {
    valid: boolean; counted: number; possibleOnPage: number;
    missingEvidence: number; unacceptableClaims: number;
    reasons: string[];
  };
};
const statuses: Category[] = [
  "REVIEW_POSSIBLE_ADVISORY",
  "REVIEW_PROVIDER_UNCERTAINTY",
  "REVIEW_SOURCE_INTEGRITY",
  "REVIEW_MISSING_MAPPING",
  "REVIEW_UNKNOWN_VERSION",
  "REVIEW_STALE_OBSERVATION",
  "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION",
];
function message(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Unable to prepare asset action guidance.";
}
function date(iso: string) {
  const item = new Date(iso);
  return Number.isFinite(item.getTime()) ?
    item.toLocaleString() : "Invalid observation date";
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    padding: 10, border: "1px solid #8885", borderRadius: 8,
  }}>
    <strong>{value}</strong><p>{label}</p>
  </div>;
}
function GuidanceCard({ row, busy, canManage, onOpen }: {
  row: Advice; busy: boolean; canManage: boolean;
  onOpen: (row: Advice, reason: string) => Promise<void>;
}) {
  const [showEvidence, setShowEvidence] = useState(false);
  const [openingReason, setOpeningReason] = useState("");
  return <article style={{
    border: "1px solid #8885", borderRadius: 9,
    padding: 14, marginBlock: 10,
  }}>
    <h4>{row.product || "Unknown software"} · {row.assetId}</h4>
    <p>
      <strong>{row.priority}</strong> · {row.status}
      {" "}· Version {row.version ?? "not declared"}
    </p>
    <p>Inventory row {row.sourceRow}.
      Observed {date(row.observedAt)}.
      Provider query: {row.providerStatus ?? "not matched"}.</p>
    <p>Mapping: {row.ecosystem ?? "not mapped"} /
      {" "}{row.packageName ?? "not mapped"}.
      Confidence: {row.confidence}.</p>
    {row.possibleIds.length > 0 &&
      <div><strong>Candidate advisories for human review</strong>
        <ul>{row.possibleIds.map(id =>
          <li key={id}><code>{id}</code></li>)}</ul>
      </div>}
    {(row.providerOnlyIds.length > 0 ||
      row.unresolvedIds.length > 0 ||
      row.withdrawnIds.length > 0) && <details>
      <summary>Unresolved, provider-only and withdrawn advisories</summary>
      <p>Provider-only: {row.providerOnlyIds.join(", ") || "none"}.</p>
      <p>Unresolved: {row.unresolvedIds.join(", ") || "none"}.</p>
      <p>Withdrawn: {row.withdrawnIds.join(", ") || "none"}.</p>
    </details>}
    <p><strong>Why this review was proposed</strong></p>
    <ul>{row.reasons.map((reason, i) =>
      <li key={i}>{reason}</li>)}</ul>
    <details>
      <summary>{row.actions.length} suggested human actions</summary>
      <ol>{row.actions.map(action =>
        <li key={action.code}>
          <strong>{action.title}</strong>
          <p>{action.instruction}</p>
          <p>Human verification required: Yes.</p>
        </li>)}</ol>
    </details>
    <button type="button"
      onClick={() => setShowEvidence(value => !value)}>
      {showEvidence ? "Hide" : "Show"} source fingerprint
    </button>
    {showEvidence && <p style={{ overflowWrap: "anywhere" }}>
      <code>{row.evidenceFingerprint}</code>
    </p>}
    {canManage && row.priority !== "INFORMATION" &&
      <fieldset disabled={busy} style={{
        border: "1px solid #8885", borderRadius: 8, padding: 10,
      }}>
        <legend>Open a human review directly from this evidence</legend>
        <label>Why does this candidate require investigation?
          <textarea rows={3} maxLength={1000} value={openingReason}
            onChange={event => setOpeningReason(event.target.value)}
            placeholder="Describe the observed evidence and authorized investigation"/>
        </label>
        <button type="button" disabled={busy ||
          openingReason.trim().length < 20}
          onClick={() => void onOpen(row, openingReason)}>
          Open audited review case
        </button>
        <p>Server recomputes the exact candidate fingerprint before
          creating any work. A review is not a verified finding.</p>
      </fieldset>}
    <p><small>
      Candidate review only. Not a confirmed exploit, verified
      vulnerability, remediated endpoint or safety assessment.
    </small></p>
  </article>;
}
export function AssetActionGuidanceWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const api = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/action-guidance";
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [onlyReviewable, setOnlyReviewable] = useState(true);
  const [ageDays, setAgeDays] = useState(30);
  const [status, setStatus] = useState<Category | "ALL">("ALL");
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [opened, setOpened] = useState<string | null>(null);
  const filters = useMemo(() => ({
    onlyReviewable, status, ageDays, pageSize,
  }), [onlyReviewable, status, ageDays, pageSize]);
  async function inspect(nextOffset = offset) {
    if (busy) return;
    let mappings: unknown;
    try {
      mappings = JSON.parse(bindings);
      if (!Array.isArray(mappings))
        throw new Error("Bindings must be a JSON array.");
    } catch (cause) {
      setError("Invalid package mapping JSON: " + message(cause));
      return;
    }
    if (!importId.trim() || !inspectionId.trim()) {
      setError("Choose an inventory import and a stored inspection ID.");
      return;
    }
    setBusy(true); setError(null); setCopied(false);
    try {
      const response = await fetch(api, {
        method: "POST", cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json", "Content-Type": "application/json",
        },
        body: JSON.stringify({
          importId: importId.trim(),
          inspectionId: inspectionId.trim(),
          bindings: mappings, offset: nextOffset, limit: filters.pageSize,
          onlyReviewable: filters.onlyReviewable,
          status: filters.status === "ALL" ? null : filters.status,
          maxObservationAgeDays: filters.ageDays,
        }),
      });
      const data: unknown = await response.json();
      if (!response.ok)
        throw new Error((data as { error?: string }).error ??
          "Guidance HTTP " + response.status);
      const report = data as Result;
      if (!report.verification?.valid)
        throw new Error("Evidence consistency verification did not pass.");
      setResult(report); setOffset(nextOffset);
    } catch (cause) {
      setResult(null); setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  function resetPage() {
    setOffset(0); setResult(null); setError(null);
  }
  async function openFromEvidence(row: Advice, reason: string) {
    if (!canManage || busy || !result) return;
    let mappings: unknown;
    try {
      mappings = JSON.parse(bindings);
      if (!Array.isArray(mappings))
        throw new Error("Mappings must be a JSON array.");
    } catch (cause) {
      setError(message(cause)); return;
    }
    setBusy(true); setOpened(null); setError(null);
    try {
      const response = await fetch("/api/organizations/" +
        encodeURIComponent(slug) + "/assets/action-cases", {
        method: "POST", cache: "no-store", credentials: "same-origin",
        headers: {
          Accept: "application/json", "Content-Type": "application/json",
        },
        body: JSON.stringify({
          importId: result.importId, inspectionId: result.inspectionId,
          evidenceFingerprint: row.evidenceFingerprint,
          bindings: mappings, reason,
        }),
      });
      const resultBody: unknown = await response.json();
      if (!response.ok) throw new Error(
        (resultBody as { error?: string }).error ??
        "Unable to open evidence-backed review case.");
      const created = resultBody as {
        replayed: boolean; case: { id: string };
      };
      setOpened((created.replayed ? "Existing" : "New") +
        " audited review case " + created.case.id +
        " is available in the case register below.");
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }
  function copyReport() {
    if (!result) return;
    const summary = JSON.stringify({
      schema: result.schema,
      importId: result.importId,
      inspectionId: result.inspectionId,
      inventoryDigest: result.inventoryDigest,
      inspectionDigest: result.inspectionDigest,
      evaluatedAt: result.evaluatedAt,
      summary: result.summary,
      reportDigest: result.reportDigest,
      rows: result.rows,
      implications: result.implications,
    }, null, 2);
    void navigator.clipboard.writeText(summary).then(() =>
      setCopied(true)).catch(cause => setError(message(cause)));
  }
  return <section aria-label="Asset evidence guided reviews" style={{
    border: "1px solid #8885", borderRadius: 12,
    padding: 16, marginBlock: 22,
  }}>
    <h2>Asset evidence → guided actions</h2>
    <p>Connect a declared inventory to a saved OSV inspection
      with explicit product-to-package bindings. Candidate advisories
      are only proposals for human investigation.
      This workspace does not create security findings, update
      CyberScore or contact external providers.</p>
    {error && <p role="alert">{error}</p>}
    <fieldset disabled={busy}>
      <legend>Evidence selection and package mapping</legend>
      <label>Committed inventory import ID
        <input value={importId} maxLength={150}
          onChange={event => { setImportId(event.target.value); resetPage(); }}
          placeholder="Paste saved import ID"/>
      </label>
      <label>Stored OSV inspection ID
        <input value={inspectionId} maxLength={150}
          onChange={event => { setInspectionId(event.target.value); resetPage(); }}
          placeholder="Paste inspection ID from history"/>
      </label>
      <label>Verified product-to-package bindings (JSON array)
        <textarea rows={5} value={bindings} maxLength={60000}
          onChange={event => { setBindings(event.target.value); resetPage(); }}
          spellCheck={false}/>
      </label>
      <details>
        <summary>Example mapping — fictional software</summary>
        <pre style={{ overflowWrap: "anywhere", whiteSpace: "pre-wrap" }}>
          {JSON.stringify([{
            inventoryProduct: "Example Package",
            ecosystem: "npm",
            packageName: "example-package",
            expectedPurl: null,
          }], null, 2)}
        </pre>
        <p>This example does not identify a real installed package
          or authorize any OSV.dev request.</p>
      </details>
      <div style={{
        display: "flex", flexWrap: "wrap", gap: 12, marginBlock: 10,
      }}>
        <label>Category
          <select value={status}
            onChange={event => {
              setStatus(event.target.value as Category | "ALL");
              resetPage();
            }}>
            <option value="ALL">All categories</option>
            {statuses.map(code =>
              <option value={code} key={code}>{code}</option>)}
          </select>
        </label>
        <label>Inventory freshness threshold
          <select value={ageDays} onChange={event => {
            setAgeDays(Number(event.target.value)); resetPage();
          }}>
            {[7, 14, 30, 60, 90, 180, 365].map(value =>
              <option key={value} value={value}>{value} days</option>)}
          </select>
        </label>
        <label>Page size
          <select value={pageSize} onChange={event => {
            setPageSize(Number(event.target.value)); resetPage();
          }}>
            {[10, 20, 50, 100].map(value =>
              <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={onlyReviewable}
          onChange={event => {
            setOnlyReviewable(event.target.checked); resetPage();
          }}/>
        Show only cases requiring human investigation
      </label>
      <button type="button" onClick={() => void inspect(0)}>
        {busy ? "Evaluating stored evidence…" : "Prepare action guidance"}
      </button>
    </fieldset>
    {opened && <p role="status">{opened}</p>}
    {result && <section>
      <h3>Evidence-backed review summary</h3>
      <p>Source snapshot {result.importId}.
        Saved OSV inspection {result.inspectionId}.
        Evaluated {date(result.evaluatedAt)}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Metric label="Inventory records examined"
          value={result.summary.examined}/>
        <Metric label="Candidate advisory reviews"
          value={result.summary.possible}/>
        <Metric label="Incomplete provider evidence"
          value={result.summary.providerUncertain}/>
        <Metric label="Products awaiting mapping"
          value={result.summary.missingMappings}/>
        <Metric label="Unknown versions"
          value={result.summary.unknownVersions}/>
        <Metric label="Stale observations"
          value={result.summary.staleObservations}/>
        <Metric label="No positive ID in scoped inspection"
          value={result.summary.scopedNoPositiveMatch}/>
        <Metric label="Urgent reviews"
          value={result.summary.urgentReviews}/>
      </div>
      <p>Evidence verification: <strong>
        {result.verification.valid ? "PASS" : "NOT VERIFIED"}
      </strong>. Page {result.offset + 1}–{
        result.offset + result.rows.length} of {
        result.totalRows} matching rows.
        Stored evidence is read-only.</p>
      {result.rows.map(row =>
        <GuidanceCard key={row.id} row={row}
          busy={busy} canManage={canManage}
          onOpen={openFromEvidence}/>)}
      {result.rows.length === 0 &&
        <p>No cases match these filters in the bounded inspection.
          This is not a statement that the inventory is safe.</p>}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button type="button" disabled={busy || offset === 0}
          onClick={() => void inspect(Math.max(0, offset - pageSize))}>
          Previous
        </button>
        <button type="button" disabled={busy || !result.hasMore}
          onClick={() => void inspect(offset + pageSize)}>
          Next
        </button>
        <button type="button" onClick={copyReport}>Copy evidence page JSON</button>
      </div>
      {copied && <p role="status">Copied current evidence page.</p>}
      <button type="button" onClick={() =>
        setExpanded(value => !value)}>
        {expanded ? "Hide" : "Show"} provenance and limitations
      </button>
      {expanded && <div>
        <p>Inventory SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {result.inventoryDigest}</code></p>
        <p>Inspection SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {result.inspectionDigest}</code></p>
        <p>Report SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {result.reportDigest}</code></p>
        <ul>{result.implications.map((line, i) =>
          <li key={i}>{line}</li>)}</ul>
      </div>}
    </section>}
    <p>{canManage ?
      "Review work may later be recorded through an independently audited workflow." :
      "You have read-only access; no administrative action is available."}
    </p>
  </section>;
}
