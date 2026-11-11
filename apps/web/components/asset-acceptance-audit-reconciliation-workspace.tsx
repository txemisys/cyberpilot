"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Issue = {
  code: string;
  severity: "BLOCK" | "REVIEW";
  entity: string;
  resourceId: string | null;
  auditId: string | null;
  revision: number | null;
  detail: string;
  nextAction: string;
};
type Event = {
  id: string;
  resourceType: string;
  resourceId: string | null;
  organizationId: string;
  action: string;
  operation: string;
  createdAt: string;
  actorUserId: string | null;
  revisionBefore: number | null;
  revisionAfter: number | null;
  sourceDigest: string | null;
  dossierDigest: string | null;
  stepCode: string | null;
  evidenceId: string | null;
  from: string | null;
  to: string | null;
  issues: Issue[];
};
type Review = {
  id: string;
  stepCode: string;
  state: string;
  revision: number;
  sourceRunRevision: number;
  reviewerUserId: string;
  originalOperatorUserId: string;
  currentReferenceMatches: boolean;
  independentlyReviewed: boolean;
  auditEvents: number;
  issueCodes: string[];
};
type Reconciliation = {
  schema: string;
  organizationId: string;
  runId: string;
  checkedAt: string;
  state: string;
  revision: number;
  sourceDigest: string;
  dossierDigest: string;
  totalRunEvents: number;
  totalReviewEvents: number;
  runAuditComplete: boolean;
  reviewAuditComplete: boolean;
  runStateConsistent: boolean;
  reviewReferencesCurrent: boolean;
  evidenceReviewsComplete: boolean;
  evidenceIndependenceComplete: boolean;
  independentlyReviewedSteps: number;
  recordedSteps: number;
  reviewCount: number;
  events: Event[];
  reviews: Review[];
  issues: Issue[];
  blockers: number;
  warnings: number;
  localAuditIntegrityVerified: boolean;
  readyForIndependentHumanDecision: boolean;
  externallySigned: false;
  legallyApproved: false;
  backupsErased: false;
  providerLiveChecked: false;
  phaseClosed: false;
  mergeAuthorized: false;
  digest: string;
  limitations: string[];
};
type ResponseBody = {
  report: Reconciliation;
  verification: { valid: boolean; issues: string[] };
  manifest: {
    reportDigest: string;
    outstandingCodes: string[];
    auditIntegrity: boolean;
    externalSignatureVerified: false;
  };
  playbook: Array<{
    order: number;
    code: string;
    severity: string;
    entity: string;
    resourceId: string | null;
    action: string;
    noAutomaticRepair: true;
  }>;
};
type RunOption = {
  id: string;
  state: string;
  revision: number;
  importId: string;
  inspectionId: string;
};
type Props = { slug: string; canManage: boolean };
function describeError(value: unknown) {
  return value instanceof Error ? value.message :
    "The independent audit reconciliation could not be completed.";
}
function exportJson(value: unknown, file: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)],
    { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
function truncate(value: string | null, length = 25) {
  if (value === null) return "—";
  return value.length > length ? value.slice(0, 12) + "…" +
    value.slice(-9) : value;
}
function statusColor(value: boolean) {
  return value ? "#16804c" : "#a42b2b";
}
export function AssetAcceptanceAuditReconciliationWorkspace({
  slug, canManage,
}: Props) {
  const prefix = `/api/organizations/${encodeURIComponent(slug)}/assets`;
  const [runId, setRunId] = useState("");
  const [knownRuns, setKnownRuns] = useState<RunOption[]>([]);
  const [maxRunEvents, setMaxRunEvents] = useState(250);
  const [maxReviewEvents, setMaxReviewEvents] = useState(250);
  const [includeEventDetails, setIncludeEventDetails] = useState(false);
  const [report, setReport] = useState<ResponseBody | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [issueFilter, setIssueFilter] = useState("ALL");
  const [eventFilter, setEventFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [showEvents, setShowEvents] = useState(true);
  const [showReviews, setShowReviews] = useState(true);
  const [showIssues, setShowIssues] = useState(true);
  const [showPlan, setShowPlan] = useState(true);
  const [showManifest, setShowManifest] = useState(false);
  const [showCaveats, setShowCaveats] = useState(false);
  const value = report?.report ?? null;
  const refresh = useCallback(async () => {
    if (!canManage) return;
    const response = await fetch(prefix +
      "/offline-acceptance-runs?limit=100&offset=0", {
        cache: "no-store",
      });
    const payload = await response.json() as {
      runs?: RunOption[]; error?: string;
    };
    if (!response.ok)
      throw new Error(payload.error ?? "Cannot list the operator runs.");
    setKnownRuns(payload.runs ?? []);
    setRunId(current => current || payload.runs?.[0]?.id || "");
  }, [prefix, canManage]);
  useEffect(() => {
    void refresh().catch(cause => setError(describeError(cause)));
  }, [refresh]);
  useEffect(() => {
    setReport(null);
    setNotice("");
  }, [runId]);
  const filteredIssues = useMemo(() => value?.issues.filter(item =>
    (issueFilter === "ALL" || item.severity === issueFilter ||
      item.entity === issueFilter) &&
    (!search.trim() ||
      [item.code, item.detail, item.nextAction,
        item.resourceId ?? ""].join(" ").toLowerCase()
        .includes(search.trim().toLowerCase()))) ?? [],
    [value, issueFilter, search]);
  const filteredEvents = useMemo(() => value?.events.filter(item =>
    eventFilter === "ALL" || item.resourceType === eventFilter) ?? [],
    [value, eventFilter]);
  async function inspect() {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    setReport(null);
    try {
      const response = await fetch(prefix +
        "/acceptance-audit-reconciliation", {
          method: "POST", cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            runId,
            maximumRunEvents: maxRunEvents,
            maximumReviewEvents: maxReviewEvents,
            includeEventDetails,
          }),
        });
      const result = await response.json() as ResponseBody & {
        error?: string;
      };
      if (!response.ok)
        throw new Error(result.error ?? "Audit reconciliation rejected.");
      if (!result.verification?.valid)
        throw new Error("The returned reconciliation failed its digest verification.");
      setReport(result);
      setNotice("Full bounded local audit inspection completed without changes.");
    } catch (cause) {
      setError(describeError(cause));
    } finally { setBusy(false); }
  }
  if (!canManage) return <section aria-label="Acceptance audit review">
    <h2>Acceptance audit reconciliation</h2>
    <p>Only organization administrators may reconstruct and export this history.</p>
  </section>;
  return <section aria-label="Operator and reviewer audit reconciliation"
    style={{ marginBlock: "2rem" }}>
    <h2>Independent acceptance audit reconciliation</h2>
    <p>Reconstruct every CAS transition from operator and reviewer
      audit events. An absent, repeated, cross-tenant or altered revision
      is reported as a blocker, not silently repaired. Local hash checks
      never constitute external legal, LIVE or human signoff.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <fieldset disabled={busy}>
        <legend>Exact tenant-scoped operator run</legend>
        <label>Run ID
          <input value={runId} required minLength={5} maxLength={150}
            onChange={event => setRunId(event.target.value)} />
        </label>
        {knownRuns.length > 0 && <label>Choose recent run
          <select value={knownRuns.some(x => x.id === runId)
            ? runId : ""}
            onChange={event => setRunId(event.target.value)}>
            {!knownRuns.some(x => x.id === runId) &&
              <option value="">Custom run ID</option>}
            {knownRuns.map(item =>
              <option value={item.id} key={item.id}>
                {item.state} · revision {item.revision} · {item.importId}
              </option>)}
          </select>
        </label>}
        <label>Maximum operator events
          <input type="number" min={1} max={1000}
            value={maxRunEvents} onChange={event =>
              setMaxRunEvents(Number(event.target.value))} />
        </label>
        <label>Maximum reviewer events
          <input type="number" min={1} max={1000}
            value={maxReviewEvents} onChange={event =>
              setMaxReviewEvents(Number(event.target.value))} />
        </label>
        <label><input type="checkbox" checked={includeEventDetails}
          onChange={event => setIncludeEventDetails(event.target.checked)} />
          Include detailed internal audit event diagnostics
        </label>
        <button type="submit">Reconcile both audit chains</button>
        <button type="button" onClick={() => void refresh()
          .catch(cause => setError(describeError(cause)))}>
          Refresh run selection
        </button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {value && <article>
      <h3>Independent reconstruction result</h3>
      <dl>
        <dt>Run state</dt><dd>{value.state}</dd>
        <dt>Run CAS revision</dt><dd>{value.revision}</dd>
        <dt>Operator audit events</dt><dd>{value.totalRunEvents}</dd>
        <dt>Evidence review audit events</dt>
        <dd>{value.totalReviewEvents}</dd>
        <dt>Operator audit completeness</dt>
        <dd style={{ color: statusColor(value.runAuditComplete) }}>
          {value.runAuditComplete ? "Complete" : "Incomplete"}</dd>
        <dt>Reviewer audit completeness</dt>
        <dd style={{ color: statusColor(value.reviewAuditComplete) }}>
          {value.reviewAuditComplete ? "Complete" : "Incomplete"}</dd>
        <dt>Recorded operator steps</dt><dd>{value.recordedSteps}/9</dd>
        <dt>Independently reviewed steps</dt>
        <dd>{value.independentlyReviewedSteps}/9</dd>
        <dt>Changed references</dt>
        <dd>{value.reviewReferencesCurrent ? "None detected" :
          "Reference mismatch present"}</dd>
        <dt>Blocking inconsistencies</dt><dd>{value.blockers}</dd>
        <dt>Review recommendations</dt><dd>{value.warnings}</dd>
        <dt>Local audit integrity</dt>
        <dd>{value.localAuditIntegrityVerified ?
          "Verified within current bounded history" : "NOT verified"}</dd>
        <dt>Ready for actual independent human decision</dt>
        <dd>{value.readyForIndependentHumanDecision ?
          "Review can proceed; not approved" :
          "No, evidence or audit is incomplete"}</dd>
      </dl>
      <button type="button" onClick={() => exportJson(report,
        `acceptance-audit-reconciliation-${value.runId}.json`)}>
        Export report, manifest and reconciliation playbook
      </button>
      <h3>Audit irregularities</h3>
      <button type="button" onClick={() => setShowIssues(x => !x)}>
        {showIssues ? "Hide" : "Show"} issues ({value.issues.length})
      </button>
      {showIssues && <section>
        <label>Filter
          <select value={issueFilter}
            onChange={event => setIssueFilter(event.target.value)}>
            <option value="ALL">All</option>
            <option value="BLOCK">Blockers</option>
            <option value="REVIEW">Manual reviews</option>
            <option value="RUN">Operator chain</option>
            <option value="EVIDENCE_REVIEW">Reviewer chain</option>
            <option value="STEP">Individual evidence</option>
          </select>
        </label>
        <label>Search issue
          <input value={search}
            onChange={event => setSearch(event.target.value)} />
        </label>
        {!filteredIssues.length && <p>No matching audit issues.</p>}
        <ul>{filteredIssues.map((item, index) => <li key={
          item.code + (item.auditId ?? "") + index}>
          <strong>{item.severity} · {item.code}</strong>
          <p>{item.nextAction}</p>
          {item.resourceId && <p>Resource: <code>{item.resourceId}</code></p>}
          {item.auditId && <p>Event: <code>{item.auditId}</code></p>}
          {item.revision !== null && <p>Revision: {item.revision}</p>}
        </li>)}</ul>
      </section>}
      <h3>Independent reviewer register</h3>
      <button type="button" onClick={() => setShowReviews(x => !x)}>
        {showReviews ? "Hide" : "Show"} reviewer references
      </button>
      {showReviews && <ol>{value.reviews.map(row =>
        <li key={row.id}>
          <strong>{row.stepCode}: {row.state}</strong>
          <p>Review revision {row.revision},
            operator source revision {row.sourceRunRevision}</p>
          <p>Reviewer {row.reviewerUserId};
            original operator {row.originalOperatorUserId}</p>
          <p>Current digest matches:
            {String(row.currentReferenceMatches)}</p>
          <p>Audited independent reference:
            {String(row.independentlyReviewed)}</p>
          <p>Audits: {row.auditEvents} ·
            Issues: {row.issueCodes.join(", ") || "none"}</p>
        </li>)}</ol>}
      <h3>Recorded audit events</h3>
      <button type="button" onClick={() => setShowEvents(x => !x)}>
        {showEvents ? "Hide" : "Show"} local event chronology
      </button>
      {showEvents && <section>
        <label>Resource
          <select value={eventFilter}
            onChange={event => setEventFilter(event.target.value)}>
            <option value="ALL">Both chains</option>
            <option value="AssetOfflineAcceptanceRun">Operator events</option>
            <option value="AssetEvidenceReview">Reviewer events</option>
          </select>
        </label>
        <ol>{filteredEvents.map(event => <li key={event.id}>
          <strong>{event.action}</strong>
          <p>{event.createdAt} · revision {event.revisionAfter ?? "?"}</p>
          <p>Actor: {event.actorUserId ?? "MISSING"}</p>
          <p>{event.from ?? "INITIAL"} → {event.to ?? "UNKNOWN"}</p>
          <p>Resource: {event.resourceType} ·
            <code>{truncate(event.resourceId)}</code></p>
          {event.issues.length > 0 &&
            <p role="alert">Event issues:
              {event.issues.map(x => x.code).join(", ")}</p>}
        </li>)}</ol>
      </section>}
      <h3>Reconciliation playbook</h3>
      <button type="button" onClick={() => setShowPlan(x => !x)}>
        {showPlan ? "Hide" : "Show"} human investigation actions
      </button>
      {showPlan && <ol>{report?.playbook.map(item =>
        <li key={item.order}>
          <strong>{item.severity} · {item.code}</strong>
          <p>{item.action}</p>
          <p>No automatic repair or approval is authorized.</p>
        </li>)}</ol>}
      <button type="button" onClick={() => setShowManifest(x => !x)}>
        {showManifest ? "Hide" : "Show"} report digest
      </button>
      {showManifest && <p><code>{value.digest}</code></p>}
      <button type="button" onClick={() => setShowCaveats(x => !x)}>
        {showCaveats ? "Hide" : "Show"} limitations
      </button>
      {showCaveats && <ul>{value.limitations.map(x =>
        <li key={x}>{x}</li>)}</ul>}
    </article>}
  </section>;
}
