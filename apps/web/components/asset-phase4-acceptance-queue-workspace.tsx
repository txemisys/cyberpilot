"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type QueueSignal = {
  code: string;
  severity: "BLOCK" | "REVIEW" | "INFO";
  entityId: string | null;
  explanation: string;
  nextAction: string;
  requiresIndependentHuman: boolean;
  cannotBeResolvedBySyntheticFixtures: boolean;
};
type QueueRow = {
  runId: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  state: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  submittedAt: string | null;
  ageDays: number;
  recordedSteps: number;
  blockedSteps: number;
  missingSteps: string[];
  operatorIdentityVerifiedLocally: boolean;
  runIntegrityVerified: boolean;
  sourceDigest: string;
  dossierDigest: string;
  independentReviewCount: number;
  independentMatchedCount: number;
  independentDisputedCount: number;
  independentStaleCount: number;
  selfReviewedCount: number;
  auditCount: number;
  auditExpected: number;
  auditCompleteWithinCount: boolean;
  retentionReviewState: string | null;
  releaseReviewState: string | null;
  signals: QueueSignal[];
  blockers: number;
  humanActions: number;
  readyForIndependentSignoffCheck: boolean;
  acceptedByProduct: false;
  externalProviderVerified: false;
  privacyLegallyApproved: false;
  backupsErased: false;
  mergeAuthorized: false;
};
type QueueReport = {
  schema: string;
  organizationId: string;
  generatedAt: string;
  policy: {
    maxRuns: number;
    offset: number;
    maxAgeDays: number;
    maxReviewerAgeDays: number;
    includeDrafts: boolean;
    includeCompleted: boolean;
    maxAuditsPerRun: number;
  };
  totalMatching: number;
  returned: number;
  moreResults: boolean;
  rows: QueueRow[];
  summary: {
    drafts: number;
    inProgress: number;
    blocked: number;
    evidenceCaptured: number;
    reopened: number;
    integrityFailures: number;
    missingReviewEvidence: number;
    staleReviewEvidence: number;
    selfReviewIncidents: number;
    auditGaps: number;
    outstandingHumanActions: number;
    blockedRuns: number;
    locallyReviewReady: number;
    coverage: "PAGE_ONLY";
  };
  priorities: Array<{
    runId: string;
    severity: string;
    leadingSignals: string[];
    nextActions: string[];
    ownerRole: string;
    autoEscalated: false;
  }>;
  digest: string;
  readOnly: true;
  manualAcceptanceRecordedByQueue: false;
  automaticMergeAllowed: false;
  limitations: string[];
};
type Response = {
  report: QueueReport;
  verification: { valid: boolean; issues: string[] };
  actionPlan: Array<{
    rankWithinPage: number; runId: string;
    severity: string; ownerRole: string;
    leadingSignals: string[]; nextActions: string[];
    verifiedByHuman: false; actionExecuted: false;
  }>;
};
type Props = { slug: string; canManage: boolean };
function save(value: unknown, name: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json",
  });
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href; link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(href);
}
function detail(error: unknown) {
  return error instanceof Error ? error.message :
    "Acceptance queue could not be evaluated.";
}
function stateColor(state: string) {
  switch (state) {
    case "BLOCK": case "BLOCKED": return "#b32f2f";
    case "REVIEW": case "REOPENED": return "#987100";
    case "EVIDENCE_CAPTURED": return "#147a49";
    default: return "#64717e";
  }
}
export function AssetPhase4AcceptanceQueueWorkspace({
  slug, canManage,
}: Props) {
  const endpoint =
    `/api/organizations/${encodeURIComponent(slug)}/assets/acceptance-queue`;
  const [maxRuns, setMaxRuns] = useState(20);
  const [offset, setOffset] = useState(0);
  const [maxAgeDays, setMaxAgeDays] = useState(30);
  const [maxReviewerAgeDays, setMaxReviewerAgeDays] = useState(14);
  const [includeDrafts, setIncludeDrafts] = useState(true);
  const [includeCompleted, setIncludeCompleted] = useState(true);
  const [maxAuditsPerRun, setMaxAuditsPerRun] = useState(100);
  const [includeHumanReasons, setIncludeHumanReasons] = useState(false);
  const [report, setReport] = useState<Response | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [stateFilter, setStateFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selectedRunId, setSelectedRunId] = useState("");
  const [showSignals, setShowSignals] = useState(true);
  const [showPriorities, setShowPriorities] = useState(true);
  const [showSummary, setShowSummary] = useState(true);
  const [showCaveats, setShowCaveats] = useState(false);
  const [showDigests, setShowDigests] = useState(false);
  const [showUnknowns, setShowUnknowns] = useState(true);
  const data = report?.report ?? null;
  const filtered = useMemo(() => data?.rows.filter(row =>
    (stateFilter === "ALL" || row.state === stateFilter) &&
    (severityFilter === "ALL" ||
      (severityFilter === "BLOCK" && row.blockers > 0) ||
      (severityFilter === "REVIEW" && row.blockers === 0 &&
        row.humanActions > 0) ||
      (severityFilter === "INFO" && row.blockers === 0 &&
        row.humanActions === 0)) &&
    (!search.trim() || [row.runId, row.importId,
      row.inspectionId, row.state, ...row.signals.map(s => s.code)]
      .join(" ").toLowerCase()
      .includes(search.toLowerCase().trim()))) ?? [],
    [data, stateFilter, severityFilter, search]);
  const selected = useMemo(() =>
    data?.rows.find(row => row.runId === selectedRunId) ?? null,
    [data, selectedRunId]);
  const fetchQueue = useCallback(async (nextOffset: number) => {
    if (!canManage) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch(endpoint, {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          maxRuns, offset: nextOffset,
          maxAgeDays, maxReviewerAgeDays,
          includeDrafts, includeCompleted,
          includeHumanReasons, maxAuditsPerRun,
        }),
      });
      const payload = await response.json() as Response & {
        error?: string;
      };
      if (!response.ok)
        throw new Error(payload.error ?? "Acceptance queue rejected.");
      if (!payload.verification?.valid)
        throw new Error("Independent queue integrity verification failed.");
      setReport(payload);
      setOffset(nextOffset);
      setSelectedRunId("");
      setMessage("Read-only bounded operator and reviewer queue evaluated.");
    } catch (cause) {
      setError(detail(cause));
      setReport(null);
    } finally { setBusy(false); }
  }, [canManage, endpoint, maxRuns, maxAgeDays, maxReviewerAgeDays,
    includeDrafts, includeCompleted, includeHumanReasons, maxAuditsPerRun]);
  useEffect(() => { setReport(null); }, [
    maxRuns, maxAgeDays, maxReviewerAgeDays, includeDrafts,
    includeCompleted, includeHumanReasons, maxAuditsPerRun,
  ]);
  if (!canManage) return <section aria-label="Phase 4 acceptance queue">
    <h2>Offline acceptance queue</h2>
    <p>ADMIN or OWNER is required to inspect these records.</p>
  </section>;
  return <section aria-label="Phase 4 acceptance queue"
    style={{ marginBlock: "2rem" }}>
    <h2>Phase 4 acceptance review queue</h2>
    <p>This read-only queue prioritizes real operator runs using
      source consistency, fixed checklist state, independent reviewer
      evidence, audit counts, aging and human privacy/release
      dependencies. All summaries refer only to the current page.</p>
    <form onSubmit={event => {
      event.preventDefault();
      void fetchQueue(0);
    }}>
      <fieldset disabled={busy}>
        <legend>Bounded tenant-local inspection policy</legend>
        <label>Runs per page
          <input type="number" min={1} max={50}
            value={maxRuns} onChange={event =>
              setMaxRuns(Number(event.target.value))} />
        </label>
        <label>Operator evidence age limit, days
          <input type="number" min={1} max={3650}
            value={maxAgeDays} onChange={event =>
              setMaxAgeDays(Number(event.target.value))} />
        </label>
        <label>Independent review age limit, days
          <input type="number" min={1} max={3650}
            value={maxReviewerAgeDays} onChange={event =>
              setMaxReviewerAgeDays(Number(event.target.value))} />
        </label>
        <label>Maximum audit events inspected per run
          <input type="number" min={1} max={1000}
            value={maxAuditsPerRun} onChange={event =>
              setMaxAuditsPerRun(Number(event.target.value))} />
        </label>
        <label><input type="checkbox" checked={includeDrafts}
          onChange={event =>
            setIncludeDrafts(event.target.checked)} />
          Include draft runs
        </label>
        <label><input type="checkbox" checked={includeCompleted}
          onChange={event =>
            setIncludeCompleted(event.target.checked)} />
          Include runs with evidence captured
        </label>
        <label><input type="checkbox" checked={includeHumanReasons}
          onChange={event =>
            setIncludeHumanReasons(event.target.checked)} />
          Include sensitive operator reason disclosures when available
        </label>
        <button type="submit">Evaluate acceptance queue</button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {data && <article>
      <h3>Bounded page health</h3>
      <button type="button" onClick={() =>
        setShowSummary(v => !v)}>
        {showSummary ? "Hide" : "Show"} page summary
      </button>
      {showSummary && <dl>
        <dt>Tenant</dt><dd>{data.organizationId}</dd>
        <dt>Evaluated</dt><dd>{data.generatedAt}</dd>
        <dt>Matching runs</dt><dd>{data.totalMatching}</dd>
        <dt>Current page rows</dt><dd>{data.returned}</dd>
        <dt>Blocked runs</dt><dd>{data.summary.blockedRuns}</dd>
        <dt>Local integrity failures</dt>
        <dd>{data.summary.integrityFailures}</dd>
        <dt>Missing independent review coverage</dt>
        <dd>{data.summary.missingReviewEvidence}</dd>
        <dt>Stale independent evidence</dt>
        <dd>{data.summary.staleReviewEvidence}</dd>
        <dt>Self-review incidents</dt>
        <dd>{data.summary.selfReviewIncidents}</dd>
        <dt>Audit count gaps</dt><dd>{data.summary.auditGaps}</dd>
        <dt>Human actions still outstanding</dt>
        <dd>{data.summary.outstandingHumanActions}</dd>
        <dt>Locally ready to request review</dt>
        <dd>{data.summary.locallyReviewReady}</dd>
        <dt>Coverage</dt><dd>{data.summary.coverage}</dd>
      </dl>}
      <button type="button" onClick={() =>
        save(report, `assets-phase4-queue-${offset}.json`)}>
        Export queue, current page and ranked actions
      </button>
      <button type="button" onClick={() => setShowDigests(x => !x)}>
        {showDigests ? "Hide" : "Show"} local report digest
      </button>
      {showDigests && <p><code>{data.digest}</code></p>}
      <h3>Operator run table</h3>
      <label>Run state
        <select value={stateFilter}
          onChange={event => setStateFilter(event.target.value)}>
          <option value="ALL">All states</option>
          <option value="DRAFT">Draft</option>
          <option value="IN_PROGRESS">In progress</option>
          <option value="BLOCKED">Blocked</option>
          <option value="EVIDENCE_CAPTURED">Evidence captured</option>
          <option value="REOPENED">Reopened</option>
        </select>
      </label>
      <label>Severity
        <select value={severityFilter}
          onChange={event => setSeverityFilter(event.target.value)}>
          <option value="ALL">All</option>
          <option value="BLOCK">Blocked</option>
          <option value="REVIEW">Review without blocker</option>
          <option value="INFO">Informational</option>
        </select>
      </label>
      <label>Search ID or signal
        <input value={search}
          onChange={event => setSearch(event.target.value)} />
      </label>
      <ol>{filtered.map(row =>
        <li key={row.runId}>
          <button type="button"
            onClick={() => setSelectedRunId(current =>
              current === row.runId ? "" : row.runId)}
            aria-pressed={row.runId === selectedRunId}>
            {row.state} · {row.importId} ·
            {row.recordedSteps}/9 recorded ·
            {row.independentMatchedCount}/9 matched ·
            {row.blockers} blockers
          </button>
        </li>)}</ol>
      <button type="button" disabled={busy || offset === 0}
        onClick={() => void fetchQueue(Math.max(0, offset - maxRuns))}>
        Previous page
      </button>
      <span> {offset + 1}–
        {Math.min(offset + data.returned, data.totalMatching)}
        of {data.totalMatching} </span>
      <button type="button" disabled={busy || !data.moreResults}
        onClick={() => void fetchQueue(offset + maxRuns)}>
        Next page
      </button>
      {selected && <section aria-label="Selected operator run">
        <h3>Run {selected.runId}</h3>
        <dl>
          <dt>Revision</dt><dd>{selected.revision}</dd>
          <dt>Evidence last updated</dt><dd>{selected.updatedAt}</dd>
          <dt>Evidence age (days)</dt><dd>{selected.ageDays}</dd>
          <dt>Audit count</dt>
          <dd>{selected.auditCount}/{selected.auditExpected}</dd>
          <dt>Release review</dt>
          <dd>{selected.releaseReviewState ?? "MISSING"}</dd>
          <dt>Retention review</dt>
          <dd>{selected.retentionReviewState ?? "MISSING"}</dd>
          <dt>Locally ready for human signoff check</dt>
          <dd>{String(selected.readyForIndependentSignoffCheck)}</dd>
          <dt>Product acceptance</dt><dd>Not granted by queue</dd>
          <dt>Merge authorization</dt><dd>Not granted by queue</dd>
        </dl>
        <h4>Incomplete or blocked checklist stages</h4>
        <ul>{selected.missingSteps.map(code =>
          <li key={code}>{code}</li>)}</ul>
        <button type="button" onClick={() =>
          setShowSignals(x => !x)}>
          {showSignals ? "Hide" : "Show"} detailed evidence signals
        </button>
        {showSignals && <ol>{selected.signals.map((signal, index) =>
          <li key={signal.code + index}>
            <strong style={{ color: stateColor(signal.severity) }}>
              {signal.severity}: {signal.code}
            </strong>
            <p>{signal.explanation}</p>
            <p>Next: {signal.nextAction}</p>
            <p>Independent human required:
              {String(signal.requiresIndependentHuman)}</p>
          </li>)}</ol>}
        <button type="button" onClick={() =>
          setShowUnknowns(x => !x)}>
          {showUnknowns ? "Hide" : "Show"} unverified claims
        </button>
        {showUnknowns && <p>Provider LIVE, legal privacy approval,
          backup erasure and authorization to merge are not verified.
          The queue cannot modify any of those statuses.</p>}
      </section>}
      <h3>Prioritized human action register</h3>
      <button type="button" onClick={() =>
        setShowPriorities(x => !x)}>
        {showPriorities ? "Hide" : "Show"} ranked run actions
      </button>
      {showPriorities && <ol>{report?.actionPlan.map(item =>
        <li key={item.runId}>
          <strong style={{ color: stateColor(item.severity) }}>
            {item.rankWithinPage}. {item.severity} · {item.ownerRole}
          </strong>
          <p>Run: {item.runId}</p>
          <p>{item.leadingSignals.join(", ")}</p>
          <ul>{item.nextActions.map(action =>
            <li key={action}>{action}</li>)}</ul>
        </li>)}</ol>}
      <button type="button" onClick={() =>
        setShowCaveats(x => !x)}>
        {showCaveats ? "Hide" : "Show"} evaluation limitations
      </button>
      {showCaveats && <ul>{data.limitations.map(item =>
        <li key={item}>{item}</li>)}</ul>}
    </article>}
  </section>;
}
