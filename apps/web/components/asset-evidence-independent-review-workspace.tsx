"use client";
import { useCallback, useEffect, useMemo, useState } from "react";

type Step = {
  code: string; status: string; evidenceId: string | null;
  evidenceDescription: string | null; recordedByUserId: string | null;
  recordedAt: string | null; reason: string | null;
  limitations: string[];
};
type Run = {
  id: string; revision: number; state: string;
  importId: string; inspectionId: string; steps: Step[];
};
type EvidenceReview = {
  id: string; stepCode: string; revision: number;
  sourceRunRevision: number; reviewState: string;
  evidenceDigest: string; originalOperatorUserId: string;
  reviewerUserId: string; reviewerReason: string;
  referenceLocation: string | null;
  referenceObservedAt: string | null;
  crossCheckedIdentifiers: string[]; limitations: string[];
  updatedAt: string;
};
type Attestation = {
  stepCode: string; result: string; sourceVerified: boolean;
  referenceStillMatches: boolean; reviewerIsIndependent: boolean;
  evidenceDigest: string; currentEvidenceDigest: string | null;
  issues: Array<{ code: string; message: string; severity: string }>;
  digest: string;
};
type Report = {
  runId: string; runRevision: number; runState: string;
  totalSteps: number; evidenceRecorded: number;
  independentReferencesMatched: number;
  disputed: number; stale: number; missing: number;
  readyForHumanSignoff: boolean;
  mergeAuthorized: false; legalSignoffVerified: false;
  assessments: Attestation[]; reviews: EvidenceReview[];
  outstanding: Array<{ stepCode: string; reason: string; nextAction: string }>;
  caveats: string[];
  digest: string;
};
type Props = { slug: string; canManage: boolean };
function exportJson(value: unknown, filename: string) {
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
function explanation(error: unknown) {
  return error instanceof Error ? error.message :
    "Independent review action was not completed.";
}
function digestForStep(step: Step): string {
  // Fingerprints are calculated on the server; a UI never supplies a
  // fabricated source hash. Empty here is an intentional fail-closed default.
  void step;
  return "";
}
export function AssetEvidenceIndependentReviewWorkspace({
  slug, canManage,
}: Props) {
  const runsUrl =
    `/api/organizations/${encodeURIComponent(slug)}/assets/offline-acceptance-runs`;
  const endpoint =
    `/api/organizations/${encodeURIComponent(slug)}/assets/evidence-reviews`;
  const [runId, setRunId] = useState("");
  const [runs, setRuns] = useState<Run[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [stepCode, setStepCode] = useState("");
  const [state, setState] = useState("NOT_CHECKED");
  const [reason, setReason] = useState("");
  const [referenceLocation, setReferenceLocation] = useState("");
  const [referenceObservedAt, setReferenceObservedAt] = useState("");
  const [crossChecks, setCrossChecks] = useState("");
  const [limitations, setLimitations] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revealReasons, setRevealReasons] = useState(false);
  const [showSummary, setShowSummary] = useState(true);
  const [showOutstanding, setShowOutstanding] = useState(true);
  const [showCaveats, setShowCaveats] = useState(false);
  const [showHistory, setShowHistory] = useState(true);
  const [filter, setFilter] = useState("ALL");
  const [selectedReviewId, setSelectedReviewId] = useState("");
  const selectedReview = useMemo(() =>
    report?.reviews.find(r => r.id === selectedReviewId) ?? null,
    [report, selectedReviewId]);
  const selectedAttestation = useMemo(() =>
    report?.assessments.find(a => a.stepCode === stepCode) ?? null,
    [report, stepCode]);
  const selectedStep = useMemo(() =>
    run?.steps.find(s => s.code === stepCode) ?? null,
    [run, stepCode]);
  const visible = useMemo(() =>
    report?.assessments.filter(a => filter === "ALL" ||
      (filter === "UNVERIFIED" && !a.sourceVerified) ||
      a.result === filter) ?? [],
    [report, filter]);
  const reloadRuns = useCallback(async () => {
    if (!canManage) return;
    const response = await fetch(runsUrl + "?limit=100&offset=0",
      { cache: "no-store" });
    const result = await response.json() as {
      runs?: Run[]; error?: string;
    };
    if (!response.ok)
      throw new Error(result.error ?? "Cannot list acceptance runs.");
    setRuns(result.runs ?? []);
    setRunId(current => current || result.runs?.[0]?.id || "");
  }, [canManage, runsUrl]);
  useEffect(() => {
    if (canManage) void reloadRuns().catch(
      cause => setError(explanation(cause)));
  }, [canManage, reloadRuns]);
  const load = useCallback(async (id: string, disclose: boolean) => {
    if (!id) throw new Error("An exact operator run identifier is required.");
    const [runResponse, checkResponse] = await Promise.all([
      fetch(runsUrl + "?limit=100&offset=0", { cache: "no-store" }),
      fetch(endpoint + "?runId=" + encodeURIComponent(id) +
        "&includeOperatorReason=" + String(disclose), { cache: "no-store" }),
    ]);
    const runsPayload = await runResponse.json() as {
      runs?: Run[]; error?: string;
    };
    const checked = await checkResponse.json() as {
      report?: Report; error?: string;
    };
    if (!runResponse.ok)
      throw new Error(runsPayload.error ?? "Cannot read operator run.");
    if (!checkResponse.ok)
      throw new Error(checked.error ?? "Cannot inspect evidence references.");
    const exact = runsPayload.runs?.find(item => item.id === id);
    if (!exact)
      throw new Error("Run is not within the first 100 results; use a more focused register.");
    setRun(exact);
    setReport(checked.report ?? null);
    setStepCode(current => exact.steps.some(s => s.code === current)
      ? current : exact.steps[0]?.code ?? "");
    setSelectedReviewId("");
  }, [endpoint, runsUrl]);
  async function inspect() {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      await load(runId, revealReasons);
      setNotice("Independent reference coverage reconstructed without writing data.");
    } catch (cause) { setError(explanation(cause)); }
    finally { setBusy(false); }
  }
  async function submit(method: "POST" | "PATCH") {
    if (!report || !run || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      if (!selectedAttestation?.currentEvidenceDigest)
        throw new Error("The operator step has no existing recorded reference.");
      if (method === "PATCH" && !selectedReview)
        throw new Error("Select the existing review before revising its verdict.");
      const command = {
        runId: run.id, stepCode,
        expectedRunRevision: run.revision,
        expectedEvidenceDigest:
          selectedAttestation.currentEvidenceDigest ||
          digestForStep(selectedStep!),
        state, reason,
        referenceLocation: referenceLocation || null,
        referenceObservedAt: referenceObservedAt ?
          new Date(referenceObservedAt).toISOString() : null,
        crossCheckedIdentifiers: crossChecks.split("\n")
          .map(s => s.trim()).filter(Boolean),
        limitations: limitations.split("\n")
          .map(s => s.trim()).filter(Boolean),
        ...(method === "PATCH" ? {
          reviewId: selectedReview?.id,
          expectedReviewRevision: selectedReview?.revision,
        } : {}),
      };
      const response = await fetch(endpoint, {
        method, cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(command),
      });
      const result = await response.json() as {
        replayed?: boolean; error?: string;
      };
      if (!response.ok)
        throw new Error(result.error ?? "Independent review was rejected.");
      await load(run.id, revealReasons);
      setNotice(result.replayed ?
        "Matching review returned, no duplicate audit was created." :
        "Independent review and transaction audit recorded. External signoff is still absent.");
    } catch (cause) { setError(explanation(cause)); }
    finally { setBusy(false); }
  }
  if (!canManage) return <section aria-label="Independent evidence access">
    <h2>Independent operator evidence checks</h2>
    <p>Administrative access is required to review source declarations.</p>
  </section>;
  return <section aria-label="Independent source evidence review"
    style={{ marginBlock: "2rem" }}>
    <h2>Independent evidence reference checks</h2>
    <p>A second authenticated human reviews specific references supplied
      by an operator. Identical reviewers are rejected. A matched reference
      does not prove external authorship, legal approval or backup erasure.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <fieldset disabled={busy}>
        <legend>Inspect a tenant-scoped operator run</legend>
        <label>Run ID
          <input required minLength={5} maxLength={150}
            value={runId} onChange={event => setRunId(event.target.value)} />
        </label>
        <label>Recent operator run
          <select value={runs.some(x => x.id === runId) ? runId : ""}
            onChange={event => setRunId(event.target.value)}>
            <option value="">Manual run ID</option>
            {runs.map(row => <option key={row.id} value={row.id}>
              {row.state} · {row.importId} · revision {row.revision}
            </option>)}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={revealReasons}
            onChange={event => setRevealReasons(event.target.checked)} />
          Request private reviewer reasons (not shown by default)
        </label>
        <button type="submit">Inspect independent coverage</button>
        <button type="button" onClick={() => void reloadRuns()}>
          Refresh run list
        </button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {report && <article>
      <h3>Independent review coverage</h3>
      <button type="button" onClick={() => setShowSummary(x => !x)}>
        {showSummary ? "Hide" : "Show"} coverage totals
      </button>
      {showSummary && <dl>
        <dt>Run</dt><dd>{report.runId}</dd>
        <dt>Revision</dt><dd>{report.runRevision}</dd>
        <dt>State</dt><dd>{report.runState}</dd>
        <dt>Recorded operator steps</dt><dd>{report.evidenceRecorded}/9</dd>
        <dt>Matched by independent reviewer</dt>
        <dd>{report.independentReferencesMatched}/9</dd>
        <dt>Disputed</dt><dd>{report.disputed}</dd>
        <dt>Stale</dt><dd>{report.stale}</dd>
        <dt>No review</dt><dd>{report.missing}</dd>
        <dt>Ready for separate human signoff</dt>
        <dd>{String(report.readyForHumanSignoff)}</dd>
        <dt>Merge authorization</dt><dd>Not granted</dd>
      </dl>}
      <button type="button" onClick={() =>
        exportJson(report, `independent-source-reviews-${report.runId}.json`)}>
        Export locally verifiable reference assessment
      </button>
      <h3>Per-step evidence cross-checks</h3>
      <label>Filter verdict
        <select value={filter} onChange={event => setFilter(event.target.value)}>
          <option value="ALL">All</option>
          <option value="UNVERIFIED">Outstanding</option>
          <option value="REFERENCE_MATCHED">References matched</option>
          <option value="NOT_CHECKED">Not checked</option>
          <option value="DISPUTED">Disputed</option>
          <option value="STALE_REFERENCE">Stale</option>
        </select>
      </label>
      <ol>{visible.map(item => <li key={item.stepCode}>
        <strong>{item.stepCode} · {item.result}</strong>
        <p>Current reference matches:
          {String(item.referenceStillMatches)}.
          Independent reviewer: {String(item.reviewerIsIndependent)}.</p>
        <p>Evidence digest: <code>{item.currentEvidenceDigest ?? "MISSING"}</code></p>
        {item.issues.map(problem =>
          <p key={problem.code}>{problem.severity} ·
            {problem.code}: {problem.message}</p>)}
        <button type="button" onClick={() => setStepCode(item.stepCode)}>
          Review this step
        </button>
      </li>)}</ol>
      <h3>Record a genuine independent human review</h3>
      <fieldset disabled={busy}>
        <legend>Selected step and expected reference digest</legend>
        <label>Step
          <select value={stepCode}
            onChange={event => setStepCode(event.target.value)}>
            {run?.steps.map(step =>
              <option key={step.code} value={step.code}>{step.code}</option>)}
          </select>
        </label>
        <p>Recorded source:
          {selectedStep?.evidenceId ?? "No reference supplied"}</p>
        <p>Source author:
          {selectedStep?.recordedByUserId ?? "UNKNOWN"}</p>
        <p>Reference fingerprint:
          <code>{selectedAttestation?.currentEvidenceDigest ?? "UNKNOWN"}</code>
        </p>
        <label>Review finding
          <select value={state} onChange={event => setState(event.target.value)}>
            <option value="NOT_CHECKED">Not checked</option>
            <option value="REFERENCE_MATCHED">Local reference matched</option>
            <option value="DISPUTED">Source evidence disputed</option>
            <option value="STALE_REFERENCE">Source reference stale</option>
          </select>
        </label>
        <label>Independent reviewer reason (20–1500 characters)
          <textarea value={reason} minLength={20} maxLength={1500}
            onChange={event => setReason(event.target.value)} rows={3} />
        </label>
        <label>Location or internal path/reference checked
          <input value={referenceLocation} maxLength={500}
            onChange={event => setReferenceLocation(event.target.value)} />
        </label>
        <label>When the source reference was observed
          <input type="datetime-local" value={referenceObservedAt}
            onChange={event => setReferenceObservedAt(event.target.value)} />
        </label>
        <label>Independent cross-check identifiers, one per line
          <textarea value={crossChecks} rows={4}
            onChange={event => setCrossChecks(event.target.value)} />
        </label>
        <label>Limitations, one per line
          <textarea value={limitations} rows={3}
            onChange={event => setLimitations(event.target.value)} />
        </label>
        <button type="button" onClick={() => void submit("POST")}>
          Create independent review
        </button>
        <label>Existing review to revise
          <select value={selectedReviewId}
            onChange={event => setSelectedReviewId(event.target.value)}>
            <option value="">Choose existing review</option>
            {report.reviews.filter(r => r.stepCode === stepCode)
              .map(item => <option key={item.id} value={item.id}>
                {item.reviewState} · revision {item.revision}
              </option>)}
          </select>
        </label>
        <button type="button" onClick={() => void submit("PATCH")}>
          Revise review with exact CAS revision
        </button>
      </fieldset>
      <button type="button" onClick={() =>
        setShowOutstanding(x => !x)}>
        {showOutstanding ? "Hide" : "Show"} outstanding reconciliation
      </button>
      {showOutstanding && <ul>{report.outstanding.map(item =>
        <li key={item.stepCode}>
          <strong>{item.stepCode}</strong>
          <p>{item.reason}</p><p>{item.nextAction}</p>
        </li>)}</ul>}
      <button type="button" onClick={() =>
        setShowHistory(x => !x)}>
        {showHistory ? "Hide" : "Show"} reviewer register
      </button>
      {showHistory && <ul>{report.reviews.map(item =>
        <li key={item.id}>
          {item.stepCode}: {item.reviewState} · revision {item.revision}
          <p>Reviewed by: {item.reviewerUserId}</p>
          <p>Operator: {item.originalOperatorUserId}</p>
          <p>Last updated: {item.updatedAt}</p>
        </li>)}</ul>}
      <button type="button" onClick={() => setShowCaveats(x => !x)}>
        {showCaveats ? "Hide" : "Show"} attestation caveats
      </button>
      {showCaveats && <ul>{report.caveats.map(item =>
        <li key={item}>{item}</li>)}</ul>}
    </article>}
  </section>;
}
