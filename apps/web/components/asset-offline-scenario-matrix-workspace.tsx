"use client";

import { useMemo, useState } from "react";

type ScenarioId =
  "CLEAN_REVIEW" | "NO_REVIEW" | "AMBIGUOUS_VERSION" |
  "MISSING_MAPPING" | "INCOMPLETE_PROVIDER" |
  "MISSING_AUDIT" | "ALTERED_FINGERPRINT" |
  "STALE_OBSERVATION" | "FOREIGN_TENANT" |
  "INCOMPLETE_SNAPSHOT" | "DUPLICATE_CASE" |
  "INVALID_CHECKLIST" | "UNRESOLVED_PROVIDER";
const options: ScenarioId[] = [
  "CLEAN_REVIEW", "NO_REVIEW", "AMBIGUOUS_VERSION",
  "MISSING_MAPPING", "INCOMPLETE_PROVIDER",
  "MISSING_AUDIT", "ALTERED_FINGERPRINT",
  "STALE_OBSERVATION", "FOREIGN_TENANT",
  "INCOMPLETE_SNAPSHOT", "DUPLICATE_CASE",
  "INVALID_CHECKLIST", "UNRESOLVED_PROVIDER",
];
type Result = {
  id: ScenarioId; label: string; passed: boolean;
  expectedAccepted: boolean; observedAccepted: boolean | null;
  expectedException: boolean; observedException: boolean;
  errorCode: string | null;
  expectedBlockers: string[]; actualBlockers: string[];
  unexpectedBlockers: string[]; missingBlockers: string[];
  expectedAdvisories: string[]; missingAdvisories: string[];
  adviceStatuses: string[]; missingAdviceStatuses: string[];
  sourceImportId: string; sourceInspectionId: string;
  candidateCount: number; reviewCaseCount: number;
  validatedReport: boolean;
  reportFingerprint: string | null;
  concerns: string[];
};
type Matrix = {
  schema: string; generatedAt: string;
  synthetic: true; source: string; organizationId: string;
  totalRequested: number; totalExecuted: number;
  passed: number; failed: number; results: Result[];
  resultsDigest: string; fixtureVersion: number;
  externalProviderContacted: false;
  customerDatabaseRead: false;
  customerDatabaseWritten: false;
  userActionRecorded: false;
  releaseAutomaticallyApproved: false;
  warnings: string[];
  verification: {
    valid: boolean; digestValid: boolean;
    resultCountValid: boolean; noSideEffects: boolean;
    scenarioCoverageValid: boolean; reasons: string[];
  };
};
function issue(error: unknown) {
  return error instanceof Error ? error.message :
    "Scenario matrix cannot be evaluated.";
}
function stamp(value: string) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid timestamp";
}
function ScenarioCard({ result }: { result: Result }) {
  const [expanded, setExpanded] = useState(false);
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{result.passed ? "PASS" : "FAIL"} · {result.id}</strong>
    <p>{result.label}</p>
    <p>Expected release eligibility:
      {" "}{result.expectedAccepted ? "ELIGIBLE" : "BLOCKED"}.
      Observed: {result.observedAccepted === null ? "EXCEPTION" :
        result.observedAccepted ? "ELIGIBLE" : "BLOCKED"}.</p>
    <p>Expected explicit exception:
      {" "}{result.expectedException ? "YES" : "NO"}.
      Observed exception: {result.observedException ? "YES" : "NO"}.</p>
    {result.concerns.length > 0 && <div role="alert">
      <strong>Acceptance mismatches</strong>
      <ul>{result.concerns.map((text, i) =>
        <li key={i}>{text}</li>)}</ul>
    </div>}
    <button type="button" onClick={() => setExpanded(x => !x)}>
      {expanded ? "Hide" : "Inspect"} fixture and expected gates
    </button>
    {expanded && <section>
      <p>Import: {result.sourceImportId}.
        Inspection: {result.sourceInspectionId}.</p>
      <p>Stored positive advisories: {result.candidateCount}.
        Human cases: {result.reviewCaseCount}.</p>
      <p>Report verified: {result.validatedReport ? "YES" : "NO"}.
        Error category: {result.errorCode ?? "none"}.</p>
      <p>Expected blockers:
        {" "}{result.expectedBlockers.join(", ") || "none"}.</p>
      <p>Actual blockers:
        {" "}{result.actualBlockers.join(", ") || "none"}.</p>
      <p>Missing blockers:
        {" "}{result.missingBlockers.join(", ") || "none"}.</p>
      <p>Unexpected blockers:
        {" "}{result.unexpectedBlockers.join(", ") || "none"}.</p>
      <p>Expected advisory gates:
        {" "}{result.expectedAdvisories.join(", ") || "none"}.</p>
      <p>Missing advisory gates:
        {" "}{result.missingAdvisories.join(", ") || "none"}.</p>
      <p>Conservative advice categories:
        {" "}{result.adviceStatuses.join(", ") || "none"}.</p>
      <p>Missing advice categories:
        {" "}{result.missingAdviceStatuses.join(", ") || "none"}.</p>
      {result.reportFingerprint && <p>
        Synthetic acceptance SHA-256:
        {" "}<code style={{ overflowWrap: "anywhere" }}>
          {result.reportFingerprint}</code></p>}
    </section>}
  </article>;
}
export function AssetOfflineScenarioMatrixWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/offline-scenarios";
  const [selected, setSelected] = useState<ScenarioId[]>(options);
  const [ageDays, setAgeDays] = useState(30);
  const [mappedPercent, setMappedPercent] = useState(100);
  const [requireCaseAudit, setRequireCaseAudit] = useState(true);
  const [requireAllReviews, setRequireAllReviews] = useState(true);
  const [report, setReport] = useState<Matrix | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassing, setShowPassing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [selectedFilter, setSelectedFilter] = useState("");
  const visible = useMemo(() =>
    report?.results.filter(row =>
      (showPassing || !row.passed) &&
      (!selectedFilter || (row.id + " " + row.label)
        .toLowerCase().includes(selectedFilter.toLowerCase()))) ?? [],
  [report, showPassing, selectedFilter]);
  function changeScenario(value: ScenarioId, included: boolean) {
    setSelected(old => included ?
      options.filter(item => item === value || old.includes(item)) :
      old.filter(item => item !== value));
    setReport(null);
  }
  async function run() {
    if (busy || selected.length === 0) return;
    setBusy(true); setError(null); setCopied(false);
    try {
      const response = await fetch(endpoint, {
        method: "POST", cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          scenarios: selected, maximumScenarios: 13,
          maximumInventoryAgeDays: ageDays,
          minimumMappedPercent: mappedPercent,
          requireCaseAudit,
          requireAllCandidateReviews: requireAllReviews,
        }),
      });
      const value: unknown = await response.json();
      if (!response.ok)
        throw new Error((value as { error?: string }).error ??
          "Offline scenario HTTP " + response.status);
      const result = value as Matrix;
      if (!result.verification.valid || !result.synthetic ||
          result.externalProviderContacted ||
          result.customerDatabaseRead ||
          result.customerDatabaseWritten ||
          result.releaseAutomaticallyApproved)
        throw new Error("Reference matrix has inconsistent safety flags.");
      setReport(result);
    } catch (cause) {
      setReport(null); setError(issue(cause));
    } finally { setBusy(false); }
  }
  function copy() {
    if (!report) return;
    void navigator.clipboard.writeText(
      JSON.stringify(report, null, 2)).then(() =>
      setCopied(true)).catch(cause =>
      setError(issue(cause)));
  }
  if (!canManage) return null;
  return <section aria-label="Offline synthetic acceptance scenarios"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 22,
    }}>
    <h2>Assets — reproducible offline acceptance scenarios</h2>
    <p>Execute the same production advice and acceptance engines
      against fixed synthetic fixtures. Validate the result,
      expected blockers, partial source behavior and independent
      integrity checks before manual operator signoff.</p>
    <p>The fixtures never read customer inventory or contact
      external tenants. Passing them does not approve the release.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Checking deterministic product scenarios…</p>}
    <fieldset disabled={busy}>
      <legend>Choose explicit reference cases</legend>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))",
      }}>
        {options.map(value =>
          <label key={value}>
            <input type="checkbox" checked={selected.includes(value)}
              onChange={event =>
                changeScenario(value, event.target.checked)}/>
            {value.replaceAll("_", " ")}
          </label>)}
      </div>
      <div style={{
        display: "flex", gap: 8, flexWrap: "wrap",
        marginBlock: 12,
      }}>
        <button type="button" onClick={() => {
          setSelected(options); setReport(null);
        }}>Select all</button>
        <button type="button" onClick={() => {
          setSelected(["CLEAN_REVIEW", "NO_REVIEW",
            "INCOMPLETE_SNAPSHOT", "FOREIGN_TENANT"]);
          setReport(null);
        }}>Use critical four</button>
      </div>
      <label>Maximum inventory age
        <select value={ageDays}
          onChange={event => {
            setAgeDays(Number(event.target.value)); setReport(null);
          }}>
          {[7, 14, 30, 60, 90, 180, 365].map(value =>
            <option key={value} value={value}>{value} days</option>)}
        </select>
      </label>
      <label>Minimum software mapped
        <select value={mappedPercent}
          onChange={event => {
            setMappedPercent(Number(event.target.value)); setReport(null);
          }}>
          {[0, 25, 50, 75, 80, 90, 100].map(value =>
            <option key={value} value={value}>{value}%</option>)}
        </select>
      </label>
      <label>
        <input type="checkbox" checked={requireCaseAudit}
          onChange={event => {
            setRequireCaseAudit(event.target.checked); setReport(null);
          }}/>
        Audit records are a blocking requirement
      </label>
      <label>
        <input type="checkbox" checked={requireAllReviews}
          onChange={event => {
            setRequireAllReviews(event.target.checked); setReport(null);
          }}/>
        Every positive candidate requires human review
      </label>
      <button type="button" disabled={!selected.length || busy}
        onClick={() => void run()}>
        Run selected acceptance regression matrix
      </button>
    </fieldset>
    {report && <section>
      <h3>Reference regression verdict</h3>
      <p>Evaluated {stamp(report.generatedAt)}.
        Fixture version {report.fixtureVersion}.</p>
      <p><strong>{report.failed === 0 ?
        "ALL SELECTED REFERENCES PASSED" :
        "REFERENCE REGRESSIONS DETECTED"}</strong>.
        {" "}{report.passed} passing of {report.totalExecuted}.
        {" "}{report.failed} failing.</p>
      <p>Structural SHA-256 validation:
        {" "}{report.verification.digestValid ? "PASS" : "FAIL"}.
        Expected scenario coverage:
        {" "}{report.verification.scenarioCoverageValid ? "PASS" : "FAIL"}.
      </p>
      <p>Customer data accessed: NO.
        Provider contact: NO.
        Automatic release approval: NO.</p>
      <h3>Scenario-level trace</h3>
      <label>
        <input type="checkbox" checked={showPassing}
          onChange={event => setShowPassing(event.target.checked)}/>
        Include passing fixtures
      </label>
      <label>Filter reference scenario
        <input value={selectedFilter}
          onChange={event => setSelectedFilter(event.target.value)}/>
      </label>
      {visible.length === 0 &&
        <p>There are no failing scenarios under these filters.
          A manual end-to-end release review is still required.</p>}
      {visible.map(value =>
        <ScenarioCard key={value.id} result={value}/>)}
      <details>
        <summary>Reference suite fingerprint and limitations</summary>
        <p>SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.resultsDigest}</code></p>
        <ul>{report.warnings.map((value, i) =>
          <li key={i}>{value}</li>)}</ul>
        {report.verification.reasons.length > 0 &&
          <ul>{report.verification.reasons.map((value, i) =>
            <li key={i}>{value}</li>)}</ul>}
      </details>
      <button type="button" onClick={copy}>
        Copy reference matrix report JSON
      </button>
      {copied && <p role="status">Reference scenario report copied.</p>}
    </section>}
  </section>;
}
