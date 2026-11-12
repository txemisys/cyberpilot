"use client";

import { useMemo, useState } from "react";

type Gate = {
  id: string; level: "PASS" | "BLOCK" | "ADVISORY";
  description: string; actual: number; expected: number | null;
  affectedCaseIds: string[]; affectedAssetIds: string[];
  explanation: string;
};
type Case = {
  caseId: string; assetId: string; productKey: string;
  category: string; status: string; revision: number;
  fingerprintsMatch: boolean; sourceConsistent: boolean;
  workflowConsistent: boolean; stepCodesMatch: boolean;
  auditObserved: boolean; stale: boolean;
  issues: string[]; proposedNextActions: string[];
};
type Report = {
  schema: string; organizationId: string;
  importId: string; inspectionId: string; evaluatedAt: string;
  source: {
    origin: string; inspectionOrigin: string;
    inventoryDigest: string; inspectionDigest: string;
    deviceCount: number; queryCount: number;
    reviewCaseCount: number; auditCount: number;
    positiveCandidateCount: number;
    unknownEvidenceCount: number;
    completeWithinSnapshot: boolean;
  };
  gates: Gate[]; cases: Case[];
  scorecard: {
    passed: number; blocked: number; advisory: number;
    casesEvaluated: number; casesWithIssues: number;
    possibleCandidatesWithoutReview: number; mappedPercent: number;
    totalIssues: number;
  };
  acceptanceEligible: boolean;
  manualAcceptanceStillRequired: true;
  noExternalTenantsRequired: true;
  databaseWrites: 0; providerRequests: 0;
  findingsModified: false; cyberScoreModified: false;
  reportDigest: string; warnings: string[];
};
function problem(value: unknown) {
  return value instanceof Error ? value.message :
    "Unable to inspect offline acceptance.";
}
function pretty(value: string) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid timestamp";
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    border: "1px solid #8885", padding: 11,
    borderRadius: 8,
  }}>
    <strong>{value}</strong><p>{label}</p>
  </div>;
}
function GateCard({ value }: { value: Gate }) {
  const [expanded, setExpanded] = useState(false);
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{value.level} · {value.id}</strong>
    <p>{value.description}</p>
    <p>Actual: {value.actual}. Expected:
      {" "}{value.expected === null ? "not applicable" : value.expected}.
    </p>
    <button type="button" onClick={() =>
      setExpanded(previous => !previous)}>
      {expanded ? "Hide" : "Explain"} gate result
    </button>
    {expanded && <>
      <p>{value.explanation}</p>
      {value.affectedAssetIds.length > 0 &&
        <details>
          <summary>{value.affectedAssetIds.length} affected asset IDs</summary>
          <ul>{value.affectedAssetIds.map(id =>
            <li key={id}><code>{id}</code></li>)}</ul>
        </details>}
      {value.affectedCaseIds.length > 0 &&
        <details>
          <summary>{value.affectedCaseIds.length} affected review cases</summary>
          <ul>{value.affectedCaseIds.map(id =>
            <li key={id}><code>{id}</code></li>)}</ul>
        </details>}
    </>}
  </article>;
}
function CaseCard({ value }: { value: Case }) {
  const [expanded, setExpanded] = useState(false);
  const pass = value.issues.length === 0;
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{pass ? "CONSISTENT" : "REVIEW REQUIRED"} · {value.assetId}</strong>
    <p>Case {value.caseId}. {value.category} · {value.status}.
      Revision {value.revision}.</p>
    <p>Source fingerprint: {value.fingerprintsMatch ? "PASS" : "FAIL"}.
      Workflow: {value.workflowConsistent ? "PASS" : "FAIL"}.
      Audit: {value.auditObserved ? "OBSERVED" : "MISSING"}.
    </p>
    <button type="button" onClick={() =>
      setExpanded(previous => !previous)}>
      {expanded ? "Hide" : "Review"} case acceptance details
    </button>
    {expanded && <>
      <p>Product key: {value.productKey}</p>
      <ul>
        <li>Source IDs and digests: {value.sourceConsistent ? "PASS" : "FAIL"}</li>
        <li>Step/action agreement: {value.stepCodesMatch ? "PASS" : "FAIL"}</li>
        <li>Case age: {value.stale ? "OUT OF POLICY" : "WITHIN POLICY"}</li>
      </ul>
      {value.issues.length > 0 && <>
        <strong>Detected discrepancies</strong>
        <ul>{value.issues.map((issue, index) =>
          <li key={index}>{issue}</li>)}</ul>
      </>}
      <strong>Operator follow-up</strong>
      <ol>{value.proposedNextActions.map((action, index) =>
        <li key={index}>{action}</li>)}</ol>
    </>}
  </article>;
}
const defaultPolicy = {
  maximumInventoryAgeDays: 30,
  minimumMappedPercent: 80,
  allowIncompleteInspections: false,
  requireCaseAudit: true,
  requireAllCandidateReviews: true,
  maximumCaseAgeDays: 90,
  maxCases: 500,
};
export function AssetOfflineAcceptanceWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const api = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/offline-acceptance";
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [bindingsText, setBindingsText] = useState("[]");
  const [policy, setPolicy] = useState(defaultPolicy);
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [includePassed, setIncludePassed] = useState(false);
  const [includeConsistentCases, setIncludeConsistentCases] =
    useState(false);
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);
  const visibleGates = useMemo(() =>
    report?.gates.filter(gate =>
      includePassed || gate.level !== "PASS") ?? [],
  [report, includePassed]);
  const visibleCases = useMemo(() =>
    report?.cases.filter(item =>
      (includeConsistentCases || item.issues.length > 0) &&
      (!filter.trim() || (item.assetId + " " + item.caseId +
        " " + item.productKey).toLowerCase().includes(
        filter.trim().toLowerCase()))) ?? [],
  [report, includeConsistentCases, filter]);
  function setNumeric(
    name: "maximumInventoryAgeDays" | "minimumMappedPercent" |
      "maximumCaseAgeDays" | "maxCases", value: number,
  ) {
    setPolicy(previous => ({ ...previous, [name]: value }));
    setReport(null);
  }
  function setBoolean(
    name: "allowIncompleteInspections" | "requireCaseAudit" |
      "requireAllCandidateReviews", value: boolean,
  ) {
    setPolicy(previous => ({ ...previous, [name]: value }));
    setReport(null);
  }
  async function inspect() {
    if (busy) return;
    let bindings: unknown;
    try {
      bindings = JSON.parse(bindingsText);
      if (!Array.isArray(bindings))
        throw new Error("Mappings must be a JSON array.");
    } catch (cause) { setError(problem(cause)); return; }
    setBusy(true); setReport(null);
    setError(null); setCopied(false);
    try {
      const response = await fetch(api, {
        method: "POST", cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          importId: importId.trim(),
          inspectionId: inspectionId.trim(),
          bindings, policy,
        }),
      });
      const result: unknown = await response.json();
      if (!response.ok)
        throw new Error((result as { error?: string }).error ??
          "Offline acceptance HTTP " + response.status);
      const value = result as Report;
      if (!value.manualAcceptanceStillRequired ||
          value.databaseWrites !== 0 || value.providerRequests !== 0)
        throw new Error("Unexpected acceptance side-effect contract.");
      setReport(value);
    } catch (cause) {
      setError(problem(cause));
    } finally { setBusy(false); }
  }
  function copy() {
    if (!report) return;
    void navigator.clipboard.writeText(
      JSON.stringify(report, null, 2)).then(() =>
      setCopied(true)).catch(cause =>
      setError(problem(cause)));
  }
  if (!canManage) return null;
  return <section aria-label="Offline acceptance readiness"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 22,
    }}>
    <h2>Assets — offline acceptance review</h2>
    <p>Reconcile saved CSV inventory, an OSV inspection and
      audited human review cases without contacting external
      tenants. This report is an operator acceptance aid,
      not proof of endpoint safety or permission to merge.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Evaluating complete local evidence…</p>}
    <fieldset disabled={busy}>
      <legend>Select the evidence boundary</legend>
      <label>Committed inventory snapshot ID
        <input value={importId} maxLength={150}
          onChange={event => {
            setImportId(event.target.value); setReport(null);
          }}/>
      </label>
      <label>Saved OSV inspection ID
        <input value={inspectionId} maxLength={150}
          onChange={event => {
            setInspectionId(event.target.value); setReport(null);
          }}/>
      </label>
      <label>Explicit product-package bindings
        <textarea rows={5} maxLength={60000}
          spellCheck={false} value={bindingsText}
          onChange={event => {
            setBindingsText(event.target.value); setReport(null);
          }}/>
      </label>
      <details>
        <summary>Example binding format</summary>
        <pre style={{
          overflowWrap: "anywhere", whiteSpace: "pre-wrap",
        }}>{JSON.stringify([{
          inventoryProduct: "Example Package",
          ecosystem: "npm", packageName: "example-package",
          expectedPurl: null,
        }], null, 2)}</pre>
        <p>Use verified mappings for actual products.
          Example data is fictional.</p>
      </details>
      <h3>Offline acceptance policy</h3>
      <div style={{
        display: "grid", gap: 12,
        gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))",
      }}>
        <label>Maximum observation age
          <select value={policy.maximumInventoryAgeDays}
            onChange={event => setNumeric(
              "maximumInventoryAgeDays", Number(event.target.value))}>
            {[7, 14, 30, 60, 90, 180, 365].map(n =>
              <option key={n} value={n}>{n} days</option>)}
          </select>
        </label>
        <label>Minimum mapped software
          <select value={policy.minimumMappedPercent}
            onChange={event => setNumeric(
              "minimumMappedPercent", Number(event.target.value))}>
            {[0, 25, 50, 75, 80, 90, 100].map(n =>
              <option key={n} value={n}>{n}%</option>)}
          </select>
        </label>
        <label>Maximum case age
          <select value={policy.maximumCaseAgeDays}
            onChange={event => setNumeric(
              "maximumCaseAgeDays", Number(event.target.value))}>
            {[7, 30, 60, 90, 180, 365].map(n =>
              <option key={n} value={n}>{n} days</option>)}
          </select>
        </label>
        <label>Maximum cases to examine
          <select value={policy.maxCases}
            onChange={event => setNumeric(
              "maxCases", Number(event.target.value))}>
            {[10, 25, 50, 100, 250, 500, 1000].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox"
          checked={policy.allowIncompleteInspections}
          onChange={event => setBoolean(
            "allowIncompleteInspections", event.target.checked)}/>
        Allow incomplete inspection as an explicit advisory,
        never as successful provider coverage
      </label>
      <label>
        <input type="checkbox" checked={policy.requireCaseAudit}
          onChange={event => setBoolean(
            "requireCaseAudit", event.target.checked)}/>
        Block when a case has no audit record
      </label>
      <label>
        <input type="checkbox" checked={policy.requireAllCandidateReviews}
          onChange={event => setBoolean(
            "requireAllCandidateReviews", event.target.checked)}/>
        Require human cases for all positive advisory candidates
      </label>
      <button type="button" disabled={busy || !importId.trim() ||
        !inspectionId.trim()}
        onClick={() => void inspect()}>
        Assess offline phase acceptance
      </button>
    </fieldset>
    {report && <section>
      <h3>Acceptance results</h3>
      <p>Local checklist eligibility: <strong>{
        report.acceptanceEligible ? "ELIGIBLE FOR HUMAN REVIEW" :
          "BLOCKED"}</strong>.
        Final manual acceptance: <strong>NOT PERFORMED</strong>.</p>
      <p>Evaluated {pretty(report.evaluatedAt)}.
        Inventory: {report.importId}.
        Inspection: {report.inspectionId}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Metric label="Passing gates" value={report.scorecard.passed}/>
        <Metric label="Blocking gates" value={report.scorecard.blocked}/>
        <Metric label="Advisory gates" value={report.scorecard.advisory}/>
        <Metric label="Observed devices" value={report.source.deviceCount}/>
        <Metric label="Stored package queries" value={report.source.queryCount}/>
        <Metric label="Saved review cases" value={report.scorecard.casesEvaluated}/>
        <Metric label="Review cases with issues"
          value={report.scorecard.casesWithIssues}/>
        <Metric label="Potential advisories without case"
          value={report.scorecard.possibleCandidatesWithoutReview}/>
        <Metric label="Mapping coverage"
          value={report.scorecard.mappedPercent}/>
      </div>
      <p>Provider contacted: NO.
        Database writes: NONE.
        Security findings modified: NO.
        CyberScore modified: NO.
        External tenants required: NO.</p>
      <h3>Acceptance gates</h3>
      <label>
        <input type="checkbox" checked={includePassed}
          onChange={event => setIncludePassed(event.target.checked)}/>
        Show passing gates as well as blockers
      </label>
      {visibleGates.map(gate =>
        <GateCard key={gate.id} value={gate}/>)}
      {visibleGates.length === 0 &&
        <p>All selected gates passed this local read-only assessment.
          Independent manual acceptance is still necessary.</p>}
      <h3>Per-case evidence consistency</h3>
      <label>Filter asset, case or software identity
        <input value={filter} onChange={event =>
          setFilter(event.target.value)}/>
      </label>
      <label>
        <input type="checkbox" checked={includeConsistentCases}
          onChange={event => setIncludeConsistentCases(event.target.checked)}/>
        Show cases without observed discrepancies
      </label>
      <p>{visibleCases.length} review cases displayed.</p>
      {visibleCases.map(item => <CaseCard key={item.caseId} value={item}/>)}
      <details>
        <summary>Report provenance and limits</summary>
        <p>Inventory digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.source.inventoryDigest}</code></p>
        <p>Inspection digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.source.inspectionDigest}</code></p>
        <p>Acceptance digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.reportDigest}</code></p>
        <ul>{report.warnings.map((line, i) =>
          <li key={i}>{line}</li>)}</ul>
      </details>
      <button type="button" onClick={copy}>Copy acceptance evidence JSON</button>
      {copied && <p role="status">Local evidence report copied.</p>}
      <p>Exported IDs and source metadata can be sensitive.
        Share only via authorized audit channels.</p>
    </section>}
  </section>;
}
