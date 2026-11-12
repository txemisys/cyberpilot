"use client";

import { useMemo, useState } from "react";

type Evidence = {
  kind: string;
  sourceId: string | null;
  digest: string | null;
  available: boolean;
  independentlyAuthenticated: false;
  sourceClass: string;
  ownerRole: string;
  caveat: string;
};
type Concern = {
  code: string;
  level: "BLOCK" | "HUMAN" | "EXCLUDED";
  owner: string;
  description: string;
  nextAction: string;
  linkedDigests: string[];
  relatedRunId: string | null;
  requiresExternalEvidence: boolean;
  automaticallyResolved: false;
};
type Milestone = {
  sequence: number;
  title: string;
  owner: string;
  prerequisiteCodes: string[];
  expectedDeliverable: string;
  evidencePresent: boolean;
  humanCompletionVerified: false;
  phaseClosedByMilestone: false;
};
type Section = {
  id: string;
  title: string;
  status: "LOCAL_PASS" | "BLOCK" | "HUMAN" | "EXCLUDED";
  sourceNames: string[];
  concerns: string[];
  summary: string;
  accountableRole: string;
  nextStep: string;
};
type HandoffPackage = {
  schema: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  operatorRunId: string | null;
  evaluatedAt: string;
  source: string;
  scope: {
    acceptance: "OFFLINE";
    includesExternalTenants: false;
    includesLiveProviderCheck: false;
    requiresRealHumanWitness: true;
  };
  evidence: Evidence[];
  sections: Section[];
  concerns: Concern[];
  milestones: Milestone[];
  dependencies: Array<{
    from: string;
    to: string;
    satisfiedByLocalEvidence: boolean;
    requiresHuman: boolean;
  }>;
  summary: {
    sourcesListed: number;
    sourcesAvailable: number;
    sections: number;
    localPass: number;
    blocked: number;
    humanReview: number;
    excluded: number;
    operatorStepsRecorded: number;
    independentMatches: number;
    auditRevisionsObserved: number;
    concernsBlocking: number;
    concernsHuman: number;
    preparedForIndependentHumanReview: boolean;
    phaseAccepted: false;
    mergeAuthorized: false;
  };
  provenance: {
    inventoryDigest: string;
    inspectionDigest: string;
    offlineAcceptanceDigest: string;
    privacyDigest: string;
    referenceMatrixDigest: string;
    operationalDigest: string;
    reconciliationDigest: string | null;
    independentReviewDigest: string | null;
    dossierDigest: string;
    releaseDigest: string | null;
    noExternalSignature: true;
  };
  nextActionPlan: Array<{
    priority: number;
    owner: string;
    title: string;
    concernCodes: string[];
    references: string[];
    mustBeManuallyRecorded: true;
    automaticallyExecuted: false;
  }>;
  digest: string;
  limitations: string[];
  databaseWrites: 0;
  providerRequests: 0;
  productAccepted: false;
  githubMergeAuthorized: false;
};
type Body = {
  report: HandoffPackage;
  verification: { valid: boolean; issues: string[] };
  manifest: {
    packageDigest: string;
    unresolvedHumanMilestones: number[];
    sources: Evidence[];
    mergeAuthorized: false;
  };
  checklist: Array<Milestone & {
    actionNeeded: boolean;
    canBeAutomaticallyApproved: false;
  }>;
};
type Props = { slug: string; canManage: boolean };
function json(value: string, label: string) {
  try { return JSON.parse(value) as unknown; }
  catch { throw new Error(label + " must contain valid JSON."); }
}
function saveJson(value: unknown, name: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json",
  });
  const address = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = address;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(address);
}
function errorText(error: unknown) {
  return error instanceof Error ? error.message :
    "Cannot construct the evidence handoff package.";
}
function color(value: string) {
  if (value === "LOCAL_PASS") return "#157e49";
  if (value === "BLOCK") return "#ac3232";
  if (value === "HUMAN") return "#987500";
  return "#687582";
}
export function AssetPhase4HandoffWorkspace({ slug, canManage }: Props) {
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [runId, setRunId] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [acceptancePolicy, setAcceptancePolicy] = useState("{}");
  const [privacyPolicy, setPrivacyPolicy] = useState("{}");
  const [maxAuditEvents, setMaxAuditEvents] = useState(250);
  const [maxEvidenceAgeDays, setMaxEvidenceAgeDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [body, setBody] = useState<Body | null>(null);
  const [owner, setOwner] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [text, setText] = useState("");
  const [showSources, setShowSources] = useState(true);
  const [showSections, setShowSections] = useState(true);
  const [showMilestones, setShowMilestones] = useState(true);
  const [showConcerns, setShowConcerns] = useState(true);
  const [showDependencies, setShowDependencies] = useState(false);
  const [showLimitations, setShowLimitations] = useState(false);
  const [showDigests, setShowDigests] = useState(false);
  const report = body?.report ?? null;
  const owners = useMemo(() => [...new Set(
    report?.sections.map(s => s.accountableRole) ?? [])].sort(), [report]);
  const sections = useMemo(() => report?.sections.filter(s =>
    (status === "ALL" || s.status === status) &&
    (owner === "ALL" || s.accountableRole === owner) &&
    (!text.trim() || [s.title, s.id, s.summary, s.nextStep]
      .join(" ").toLowerCase().includes(text.toLowerCase().trim()))) ??
    [], [report, status, owner, text]);
  async function inspect() {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    setBody(null);
    try {
      const response = await fetch(
        `/api/organizations/${encodeURIComponent(slug)}/assets/phase4-handoff`, {
          method: "POST", cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            importId, inspectionId, runId: runId || null,
            bindings: json(bindings, "Package mappings"),
            acceptancePolicy: json(acceptancePolicy, "Acceptance policy"),
            privacyPolicy: json(privacyPolicy, "Privacy policy"),
            maxAuditEvents, maxEvidenceAgeDays,
          }),
        });
      const payload = await response.json() as Body & {
        error?: string;
      };
      if (!response.ok)
        throw new Error(payload.error ?? "Phase 4 handoff request rejected.");
      if (!payload.verification?.valid)
        throw new Error("Evidence handoff failed independent verification.");
      setBody(payload);
      setNotice("Read-only evidence package generated. Human review remains pending.");
    } catch (cause) {
      setError(errorText(cause));
    } finally { setBusy(false); }
  }
  if (!canManage) return <section aria-label="Phase 4 handoff">
    <h2>Phase 4 evidence handoff</h2>
    <p>ADMIN or OWNER is required to export operational evidence.</p>
  </section>;
  return <section aria-label="Phase 4 evidence handoff"
    style={{ marginBlock: "2rem" }}>
    <h2>Phase 4 accountable human handoff package</h2>
    <p>Consolidate source lineage, operator evidence, independent review
      and outstanding responsibilities. Export an unsigned manifest and
      explicit milestones. The output cannot approve LIVE, backup erasure,
      privacy compliance, product acceptance or a GitHub merge.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <fieldset disabled={busy}>
        <legend>Scope the evidence package precisely</legend>
        <label>Inventory import ID
          <input required minLength={5} maxLength={150} value={importId}
            onChange={event => setImportId(event.target.value)} />
        </label>
        <label>Stored inspection ID
          <input required minLength={5} maxLength={150} value={inspectionId}
            onChange={event => setInspectionId(event.target.value)} />
        </label>
        <label>Operator run ID (optional)
          <input maxLength={150} value={runId}
            onChange={event => setRunId(event.target.value)} />
        </label>
        <label>Exact package bindings JSON
          <textarea rows={4} spellCheck={false} value={bindings}
            onChange={event => setBindings(event.target.value)} />
        </label>
        <label>Offline acceptance policy JSON
          <textarea rows={3} spellCheck={false} value={acceptancePolicy}
            onChange={event => setAcceptancePolicy(event.target.value)} />
        </label>
        <label>Privacy policy JSON
          <textarea rows={3} spellCheck={false} value={privacyPolicy}
            onChange={event => setPrivacyPolicy(event.target.value)} />
        </label>
        <label>Maximum audit events per chain
          <input type="number" min={1} max={1000}
            value={maxAuditEvents}
            onChange={event => setMaxAuditEvents(Number(event.target.value))} />
        </label>
        <label>Evidence age policy, days
          <input type="number" min={1} max={3650}
            value={maxEvidenceAgeDays}
            onChange={event => setMaxEvidenceAgeDays(Number(event.target.value))} />
        </label>
        <button type="submit">Assemble read-only human handoff package</button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {report && <article>
      <h3>Package readiness (not acceptance)</h3>
      <dl>
        <dt>Tenant</dt><dd>{report.organizationId}</dd>
        <dt>Generated at</dt><dd>{report.evaluatedAt}</dd>
        <dt>Source records</dt>
        <dd>{report.summary.sourcesAvailable}/{report.summary.sourcesListed}</dd>
        <dt>Operator steps recorded</dt>
        <dd>{report.summary.operatorStepsRecorded}/9</dd>
        <dt>Independently matched references</dt>
        <dd>{report.summary.independentMatches}/9</dd>
        <dt>Local CAS events</dt>
        <dd>{report.summary.auditRevisionsObserved}</dd>
        <dt>Blocking concerns</dt>
        <dd>{report.summary.concernsBlocking}</dd>
        <dt>Human concerns</dt>
        <dd>{report.summary.concernsHuman}</dd>
        <dt>Prepared for independent review</dt>
        <dd>{String(report.summary.preparedForIndependentHumanReview)}</dd>
        <dt>Product accepted</dt><dd>No</dd>
        <dt>Merge authorized</dt><dd>No</dd>
      </dl>
      <button type="button" onClick={() =>
        saveJson(body, `phase4-human-handoff-${report.importId}.json`)}>
        Export report, manifest and nine-step human checklist
      </button>
      <button type="button" onClick={() =>
        setShowDigests(x => !x)}>
        {showDigests ? "Hide" : "Show"} SHA-256 references
      </button>
      {showDigests && <dl>
        <dt>Package</dt><dd><code>{report.digest}</code></dd>
        <dt>Inventory</dt><dd><code>{report.provenance.inventoryDigest}</code></dd>
        <dt>Inspection</dt><dd><code>{report.provenance.inspectionDigest}</code></dd>
        <dt>CAS reconciliation</dt>
        <dd><code>{report.provenance.reconciliationDigest ?? "MISSING"}</code></dd>
      </dl>}
      <h3>Source manifest</h3>
      <button type="button" onClick={() =>
        setShowSources(x => !x)}>
        {showSources ? "Hide" : "Show"} source register
      </button>
      {showSources && <ol>{report.evidence.map(item =>
        <li key={item.kind}>
          <strong>{item.kind} · {item.available ? "Available" : "Missing"}</strong>
          <p>Role: {item.ownerRole}; source: {item.sourceClass}</p>
          <p>ID: {item.sourceId ?? "None"}</p>
          <p>{item.caveat}</p>
          <p>Independently externally authenticated: No</p>
        </li>)}</ol>}
      <h3>Responsibilities and stage disposition</h3>
      <button type="button" onClick={() => setShowSections(x => !x)}>
        {showSections ? "Hide" : "Show"} sections
      </button>
      {showSections && <section>
        <label>Stage result
          <select value={status}
            onChange={event => setStatus(event.target.value)}>
            <option value="ALL">All</option>
            <option value="LOCAL_PASS">Local check passed</option>
            <option value="BLOCK">Blocked</option>
            <option value="HUMAN">Requires human</option>
            <option value="EXCLUDED">Excluded</option>
          </select>
        </label>
        <label>Accountable role
          <select value={owner} onChange={event => setOwner(event.target.value)}>
            <option value="ALL">All</option>
            {owners.map(item =>
              <option value={item} key={item}>{item}</option>)}
          </select>
        </label>
        <label>Search topic
          <input value={text}
            onChange={event => setText(event.target.value)} />
        </label>
        <ol>{sections.map(item => <li key={item.id}>
          <strong style={{ color: color(item.status) }}>
            {item.status} · {item.title}</strong>
          <p>{item.summary}</p>
          <p>Owner: {item.accountableRole}</p>
          <p>Next: {item.nextStep}</p>
        </li>)}</ol>
      </section>}
      <h3>Manual milestones</h3>
      <button type="button" onClick={() =>
        setShowMilestones(x => !x)}>
        {showMilestones ? "Hide" : "Show"} nine milestone checklist
      </button>
      {showMilestones && <ol>{body?.checklist.map(item =>
        <li key={item.sequence}>
          <strong>{item.title}</strong>
          <p>Responsible: {item.owner}</p>
          <p>Deliverable: {item.expectedDeliverable}</p>
          <p>Local evidence present: {String(item.evidencePresent)}</p>
          <p>Actually completed by human: No independent verification</p>
          {item.prerequisiteCodes.length > 0 &&
            <p>Dependencies: {item.prerequisiteCodes.join(", ")}</p>}
        </li>)}</ol>}
      <h3>Concern register</h3>
      <button type="button" onClick={() =>
        setShowConcerns(x => !x)}>
        {showConcerns ? "Hide" : "Show"} blocking and human concerns
      </button>
      {showConcerns && <ol>{report.concerns.map((item, index) =>
        <li key={item.code + index}>
          <strong>{item.level} · {item.code}</strong>
          <p>{item.description}</p>
          <p>Next: {item.nextAction}</p>
          <p>Owner: {item.owner}</p>
          {item.requiresExternalEvidence &&
            <p>Requires verification outside this tool.</p>}
        </li>)}</ol>}
      <button type="button" onClick={() =>
        setShowDependencies(x => !x)}>
        {showDependencies ? "Hide" : "Show"} inter-stage dependencies
      </button>
      {showDependencies && <ol>{report.dependencies.map((edge, i) =>
        <li key={edge.from + edge.to + i}>
          {edge.from} → {edge.to};
          local prerequisite passed: {String(edge.satisfiedByLocalEvidence)}
        </li>)}</ol>}
      <button type="button" onClick={() =>
        setShowLimitations(x => !x)}>
        {showLimitations ? "Hide" : "Show"} mandatory limitations
      </button>
      {showLimitations && <ul>{report.limitations.map(note =>
        <li key={note}>{note}</li>)}</ul>}
    </article>}
  </section>;
}
