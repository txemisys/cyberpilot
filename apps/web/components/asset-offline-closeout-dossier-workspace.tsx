"use client";

import { useEffect, useMemo, useState } from "react";

type CloseoutGate = {
  code: string;
  status: "PASS" | "BLOCK" | "REVIEW" | "EXCLUDED";
  evidenceKind: string;
  explanation: string;
  nextAction: string;
  evidence: string[];
  observed: number | null;
  expected: number | null;
  affectedIds: string[];
};
type CloseoutDossier = {
  schema: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  evaluatedAt: string;
  source: string;
  inventory: {
    inventoryDigest: string; inspectionDigest: string;
    deviceCount: number; queryCount: number;
    mappedPercent: number; possibleCandidates: number;
    unknownEvidence: number; casesEvaluated: number;
    positiveWithoutReview: number;
    completeWithinSnapshot: boolean;
  };
  acceptance: {
    digest: string; reportValid: boolean; eligible: boolean;
    blockedGates: string[]; advisoryGates: string[];
    scorecard: { blocked: number; advisory: number;
      casesEvaluated: number };
  };
  privacy: {
    digest: string; fullyExamined: boolean;
    blocked: number; reviewNeeded: number;
    pendingOperatorApproval: boolean;
    hostnameSignals: number; ownerHashSignals: number;
    openCasesBeyondPolicy: number; importCount: number;
    gates: Array<{ id: string; severity: string;
      explanation: string; affectedImportIds: string[] }>;
  };
  scenario: {
    digest: string; passed: number; executed: number;
    failed: number; complete: boolean;
    mismatches: string[]; notTenantAcceptance: true;
  };
  release: {
    present: boolean; reviewId: string | null; state: string;
    revision: number | null; verified: boolean;
    acceptedOffline: boolean; auditConsistent: boolean;
    auditEvents: number; decidedBy: string | null;
    auditIssues: string[]; independentIssues: string[];
  };
  retention: {
    present: boolean; reviewId: string | null;
    state: string; verified: boolean;
    backupDisposition: string; personalDataDisposition: string;
    nextReviewAt: string | null; outstandingExceptions: number;
    independentIssues: string[];
  };
  gates: CloseoutGate[];
  counts: {
    passed: number; blocked: number; manualReview: number;
    excluded: number; total: number;
  };
  missingHumanActions: string[];
  reproducibleAutomatedEvaluation: boolean;
  readyForManualCloseout: boolean;
  offlineProductAccepted: false;
  mergeAuthorized: false;
  liveProviderValidated: false;
  sourceDigest: string;
  digest: string;
  caveats: string[];
};
type ReportResponse = {
  dossier: CloseoutDossier;
  verification: { valid: boolean; issues: string[] };
  manifest: {
    sources: Array<{ type: string; digest: string;
      identifier: string | null }>;
    missingEvidence: string[];
    outstandingManualSignoffs: string[];
    dossierDigest: string;
  };
  playbook: Array<{
    gate: string; status: string; explanation: string;
    nextAction: string; cannotSelfApprove: boolean;
  }>;
};
type Props = { slug: string; canManage: boolean };
type Filter = "ALL" | "BLOCK" | "REVIEW" | "PASS" | "EXCLUDED";
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
function maybeParse(input: string, label: string) {
  try { return JSON.parse(input) as unknown; }
  catch { throw new Error("Invalid JSON in " + label + "."); }
}
function readable(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Offline acceptance dossier unavailable.";
}
function badge(status: string) {
  switch (status) {
    case "PASS": return "Verified automated gate";
    case "BLOCK": return "Blocking evidence issue";
    case "REVIEW": return "Explicit human action required";
    default: return "Out of offline scope";
  }
}
function statusColor(status: string) {
  if (status === "PASS") return "#147d46";
  if (status === "BLOCK") return "#bd3535";
  if (status === "REVIEW") return "#956c00";
  return "#66717b";
}
export function AssetOfflineCloseoutDossierWorkspace({
  slug, canManage,
}: Props) {
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [bindings, setBindings] = useState("[]");
  const [acceptancePolicy, setAcceptancePolicy] = useState("{}");
  const [privacyPolicy, setPrivacyPolicy] = useState("{}");
  const [maxAuditEvents, setMaxAuditEvents] = useState(250);
  const [includeHumanReasons, setIncludeHumanReasons] = useState(false);
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<Filter>("ALL");
  const [search, setSearch] = useState("");
  const [showManifest, setShowManifest] = useState(true);
  const [showPrivacy, setShowPrivacy] = useState(true);
  const [showSources, setShowSources] = useState(true);
  const [showPlaybook, setShowPlaybook] = useState(true);
  const [showCaveats, setShowCaveats] = useState(false);
  const [showRawDigests, setShowRawDigests] = useState(false);
  const [scopeReviewed, setScopeReviewed] = useState(false);
  const [limitationsReviewed, setLimitationsReviewed] = useState(false);
  const [humanWitness, setHumanWitness] = useState(false);
  const [privacyContact, setPrivacyContact] = useState(false);
  const [backupContact, setBackupContact] = useState(false);
  const [exportConfirmed, setExportConfirmed] = useState(false);
  const dossier = report?.dossier ?? null;
  const filtered = useMemo(() => dossier?.gates.filter(gate =>
    (filter === "ALL" || gate.status === filter) &&
    (search.trim() === "" ||
      (gate.code + gate.explanation + gate.nextAction).toLowerCase()
        .includes(search.trim().toLowerCase()))) ?? [],
    [dossier, filter, search]);
  const manualChecklist = useMemo(() => [
    ["scope", scopeReviewed, "Tenant, import and inspection IDs checked against reality."],
    ["limitations", limitationsReviewed, "Partial coverage and external/LIVE exclusions understood."],
    ["witness", humanWitness, "Representative operator walk-through performed outside this synthetic tool."],
    ["privacy", privacyContact, "Responsible privacy officer independently contacted."],
    ["backup", backupContact, "Backup and export lifecycle owner independently contacted."],
    ["exports", exportConfirmed, "Evidence package exported to an appropriate secure repository."],
  ] as const, [scopeReviewed, limitationsReviewed, humanWitness,
    privacyContact, backupContact, exportConfirmed]);
  const manualChecklistComplete = manualChecklist.every(x => x[1]);
  useEffect(() => {
    setReport(null);
    setMessage("");
  }, [importId, inspectionId, bindings, acceptancePolicy, privacyPolicy]);
  async function evaluate() {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    setReport(null);
    try {
      const input = {
        importId, inspectionId,
        bindings: maybeParse(bindings, "package bindings"),
        acceptancePolicy: maybeParse(
          acceptancePolicy, "acceptance policy"),
        privacyPolicy: maybeParse(privacyPolicy, "privacy policy"),
        maxAuditEvents, includeHumanReasons,
      };
      const response = await fetch(
        `/api/organizations/${encodeURIComponent(slug)}/assets/offline-closeout-dossier`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store",
          body: JSON.stringify(input),
        });
      const result = await response.json() as ReportResponse & {
        error?: string;
      };
      if (!response.ok)
        throw new Error(result.error ?? "Closeout evaluation was rejected.");
      if (!result.verification?.valid)
        throw new Error("Independent dossier integrity verification failed.");
      setReport(result);
      setMessage("Read-only evidence evaluation completed. Manual acceptance remains independent.");
    } catch (cause) {
      setError(readable(cause));
    } finally {
      setBusy(false);
    }
  }
  if (!canManage) return <section aria-label="Offline closeout access">
    <h2>Offline phase acceptance dossier</h2>
    <p>ADMIN/OWNER access is required for source evidence evaluation.</p>
  </section>;
  return <section aria-label="Offline phase closeout dossier"
    style={{ marginBlock: "2rem" }}>
    <h2>Phase 4: reproducible offline closeout</h2>
    <p>This read-only dossier combines stored inventory, OSV inspection,
      human review cases, privacy readiness, synthetic reference matrix
      and independently audited manual decisions. It never marks Phase 4
      complete, signs a legal approval, erases backups or contacts a provider.</p>
    <form onSubmit={event => { event.preventDefault(); void evaluate(); }}>
      <fieldset disabled={busy}>
        <legend>Exactly scoped evidence</legend>
        <label>Inventory import identifier
          <input required value={importId}
            onChange={event => setImportId(event.target.value)}
            minLength={5} maxLength={150} />
        </label>
        <label>Stored OSV inspection identifier
          <input required value={inspectionId}
            onChange={event => setInspectionId(event.target.value)}
            minLength={5} maxLength={150} />
        </label>
        <label>Package-to-provider bindings JSON array
          <textarea rows={5} spellCheck={false} value={bindings}
            onChange={event => setBindings(event.target.value)} />
        </label>
        <label>Acceptance policy JSON object
          <textarea rows={3} spellCheck={false} value={acceptancePolicy}
            onChange={event => setAcceptancePolicy(event.target.value)} />
        </label>
        <label>Privacy policy JSON object
          <textarea rows={3} spellCheck={false} value={privacyPolicy}
            onChange={event => setPrivacyPolicy(event.target.value)} />
        </label>
        <label>Maximum release audit events
          <input type="number" min={1} max={1000}
            value={maxAuditEvents}
            onChange={event => setMaxAuditEvents(Number(event.target.value))} />
        </label>
        <label>
          <input type="checkbox" checked={includeHumanReasons}
            onChange={event => setIncludeHumanReasons(event.target.checked)} />
          Include human operator reasons in private report
        </label>
        <button type="submit">Evaluate tenant evidence (read-only)</button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {dossier && <article>
      <h3>Closeout evidence summary</h3>
      <p>Automated source checks complete:
        {dossier.reproducibleAutomatedEvaluation ? "Yes" : "No"}.
        Human product acceptance: <strong>not granted</strong>.
        Merge authorization: <strong>not granted</strong>.</p>
      <dl>
        <dt>Tenant</dt><dd>{dossier.organizationId}</dd>
        <dt>Evaluated</dt><dd>{dossier.evaluatedAt}</dd>
        <dt>Automated checks passed</dt><dd>{dossier.counts.passed}</dd>
        <dt>Evidence blockers</dt><dd>{dossier.counts.blocked}</dd>
        <dt>Manual reviews</dt><dd>{dossier.counts.manualReview}</dd>
        <dt>Explicit exclusions</dt><dd>{dossier.counts.excluded}</dd>
        <dt>Full gate count</dt><dd>{dossier.counts.total}</dd>
        <dt>Reference suite</dt>
        <dd>{dossier.scenario.passed}/{dossier.scenario.executed}
          synthetic cases; {dossier.scenario.complete ?
            "complete reference" : "incomplete reference"}</dd>
        <dt>Release review</dt>
        <dd>{dossier.release.state}; verified:
          {String(dossier.release.verified)}; audited:
          {String(dossier.release.auditConsistent)}</dd>
        <dt>Retention review</dt>
        <dd>{dossier.retention.state}; verified:
          {String(dossier.retention.verified)}</dd>
      </dl>
      <button type="button" onClick={() =>
        saveJson(report, `assets-phase4-dossier-${dossier.importId}.json`)}>
        Export full dossier, manifest and action plan
      </button>
      <button type="button" onClick={() =>
        setShowRawDigests(x => !x)}>
        {showRawDigests ? "Hide" : "Show"} source digests
      </button>
      {showRawDigests && <dl>
        <dt>Inventory</dt><dd><code>{dossier.inventory.inventoryDigest}</code></dd>
        <dt>Inspection</dt><dd><code>{dossier.inventory.inspectionDigest}</code></dd>
        <dt>Acceptance</dt><dd><code>{dossier.acceptance.digest}</code></dd>
        <dt>Privacy</dt><dd><code>{dossier.privacy.digest}</code></dd>
        <dt>Reference suite</dt><dd><code>{dossier.scenario.digest}</code></dd>
        <dt>Manifest</dt><dd><code>{dossier.sourceDigest}</code></dd>
        <dt>Dossier</dt><dd><code>{dossier.digest}</code></dd>
      </dl>}
      <h3>Evidence gatebook</h3>
      <label>Filter by result
        <select value={filter} onChange={event =>
          setFilter(event.target.value as Filter)}>
          <option value="ALL">All gates</option>
          <option value="BLOCK">Blockers</option>
          <option value="REVIEW">Human actions</option>
          <option value="PASS">Passed</option>
          <option value="EXCLUDED">Out of scope</option>
        </select>
      </label>
      <label>Find gate or instruction
        <input value={search}
          onChange={event => setSearch(event.target.value)} />
      </label>
      <ol>{filtered.map(item => <li key={item.code}>
        <strong style={{ color: statusColor(item.status) }}>
          {item.code} — {badge(item.status)}</strong>
        <p>{item.explanation}</p>
        <p><strong>Next:</strong> {item.nextAction}</p>
        {item.observed !== null && <p>Observed: {item.observed};
          expected: {item.expected ?? "not constrained"}</p>}
        {item.evidence.length > 0 && <p>Evidence references:
          {item.evidence.join(", ")}</p>}
        <p>Evidence category: {item.evidenceKind}</p>
      </li>)}</ol>
      <h3>
        <button type="button" onClick={() =>
          setShowSources(x => !x)}>
          {showSources ? "Hide" : "Show"} persisted source summary
        </button>
      </h3>
      {showSources && <section>
        <p>Declared assets: {dossier.inventory.deviceCount};
          stored OSV queries: {dossier.inventory.queryCount};
          mapped: {dossier.inventory.mappedPercent}%.</p>
        <p>Positive candidates without review:
          {dossier.inventory.positiveWithoutReview};
          unknown source evidence: {dossier.inventory.unknownEvidence}.</p>
        <p>Privacy signals: {dossier.privacy.hostnameSignals} hostnames,
          {dossier.privacy.ownerHashSignals} owner hashes.</p>
        <p>Open case age breaches:
          {dossier.privacy.openCasesBeyondPolicy}.</p>
      </section>}
      <h3><button type="button" onClick={() =>
        setShowPrivacy(x => !x)}>
        {showPrivacy ? "Hide" : "Show"} privacy gates
      </button></h3>
      {showPrivacy && <ul>{dossier.privacy.gates.map(item =>
        <li key={item.id}>
          <strong>{item.severity} · {item.id}</strong>
          <p>{item.explanation}</p>
        </li>)}</ul>}
      <h3><button type="button" onClick={() =>
        setShowManifest(x => !x)}>
        {showManifest ? "Hide" : "Show"} evidence manifest
      </button></h3>
      {showManifest && <ul>{report?.manifest.sources.map(item =>
        <li key={item.type}>
          <strong>{item.type}</strong> · {item.identifier}
          <p><code>{item.digest}</code></p>
        </li>)}</ul>}
      <h3><button type="button" onClick={() =>
        setShowPlaybook(x => !x)}>
        {showPlaybook ? "Hide" : "Show"} closing actions
      </button></h3>
      {showPlaybook && <ol>{report?.playbook.map(item =>
        <li key={item.gate}>
          <strong>{item.status} · {item.gate}</strong>
          <p>{item.nextAction}</p>
          {item.cannotSelfApprove && <p>Independent human review required.</p>}
        </li>)}</ol>}
      <h3>Local operator walkthrough checklist</h3>
      <p>Checkmarks are only a temporary local display; they are not
        uploaded as operator signatures or audit decisions.</p>
      <fieldset>
        <legend>Explicit preparation confirmations</legend>
        {manualChecklist.map(([id, checked, description]) =>
          <label key={id} style={{ display: "block" }}>
            <input type="checkbox" checked={checked}
              onChange={event => {
                const value = event.target.checked;
                if (id === "scope") setScopeReviewed(value);
                if (id === "limitations") setLimitationsReviewed(value);
                if (id === "witness") setHumanWitness(value);
                if (id === "privacy") setPrivacyContact(value);
                if (id === "backup") setBackupContact(value);
                if (id === "exports") setExportConfirmed(value);
              }} />
            {description}
          </label>)}
      </fieldset>
      <p>Local checklist completed: {manualChecklistComplete ? "Yes" : "No"}.
        This does not change the backend decision or permit merging.</p>
      <button type="button" onClick={() => saveJson({
        schema: "cyberpilot.assets.offline.local-checklist.v1",
        generatedAt: new Date().toISOString(),
        organizationId: dossier.organizationId,
        importId: dossier.importId,
        dossierDigest: dossier.digest,
        localSelections: manualChecklist.map(([id, checked, label]) =>
          ({ id, checked, label })),
        independentlyVerified: false,
        authorizationToMerge: false,
      }, `offline-local-checklist-${dossier.importId}.json`)}>
        Export explicitly unverified local checklist
      </button>
      <h3><button type="button" onClick={() =>
        setShowCaveats(x => !x)}>
        {showCaveats ? "Hide" : "Show"} source and acceptance caveats
      </button></h3>
      {showCaveats && <ul>{dossier.caveats.map(note =>
        <li key={note}>{note}</li>)}</ul>}
    </article>}
  </section>;
}
