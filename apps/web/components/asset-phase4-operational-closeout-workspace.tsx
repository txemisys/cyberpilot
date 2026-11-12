"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Stage = {
  area: string;
  state: "PASS_LOCAL" | "BLOCKED" | "HUMAN_REVIEW" | "EXCLUDED";
  title: string;
  finding: string;
  evidenceIds: string[];
  prerequisites: string[];
  blockerCodes: string[];
  ownerRole: string;
  nextAction: string;
  scope: string;
  noAutoApproval: true;
};
type Dependency = {
  source: string;
  target: string;
  satisfied: boolean;
  reason: string;
};
type Action = {
  priority: string;
  area: string;
  ownerRole: string;
  description: string;
  evidence: string[];
  mustBeExternallyVerified: boolean;
  mayNotBeAutoCompleted: true;
};
type OperationalReport = {
  schema: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  operatorRunId: string | null;
  evaluatedAt: string;
  sourceDigests: {
    closeout: string;
    operatorSource: string | null;
    audit: string | null;
  };
  stages: Stage[];
  dependencies: Dependency[];
  actions: Action[];
  overview: {
    total: number;
    passed: number;
    blocked: number;
    needsHuman: number;
    excluded: number;
    dependencyBlocked: number;
    evidenceRecorded: number;
    independentChecks: number;
    canRequestHumanReview: boolean;
    technicallyPreparedForOfflineSignoff: boolean;
    operationallyAccepted: false;
    authorizationToMerge: false;
  };
  policy: {
    offlineOnly: true;
    providerLiveTestExcluded: true;
    manualWitnessMustBeConfirmedExternally: true;
  };
  localDatabaseWrites: 0;
  liveProviderRequests: 0;
  mergeAuthorized: false;
  digest: string;
  limitations: string[];
};
type Body = {
  report: OperationalReport;
  verification: { valid: boolean; issues: string[] };
  export: {
    schema: string;
    sourceDigest: string;
    actionPlan: Array<{
      order: number;
      area: string;
      priority: string;
      ownerRole: string;
      description: string;
      predecessors: string[];
      automaticApprovalPossible: false;
      actualCompletionUnknown: true;
    }>;
    cannotAuthorizeMerge: true;
  };
};
type Run = {
  id: string;
  state: string;
  importId: string;
  inspectionId: string;
  revision: number;
};
type Props = { slug: string; canManage: boolean };
function download(value: unknown, name: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
function parse(value: string, name: string) {
  try { return JSON.parse(value) as unknown; }
  catch { throw new Error(name + " must contain valid JSON."); }
}
function friendly(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "Could not construct the Phase 4 operational closeout report.";
}
function statusColor(state: Stage["state"]) {
  switch (state) {
    case "PASS_LOCAL": return "#148047";
    case "BLOCKED": return "#aa2828";
    case "HUMAN_REVIEW": return "#967000";
    default: return "#68757f";
  }
}
export function AssetPhase4OperationalCloseoutWorkspace({
  slug, canManage,
}: Props) {
  const base = `/api/organizations/${encodeURIComponent(slug)}/assets`;
  const [importId, setImportId] = useState("");
  const [inspectionId, setInspectionId] = useState("");
  const [runId, setRunId] = useState("");
  const [runs, setRuns] = useState<Run[]>([]);
  const [bindings, setBindings] = useState("[]");
  const [acceptancePolicy, setAcceptancePolicy] = useState("{}");
  const [privacyPolicy, setPrivacyPolicy] = useState("{}");
  const [maxAuditEvents, setMaxAuditEvents] = useState(250);
  const [report, setReport] = useState<Body | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [ownerFilter, setOwnerFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [onlyBlockedDependencies, setOnlyBlockedDependencies] =
    useState(true);
  const [showSources, setShowSources] = useState(true);
  const [showDependencies, setShowDependencies] = useState(true);
  const [showActions, setShowActions] = useState(true);
  const [showLimitations, setShowLimitations] = useState(false);
  const [showDigests, setShowDigests] = useState(false);
  const value = report?.report ?? null;
  const loadRuns = useCallback(async () => {
    if (!canManage) return;
    const response = await fetch(
      base + "/offline-acceptance-runs?offset=0&limit=100",
      { cache: "no-store" });
    const body = await response.json() as {
      runs?: Run[]; error?: string;
    };
    if (!response.ok)
      throw new Error(body.error ?? "Cannot list current operator runs.");
    setRuns(body.runs ?? []);
  }, [base, canManage]);
  useEffect(() => {
    void loadRuns().catch(cause => setError(friendly(cause)));
  }, [loadRuns]);
  useEffect(() => {
    setReport(null);
  }, [importId, inspectionId, runId, bindings,
    acceptancePolicy, privacyPolicy]);
  const visibleStages = useMemo(() => value?.stages.filter(item =>
    (statusFilter === "ALL" || item.state === statusFilter) &&
    (ownerFilter === "ALL" || item.ownerRole === ownerFilter) &&
    (!search.trim() ||
      [item.title, item.area, item.nextAction, item.finding]
        .join(" ").toLowerCase().includes(search.trim().toLowerCase()))) ??
    [], [value, statusFilter, ownerFilter, search]);
  const owners = useMemo(() => [...new Set(
    value?.stages.map(x => x.ownerRole) ?? [])].sort(), [value]);
  const dependencies = useMemo(() =>
    value?.dependencies.filter(item =>
      !onlyBlockedDependencies || !item.satisfied) ?? [],
    [value, onlyBlockedDependencies]);
  const groupedActions = useMemo(() => {
    const result = new Map<string, Action[]>();
    for (const action of value?.actions ?? []) {
      const prior = result.get(action.ownerRole) ?? [];
      prior.push(action);
      result.set(action.ownerRole, prior);
    }
    return [...result.entries()].sort((a, b) =>
      a[0].localeCompare(b[0]));
  }, [value]);
  async function inspect() {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    setReport(null);
    try {
      const response = await fetch(base +
        "/phase4-operational-closeout", {
          method: "POST", cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            importId, inspectionId, runId: runId || null,
            bindings: parse(bindings, "Package bindings"),
            acceptancePolicy: parse(acceptancePolicy,
              "Offline acceptance policy"),
            privacyPolicy: parse(privacyPolicy, "Privacy policy"),
            maxAuditEvents,
          }),
        });
      const result = await response.json() as Body & { error?: string };
      if (!response.ok)
        throw new Error(result.error ?? "Operational report rejected.");
      if (!result.verification?.valid)
        throw new Error("Operational report failed independent digest checks.");
      setReport(result);
      setNotice("Source-aware closeout plan generated without writes or signoff.");
    } catch (cause) {
      setError(friendly(cause));
    } finally { setBusy(false); }
  }
  if (!canManage) return <section aria-label="Phase 4 operational closeout">
    <h2>Operational closeout preparation</h2>
    <p>Only ADMIN or OWNER can evaluate scoped acceptance material.</p>
  </section>;
  return <section aria-label="Phase 4 operational closeout"
    style={{ marginBlock: "2rem" }}>
    <h2>Phase 4 operational closeout board</h2>
    <p>Examine how actual tenant evidence, independent reference checks,
      release decisions, retention exceptions and human obligations fit
      together. This board only recommends next actions; it cannot
      approve privacy, change the GitHub PR or attest LIVE providers.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <fieldset disabled={busy}>
        <legend>Bind an exact offline evidence selection</legend>
        <label>Inventory ID
          <input required minLength={5} maxLength={150}
            value={importId} onChange={event =>
              setImportId(event.target.value)} />
        </label>
        <label>Persisted OSV inspection ID
          <input required minLength={5} maxLength={150}
            value={inspectionId} onChange={event =>
              setInspectionId(event.target.value)} />
        </label>
        <label>Operator run ID (optional)
          <input value={runId} onChange={event =>
            setRunId(event.target.value)} maxLength={150} />
        </label>
        {runs.length > 0 && <label>Choose a recent operator run
          <select value={runs.some(item => item.id === runId) ?
            runId : ""}
            onChange={event => {
              const chosen = runs.find(item => item.id === event.target.value);
              if (chosen) {
                setRunId(chosen.id);
                setImportId(chosen.importId);
                setInspectionId(chosen.inspectionId);
              } else setRunId("");
            }}>
            <option value="">No operator run</option>
            {runs.map(item => <option key={item.id} value={item.id}>
              {item.state} · {item.importId} · rev {item.revision}
            </option>)}
          </select>
        </label>}
        <label>Exact package mappings JSON
          <textarea spellCheck={false} rows={4} value={bindings}
            onChange={event => setBindings(event.target.value)} />
        </label>
        <label>Offline acceptance policy JSON
          <textarea spellCheck={false} rows={3}
            value={acceptancePolicy}
            onChange={event => setAcceptancePolicy(event.target.value)} />
        </label>
        <label>Privacy policy JSON
          <textarea spellCheck={false} rows={3}
            value={privacyPolicy}
            onChange={event => setPrivacyPolicy(event.target.value)} />
        </label>
        <label>Maximum records per audit chain
          <input type="number" min={1} max={1000}
            value={maxAuditEvents}
            onChange={event => setMaxAuditEvents(Number(event.target.value))} />
        </label>
        <button type="submit">Build read-only operational readiness board</button>
        <button type="button" onClick={() => void loadRuns()
          .catch(cause => setError(friendly(cause)))}>
          Refresh available operator runs
        </button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {value && <article>
      <h3>Closeout readiness summary</h3>
      <p><strong>Operational acceptance: not granted.</strong>
        GitHub merge permission: not granted. These conditions cannot
        be asserted through a local checklist or synthetic regression suite.</p>
      <dl>
        <dt>Tenant</dt><dd>{value.organizationId}</dd>
        <dt>Inspection</dt><dd>{value.inspectionId}</dd>
        <dt>Evidence evaluated at</dt><dd>{value.evaluatedAt}</dd>
        <dt>Areas in closeout plan</dt><dd>{value.overview.total}</dd>
        <dt>Local automated checks passed</dt>
        <dd>{value.overview.passed}</dd>
        <dt>Unresolved blockers</dt><dd>{value.overview.blocked}</dd>
        <dt>Human reviews required</dt>
        <dd>{value.overview.needsHuman}</dd>
        <dt>Explicit LIVE exclusions</dt>
        <dd>{value.overview.excluded}</dd>
        <dt>Prerequisite links not satisfied</dt>
        <dd>{value.overview.dependencyBlocked}</dd>
        <dt>Operator evidence references</dt>
        <dd>{value.overview.evidenceRecorded}/9</dd>
        <dt>Independent evidence matches</dt>
        <dd>{value.overview.independentChecks}/9</dd>
        <dt>Technically prepared</dt>
        <dd>{String(value.overview.technicallyPreparedForOfflineSignoff)}</dd>
        <dt>Ready to request actual human review</dt>
        <dd>{String(value.overview.canRequestHumanReview)}</dd>
      </dl>
      <button type="button" onClick={() => download(report,
        `phase4-operational-plan-${value.importId}.json`)}>
        Export verification, action plan and evidence board
      </button>
      <button type="button" onClick={() => setShowDigests(x => !x)}>
        {showDigests ? "Hide" : "Show"} report fingerprints
      </button>
      {showDigests && <dl>
        <dt>Closeout source</dt>
        <dd><code>{value.sourceDigests.closeout}</code></dd>
        <dt>Operational report</dt><dd><code>{value.digest}</code></dd>
      </dl>}
      <h3>Closeout areas and responsible roles</h3>
      <label>Status
        <select value={statusFilter} onChange={event =>
          setStatusFilter(event.target.value)}>
          <option value="ALL">All</option>
          <option value="BLOCKED">Blocking</option>
          <option value="HUMAN_REVIEW">Requires person</option>
          <option value="PASS_LOCAL">Passed local check</option>
          <option value="EXCLUDED">Not in offline scope</option>
        </select>
      </label>
      <label>Responsible role
        <select value={ownerFilter}
          onChange={event => setOwnerFilter(event.target.value)}>
          <option value="ALL">All responsible roles</option>
          {owners.map(owner =>
            <option key={owner} value={owner}>{owner}</option>)}
        </select>
      </label>
      <label>Search action
        <input value={search}
          onChange={event => setSearch(event.target.value)} />
      </label>
      <ol>{visibleStages.map(stage => <li key={stage.area}>
        <strong style={{ color: statusColor(stage.state) }}>
          {stage.state} · {stage.title}
        </strong>
        <p>Responsible: {stage.ownerRole} · {stage.scope}</p>
        <p>{stage.finding}</p>
        <p><strong>Next action:</strong> {stage.nextAction}</p>
        {stage.prerequisites.length > 0 &&
          <p>Prerequisites: {stage.prerequisites.join(", ")}</p>}
        {stage.evidenceIds.length > 0 &&
          <p>Evidence: {stage.evidenceIds.join(", ")}</p>}
        <p>Automatic approval: prohibited.</p>
      </li>)}</ol>
      <h3>Dependencies</h3>
      <button type="button" onClick={() =>
        setShowDependencies(x => !x)}>
        {showDependencies ? "Hide" : "Show"} dependency edges
      </button>
      {showDependencies && <section>
        <label><input type="checkbox"
          checked={onlyBlockedDependencies}
          onChange={event =>
            setOnlyBlockedDependencies(event.target.checked)} />
          Show unsatisfied dependencies only
        </label>
        <ul>{dependencies.map((edge, index) => <li key={
          edge.source + edge.target + index}>
          <strong>{edge.source} → {edge.target}</strong>
          <p>{edge.satisfied ? "Local prerequisite passed" :
            "Prerequisite remains open"}</p>
          <p>{edge.reason}</p>
        </li>)}</ul>
      </section>}
      <h3>Responsibilities and next actions</h3>
      <button type="button" onClick={() =>
        setShowActions(x => !x)}>
        {showActions ? "Hide" : "Show"} owner action groups
      </button>
      {showActions && <section>{groupedActions.map(([owner, actions]) =>
        <section key={owner}>
          <h4>{owner}</h4>
          <ol>{actions.map(action => <li key={action.area}>
            <strong>{action.priority}: {action.area}</strong>
            <p>{action.description}</p>
            {action.mustBeExternallyVerified &&
              <p>Independent confirmation required.</p>}
          </li>)}</ol>
        </section>)}</section>}
      <h3>Evidence caveats</h3>
      <button type="button" onClick={() =>
        setShowSources(x => !x)}>
        {showSources ? "Hide" : "Show"} provenance
      </button>
      {showSources && <p>Local PostgreSQL evidence is a bounded
        internal source. CI and external provider states are intentionally
        not inferred by this report.</p>}
      <button type="button" onClick={() =>
        setShowLimitations(x => !x)}>
        {showLimitations ? "Hide" : "Show"} operational caveats
      </button>
      {showLimitations && <ul>{value.limitations.map(item =>
        <li key={item}>{item}</li>)}</ul>}
    </article>}
  </section>;
}
