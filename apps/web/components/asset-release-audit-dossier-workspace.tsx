"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type AuditIssue = {
  code: string;
  severity: "BLOCK" | "REVIEW";
  eventId: string | null;
  revision: number | null;
  detail: string;
};
type AuditEvent = {
  id: string;
  action: string;
  operation: string | null;
  occurredAt: string;
  actorUserId: string | null;
  actorType: string;
  from: string | null;
  to: string | null;
  revisionBefore: number | null;
  revisionAfter: number | null;
  evidenceBundleDigest: string | null;
  reason: string | null;
  acknowledgements: string[];
  blockersAtDecision: string[];
  integrity: string;
  issues: AuditIssue[];
};
type Dossier = {
  schema: string;
  checkedAt: string;
  organizationId: string;
  reviewId: string;
  importId: string;
  inspectionId: string;
  persistedState: string;
  persistedRevision: number;
  persistedBundleDigest: string;
  persistedVerification: { verified: boolean; reasons: string[] };
  totalEvents: number;
  completeEventSet: boolean;
  events: AuditEvent[];
  revisions: Array<{
    revision: number; operation: string;
    from: string | null; to: string;
    actorUserId: string | null; occurredAt: string;
    evidenceBundleDigest: string; changeSummary: string[];
  }>;
  issues: AuditIssue[];
  blockers: number;
  reviewsNeeded: number;
  auditConsistent: boolean;
  evidenceConsistent: boolean;
  decisionComplete: boolean;
  requiresHumanReconciliation: boolean;
  acceptanceRecorded: boolean;
  digest: string;
  caveats: string[];
};
type DossierResponse = {
  dossier: Dossier;
  verification: { valid: boolean; reasons: string[] };
  playbook: Array<{ priority: string; issue: string; instruction: string }>;
};
type ListResponse = {
  reviews: Array<{
    id: string; state: string; revision: number;
    importId: string; inspectionId: string;
    evidenceBundleDigest: string;
  }>;
  total: number;
};
type Props = { slug: string; canManage: boolean };
function requestError(response: Response, value: unknown) {
  if (typeof value === "object" && value &&
      "error" in value && typeof value.error === "string")
    return value.error;
  return "Audit request was rejected (HTTP " + response.status + ").";
}
function exportJson(value: unknown, name: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)],
    { type: "application/json" });
  const address = URL.createObjectURL(blob);
  const node = document.createElement("a");
  node.href = address;
  node.download = name;
  document.body.appendChild(node);
  node.click();
  node.remove();
  URL.revokeObjectURL(address);
}
function compact(value: string | null | undefined) {
  if (!value) return "—";
  if (value.length < 23) return value;
  return value.slice(0, 12) + "…" + value.slice(-8);
}
function labelFor(state: boolean) {
  return state ? "Verified" : "Needs reconciliation";
}
function colorFor(level: string) {
  return level === "BLOCK" || level === "INVALID" ? "#a61b1b" :
    level === "REVIEW" ? "#986a00" : "#167548";
}
export function AssetReleaseAuditDossierWorkspace({
  slug, canManage,
}: Props) {
  const [reviewId, setReviewId] = useState("");
  const [known, setKnown] = useState<ListResponse["reviews"]>([]);
  const [maximumEvents, setMaximumEvents] = useState(250);
  const [includeDecisionReasons, setIncludeDecisionReasons] = useState(false);
  const [includeMetadata, setIncludeMetadata] = useState(false);
  const [report, setReport] = useState<DossierResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadingList, setLoadingList] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [gateFilter, setGateFilter] = useState<"ALL" | "BLOCK" | "REVIEW">("ALL");
  const [eventFilter, setEventFilter] = useState("ALL");
  const [showDigest, setShowDigest] = useState(false);
  const [showIssues, setShowIssues] = useState(true);
  const [showTimeline, setShowTimeline] = useState(true);
  const [showEvents, setShowEvents] = useState(true);
  const [showPlaybook, setShowPlaybook] = useState(true);
  const [showCaveats, setShowCaveats] = useState(true);
  const base = `/api/organizations/${encodeURIComponent(slug)}/assets`;
  const listReviews = useCallback(async () => {
    setLoadingList(true);
    try {
      const response = await fetch(
        base + "/release-reviews?offset=0&limit=100",
        { cache: "no-store" });
      const payload = await response.json() as ListResponse & {
        error?: string;
      };
      if (!response.ok) throw new Error(requestError(response, payload));
      setKnown(payload.reviews);
      setReviewId(current => current || payload.reviews[0]?.id || "");
      setMessage(payload.total > payload.reviews.length
        ? "Only the first 100 reviews are listed; enter another ID manually."
        : "");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Could not list local reviews.");
    } finally {
      setLoadingList(false);
    }
  }, [base]);
  useEffect(() => {
    if (canManage) void listReviews();
  }, [canManage, listReviews]);
  async function inspect() {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    setReport(null);
    try {
      const response = await fetch(base + "/release-audit-dossier", {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reviewId, maximumEvents, includeDecisionReasons,
          includeMetadata,
        }),
      });
      const value = await response.json() as DossierResponse & {
        error?: string;
      };
      if (!response.ok) throw new Error(requestError(response, value));
      if (!value.verification?.valid)
        throw new Error("The returned dossier did not pass independent integrity checks.");
      setReport(value);
      setMessage("Read-only historical reconstruction completed. No decision was written.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message :
        "Audit inspection failed.");
    } finally {
      setBusy(false);
    }
  }
  const dossier = report?.dossier ?? null;
  const issues = useMemo(() => dossier?.issues.filter(item =>
    gateFilter === "ALL" || item.severity === gateFilter) ?? [],
    [dossier, gateFilter]);
  const events = useMemo(() => dossier?.events.filter(item =>
    eventFilter === "ALL" || item.operation === eventFilter ||
    (eventFilter === "INVALID" && item.integrity === "INVALID")) ?? [],
    [dossier, eventFilter]);
  const distinctOperations = useMemo(() =>
    [...new Set(dossier?.events.map(item => item.operation).filter(
      (item): item is string => !!item) ?? [])].sort(), [dossier]);
  if (!canManage) return <section aria-label="Release audit dossier">
    <h2>Offline release decision audit</h2>
    <p>Only organization administrators may inspect human release audit history.</p>
  </section>;
  return <section aria-label="Offline release decision audit"
    style={{ marginBlock: "2rem" }}>
    <h2>Release audit dossier and CAS history</h2>
    <p>Inspect persisted human release events independently of the original
      decision workflow. Missing revisions, cross-tenant references, altered
      evidence and incomplete reasons are treated conservatively. This is not
      a signature, a LIVE provider validation, or approval of retention.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect(); }}>
      <fieldset disabled={busy || loadingList}>
        <legend>Exact tenant-scoped release review</legend>
        <label>Review ID
          <input value={reviewId}
            onChange={event => setReviewId(event.target.value)}
            minLength={5} maxLength={150} required />
        </label>
        {known.length > 0 && <label>Choose a recent review
          <select value={known.some(item => item.id === reviewId)
            ? reviewId : ""}
            onChange={event => setReviewId(event.target.value)}>
            {!known.some(item => item.id === reviewId) &&
              <option value="">Custom review ID</option>}
            {known.map(item => <option key={item.id} value={item.id}>
              {item.state} · {item.importId} · revision {item.revision}
            </option>)}
          </select>
        </label>}
        <label>Maximum audit rows to inspect
          <input type="number" min={1} max={1000}
            value={maximumEvents}
            onChange={event => setMaximumEvents(Number(event.target.value))} />
        </label>
        <label>
          <input type="checkbox" checked={includeDecisionReasons}
            onChange={event => setIncludeDecisionReasons(event.target.checked)} />
          Include human decision reasons in this private response
        </label>
        <label>
          <input type="checkbox" checked={includeMetadata}
            onChange={event => setIncludeMetadata(event.target.checked)} />
          Include detailed audit metadata diagnostics
        </label>
        <button type="submit">Inspect complete bounded history</button>
        <button type="button" onClick={() => void listReviews()}>
          Reload review list
        </button>
      </fieldset>
    </form>
    {error && <p role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {dossier && <article>
      <h3>Reconstruction result</h3>
      <dl>
        <dt>Current persisted state</dt>
        <dd>{dossier.persistedState}</dd>
        <dt>CAS revision</dt>
        <dd>{dossier.persistedRevision}</dd>
        <dt>Audit integrity</dt>
        <dd style={{ color: colorFor(dossier.auditConsistent ? "PASS" : "BLOCK") }}>
          {labelFor(dossier.auditConsistent)}
        </dd>
        <dt>Persisted evidence integrity</dt>
        <dd>{labelFor(dossier.evidenceConsistent)}</dd>
        <dt>All events collected</dt>
        <dd>{dossier.completeEventSet ? "Yes" : "No"}</dd>
        <dt>Events examined</dt>
        <dd>{dossier.totalEvents}</dd>
        <dt>Mandatory blockers</dt>
        <dd>{dossier.blockers}</dd>
        <dt>Additional reviews</dt>
        <dd>{dossier.reviewsNeeded}</dd>
        <dt>Human offline acceptance</dt>
        <dd>{dossier.acceptanceRecorded
          ? "Audited acceptance recorded (not LIVE)"
          : "Not established by this audit history"}</dd>
        <dt>Examined at</dt>
        <dd>{dossier.checkedAt}</dd>
      </dl>
      <button type="button" onClick={() => setShowDigest(value => !value)}>
        {showDigest ? "Hide" : "Show"} integrity digests
      </button>
      {showDigest && <div>
        <p>Audit dossier digest: <code>{dossier.digest}</code></p>
        <p>Persisted bundle digest:
          <code>{dossier.persistedBundleDigest}</code>
        </p>
        <p>These hashes detect local changes only and cannot authenticate an author.</p>
      </div>}
      <button type="button" onClick={() => exportJson(report,
        `release-audit-${dossier.reviewId}.json`)}>
        Export bounded audit dossier JSON
      </button>
      <h3>
        <button type="button" onClick={() => setShowIssues(x => !x)}>
          {showIssues ? "Hide" : "Show"} issues ({dossier.issues.length})
        </button>
      </h3>
      {showIssues && <section aria-label="Release audit issues">
        <label>Severity
          <select value={gateFilter} onChange={event =>
            setGateFilter(event.target.value as typeof gateFilter)}>
            <option value="ALL">All</option>
            <option value="BLOCK">Mandatory blockers</option>
            <option value="REVIEW">Review required</option>
          </select>
        </label>
        {issues.length === 0 && <p>No matching issues in this stored audit.</p>}
        <ul>
          {issues.map((item, index) => <li key={item.code + index}>
            <strong style={{ color: colorFor(item.severity) }}>
              {item.severity} · {item.code}
            </strong>
            <p>{item.detail}</p>
            {item.eventId && <p>Event: <code>{item.eventId}</code></p>}
            {item.revision !== null && <p>Revision {item.revision}</p>}
          </li>)}
        </ul>
      </section>}
      <h3><button type="button" onClick={() =>
        setShowTimeline(x => !x)}>
        {showTimeline ? "Hide" : "Show"} revision timeline
      </button></h3>
      {showTimeline && <ol>
        {dossier.revisions.map(item => <li key={item.eventId}>
          <strong>Revision {item.revision}: {item.operation}</strong>
          <p>{item.from ?? "INITIAL"} → {item.to}</p>
          <p>Event {item.eventId} · {item.occurredAt}</p>
          <p>Actor: {item.actorUserId ?? "UNVERIFIED"}</p>
          <p>Digest: <code>{compact(item.evidenceBundleDigest)}</code></p>
          <ul>{item.changeSummary.map(code =>
            <li key={code}>{code}</li>)}</ul>
        </li>)}
      </ol>}
      <h3><button type="button" onClick={() =>
        setShowEvents(x => !x)}>
        {showEvents ? "Hide" : "Show"} raw normalized audit events
      </button></h3>
      {showEvents && <section>
        <label>Operation
          <select value={eventFilter} onChange={event =>
            setEventFilter(event.target.value)}>
            <option value="ALL">All operations</option>
            <option value="INVALID">Invalid events</option>
            {distinctOperations.map(op =>
              <option value={op} key={op}>{op}</option>)}
          </select>
        </label>
        {events.length === 0 && <p>No matching audit events.</p>}
        <ol>{events.map(event => <li key={event.id}>
          <strong style={{ color: colorFor(event.integrity) }}>
            {event.operation ?? event.action} · {event.integrity}
          </strong>
          <p>{event.occurredAt} · revision {event.revisionAfter ?? "?"}</p>
          <p>Actor {event.actorUserId ?? "UNKNOWN"} ·
            {event.from ?? "INITIAL"} → {event.to ?? "UNKNOWN"}</p>
          <p>Bundle digest: <code>{compact(event.evidenceBundleDigest)}</code></p>
          {event.reason && <p>Reason: {event.reason}</p>}
          {event.blockersAtDecision.length > 0 &&
            <p>Decision blockers: {event.blockersAtDecision.join(", ")}</p>}
          {event.issues.map((problem, index) =>
            <p role="alert" key={problem.code + index}>
              {problem.code}: {problem.detail}
            </p>)}
        </li>)}</ol>
      </section>}
      <h3><button type="button" onClick={() =>
        setShowPlaybook(x => !x)}>
        {showPlaybook ? "Hide" : "Show"} reconciliation playbook
      </button></h3>
      {showPlaybook && <ol>
        {report?.playbook.map((step, index) => <li key={index}>
          <strong>{step.priority} · {step.issue}</strong>
          <p>{step.instruction}</p>
        </li>)}
      </ol>}
      <h3><button type="button" onClick={() =>
        setShowCaveats(x => !x)}>
        {showCaveats ? "Hide" : "Show"} evidence limitations
      </button></h3>
      {showCaveats && <ul>{dossier.caveats.map(note =>
        <li key={note}>{note}</li>)}</ul>}
    </article>}
  </section>;
}
