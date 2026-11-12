"use client";

import { useEffect, useMemo, useState } from "react";

type Node = {
  id: string;
  type: "SIGNATURE" | "SCHEDULE_RUN" | "QUOTA" |
    "INSPECTION" | "AUDIT";
  referenceId: string; scheduleId: string | null;
  eventAt: string; state: string; digest: string;
  attributes: Record<string, string | number | boolean | null>;
};
type Edge = {
  from: string; to: string;
  relation: string;
  confidence: "EXACT_REFERENCE" | "HEURISTIC";
  evidence: string;
};
type Anomaly = {
  id: string; code: string;
  severity: "WARNING" | "CRITICAL";
  nodeId: string | null;
  description: string; remediation: string;
  supportedBy: string[];
};
type Report = {
  schema: string; organizationId: string;
  evaluatedAt: string; windowStart: string; windowEnd: string;
  complete: boolean; truncatedCollections: string[];
  collectionCounts: {
    signatures: number; runs: number; quotas: number;
    inspections: number; audits: number;
  };
  nodes: Node[]; edges: Edge[]; anomalies: Anomaly[];
  summary: {
    nodes: number; edges: number;
    exactReferences: number; heuristicLinks: number;
    criticalAnomalies: number; warningAnomalies: number;
    unfinishedClaims: number; unknownProviderResults: number;
    unresolvedQuotas: number;
  };
  reportDigest: string; warnings: string[];
  verification?: {
    validForInternalReview: boolean;
    fingerprintValid: boolean;
    nodeDigestsValid: boolean;
    referencesValid: boolean;
    summaryValid: boolean;
    orderingValid: boolean;
    completeWithinWindow: boolean;
    checkedNodes: number;
    issues: string[];
    warnings: string[];
  };
  liveProviderVerified: false; changesCommitted: false;
  networkRequestsMade: 0; findingsModified: false;
};
function date(value: string | null) {
  if (!value) return "Unknown";
  const d = new Date(value);
  return Number.isFinite(d.getTime()) ?
    d.toLocaleString() : "Invalid date";
}
function errorText(cause: unknown) {
  return cause instanceof Error ? cause.message :
    "OSV forensic report unavailable.";
}
async function read<T>(
  url: string, method: "GET" | "POST",
  value?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method, cache: "no-store", credentials: "same-origin",
    headers: method === "GET" ?
      { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(method === "GET" ? {} : {
      body: JSON.stringify(value),
    }),
  });
  const data: unknown = await response.json();
  if (!response.ok) {
    const error = data as { error?: string };
    throw new Error(error.error ??
      "OSV forensic request HTTP " + response.status);
  }
  return data as T;
}
function Metric({ label, value }: { label: string; value: number }) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}>
    <strong>{value}</strong><p>{label}</p>
  </div>;
}
function NodeDetails({ value }: { value: Node }) {
  return <article style={{
    padding: 12, marginBlock: 8, borderRadius: 8,
    border: "1px solid #8885",
  }}>
    <strong>{value.type} · {value.state}</strong>
    <p>Record: <code>{value.referenceId}</code>.
      Timestamp: {date(value.eventAt)}.</p>
    <p>Schedule:
      {" "}{value.scheduleId ?? "Not assigned"}.</p>
    <details>
      <summary>Local provenance and normalized fields</summary>
      <p>SHA-256 evidence fingerprint:
        {" "}<code style={{ overflowWrap: "anywhere" }}>
          {value.digest}</code></p>
      <pre style={{
        overflowWrap: "anywhere", whiteSpace: "pre-wrap",
        fontSize: "0.82rem",
      }}>{JSON.stringify(value.attributes, null, 2)}</pre>
    </details>
  </article>;
}
function AnomalyDetails({ item }: { item: Anomaly }) {
  return <article style={{
    padding: 12, borderRadius: 8,
    border: "1px solid #8885", marginBlock: 8,
  }}>
    <strong>{item.severity} · {item.code}</strong>
    <p>{item.description}</p>
    <p>Operator investigation: {item.remediation}</p>
    {item.nodeId && <p>Local record:
      {" "}<code>{item.nodeId}</code>.</p>}
    <details>
      <summary>Evidence fingerprints</summary>
      <ul>{item.supportedBy.map((hash, index) =>
        <li key={index}>
          <code style={{ overflowWrap: "anywhere" }}>{hash}</code>
        </li>)}</ul>
    </details>
  </article>;
}
export function AssetOsvDispatchForensicsWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/osv-dispatch-forensics";
  const [report, setReport] = useState<Report | null>(null);
  const [lookback, setLookback] = useState(72);
  const [limit, setLimit] = useState(100);
  const [scheduleId, setScheduleId] = useState("");
  const [includeAudit, setIncludeAudit] = useState(true);
  const [includeInspections, setIncludeInspections] = useState(true);
  const [includeQuota, setIncludeQuota] = useState(true);
  const [strictCompleteness, setStrictCompleteness] = useState(true);
  const [typeFilter, setTypeFilter] = useState<Node["type"] | "ALL">("ALL");
  const [severity, setSeverity] =
    useState<Anomaly["severity"] | "ALL">("ALL");
  const [showLinks, setShowLinks] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const visibleNodes = useMemo(() =>
    report?.nodes.filter(row =>
      typeFilter === "ALL" || row.type === typeFilter) ?? [],
  [report, typeFilter]);
  const visibleAnomalies = useMemo(() =>
    report?.anomalies.filter(row =>
      severity === "ALL" || row.severity === severity) ?? [],
  [report, severity]);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    void read<Report>(endpoint, "GET").then(value => {
      if (!cancelled) {
        setReport(value); setError(null);
      }
    }).catch(cause => {
      if (!cancelled) setError(errorText(cause));
    });
    return () => { cancelled = true; };
  }, [canManage, endpoint, revision]);
  async function inspect() {
    if (busy) return;
    setBusy(true); setError(null);
    try {
      setReport(await read<Report>(endpoint, "POST", {
        scheduleId: scheduleId.trim() || null,
        lookbackHours: lookback, maximumRecords: limit,
        includeAudit, includeInspections, includeQuota,
        strictCompleteness,
      }));
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  function copyReport() {
    if (!report) return;
    const canonical = JSON.stringify(report, null, 2);
    void navigator.clipboard.writeText(canonical).catch(cause =>
      setError(errorText(cause)));
  }
  if (!canManage) return null;
  return <section aria-label="OSV dispatch forensic reconciliation"
    style={{
      padding: 16, border: "1px solid #8885",
      borderRadius: 12, marginBlock: 20,
    }}>
    <h2>Signed OSV dispatch forensic reconciliation</h2>
    <p>Reconstruct a bounded local evidence graph across
      accepted signing nonces, schedule executions, quota
      reservations, stored inspections and AuditEvents.
      Connections are labeled as exact references or
      merely time-adjacent. No provider is contacted.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Reconstructing local evidence…</p>}
    <fieldset disabled={busy}>
      <legend>Forensic evidence window</legend>
      <label>Schedule ID (optional)
        <input maxLength={150} value={scheduleId}
          onChange={event => setScheduleId(event.target.value)}
          placeholder="Scope to a specific saved schedule"/>
      </label>
      <div style={{
        display: "flex", flexWrap: "wrap", gap: 12,
      }}>
        <label>Lookback hours
          <select value={lookback}
            onChange={event => setLookback(Number(event.target.value))}>
            {[1, 6, 24, 72, 168, 720].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum records per collection
          <select value={limit}
            onChange={event => setLimit(Number(event.target.value))}>
            {[25, 50, 100, 250, 500].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={includeAudit}
          onChange={event => setIncludeAudit(event.target.checked)}/>
        Include audit history
      </label>
      <label>
        <input type="checkbox" checked={includeInspections}
          onChange={event =>
            setIncludeInspections(event.target.checked)}/>
        Include persisted OSV inspections
      </label>
      <label>
        <input type="checkbox" checked={includeQuota}
          onChange={event => setIncludeQuota(event.target.checked)}/>
        Include provider quota reservations
      </label>
      <label>
        <input type="checkbox" checked={strictCompleteness}
          onChange={event =>
            setStrictCompleteness(event.target.checked)}/>
        Reject reports with any truncated collection
      </label>
      <button type="button" onClick={() => void inspect()}>
        Reconcile local OSV evidence
      </button>
      <button type="button" onClick={() =>
        setRevision(n => n + 1)}>
        Reload default forensic view
      </button>
    </fieldset>
    {report && <section>
      <h3>Evidence completeness</h3>
      <p>Coverage: <strong>{report.complete ?
        "COMPLETE WITHIN QUERY WINDOW" : "INCOMPLETE"}</strong>.
        Examined: {date(report.evaluatedAt)}.
        From {date(report.windowStart)} to
        {" "}{date(report.windowEnd)}.</p>
      {!report.complete && <p role="alert">
        Truncated: {report.truncatedCollections.join(", ")}.
        Missing records must never be treated as absent evidence.
      </p>}
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Metric label="Evidence nodes" value={report.summary.nodes}/>
        <Metric label="References" value={report.summary.edges}/>
        <Metric label="Exact links"
          value={report.summary.exactReferences}/>
        <Metric label="Heuristic links"
          value={report.summary.heuristicLinks}/>
        <Metric label="Critical anomalies"
          value={report.summary.criticalAnomalies}/>
        <Metric label="Warning anomalies"
          value={report.summary.warningAnomalies}/>
        <Metric label="Unfinished claims"
          value={report.summary.unfinishedClaims}/>
        <Metric label="Unsettled quotas"
          value={report.summary.unresolvedQuotas}/>
      </div>
      <p>Provider verification: NO.
        Network requests made: 0.
        Application records modified: NO.
        Endpoint findings modified: NO.</p>
      {report.verification && <section>
        <h3>Independent local integrity checks</h3>
        <p>Internal consistency:
          {" "}<strong>{report.verification.validForInternalReview ?
            "VERIFIED WITHIN WINDOW" : "NOT VERIFIED"}</strong>.
          Nodes checked: {report.verification.checkedNodes}.</p>
        <ul>
          <li>Canonical fingerprint: {report.verification.fingerprintValid ?
            "PASS" : "FAIL"}</li>
          <li>Individual record digests: {report.verification.nodeDigestsValid ?
            "PASS" : "FAIL"}</li>
          <li>Graph references: {report.verification.referencesValid ?
            "PASS" : "FAIL"}</li>
          <li>Summary and ordering: {
            report.verification.summaryValid &&
            report.verification.orderingValid ? "PASS" : "FAIL"}</li>
          <li>Collection completeness: {
            report.verification.completeWithinWindow ? "PASS" : "FAIL"}</li>
        </ul>
        {report.verification.issues.length > 0 &&
          <div role="alert">
            <p>Evidence integrity warnings:</p>
            <ul>{report.verification.issues.map((issue, index) =>
              <li key={index}>{issue}</li>)}</ul>
          </div>}
        <details>
          <summary>Fingerprint verification limitations</summary>
          <ul>{report.verification.warnings.map((warning, index) =>
            <li key={index}>{warning}</li>)}</ul>
        </details>
      </section>}
      <h3>Operational anomalies</h3>
      <label>Severity
        <select value={severity}
          onChange={event =>
            setSeverity(event.target.value as typeof severity)}>
          {(["ALL", "CRITICAL", "WARNING"] as const).map(value =>
            <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      {visibleAnomalies.length === 0 &&
        <p>No anomalies observed in the selected local data window.
          This does not prove provider or endpoint safety.</p>}
      {visibleAnomalies.map(item =>
        <AnomalyDetails key={item.id} item={item}/>)}
      <h3>Normalized evidence</h3>
      <label>Record category
        <select value={typeFilter}
          onChange={event =>
            setTypeFilter(event.target.value as typeof typeFilter)}>
          {(["ALL", "SIGNATURE", "SCHEDULE_RUN", "QUOTA",
            "INSPECTION", "AUDIT"] as const).map(value =>
              <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <p>{visibleNodes.length} records visible.</p>
      {visibleNodes.map(item =>
        <NodeDetails key={item.id} value={item}/>)}
      <h3>Provenance links</h3>
      <label>
        <input type="checkbox" checked={showLinks}
          onChange={event => setShowLinks(event.target.checked)}/>
        Show all exact and heuristic links
      </label>
      {showLinks && report.edges.map((link, index) =>
        <article key={link.from + link.to + index} style={{
          border: "1px solid #8885", borderRadius: 8,
          padding: 10, marginBlock: 6,
        }}>
          <strong>{link.confidence} · {link.relation}</strong>
          <p><code>{link.from}</code> to
            {" "}<code>{link.to}</code></p>
          <p>{link.evidence}</p>
        </article>)}
      <details>
        <summary>Forensic fingerprint and evidence limitations</summary>
        <p>Report digest:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.reportDigest}</code></p>
        <ul>{report.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
      </details>
      <button type="button" onClick={copyReport}>
        Copy forensic report JSON
      </button>
      <p>Exports may contain internal record identifiers,
        signing key IDs and operational metadata. Share only
        through authorized incident response channels.</p>
    </section>}
  </section>;
}
