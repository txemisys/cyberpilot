"use client";

import { useState } from "react";

type Finding = {
  caseKey: string | null;
  kind: string;
  severity: "CRITICAL" | "HIGH" | "REVIEW" | "INFO";
  beforeTime: string;
  afterTime: string;
  eventId: string | null;
  beforeRevision: number | null;
  afterRevision: number | null;
  message: string;
  followup: string;
};
type Transition = {
  from: string;
  to: string;
  inspectedCases: number;
  incompleteScope: boolean;
  findings: Finding[];
};
type Continuity = {
  organizationId: string;
  from: string;
  to: string;
  captures: number;
  caseIdentities: number;
  eventIdentities: number;
  totals: Record<string, number>;
  transitions: Transition[];
  affectedCaseKeys: string[];
  limitations: string[];
};
const MAX_FILES = 12;
const MAX_FILE_BYTES = 1_900_000;
type Props = { slug: string };
export default function IntegrityContinuityClient({ slug }: Props) {
  const [files, setFiles] = useState<File[]>([]);
  const [report, setReport] = useState<Continuity | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [severity, setSeverity] = useState("ALL");
  const [showResolved, setShowResolved] = useState(false);
  const [selectedTransition, setSelectedTransition] = useState("ALL");
  const base = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/continuity`;
  async function execute(format: "json" | "csv") {
    if (files.length < 2 || files.length > MAX_FILES) {
      setFailure("Select between two and twelve source-matched JSON captures.");
      return;
    }
    setFailure(null);
    if (format === "json") {
      setReport(null);
      setLoading(true);
    } else setExporting(true);
    try {
      const captures: unknown[] = [];
      for (const file of files) {
        if (!file.name.toLowerCase().endsWith(".json") ||
            file.size === 0 || file.size > MAX_FILE_BYTES)
          throw new Error(`Invalid file type or size: ${file.name}`);
        try {
          captures.push(JSON.parse(await file.text()) as unknown);
        } catch {
          throw new Error(`Invalid JSON file: ${file.name}`);
        }
      }
      const response = await fetch(`${base}?format=${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ captures }),
        cache: "no-store",
      });
      if (!response.ok) {
        const value: unknown = await response.json().catch(() => null);
        throw new Error(value && typeof value === "object" &&
          "error" in value && typeof value.error === "string"
          ? value.error : "Unable to inspect review continuity.");
      }
      if (format === "json") {
        setReport(await response.json() as Continuity);
      } else {
        const url = URL.createObjectURL(await response.blob());
        try {
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = "integrity-review-continuity.csv";
          document.body.append(anchor);
          anchor.click();
          anchor.remove();
        } finally {
          URL.revokeObjectURL(url);
        }
      }
    } catch (error) {
      setFailure(error instanceof Error ? error.message : "Unexpected continuity error.");
    } finally {
      setLoading(false);
      setExporting(false);
    }
  }
  const transitions = report?.transitions.flatMap((transition, index) =>
    transition.findings.map(item => ({ ...item, transitionIndex: index }))) ?? [];
  const displayed = transitions.filter(item =>
    (severity === "ALL" || item.severity === severity) &&
    (selectedTransition === "ALL" || item.transitionIndex === Number(selectedTransition)) &&
    (showResolved || item.severity !== "INFO"));
  return (
    <section aria-label="Review audit event continuity">
      <h2>Audit-event continuity across captured reviews</h2>
      <p>
        Inspect transitions in recorded human review events and work revisions.
        Choose two to twelve snapshots in chronological order. This analysis
        detects possible audit inconsistencies; it cannot authenticate the
        underlying snapshots or independently verify security outcomes.
      </p>
      <div className="remediation-actions">
        <label htmlFor="review-continuity-files">Ordered JSON captures</label>
        <input id="review-continuity-files" type="file"
          accept=".json,application/json" multiple
          onChange={event => {
            setFiles(Array.from(event.target.files ?? []));
            setReport(null);
            setFailure(null);
          }} />
        <button type="button" className="secondary-button"
          disabled={loading || exporting || files.length < 2 || files.length > 12}
          onClick={() => void execute("json")}>
          {loading ? "Reviewing events…" : "Check review continuity"}
        </button>
        <button type="button" className="secondary-button"
          disabled={loading || exporting || files.length < 2 || files.length > 12}
          onClick={() => void execute("csv")}>
          {exporting ? "Preparing CSV…" : "Download continuity CSV"}
        </button>
      </div>
      <p>{files.length} of 2–12 required snapshots selected.</p>
      {failure ? <p role="alert" className="auth-error">{failure}</p> : null}
      {report ? (
        <section aria-label="Recorded review continuity results">
          <h3>Event continuity observations</h3>
          <p>
            {report.captures} captures, {report.caseIdentities} distinct case IDs
            and {report.eventIdentities} distinct recorded event IDs.
            {" "}Observed from {report.from} through {report.to}.
          </p>
          <div className="panel" aria-label="Continuity severity counts">
            {Object.entries(report.totals).map(([name, count]) => (
              <div key={name}>
                <p className="panel-label">{name}</p>
                <p className="panel-value">{count}</p>
              </div>
            ))}
          </div>
          <div className="remediation-actions">
            <label htmlFor="continuity-severity">Severity</label>
            <select id="continuity-severity" value={severity}
              onChange={event => setSeverity(event.target.value)}>
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="REVIEW">Requires review</option>
              <option value="INFO">Informational</option>
            </select>
            <label htmlFor="continuity-transition">Capture transition</label>
            <select id="continuity-transition" value={selectedTransition}
              onChange={event => setSelectedTransition(event.target.value)}>
              <option value="ALL">All transitions</option>
              {report.transitions.map((transition, index) => (
                <option key={transition.to} value={index}>
                  {index + 1}: {transition.to}
                </option>
              ))}
            </select>
            <label htmlFor="continuity-information">
              <input id="continuity-information" type="checkbox"
                checked={showResolved}
                onChange={event => setShowResolved(event.target.checked)} />
              Include informational observations
            </label>
          </div>
          <p>{displayed.length} of {transitions.length} observations match
            the selected filters.</p>
          {report.transitions.some(item => item.incompleteScope) ? (
            <p className="permission-warning">
              Some capture transitions have incomplete source coverage.
              Missing cases must not be treated as resolved.
            </p>
          ) : null}
          {displayed.length ? (
            <div className="remediation-list">
              {displayed.slice(0, 200).map((item, index) => (
                <article key={`${item.transitionIndex}-${item.caseKey}-${item.kind}-${index}`}
                  className="remediation-card">
                  <div className="remediation-heading">
                    <h4>{item.kind.replaceAll("_", " ")}</h4>
                    <span className="role-badge">{item.severity}</span>
                  </div>
                  <p>Case identity: {item.caseKey ?? "Capture scope"}</p>
                  <p>Between {item.beforeTime} and {item.afterTime}</p>
                  <p>{item.message}</p>
                  <p><strong>Next action:</strong> {item.followup}</p>
                  {item.eventId ? <p>Event reference: {item.eventId}</p> : null}
                  {item.beforeRevision !== null || item.afterRevision !== null ? (
                    <p>Work revision: {item.beforeRevision ?? "unknown"}
                      {" → "}{item.afterRevision ?? "unknown"}</p>
                  ) : null}
                </article>
              ))}
            </div>
          ) : <p>No matching continuity anomalies in these captures.</p>}
          {displayed.length > 200 ? (
            <p>Showing first 200 matching observations. The CSV export
              contains all bounded findings.</p>
          ) : null}
          <details>
            <summary>Evidence and audit limitations</summary>
            <ul>{report.limitations.map((line, index) =>
              <li key={index}>{line}</li>)}</ul>
          </details>
        </section>
      ) : null}
    </section>
  );
}
