"use client";

import { useState } from "react";

type TimelineFollowup = {
  caseKey: string;
  priority: "URGENT" | "HIGH" | "NORMAL";
  reason: string;
  recommendedAction: string;
  requiresReverification: boolean;
};
type TimelineCase = {
  key: string;
  workItemId: string;
  code: string;
  trend: string;
  observations: number;
  transitions: number;
  reviewIsCurrent: boolean | null;
  lastKnownSeverity: string | null;
  gaps: string[];
};
type TimelineReport = {
  from: string;
  through: string;
  captures: number;
  comparable: boolean;
  completeCaptures: number;
  incompleteCaptures: number;
  counts: Record<string, number>;
  cases: TimelineCase[];
  followups: TimelineFollowup[];
  warnings: string[];
};
type Props = { slug: string };
const MAX_UPLOAD = 1_900_000;
const MAX_FILES = 12;
async function readCapture(file: File): Promise<unknown> {
  if (!file.name.toLowerCase().endsWith(".json"))
    throw new Error(`Only JSON snapshots are supported: ${file.name}`);
  if (file.size === 0 || file.size > MAX_UPLOAD)
    throw new Error(`Snapshot has invalid size: ${file.name}`);
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error(`Invalid JSON snapshot: ${file.name}`);
  }
}
export default function IntegrityTimelineClient({ slug }: Props) {
  const [files, setFiles] = useState<File[]>([]);
  const [result, setResult] = useState<TimelineReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [processing, setProcessing] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [onlyAttention, setOnlyAttention] = useState(true);
  const endpoint = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/timeline`;
  const canRun = files.length >= 2 && files.length <= MAX_FILES;
  async function analyze(format: "json" | "csv") {
    if (!canRun) {
      setError("Select between 2 and 12 chronological snapshots.");
      return;
    }
    setError(null);
    if (format === "json") {
      setResult(null);
      setProcessing(true);
    } else {
      setExporting(true);
    }
    try {
      const captures = await Promise.all(files.map(readCapture));
      const response = await fetch(`${endpoint}?format=${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ captures }),
        cache: "no-store",
      });
      if (!response.ok) {
        const value: unknown = await response.json().catch(() => null);
        const reason = value && typeof value === "object" &&
          "error" in value && typeof value.error === "string"
          ? value.error : "Timeline analysis failed.";
        throw new Error(reason);
      }
      if (format === "json") {
        setResult(await response.json() as TimelineReport);
      } else {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        try {
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = "integrity-case-timeline.csv";
          document.body.append(anchor);
          anchor.click();
          anchor.remove();
        } finally {
          URL.revokeObjectURL(url);
        }
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to inspect snapshots.");
    } finally {
      setProcessing(false);
      setExporting(false);
    }
  }
  const shownCases = result?.cases.filter(row =>
    !onlyAttention || !["PERSISTENT", "DISAPPEARED"].includes(row.trend) ||
      row.reviewIsCurrent === false) ?? [];
  return (
    <section aria-label="Historical integrity case analysis">
      <h2>Longitudinal integrity case review</h2>
      <p>
        Compare 2–12 saved operational case snapshots of the same organization
        and identical capture scope. Select them in chronological order,
        oldest first. The files are inspected server-side under your current
        organization membership; no audit decisions are created.
      </p>
      <p className="permission-warning">
        Completeness is based on imported capture metadata and consistency
        checks, not independent source authentication. An absent diagnostic
        never proves a remediation succeeded.
      </p>
      <div className="remediation-actions">
        <label htmlFor="integrity-timeline-files">
          Chronologically ordered JSON snapshots
        </label>
        <input
          id="integrity-timeline-files"
          type="file"
          accept=".json,application/json"
          multiple
          onChange={event => {
            setFiles(Array.from(event.target.files ?? []));
            setResult(null);
            setError(null);
          }}
        />
        <button className="secondary-button" type="button"
          disabled={!canRun || processing || exporting}
          onClick={() => void analyze("json")}>
          {processing ? "Analyzing timeline…" : "Analyze timeline"}
        </button>
        <button className="secondary-button" type="button"
          disabled={!canRun || processing || exporting}
          onClick={() => void analyze("csv")}>
          {exporting ? "Preparing export…" : "Download timeline CSV"}
        </button>
      </div>
      <p>{files.length} snapshots selected; accepted range is 2–12.</p>
      {error ? <p role="alert" className="auth-error">{error}</p> : null}
      {result ? (
        <section aria-label="Longitudinal capture results">
          <h3>Operational case chronology</h3>
          <p>{result.captures} captures from {result.from} to {result.through}.</p>
          <p>{result.completeCaptures} captures passed structural quality checks;
            {" "}{result.incompleteCaptures} remain incomplete or uncertain.</p>
          {!result.comparable ? (
            <p className="permission-warning">
              This series cannot support coverage-dependent conclusions because
              at least one capture is incomplete or structurally uncertain.
            </p>
          ) : null}
          <div className="panel" aria-label="Case trend counts">
            {Object.entries(result.counts).map(([trend, count]) => (
              <div key={trend}>
                <p className="panel-label">{trend.replaceAll("_", " ")}</p>
                <p className="panel-value">{count}</p>
              </div>
            ))}
          </div>
          <label htmlFor="timeline-attention-only">
            <input id="timeline-attention-only" type="checkbox"
              checked={onlyAttention}
              onChange={event => setOnlyAttention(event.target.checked)} />
            Focus on new, volatile, uncertain or not-currently-reviewed cases
          </label>
          <p>{shownCases.length} of {result.cases.length} captured case identities shown.</p>
          {shownCases.length === 0 ? (
            <p>No cases match the current display setting.</p>
          ) : (
            <div className="remediation-list">
              {shownCases.slice(0, 200).map(item => (
                <article key={item.key} className="remediation-card">
                  <div className="remediation-heading">
                    <h4>{item.code}</h4>
                    <span className="role-badge">{item.trend.replaceAll("_", " ")}</span>
                  </div>
                  <p>Work: {item.workItemId}</p>
                  <p>{item.observations} appearances across {result.captures} captures;
                    {" "}{item.transitions} presence transitions.</p>
                  <p>Last severity: {item.lastKnownSeverity ?? "No current severity"}</p>
                  <p>Current revision reviewed:
                    {" "}{item.reviewIsCurrent === null ? "Not known" :
                      item.reviewIsCurrent ? "Recorded" : "Not recorded"}</p>
                  {item.gaps.length ? (
                    <ul>{item.gaps.map((gap, index) => <li key={index}>{gap}</li>)}</ul>
                  ) : null}
                </article>
              ))}
            </div>
          )}
          {shownCases.length > 200 ? (
            <p className="permission-warning">
              Only the first 200 case cards are shown. Download CSV for the
              complete bounded result.
            </p>
          ) : null}
          <details>
            <summary>Source, uncertainty and review limitations</summary>
            <ul>{result.warnings.map((warning, index) =>
              <li key={index}>{warning}</li>)}</ul>
          </details>
        </section>
      ) : null}
    </section>
  );
}
