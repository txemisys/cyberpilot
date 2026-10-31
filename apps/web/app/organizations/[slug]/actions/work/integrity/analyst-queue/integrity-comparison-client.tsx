"use client";

import { useState } from "react";

type Comparison = {
  organizationId: string;
  beforeCapturedAt: string;
  afterCapturedAt: string;
  complete: boolean;
  counts: Record<string, number>;
  priority: { escalations: number; deescalations: number; indeterminate: number };
  evidence: {
    beforeReady: number; afterReady: number; beforeBlocked: number;
    afterBlocked: number; newlyBlocked: number; newlyReady: number;
    uncertain: number;
  };
  changes: Array<{
    key: string; kind: string; fields: string[];
    priorityBefore: string | null; priorityAfter: string | null;
    priorityEscalated: boolean; priorityDeescalated: boolean;
    beforeReady: boolean | null; afterReady: boolean | null;
    addedEvidenceGaps: string[]; removedEvidenceGaps: string[];
    uncertain: boolean;
  }>;
  warnings: string[];
};
type Props = { slug: string };
const MAX_UPLOAD = 1_900_000;
async function parseUpload(file: File): Promise<unknown> {
  if (file.size > MAX_UPLOAD)
    throw new Error("The snapshot exceeds the 1.9 MB browser upload limit.");
  if (!file.name.toLowerCase().endsWith(".json"))
    throw new Error("Select a JSON snapshot file.");
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error("The selected snapshot is not valid JSON.");
  }
}
export default function IntegrityComparisonClient({ slug }: Props) {
  const [before, setBefore] = useState<File | null>(null);
  const [after, setAfter] = useState<File | null>(null);
  const [report, setReport] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [downloadBusy, setDownloadBusy] = useState(false);
  const endpoint = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/compare`;
  async function runComparison(format: "json" | "csv") {
    if (!before || !after) {
      setError("Select both a previous and a current snapshot.");
      return;
    }
    setError(null);
    if (format === "json") {
      setReport(null);
      setBusy(true);
    } else setDownloadBusy(true);
    try {
      const payload = JSON.stringify({
        before: await parseUpload(before),
        after: await parseUpload(after),
      });
      const response = await fetch(`${endpoint}?format=${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
        cache: "no-store",
      });
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null);
        const message = body && typeof body === "object" && "error" in body &&
          typeof body.error === "string"
          ? body.error : "Comparison request failed.";
        throw new Error(message);
      }
      if (format === "json") {
        const result = await response.json() as Comparison;
        setReport(result);
      } else {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "integrity-capture-comparison.csv";
        document.body.append(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to compare snapshots.");
    } finally {
      setBusy(false);
      setDownloadBusy(false);
    }
  }
  return (
    <section aria-label="Compare recorded integrity case snapshots">
      <h2>Compare two captured case snapshots</h2>
      <p>
        Upload JSON snapshots previously captured for this organization.
        Both files must contain a snapshot object with organizationId,
        capturedAt, source, complete and cases. Files are processed through
        the authenticated organization API and are not stored as an audit decision.
      </p>
      <p className="permission-warning">
        The files are user-supplied and not independently authenticated. A case
        disappearing from an incomplete capture cannot be treated as resolved.
        Comparison never modifies operational records.
      </p>
      <div className="remediation-actions">
        <label htmlFor="comparison-before">Previous snapshot (JSON)</label>
        <input id="comparison-before" type="file" accept=".json,application/json"
          onChange={event => {
            setBefore(event.target.files?.[0] ?? null);
            setReport(null);
          }} />
        <label htmlFor="comparison-after">Current snapshot (JSON)</label>
        <input id="comparison-after" type="file" accept=".json,application/json"
          onChange={event => {
            setAfter(event.target.files?.[0] ?? null);
            setReport(null);
          }} />
        <button type="button" className="secondary-button"
          disabled={busy || downloadBusy || !before || !after}
          onClick={() => void runComparison("json")}>
          {busy ? "Comparing captures…" : "Compare snapshots"}
        </button>
        <button type="button" className="secondary-button"
          disabled={busy || downloadBusy || !before || !after}
          onClick={() => void runComparison("csv")}>
          {downloadBusy ? "Preparing CSV…" : "Download comparison CSV"}
        </button>
      </div>
      {error ? <p role="alert" className="auth-error">{error}</p> : null}
      {report ? (
        <section aria-label="Snapshot comparison results">
          <h3>Recorded differences</h3>
          <p>
            {report.beforeCapturedAt} compared with {report.afterCapturedAt}.
            {report.complete
              ? " Both supplied snapshots declare complete coverage."
              : " At least one supplied snapshot is incomplete."}
          </p>
          <div className="panel" aria-label="Comparison totals">
            {Object.entries(report.counts).map(([kind, count]) => (
              <div key={kind}>
                <p className="panel-label">{kind.replaceAll("_", " ")}</p>
                <p className="panel-value">{count}</p>
              </div>
            ))}
          </div>
          <section aria-label="Priority changes">
            <h3>Operational priority drift</h3>
            <p>{report.priority.escalations} escalations and
              {" "}{report.priority.deescalations} deescalations,
              with {report.priority.indeterminate} indeterminate changes.</p>
            <p>
              A reduced review priority does not prove a remediation
              succeeded or that a security control is effective.
            </p>
          </section>
          <section aria-label="Evidence metadata drift">
            <h3>Evidence-readiness drift</h3>
            <ul>
              <li>Previously ready: {report.evidence.beforeReady}</li>
              <li>Currently ready: {report.evidence.afterReady}</li>
              <li>Newly blocked: {report.evidence.newlyBlocked}</li>
              <li>Newly ready: {report.evidence.newlyReady}</li>
              <li>Uncertain changes: {report.evidence.uncertain}</li>
            </ul>
          </section>
          <section aria-label="Changed case details">
            <h3>Case-by-case differences</h3>
            {report.changes.length === 0 ? (
              <p>No changed case identities were detected in the supplied snapshots.</p>
            ) : (
              <div className="remediation-list">
                {report.changes.map(change => (
                  <article className="remediation-card" key={change.key}>
                    <div className="remediation-heading">
                      <h4>{change.key}</h4>
                      <span className="role-badge">{change.kind}</span>
                    </div>
                    {change.uncertain ? (
                      <p className="permission-warning">
                        This change is indeterminate because coverage is incomplete.
                      </p>
                    ) : null}
                    <p>Changed fields: {change.fields.join(", ") || "Case presence"}</p>
                    <p>
                      Review priority: {change.priorityBefore ?? "Not present"}
                      {" → "}{change.priorityAfter ?? "Not present"}
                    </p>
                    {change.priorityEscalated ? (
                      <p className="permission-warning">
                        Operational review priority increased.
                      </p>
                    ) : null}
                    <p>
                      Evidence readiness: {String(change.beforeReady)}
                      {" → "}{String(change.afterReady)}
                    </p>
                    {change.addedEvidenceGaps.length ? (
                      <p>New evidence gaps: {change.addedEvidenceGaps.join(", ")}</p>
                    ) : null}
                    {change.removedEvidenceGaps.length ? (
                      <p>Removed evidence gaps: {change.removedEvidenceGaps.join(", ")}</p>
                    ) : null}
                  </article>
                ))}
              </div>
            )}
          </section>
          <details>
            <summary>Comparison limitations</summary>
            <ul>{report.warnings.map((warning, index) =>
              <li key={index}>{warning}</li>)}</ul>
          </details>
        </section>
      ) : null}
    </section>
  );
}
