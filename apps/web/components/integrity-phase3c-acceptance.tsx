"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Finding = {
  code: string;
  level: "BLOCKER" | "REVIEW" | "INFORMATION";
  taskId: string;
  entity: string;
  entityId: string;
  message: string;
};
type TaskReport = {
  taskId: string;
  disposition: string;
  revision: number;
  reviews: number;
  notifications: number;
  escalations: number;
  providerChecks: number;
  workLinks: number;
  auditEvents: number;
  blockers: number;
  reviewsRequired: number;
  findings: Finding[];
  digest: string;
};
type Summary = {
  tasks: number;
  taskBlockers: number;
  tasksRequiringReview: number;
  blockers: number;
  reviewsRequired: number;
  information: number;
  notifications: number;
  escalations: number;
  providerChecks: number;
  reviewEvents: number;
  auditedActions: number;
  byCode: Record<string, number>;
};
type AcceptanceReport = {
  schema: string;
  organizationId: string;
  captureId: string;
  generatedAt: string;
  offset: number;
  limit: number;
  totalTasks: number;
  hasMore: boolean;
  complete: boolean;
  outcome: "BLOCKED" | "REQUIRES_REVIEW" | "READY_FOR_MANUAL_ACCEPTANCE";
  summary: Summary;
  tasks: TaskReport[];
  digest: string;
  manualRequirements: string[];
  limitations: string[];
};
type Status = "IDLE" | "LOADING";
type Level = "ALL" | Finding["level"];
function labelOutcome(value: AcceptanceReport["outcome"]) {
  if (value === "BLOCKED") return "Blocking findings require investigation";
  if (value === "REQUIRES_REVIEW") return "Manual review required";
  return "Automated diagnostics passed on this capture";
}
function safeTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}
function errorMessage(cause: unknown) {
  return cause instanceof Error ? cause.message : "Acceptance inspection failed.";
}
async function fetchReport(
  url: string, signal: AbortSignal,
): Promise<AcceptanceReport> {
  const response = await fetch(url, {
    method: "GET", cache: "no-store",
    credentials: "same-origin", signal,
    headers: { Accept: "application/json" },
  });
  const result: unknown = await response.json();
  if (!response.ok) {
    const error = result as { error?: string };
    throw new Error(error.error ?? "Request returned " + response.status);
  }
  return result as AcceptanceReport;
}
function Metric({ value, caption }: { value: number; caption: string }) {
  return <div style={{
    padding: 12, border: "1px solid #8885", borderRadius: 8,
  }}>
    <strong>{value}</strong>
    <div>{caption}</div>
  </div>;
}
function TaskInspection({
  task, level,
}: { task: TaskReport; level: Level }) {
  const relevant = level === "ALL" ? task.findings :
    task.findings.filter(x => x.level === level);
  if (level !== "ALL" && !relevant.length) return null;
  return <article style={{
    border: "1px solid #8885", borderRadius: 10,
    padding: 14, marginBlock: 10,
  }}>
    <h4>{task.taskId}</h4>
    <p>{task.disposition} · Revision {task.revision}
      {" · "}{task.blockers} blockers
      {" · "}{task.reviewsRequired} review findings</p>
    <p>Review events: {task.reviews}
      {" · "}Inbox records: {task.notifications}
      {" · "}Escalations: {task.escalations}
      {" · "}Provider checks: {task.providerChecks}
      {" · "}Work links: {task.workLinks}
      {" · "}Triage audits: {task.auditEvents}</p>
    {relevant.length === 0 ?
      <p>No findings detected for this task on the inspected page.</p> :
      <ul>{relevant.map((finding, index) => <li
        key={finding.code + "-" + finding.entityId + "-" + index}>
        <strong>{finding.level}: {finding.code}</strong>
        <div>{finding.message}</div>
        <small>{finding.entity} · {finding.entityId}</small>
      </li>)}</ul>}
    <details>
      <summary>Task record digest</summary>
      <code style={{ overflowWrap: "anywhere" }}>{task.digest}</code>
    </details>
  </article>;
}
export function IntegrityPhase3CAcceptance({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const [capture, setCapture] = useState("");
  const [offset, setOffset] = useState(0);
  const [includeClosed, setIncludeClosed] = useState(true);
  const [providerAge, setProviderAge] = useState("168");
  const [notificationAge, setNotificationAge] = useState("72");
  const [level, setLevel] = useState<Level>("ALL");
  const [status, setStatus] = useState<Status>("IDLE");
  const [enabled, setEnabled] = useState(false);
  const [revision, setRevision] = useState(0);
  const [result, setResult] = useState<AcceptanceReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState<string[]>([]);
  const limit = 50;
  const url = useMemo(() => {
    const parameters = new URLSearchParams({
      captureId: capture.trim(), offset: String(offset),
      limit: String(limit), includeClosed: String(includeClosed),
      minimumProviderAgeHours: providerAge,
      maxNotificationAgeHours: notificationAge,
    });
    return "/api/organizations/" + encodeURIComponent(slug) +
      "/actions/work/integrity/phase3c-acceptance?" + parameters.toString();
  }, [slug, capture, offset, includeClosed, providerAge, notificationAge]);
  const clear = useCallback(() => {
    setResult(null); setError(null);
    setEnabled(false); setAcknowledged([]);
  }, []);
  useEffect(() => {
    if (!canManage || !enabled || !capture.trim()) return;
    const controller = new AbortController();
    setStatus("LOADING");
    setError(null);
    setResult(null);
    void fetchReport(url, controller.signal)
      .then(report => {
        if (!controller.signal.aborted) {
          setResult(report);
          setAcknowledged([]);
        }
      })
      .catch(cause => {
        if (!controller.signal.aborted) setError(errorMessage(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) setStatus("IDLE");
      });
    return () => controller.abort();
  }, [canManage, enabled, capture, url, revision]);
  if (!canManage) return null;
  function load() {
    if (capture.trim().length < 5) {
      setError("Enter an existing capture ID before inspecting acceptance.");
      return;
    }
    setEnabled(true);
    setRevision(previous => previous + 1);
  }
  function changeCapture(value: string) {
    setCapture(value);
    setOffset(0);
    clear();
  }
  function changePolicy(
    setter: (next: string) => void, value: string,
  ) {
    setter(value);
    setOffset(0);
    clear();
  }
  function toggleManual(requirement: string, checked: boolean) {
    setAcknowledged(previous => checked ?
      [...previous.filter(x => x !== requirement), requirement] :
      previous.filter(x => x !== requirement));
  }
  const busy = status === "LOADING";
  const manualReady = Boolean(result &&
    result.manualRequirements.length === acknowledged.length);
  const display = result?.tasks.filter(task =>
    level === "ALL" || task.findings.some(x => x.level === level)) ?? [];
  return <section aria-label="Phase 3C technical acceptance"
    style={{ border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 24 }}>
    <h2>Phase 3C acceptance diagnostics</h2>
    <p>
      Read-only inspection of persisted operational records. It detects
      workflow contradictions and highlights remaining manual release checks.
      It never approves a release or modifies security evidence.
    </p>
    <fieldset disabled={busy}>
      <legend>Report scope</legend>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        <label>Capture ID
          <input value={capture} maxLength={100}
            placeholder="Required" onChange={event =>
              changeCapture(event.target.value)} />
        </label>
        <label>Provider age threshold (hours)
          <select value={providerAge}
            onChange={event => changePolicy(setProviderAge, event.target.value)}>
            {[24, 72, 168, 336, 720].map(hours =>
              <option key={hours} value={hours}>{hours}</option>)}
          </select>
        </label>
        <label>Unread notification threshold (hours)
          <select value={notificationAge}
            onChange={event => changePolicy(setNotificationAge, event.target.value)}>
            {[12, 24, 48, 72, 168, 336].map(hours =>
              <option key={hours} value={hours}>{hours}</option>)}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={includeClosed}
            onChange={event => {
              setIncludeClosed(event.target.checked);
              setOffset(0); clear();
            }} />
          Include terminal reviews
        </label>
      </div>
      <button type="button" onClick={load}
        disabled={!capture.trim() || busy}>Run diagnostic checks</button>
    </fieldset>
    {busy && <p role="status">Checking capture records…</p>}
    {error && <p role="alert">{error}</p>}
    {result && <>
      <h3>{labelOutcome(result.outcome)}</h3>
      <p>Generated {safeTime(result.generatedAt)}
        {" · "}Capture {result.captureId}
        {" · "}Tasks: {result.totalTasks}
        {" · "}Inspected page {Math.floor(offset / limit) + 1}</p>
      {!result.complete && <p role="status">
        Incomplete capture coverage: no global approval can be inferred.
      </p>}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))",
        gap: 10,
      }}>
        <Metric value={result.summary.tasks} caption="Inspected reviews" />
        <Metric value={result.summary.blockers} caption="Blocking findings" />
        <Metric value={result.summary.reviewsRequired} caption="Review findings" />
        <Metric value={result.summary.notifications} caption="Inbox records" />
        <Metric value={result.summary.escalations} caption="Escalations" />
        <Metric value={result.summary.providerChecks} caption="Provider observations" />
      </div>
      <details>
        <summary>Report digest</summary>
        <code style={{ overflowWrap: "anywhere" }}>{result.digest}</code>
      </details>
      <h3>Findings by code</h3>
      {Object.keys(result.summary.byCode).length === 0 ?
        <p>No findings detected in the inspected page.</p> :
        <ul>{Object.entries(result.summary.byCode)
          .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .map(([code, count]) =>
            <li key={code}>{code}: {count}</li>)}</ul>}
      <label>Show findings
        <select value={level}
          onChange={event => setLevel(event.target.value as Level)}>
          <option value="ALL">All tasks</option>
          <option value="BLOCKER">Blocking findings</option>
          <option value="REVIEW">Manual review findings</option>
          <option value="INFORMATION">Informational findings</option>
        </select>
      </label>
      <p>{display.length} tasks shown after presentation filtering.</p>
      {display.map(task =>
        <TaskInspection key={task.taskId} task={task} level={level} />)}
      <div style={{ display: "flex", gap: 12 }}>
        <button type="button" disabled={busy || offset === 0}
          onClick={() => {
            setOffset(value => Math.max(0, value - limit));
            setAcknowledged([]);
          }}>Previous page</button>
        <button type="button" disabled={busy || !result.hasMore}
          onClick={() => {
            setOffset(value => value + limit);
            setAcknowledged([]);
          }}>Next page</button>
      </div>
      <h3>Manual release acceptance checklist</h3>
      <p>
        These local checkboxes are session notes only; they are not
        persisted, verified or a release authorization.
      </p>
      <ul>{result.manualRequirements.map(requirement =>
        <li key={requirement}>
          <label>
            <input type="checkbox"
              checked={acknowledged.includes(requirement)}
              onChange={event =>
                toggleManual(requirement, event.target.checked)} />
            {requirement}
          </label>
        </li>)}</ul>
      <p role="status">
        Manual notes: {acknowledged.length}/{result.manualRequirements.length}.
        {manualReady ?
          " Marked locally; formal evidence and reviewer sign-off are still required." :
          " Pending manual confirmations."}
      </p>
      <details>
        <summary>Report limitations</summary>
        <ul>{result.limitations.map(item =>
          <li key={item}>{item}</li>)}</ul>
      </details>
    </>}
  </section>;
}
