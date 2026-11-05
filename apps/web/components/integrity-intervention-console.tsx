"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type ReviewCandidate = {
  taskId: string;
  captureId: string;
  title: string;
  revision: number;
  ownerUserId: string | null;
  ownerAssigned: boolean;
  disposition: string;
  severity: string;
  urgency: string;
  priority: number;
  dueAt: string;
  signals: string[];
  actions: string[];
};
type PlanPage = {
  rows: ReviewCandidate[];
  total: number;
  hasMore: boolean;
  complete: boolean;
  warnings: string[];
};
type Operation = "REMIND_OWNER" | "NOTIFY_ADMINS" | "ASSIGN_OWNER" |
  "UNASSIGN_OWNER" | "CLEAR_REMINDERS";
type Command = {
  taskId: string;
  kind: Operation;
  expectedRevision: number;
  expectedOwnerUserId: string | null;
  assigneeUserId?: string;
  note: string;
  idempotencyKey: string;
};
type InterventionResult = {
  taskId: string;
  kind: Operation;
  status: "PREVIEW" | "APPLIED" | "REPLAYED" | "FAILED" | "SKIPPED";
  reason: string;
  errorCode: string | null;
  notificationIds: string[];
};
type ExecutionReport = {
  captureId: string;
  dryRun: boolean;
  requested: number;
  processed: number;
  applied: number;
  replayed: number;
  failed: number;
  skipped: number;
  previewed: number;
  digest: string;
  results: InterventionResult[];
  warnings: string[];
};
type Prepared = {
  captureId: string;
  commands: Command[];
};
type RequestState = "IDLE" | "FETCHING" | "PREVIEWING" | "EXECUTING";
const maxCommands = 25;
function explanation(error: unknown): string {
  return error instanceof Error ? error.message : "Operation unavailable.";
}
async function json<T>(url: string, signal: AbortSignal, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin", cache: "no-store", signal,
    headers: body === undefined ? { Accept: "application/json" } :
      { Accept: "application/json", "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const content: unknown = await response.json();
  if (!response.ok) {
    const error = content as { error?: string; code?: string };
    throw new Error(error.error ?? ("HTTP " + response.status));
  }
  return content as T;
}
function eligibleOperations(row: ReviewCandidate): Operation[] {
  if (row.disposition === "RESOLVED" || row.disposition === "WAIVED")
    return [];
  const operations: Operation[] = ["NOTIFY_ADMINS"];
  if (row.ownerAssigned) {
    operations.push("REMIND_OWNER", "CLEAR_REMINDERS", "UNASSIGN_OWNER");
  } else {
    operations.push("ASSIGN_OWNER");
  }
  return operations;
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Invalid date" : date.toLocaleString();
}
export function IntegrityInterventionConsole({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const [captureId, setCaptureId] = useState("");
  const [offset, setOffset] = useState(0);
  const [refreshToken, setRefreshToken] = useState(0);
  const [plan, setPlan] = useState<PlanPage | null>(null);
  const [state, setState] = useState<RequestState>("IDLE");
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [kind, setKind] = useState<Operation>("NOTIFY_ADMINS");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [stopOnError, setStopOnError] = useState(true);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [preview, setPreview] = useState<ExecutionReport | null>(null);
  const [execution, setExecution] = useState<ExecutionReport | null>(null);
  const [approval, setApproval] = useState(false);
  const size = 25;
  const url = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(offset), limit: String(size),
    });
    if (captureId.trim()) params.set("captureId", captureId.trim());
    return base + "/operational-planning?" + params.toString();
  }, [base, captureId, offset]);
  const resetPrepared = useCallback(() => {
    setPrepared(null);
    setPreview(null);
    setExecution(null);
    setApproval(false);
  }, []);
  useEffect(() => {
    if (!canManage) return;
    const controller = new AbortController();
    setState("FETCHING");
    setPlan(null);
    setError(null);
    void json<PlanPage>(url, controller.signal)
      .then(result => {
        if (!controller.signal.aborted) setPlan(result);
      })
      .catch(cause => {
        if (!controller.signal.aborted) setError(explanation(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) setState("IDLE");
      });
    return () => controller.abort();
  }, [canManage, url, refreshToken]);
  if (!canManage) return null;
  const rows = plan?.rows ?? [];
  const candidates = rows.filter(row => selected.includes(row.taskId));
  function chooseCapture(value: string) {
    setCaptureId(value);
    setOffset(0);
    setSelected([]);
    resetPrepared();
    setFeedback(null);
  }
  function toggle(row: ReviewCandidate) {
    if (state !== "IDLE") return;
    setSelected(previous => previous.includes(row.taskId) ?
      previous.filter(x => x !== row.taskId) :
      previous.length >= maxCommands ? previous :
        [...previous, row.taskId]);
    resetPrepared();
  }
  function selectEligible() {
    const candidates = rows.filter(row =>
      eligibleOperations(row).includes(kind));
    setSelected(candidates.slice(0, maxCommands).map(x => x.taskId));
    resetPrepared();
  }
  function clearSelection() {
    setSelected([]);
    resetPrepared();
  }
  function changeKind(value: Operation) {
    setKind(value);
    setSelected([]);
    resetPrepared();
  }
  function buildCommands(): Prepared {
    if (!captureId.trim())
      throw new Error("Select a single capture before preparing interventions.");
    if (candidates.length === 0)
      throw new Error("Select at least one review from the current page.");
    if (candidates.length > maxCommands)
      throw new Error("A batch may contain at most 25 commands.");
    if (note.trim().length < 12 || note.length > 2000)
      throw new Error("Provide a reason between 12 and 2000 characters.");
    if (kind === "ASSIGN_OWNER" && !/^[a-zA-Z0-9_-]{5,100}$/.test(assignee.trim()))
      throw new Error("Enter a valid existing organization user ID.");
    for (const row of candidates) {
      if (row.captureId !== captureId.trim())
        throw new Error("Every task must belong to the selected capture.");
      if (!eligibleOperations(row).includes(kind))
        throw new Error("Selected review is ineligible for " + kind + ".");
    }
    return {
      captureId: captureId.trim(),
      commands: candidates.map(row => ({
        taskId: row.taskId, kind,
        expectedRevision: row.revision,
        expectedOwnerUserId: row.ownerUserId,
        ...(kind === "ASSIGN_OWNER" ? {
          assigneeUserId: assignee.trim(),
        } : {}),
        note: note.trim(),
        idempotencyKey: crypto.randomUUID(),
      })),
    };
  }
  async function beginPreview() {
    if (state !== "IDLE") return;
    setError(null);
    setFeedback(null);
    resetPrepared();
    let request: Prepared;
    try {
      request = buildCommands();
    } catch (cause) {
      setError(explanation(cause));
      return;
    }
    const controller = new AbortController();
    setState("PREVIEWING");
    try {
      const result = await json<ExecutionReport>(
        base + "/interventions", controller.signal,
        { ...request, dryRun: true, stopOnError },
      );
      setPrepared(request);
      setPreview(result);
      setFeedback("Preview complete. Review the results before authorizing writes.");
    } catch (cause) {
      setError(explanation(cause));
    } finally {
      setState("IDLE");
    }
  }
  async function commit() {
    if (!prepared || !preview || state !== "IDLE" || !approval) return;
    if (preview.failed || preview.skipped ||
        preview.processed !== prepared.commands.length) {
      setError("Preview contains rejected commands. Refresh and prepare again.");
      return;
    }
    if (prepared.captureId !== captureId.trim()) {
      setError("Capture changed after preview.");
      return;
    }
    setState("EXECUTING");
    setError(null);
    setFeedback(null);
    const controller = new AbortController();
    try {
      const result = await json<ExecutionReport>(
        base + "/interventions", controller.signal,
        { ...prepared, dryRun: false, stopOnError },
      );
      setExecution(result);
      setApproval(false);
      setFeedback(result.failed ?
        "Execution completed with rejected commands. Inspect every outcome." :
        "Requested commands processed. See audit results below.");
      setRefreshToken(value => value + 1);
    } catch (cause) {
      setError(explanation(cause));
    } finally {
      setState("IDLE");
    }
  }
  function modifyNote(value: string) {
    setNote(value);
    resetPrepared();
  }
  function modifyAssignee(value: string) {
    setAssignee(value);
    resetPrepared();
  }
  const disabled = state !== "IDLE";
  const current = execution ?? preview;
  return <section aria-label="Integrity intervention console"
    style={{ marginBlock: 28, padding: 16, border: "1px solid #8885", borderRadius: 12 }}>
    <h2>Controlled integrity interventions</h2>
    <p>
      Explicit administrative operations with preview, optimistic concurrency,
      idempotency and audit events. No automatic provider verification,
      remediation closure or CyberScore change.
    </p>
    {error && <p role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {state !== "IDLE" && <p role="status">Operation: {state.toLowerCase()}</p>}
    <fieldset disabled={disabled}>
      <legend>Capture and command</legend>
      <label>Capture ID
        <input value={captureId} maxLength={100}
          onChange={event => chooseCapture(event.target.value)}
          placeholder="Required for execution" />
      </label>
      <label>Action
        <select value={kind} onChange={event =>
          changeKind(event.target.value as Operation)}>
          <option value="NOTIFY_ADMINS">Notify administrators in-app</option>
          <option value="REMIND_OWNER">Send in-app owner reminder</option>
          <option value="ASSIGN_OWNER">Assign review owner</option>
          <option value="UNASSIGN_OWNER">Unassign review owner</option>
          <option value="CLEAR_REMINDERS">Dismiss active reminders</option>
        </select>
      </label>
      {kind === "ASSIGN_OWNER" && <label>Organization member user ID
        <input value={assignee} maxLength={100}
          onChange={event => modifyAssignee(event.target.value)} />
      </label>}
      <label>Auditable reason
        <textarea rows={3} maxLength={2000} value={note}
          onChange={event => modifyNote(event.target.value)} />
      </label>
      <label>
        <input type="checkbox" checked={stopOnError}
          onChange={event => {
            setStopOnError(event.target.checked); resetPrepared();
          }} />
        Stop batch after first rejected command
      </label>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button type="button" onClick={selectEligible}>Select eligible on page</button>
        <button type="button" onClick={clearSelection}>Clear selection</button>
        <button type="button" onClick={() => {
          setRefreshToken(value => value + 1);
          resetPrepared(); setSelected([]);
        }}>Refresh review states</button>
      </div>
    </fieldset>
    <p>{selected.length} selected out of {rows.length} on the current page.
      Maximum batch size: {maxCommands}.</p>
    {!plan?.complete && plan &&
      <p>Page-limited queue: selection does not include unseen tasks.</p>}
    {rows.length === 0 && !disabled && <p>No tasks on the selected page.</p>}
    <div style={{ display: "grid", gap: 10 }}>
      {rows.map(row => <article key={row.taskId}
        style={{ padding: 12, border: "1px solid #8885", borderRadius: 8 }}>
        <label>
          <input type="checkbox" checked={selected.includes(row.taskId)}
            disabled={disabled || !eligibleOperations(row).includes(kind)}
            onChange={() => toggle(row)} />
          <strong>{row.title}</strong>
        </label>
        <p>{row.severity} · {row.disposition} · {row.urgency}
          {" · "}Priority {row.priority} · Revision {row.revision}</p>
        <p>Due {formatDate(row.dueAt)}
          {" · "}Owner {row.ownerUserId ?? "unassigned"}</p>
        <p>{row.signals.join(" · ") || "No active signals"}</p>
      </article>)}
    </div>
    {plan && <div style={{ display: "flex", gap: 12, marginBlock: 12 }}>
      <button type="button" disabled={disabled || offset === 0}
        onClick={() => {
          setOffset(value => Math.max(0, value - size));
          clearSelection();
        }}>Previous page</button>
      <button type="button" disabled={disabled || !plan.hasMore}
        onClick={() => {
          setOffset(value => value + size); clearSelection();
        }}>Next page</button>
    </div>}
    <button type="button" disabled={disabled || selected.length === 0}
      onClick={() => void beginPreview()}>Preview selected operations</button>
    {preview && <section aria-label="Intervention preview">
      <h3>Read-only preview</h3>
      <p>Requested {preview.requested} · Previewed {preview.previewed}
        {" · "}Rejected {preview.failed}</p>
      <ul>{preview.results.map((row, index) =>
        <li key={row.taskId + "-" + index}>
          {row.taskId}: {row.status} — {row.reason}
        </li>)}</ul>
      <label>
        <input type="checkbox" checked={approval}
          disabled={disabled || preview.failed > 0 ||
            preview.processed !== preview.requested}
          onChange={event => setApproval(event.target.checked)} />
        I authorize these in-app operations and understand that they may
        alter assignment or notification records.
      </label>
      <button type="button" disabled={disabled || !approval ||
        preview.failed > 0 || preview.processed !== preview.requested ||
        execution !== null}
        onClick={() => void commit()}>Commit approved operations</button>
    </section>}
    {current && <details open>
      <summary>Command results ({current.processed})</summary>
      <p>Applied {current.applied} · Replayed {current.replayed}
        {" · "}Failed {current.failed} · Skipped {current.skipped}</p>
      <ul>{current.results.map((row, index) =>
        <li key={row.taskId + "-" + index}>
          {row.kind} / {row.taskId}: {row.status} — {row.reason}
          {" · "}In-app messages: {row.notificationIds.length}
        </li>)}</ul>
      <p>Result digest: <code style={{ overflowWrap: "anywhere" }}>
        {current.digest}
      </code></p>
      <ul>{current.warnings.map(item =>
        <li key={item}>{item}</li>)}</ul>
    </details>}
  </section>;
}
