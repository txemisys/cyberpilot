"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type QueueRow = {
  taskId: string;
  title: string;
  severity: string;
  disposition: string;
  bucket: string;
  dueAt: string;
  overdueMinutes: number;
  ownerUserId: string | null;
  escalation: { id: string; level: number; state: string } | null;
  notifications: { unreadForCurrentUser: number };
  evidence: { latestProviderOutcome: string | null; providerChecks: number };
  flags: string[];
};
type InboxRow = {
  id: string;
  taskId: string;
  kind: string;
  title: string;
  message: string;
  revision: number;
  readAt: string | null;
  dismissedAt: string | null;
  createdAt: string;
};
type EscalationRow = {
  id: string;
  taskId: string;
  state: string;
  level: number;
  reason: string;
  revision: number;
  dueAt: string;
};
type Page<T> = {
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  rows?: T[];
  notifications?: T[];
  escalations?: T[];
};
type View = "QUEUE" | "INBOX" | "ESCALATIONS";
type RequestState = "IDLE" | "LOADING" | "SAVING";
function humanTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" :
    date.toLocaleString();
}
function readableError(value: unknown) {
  return value instanceof Error ? value.message : "Operation failed.";
}
async function jsonRequest<T>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options?.body ? { "Content-Type": "application/json" } : {}),
      ...(options?.headers ?? {}),
    },
  });
  const result: unknown = await response.json();
  if (!response.ok) {
    const record = result as { error?: string; code?: string };
    throw new Error(record.error ?? ("HTTP " + response.status));
  }
  return result as T;
}
const pageSize = 25;
export function IntegrityOperationsWorkspace({
  slug, canManage,
}: {
  slug: string;
  canManage: boolean;
}) {
  const base = "/api/organizations/" + encodeURIComponent(slug) +
    "/actions/work/integrity";
  const [view, setView] = useState<View>("QUEUE");
  const [state, setState] = useState<RequestState>("IDLE");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [bucket, setBucket] = useState("");
  const [severity, setSeverity] = useState("");
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [queue, setQueue] = useState<Page<QueueRow> | null>(null);
  const [inbox, setInbox] = useState<Page<InboxRow> | null>(null);
  const [escalations, setEscalations] = useState<Page<EscalationRow> | null>(null);
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [triageNote, setTriageNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const query = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(offset), limit: String(pageSize),
    });
    if (view === "QUEUE") {
      if (bucket) params.set("bucket", bucket);
      if (severity) params.set("severity", severity);
    }
    if (view === "INBOX")
      params.set("unreadOnly", String(unreadOnly));
    return params.toString();
  }, [offset, view, bucket, severity, unreadOnly]);
  const reload = useCallback(async () => {
    setState("LOADING");
    setError(null);
    try {
      if (view === "QUEUE") {
        const data = await jsonRequest<Page<QueueRow>>(
          base + "/operations-queue?" + query);
        setQueue(data);
      } else if (view === "INBOX") {
        const data = await jsonRequest<Page<InboxRow>>(
          base + "/notifications?" + query);
        setInbox(data);
      } else {
        const data = await jsonRequest<Page<EscalationRow>>(
          base + "/escalations?" + query);
        setEscalations(data);
      }
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setState("IDLE");
    }
  }, [base, view, query]);
  useEffect(() => { void reload(); }, [reload]);
  function navigate(next: View) {
    setView(next);
    setOffset(0);
    setError(null);
    setNotice(null);
  }
  async function perform(
    key: string, endpoint: string, method: "POST" | "PATCH",
    body: Record<string, unknown>,
  ) {
    if (pending) return;
    setPending(key);
    setState("SAVING");
    setError(null);
    setNotice(null);
    try {
      await jsonRequest(base + "/" + endpoint, {
        method, body: JSON.stringify(body),
      });
      setNotice("Action saved. The workspace has been refreshed.");
      await reload();
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setPending(null);
      setState("IDLE");
    }
  }
  async function inboxAction(
    row: InboxRow, action: "READ" | "UNREAD" | "DISMISS" | "RESTORE",
  ) {
    await perform(row.id, "notifications", "PATCH", {
      notificationId: row.id, action, expectedRevision: row.revision,
    });
  }
  async function escalationAction(
    row: EscalationRow, action: "ACKNOWLEDGE" | "RESOLVE" | "CANCEL" | "REOPEN",
  ) {
    const reason = window.prompt(
      "Reason for " + action.toLowerCase() + " (at least 12 characters):",
    );
    if (!reason || reason.trim().length < 12) return;
    await perform(row.id, "escalations", "PATCH", {
      escalationId: row.id, action, expectedRevision: row.revision,
      reason,
    });
  }
  async function triage(
    row: QueueRow, action: "ASSIGN" | "UNASSIGN" | "NOTIFY_OWNER" | "NOTIFY_ADMINS",
  ) {
    if (!canManage || triageNote.trim().length < 12) {
      setError("An administrator must provide a reason of at least 12 characters.");
      return;
    }
    if (action === "ASSIGN" && !assignee.trim()) {
      setError("Enter the user ID of an existing organization member.");
      return;
    }
    const revision = await jsonRequest<{
      task: { revision: number };
    }>(base + "/reviews?view=detail&taskId=" + encodeURIComponent(row.taskId));
    await perform(row.taskId, "review-triage", "POST", {
      dryRun: false,
      commands: [{
        taskId: row.taskId,
        action, expectedRevision: revision.task.revision,
        ...(action === "ASSIGN" ? { recipientUserId: assignee.trim() } : {}),
        note: triageNote.trim(),
        idempotencyKey: crypto.randomUUID(),
      }],
    });
  }
  const active = view === "QUEUE" ? queue :
    view === "INBOX" ? inbox : escalations;
  return (
    <main className="shell" style={{ maxWidth: 1180, margin: "0 auto", padding: 24 }}>
      <header>
        <p className="eyebrow">CyberPilot / Integrity / Operations</p>
        <h1>Integrity operations workspace</h1>
        <p>
          Review deadlines, triage ownership, in-app notifications and
          escalations. Human workflow completion does not certify a security control.
        </p>
      </header>
      <nav aria-label="Integrity workspace views"
        style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBlock: 20 }}>
        {(["QUEUE", "INBOX", "ESCALATIONS"] as const).map(next => (
          <button key={next} type="button"
            aria-pressed={view === next}
            onClick={() => navigate(next)}>
            {next === "QUEUE" ? "Review queue" :
              next === "INBOX" ? "My notifications" : "Escalations"}
          </button>
        ))}
        <button type="button" onClick={() => void reload()}
          disabled={state !== "IDLE"}>Refresh</button>
      </nav>
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {state !== "IDLE" && <p role="status">Working…</p>}
      {view === "QUEUE" && (
        <section aria-label="Review queue">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            <label>Bucket
              <select value={bucket} onChange={event => {
                setBucket(event.target.value); setOffset(0);
              }}>
                <option value="">All</option>
                {["OVERDUE", "DUE_SOON", "UNASSIGNED", "IN_PROGRESS",
                  "AWAITING_REVIEW", "COMPLETED", "WAIVED"].map(value => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>Severity
              <select value={severity} onChange={event => {
                setSeverity(event.target.value); setOffset(0);
              }}>
                <option value="">All</option>
                {["ERROR", "WARNING", "INFO"].map(value => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </label>
          </div>
          <p>
            {queue?.total ?? 0} tasks in the current query;
            bucket filters apply to the selected page only.
          </p>
          <div style={{ display: "grid", gap: 14 }}>
            {(queue?.rows ?? []).map(row => (
              <article key={row.taskId}
                style={{ border: "1px solid #8885", borderRadius: 8, padding: 16 }}>
                <h2 style={{ fontSize: "1.1rem" }}>{row.title}</h2>
                <p>
                  {row.severity} · {row.disposition} · {row.bucket}
                  {" · "}Due {humanTime(row.dueAt)}
                </p>
                <p>
                  Assignee: {row.ownerUserId ?? "Unassigned"}
                  {" · "}Provider: {row.evidence.latestProviderOutcome ?? "Not checked"}
                  {" · "}Unread: {row.notifications.unreadForCurrentUser}
                </p>
                {row.flags.length > 0 &&
                  <p>Flags: {row.flags.join(", ")}</p>}
                {canManage && (
                  <>
                    <button type="button"
                      onClick={() => setSelectedTask(
                        selectedTask === row.taskId ? null : row.taskId,
                      )}>
                      {selectedTask === row.taskId ? "Close triage" : "Triage"}
                    </button>
                    {selectedTask === row.taskId && (
                      <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
                        <label>Reason
                          <textarea value={triageNote}
                            onChange={event => setTriageNote(event.target.value)}
                            maxLength={2000} rows={3} />
                        </label>
                        <label>Assignee user ID
                          <input value={assignee}
                            onChange={event => setAssignee(event.target.value)} />
                        </label>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                          {(["ASSIGN", "UNASSIGN", "NOTIFY_OWNER", "NOTIFY_ADMINS"] as const)
                            .map(action => (
                              <button key={action} type="button"
                                disabled={pending !== null}
                                onClick={() => void triage(row, action)}>
                                {action.replaceAll("_", " ")}
                              </button>
                            ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </article>
            ))}
          </div>
        </section>
      )}
      {view === "INBOX" && (
        <section aria-label="My notification inbox">
          <label>
            <input type="checkbox" checked={unreadOnly}
              onChange={event => {
                setUnreadOnly(event.target.checked); setOffset(0);
              }} />
            Unread only
          </label>
          <p>{inbox?.total ?? 0} matching notifications</p>
          <div style={{ display: "grid", gap: 14 }}>
            {(inbox?.notifications ?? []).map(row => (
              <article key={row.id}
                style={{ border: "1px solid #8885", borderRadius: 8, padding: 16 }}>
                <h2 style={{ fontSize: "1.1rem" }}>{row.title}</h2>
                <p>{row.message}</p>
                <p>{row.kind} · {humanTime(row.createdAt)}
                  {" · "}{row.readAt ? "Read" : "Unread"}</p>
                <div style={{ display: "flex", gap: 8 }}>
                  <button type="button" disabled={pending !== null}
                    onClick={() => void inboxAction(
                      row, row.readAt ? "UNREAD" : "READ",
                    )}>{row.readAt ? "Mark unread" : "Mark read"}</button>
                  <button type="button" disabled={pending !== null}
                    onClick={() => void inboxAction(
                      row, row.dismissedAt ? "RESTORE" : "DISMISS",
                    )}>{row.dismissedAt ? "Restore" : "Dismiss"}</button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}
      {view === "ESCALATIONS" && (
        <section aria-label="Review escalations">
          <p>{escalations?.total ?? 0} escalation records</p>
          <div style={{ display: "grid", gap: 14 }}>
            {(escalations?.escalations ?? []).map(row => (
              <article key={row.id}
                style={{ border: "1px solid #8885", borderRadius: 8, padding: 16 }}>
                <h2 style={{ fontSize: "1.1rem" }}>
                  Level {row.level} · {row.state}
                </h2>
                <p>{row.reason}</p>
                <p>Review: {row.taskId} · Due {humanTime(row.dueAt)}</p>
                {canManage && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {(["ACKNOWLEDGE", "RESOLVE", "CANCEL", "REOPEN"] as const)
                      .filter(action =>
                        action === "REOPEN" ?
                          ["RESOLVED", "CANCELLED"].includes(row.state) :
                          action === "ACKNOWLEDGE" ? row.state === "OPEN" :
                          ["OPEN", "ACKNOWLEDGED"].includes(row.state))
                      .map(action => (
                        <button type="button" key={action}
                          disabled={pending !== null}
                          onClick={() => void escalationAction(row, action)}>
                          {action}
                        </button>
                      ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}
      {active && (
        <footer style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 24 }}>
          <button type="button" disabled={offset === 0 || state !== "IDLE"}
            onClick={() => setOffset(Math.max(0, offset - pageSize))}>
            Previous
          </button>
          <span>Page {Math.floor(offset / pageSize) + 1}</span>
          <button type="button" disabled={!active.hasMore || state !== "IDLE"}
            onClick={() => setOffset(offset + pageSize)}>
            Next
          </button>
        </footer>
      )}
    </main>
  );
}
