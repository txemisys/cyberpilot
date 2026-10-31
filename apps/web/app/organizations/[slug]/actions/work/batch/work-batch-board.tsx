"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";

type WorkStatus = "TODO" | "IN_PROGRESS" | "BLOCKED" | "DONE" | "CANCELLED";
type WorkPriority = "LOW" | "NORMAL" | "HIGH" | "URGENT";
type BatchField = "status" | "priority" | "assigneeUserId" | "dueAt";
type WorkRow = {
  id: string;
  title: string;
  description: string;
  status: WorkStatus;
  priority: WorkPriority;
  assigneeUserId: string | null;
  dueAt: string | null;
  revision: number;
  finding: { title: string; severity: string; status: string };
  remediation: { title: string; status: string };
};
type Member = { role: string; user: { id: string; name: string; email: string } };
type WorkPage = { rows: WorkRow[]; total: number; pages: number; page: number };
type Decision = {
  id: string;
  field: BatchField;
  revision: number;
  current: string | null;
  proposed: string | null;
  outcome: "READY" | "UNCHANGED" | "STALE" | "MISSING" | "INVALID";
  message: string;
};
type Preview = {
  mode: "preview";
  ready: boolean;
  executable: number;
  total: number;
  decisions: Decision[];
  note: string;
};
type Applied = {
  mode: "apply";
  changed: number;
  items: { id: string; revision: number }[];
  note: string;
};
type Change = {
  id: string;
  revision: number;
  field: BatchField;
  value: string | null;
};
type Props = { slug: string };
const statuses: WorkStatus[] = ["TODO", "IN_PROGRESS", "BLOCKED", "DONE", "CANCELLED"];
const priorities: WorkPriority[] = ["LOW", "NORMAL", "HIGH", "URGENT"];
const labels: Record<BatchField, string> = {
  status: "Work status",
  priority: "Work priority",
  assigneeUserId: "Assigned member",
  dueAt: "Target date",
};
function dateValue(value: string | null) {
  if (!value) return "";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString().slice(0, 10);
}
function originalValue(item: WorkRow, field: BatchField) {
  if (field === "dueAt") return dateValue(item.dueAt);
  return item[field] ?? "";
}
async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    if (body && typeof body === "object" && "error" in body)
      throw new Error(String(body.error));
    throw new Error(`Request failed with status ${response.status}.`);
  }
  return body as T;
}
function compareChange(a: Change, b: Change) {
  return a.id === b.id && a.field === b.field;
}
export default function WorkBatchBoard({ slug }: Props) {
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work`;
  const [rows, setRows] = useState<WorkRow[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [status, setStatus] = useState("ALL");
  const [priority, setPriority] = useState("ALL");
  const [due, setDue] = useState("ALL");
  const [assignee, setAssignee] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [field, setField] = useState<BatchField>("status");
  const [value, setValue] = useState("IN_PROGRESS");
  const [changes, setChanges] = useState<Change[]>([]);
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loading, setLoading] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loadVersion, setLoadVersion] = useState(0);
  const byId = useMemo(() => new Map(rows.map(item => [item.id, item])), [rows]);
  const validPreview = preview?.ready === true && preview.executable > 0;
  const readyForPreview = changes.length > 0 && reason.trim().length >= 10;
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({
        status, priority, due, assignee, search, page: String(page), pageSize: "50",
      });
      const result = await json<WorkPage>(`${api}?${q.toString()}`);
      setRows(result.rows);
      setTotal(result.total);
      setPages(result.pages);
      setSelected([]);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load work.");
    } finally {
      setLoading(false);
    }
  }, [api, status, priority, due, assignee, search, page, loadVersion]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    void json<{ assignees: Member[] }>(`${api}?meta=assignees`)
      .then(result => setMembers(result.assignees))
      .catch(cause => setError(
        cause instanceof Error ? cause.message : "Unable to load organization members."));
  }, [api]);
  function resetPreview() {
    setPreview(null);
    setNotice("");
  }
  function updateField(next: BatchField) {
    setField(next);
    setValue(next === "status" ? "IN_PROGRESS" :
      next === "priority" ? "HIGH" : "");
  }
  function toggle(id: string) {
    setSelected(current => current.includes(id)
      ? current.filter(value => value !== id)
      : [...current, id]);
  }
  function selectPage() {
    setSelected(rows.map(row => row.id));
  }
  function clearPage() {
    setSelected([]);
  }
  function enqueue() {
    if (!selected.length) {
      setError("Select at least one work item.");
      return;
    }
    const proposed = selected.map(id => {
      const item = byId.get(id);
      if (!item) return null;
      return {
        id, revision: item.revision, field,
        value: value === "" ? null : value,
      } satisfies Change;
    }).filter((change): change is Change => change !== null);
    const merged = [...changes];
    for (const change of proposed) {
      const index = merged.findIndex(current => compareChange(current, change));
      if (index >= 0) merged[index] = change;
      else merged.push(change);
    }
    if (merged.length > 50) {
      setError("A batch can contain at most 50 distinct field changes.");
      return;
    }
    setChanges(merged);
    resetPreview();
    setError("");
  }
  function discard(id: string, fieldToRemove: BatchField) {
    setChanges(current => current.filter(change =>
      !(change.id === id && change.field === fieldToRemove)));
    resetPreview();
  }
  function discardAll() {
    setChanges([]);
    resetPreview();
  }
  async function run(mode: "preview" | "apply") {
    if (!readyForPreview || working) return;
    setWorking(true);
    setError("");
    setNotice("");
    try {
      const body = JSON.stringify({ mode, reason, changes: changes.map(change => ({
        ...change,
        value: change.field === "dueAt" && change.value
          ? change.value : change.value,
      })) });
      if (mode === "preview") {
        const result = await json<Preview>(`${api}/batch`, { method: "POST", body });
        setPreview(result);
        if (!result.ready)
          setNotice("Review rejected or stale rows. No updates were made.");
      } else {
        if (!validPreview) throw new Error("Preview the current batch before applying.");
        const result = await json<Applied>(`${api}/batch`, { method: "POST", body });
        setChanges([]);
        setSelected([]);
        setPreview(null);
        setReason("");
        setNotice(`${result.changed} work items updated. Verification status is unchanged.`);
        setLoadVersion(version => version + 1);
      }
    } catch (cause) {
      setPreview(null);
      setError(cause instanceof Error ? cause.message : "Work batch failed.");
    } finally {
      setWorking(false);
    }
  }
  function onFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(1);
    setLoadVersion(value => value + 1);
  }
  const statusesField = field === "status";
  const prioritiesField = field === "priority";
  const assigneeField = field === "assigneeUserId";
  const dueField = field === "dueAt";
  return <div>
    <section className="panel">
      <h2>Controlled work coordination</h2>
      <p>Prepare up to 50 changes, inspect their current revisions and apply them in one
        database transaction. All changes record an actor, before/after snapshot and reason.</p>
      <p className="permission-warning">
        This only changes work tracking. It never claims a control is verified,
        resolves a security finding, or changes a remediation execution result.
      </p>
      <p><Link href={`/organizations/${slug}/actions/work`}>Return to individual work items</Link></p>
    </section>
    {error ? <p role="alert" className="auth-error">{error}</p> : null}
    {notice ? <p role="status">{notice}</p> : null}
    <form className="panel remediation-actions" onSubmit={onFilter}>
      <h2>Locate the work items</h2>
      <label htmlFor="batch-search">Search work</label>
      <input id="batch-search" value={search} maxLength={120}
        onChange={event => setSearch(event.target.value)} />
      <label htmlFor="batch-status">Status</label>
      <select id="batch-status" value={status} onChange={event => setStatus(event.target.value)}>
        <option value="ALL">Any status</option>
        {statuses.map(option => <option key={option}>{option}</option>)}
      </select>
      <label htmlFor="batch-priority">Priority</label>
      <select id="batch-priority" value={priority} onChange={event => setPriority(event.target.value)}>
        <option value="ALL">Any priority</option>
        {priorities.map(option => <option key={option}>{option}</option>)}
      </select>
      <label htmlFor="batch-due">Deadline</label>
      <select id="batch-due" value={due} onChange={event => setDue(event.target.value)}>
        <option value="ALL">Any date</option>
        <option value="OVERDUE">Overdue</option>
        <option value="NEXT_7_DAYS">Next 7 days</option>
        <option value="NO_DATE">Without deadline</option>
      </select>
      <label htmlFor="batch-assignee">Assigned member</label>
      <select id="batch-assignee" value={assignee}
        onChange={event => setAssignee(event.target.value)}>
        <option value="ALL">Everyone</option>
        <option value="UNASSIGNED">Unassigned</option>
        {members.map(person => <option key={person.user.id}
          value={person.user.id}>{person.user.name}</option>)}
      </select>
      <button type="submit" disabled={loading}>Search</button>
    </form>
    <section className="panel">
      <h2>Select work</h2>
      <p>{total} matching records · page {page} of {pages}. Only this page can be selected.</p>
      <button type="button" disabled={loading || !rows.length} onClick={selectPage}>
        Select this page
      </button>
      <button type="button" onClick={clearPage}>Clear selection</button>
      {loading ? <p>Loading work items…</p> : null}
      {!loading && rows.length === 0 ? <p>No matching work items.</p> : null}
      <div className="remediation-list">
        {rows.map(item => <article className="remediation-card" key={item.id}>
          <label>
            <input type="checkbox" checked={selected.includes(item.id)}
              onChange={() => toggle(item.id)} />
            <strong>{item.title}</strong>
          </label>
          <p>{item.status} · {item.priority} · revision {item.revision}</p>
          <p>Due: {dateValue(item.dueAt) || "Not set"} · Assigned: {
            members.find(member => member.user.id === item.assigneeUserId)?.user.name ?? "Unassigned"
          }</p>
          <p>Finding: {item.finding.title} ({item.finding.status})</p>
          <p>Remediation: {item.remediation.title} ({item.remediation.status})</p>
        </article>)}
      </div>
      <nav aria-label="Work selection pages">
        <button type="button" disabled={loading || page <= 1}
          onClick={() => setPage(current => current - 1)}>Previous</button>
        <span> Page {page} / {pages} </span>
        <button type="button" disabled={loading || page >= pages}
          onClick={() => setPage(current => current + 1)}>Next</button>
      </nav>
    </section>
    <section className="panel remediation-actions">
      <h2>Stage a change</h2>
      <p>{selected.length} work items selected. Repeated changes to the same field
        replace the previous staged value.</p>
      <label htmlFor="batch-field">Property to update</label>
      <select id="batch-field" value={field}
        onChange={event => updateField(event.target.value as BatchField)}>
        {(Object.keys(labels) as BatchField[]).map(option =>
          <option key={option} value={option}>{labels[option]}</option>)}
      </select>
      <label htmlFor="batch-value">New value</label>
      {statusesField ? <select id="batch-value" value={value}
        onChange={event => setValue(event.target.value)}>
        {statuses.map(option => <option key={option}>{option}</option>)}
      </select> : null}
      {prioritiesField ? <select id="batch-value" value={value}
        onChange={event => setValue(event.target.value)}>
        {priorities.map(option => <option key={option}>{option}</option>)}
      </select> : null}
      {assigneeField ? <select id="batch-value" value={value}
        onChange={event => setValue(event.target.value)}>
        <option value="">Unassign</option>
        {members.map(person => <option key={person.user.id}
          value={person.user.id}>{person.user.name} ({person.role})</option>)}
      </select> : null}
      {dueField ? <input id="batch-value" type="date" value={value}
        onChange={event => setValue(event.target.value)} /> : null}
      <button type="button" disabled={!selected.length} onClick={enqueue}>
        Stage for selected work
      </button>
    </section>
    <section className="panel">
      <h2>Pending changes</h2>
      <p>{changes.length} distinct field changes staged.</p>
      <button type="button" disabled={!changes.length} onClick={discardAll}>
        Discard entire batch
      </button>
      <ol>{changes.map(change => <li key={`${change.id}:${change.field}`}>
        <strong>{byId.get(change.id)?.title ?? change.id}</strong> · {labels[change.field]}:
        {" "}{change.value ?? "(clear)"} · revision {change.revision}
        <button type="button" onClick={() => discard(change.id, change.field)}>
          Remove
        </button>
      </li>)}</ol>
      <label htmlFor="batch-reason">Why are these work records changing?</label>
      <textarea id="batch-reason" minLength={10} maxLength={1000} required
        value={reason} onChange={event => { setReason(event.target.value); resetPreview(); }}
        placeholder="Explain the coordination decision for the audit history." />
      <button type="button" disabled={!readyForPreview || working}
        onClick={() => void run("preview")}>
        {working ? "Checking…" : "Preview against current revisions"}
      </button>
      {preview ? <section aria-live="polite">
        <h3>Preflight review</h3>
        <p>{preview.executable} changes ready out of {preview.total} · {
          preview.ready ? "All records valid" : "Resolve conflicts first"
        }</p>
        <p>{preview.note}</p>
        <table>
          <thead><tr><th>Work ID</th><th>Field</th><th>Current</th>
            <th>Proposed</th><th>Decision</th></tr></thead>
          <tbody>{preview.decisions.map(decision =>
            <tr key={`${decision.id}:${decision.field}`}>
              <td>{decision.id}</td><td>{decision.field}</td>
              <td>{decision.current ?? "None"}</td><td>{decision.proposed ?? "None"}</td>
              <td>{decision.outcome} — {decision.message}</td>
            </tr>)}</tbody>
        </table>
        <p>Apply re-reads the database in a transaction. Any revision conflict prevents
          the entire batch from committing.</p>
        <button type="button" disabled={!validPreview || working}
          onClick={() => void run("apply")}>
          {working ? "Applying…" : "Apply all valid changes atomically"}
        </button>
      </section> : null}
    </section>
  </div>;
}
