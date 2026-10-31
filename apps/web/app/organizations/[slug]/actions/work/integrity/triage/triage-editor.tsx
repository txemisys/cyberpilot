"use client";

import { useState, type FormEvent } from "react";
import { INTEGRITY_CODES, type IntegrityCode } from "../../../../../../../lib/work-integrity";
import {
  TRIAGE_DECISIONS, type TriageDecision,
} from "../../../../../../../lib/work-integrity-triage";

type Props = { slug: string };
type ReviewResponse = { event?: { id: string }; error?: string; code?: string };
export default function TriageEditor({ slug }: Props) {
  const [workItemId, setWorkItemId] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [code, setCode] = useState<IntegrityCode>(INTEGRITY_CODES[0]!);
  const [decision, setDecision] = useState<TriageDecision>("INVESTIGATE");
  const [revision, setRevision] = useState("1");
  const [rationale, setRationale] = useState("");
  const [reference, setReference] = useState("");
  const [previousId, setPreviousId] = useState("");
  const [busy, setBusy] = useState(false);
  const [response, setResponse] = useState<ReviewResponse | null>(null);
  const endpoint = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/triage`;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setResponse(null);
    try {
      const result = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          workItemId: workItemId.trim(),
          resourceId: resourceId.trim(),
          code, decision, revision: Number(revision),
          rationale: rationale.trim(), reference: reference.trim() || null,
          expectedPreviousEventId: previousId.trim() || null,
        }),
      });
      const json = await result.json() as ReviewResponse;
      if (!result.ok) {
        setResponse({ error: json.error ?? "The review decision could not be saved." });
        return;
      }
      if (!json.event?.id) {
        setResponse({ error: "No audit event identifier was returned." });
        return;
      }
      setResponse(json);
      setPreviousId(json.event.id);
      setRationale("");
    } catch {
      setResponse({ error: "Request failed. No successful review was confirmed." });
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="remediation-card" aria-label="Record a new integrity review decision">
      <h2>Record a review decision</h2>
      <p>Use identifiers and the current revision from the integrity diagnostic and work record.
        To update a previous review, supply its most recent audit event ID.</p>
      <form className="remediation-actions" onSubmit={submit}>
        <label htmlFor="triage-item">Work item ID</label>
        <input id="triage-item" required minLength={5} maxLength={100}
          value={workItemId} onChange={e => setWorkItemId(e.target.value)} />
        <label htmlFor="triage-resource">Linked resource ID</label>
        <input id="triage-resource" required minLength={5} maxLength={100}
          value={resourceId} onChange={e => setResourceId(e.target.value)} />
        <label htmlFor="triage-code">Diagnostic</label>
        <select id="triage-code" value={code}
          onChange={e => setCode(e.target.value as IntegrityCode)}>
          {INTEGRITY_CODES.map(value => <option key={value} value={value}>{value}</option>)}
        </select>
        <label htmlFor="triage-decision">Review decision</label>
        <select id="triage-decision" value={decision}
          onChange={e => setDecision(e.target.value as TriageDecision)}>
          {TRIAGE_DECISIONS.map(value => <option key={value} value={value}>{value}</option>)}
        </select>
        <label htmlFor="triage-revision">Current work item revision</label>
        <input id="triage-revision" type="number" min="1" max="2147483647"
          required value={revision} onChange={e => setRevision(e.target.value)} />
        <label htmlFor="triage-rationale">Rationale (10–2,000 characters)</label>
        <textarea id="triage-rationale" required minLength={10} maxLength={2000}
          rows={4} value={rationale} onChange={e => setRationale(e.target.value)} />
        <label htmlFor="triage-reference">Ticket or other reference (optional)</label>
        <input id="triage-reference" maxLength={200}
          value={reference} onChange={e => setReference(e.target.value)} />
        <label htmlFor="triage-previous">Latest audit event ID (for subsequent decisions)</label>
        <input id="triage-previous" maxLength={100}
          value={previousId} onChange={e => setPreviousId(e.target.value)} />
        <button type="submit" className="secondary-button" disabled={busy}>
          {busy ? "Recording review…" : "Record auditable review"}
        </button>
      </form>
      {response?.error ? <p role="alert" className="auth-error">{response.error}</p> : null}
      {response?.event ? (
        <p role="status">
          Review recorded as audit event {response.event.id}. This did not
          verify or resolve a security finding. Refresh this page to see its history.
        </p>
      ) : null}
    </section>
  );
}
