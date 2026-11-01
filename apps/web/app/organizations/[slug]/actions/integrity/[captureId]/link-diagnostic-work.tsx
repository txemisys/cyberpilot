"use client";

import { useState, type FormEvent } from "react";

type Props = {
  slug: string; captureId: string; caseKey: string;
};
export default function LinkDiagnosticWork({ slug, captureId, caseKey }: Props) {
  const [workItemId, setWorkItemId] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setStatus("");
    try {
      const response = await fetch(
        `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/evidence-links`,
        {
          method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ captureId, caseKey, workItemId: workItemId.trim() }),
        },
      );
      const result: { error?: string; link?: { auditId: string } } = await response.json();
      if (!response.ok) {
        setStatus(result.error ?? "The evidence link could not be recorded.");
        return;
      }
      setStatus(`Evidence association recorded (audit ${result.link?.auditId ?? "created"}). This does not verify remediation.`);
      setWorkItemId("");
    } catch {
      setStatus("The evidence link could not be recorded. Retry when connected.");
    } finally {
      setBusy(false);
    }
  }
  return <form onSubmit={submit}>
    <label>
      Associate this historical diagnostic with an existing work item
      <input value={workItemId} onChange={event => setWorkItemId(event.target.value)}
        placeholder="Existing work item ID" required minLength={5} maxLength={100}
        pattern="[a-zA-Z0-9_-]{5,100}" />
    </label>
    <button type="submit" disabled={busy}>{busy ? "Recording…" : "Record evidence association"}</button>
    {status && <p role="status">{status}</p>}
  </form>;
}
