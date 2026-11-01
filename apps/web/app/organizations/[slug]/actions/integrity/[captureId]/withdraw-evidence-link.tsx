"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type Props = {
  slug: string;
  auditId: string;
  workItemId: string;
};
export default function WithdrawEvidenceLink({ slug, auditId, workItemId }: Props) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function withdraw() {
    if (busy || !window.confirm(
      `Withdraw the evidence association with work item ${workItemId}? The audit trail will remain.`,
    )) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/evidence-links`,
        {
          method: "DELETE",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ auditId }),
        },
      );
      const result: { error?: string } = await response.json();
      if (!response.ok) {
        setError(result.error ?? "Unable to withdraw association.");
        return;
      }
      router.refresh();
    } catch {
      setError("Unable to withdraw association. Check your connection.");
    } finally {
      setBusy(false);
    }
  }
  return <span>
    <button type="button" disabled={busy} onClick={withdraw}>
      {busy ? "Withdrawing…" : "Withdraw association"}
    </button>
    {error && <span role="alert">{error}</span>}
  </span>;
}
