import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";

/** Downloadable, read-only workload handoff for an authorized organization's workspace. */
export type ActionWorkloadCsv = {
  organizationId: string;
  filename: string;
  mimeType: "text/csv; charset=utf-8";
  content: string;
};

const csv = (value: string | number | null) => {
  const raw = value === null ? "" : String(value);
  const safe = /^[=+@\-\t\r\n]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""') + '"';
};

/** Export only aggregated workload, never underlying evidence or tenant secrets. */
export function exportActionOwnerWorkloadCsv(
  summary: ActionOwnerWorkloadSummary,
  organizationId: string,
): ActionWorkloadCsv | null {
  if (!organizationId || summary.organizationId !== organizationId ||
      !/^\d{4}-\d{2}-\d{2}$/.test(summary.asOf)) return null;
  const headers = ["owner", "overdue", "upcoming", "highPriority", "earliestDueDate"];
  const rows = [...summary.assigned, summary.unassigned].map(row =>
    [row.owner ?? "UNASSIGNED", row.overdue, row.upcoming, row.highPriority, row.earliestDueDate]
      .map(csv).join(",")
  );
  return {
    organizationId,
    filename: "action-owner-workload-" + summary.asOf + ".csv",
    mimeType: "text/csv; charset=utf-8",
    content: [headers.join(","), ...rows].join("\r\n") + "\r\n",
  };
}
