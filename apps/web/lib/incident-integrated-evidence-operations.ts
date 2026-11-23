import { createHash } from "node:crypto";
import type { IncidentEvidenceCorrelation, CorrelatedSource,
  CorrelationVerdict } from "./incident-integrated-evidence-domain";
export type EvidenceReviewQueueItem = {
  id: string; sourceId: string; kind: string; incidentId: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string; requiredAction: string; requiredRole: "ADMIN" | "REVIEWER";
  dueInMinutes: number; independentlyCorrected: false;
};
export type EvidenceReviewSummary = {
  schema: "cyberpilot.incident.evidence.review-queue.v1";
  organizationId: string; incidentId: string; producedAt: string;
  items: EvidenceReviewQueueItem[]; queued: number;
  unsupported: number; stale: number; missing: number;
  error: number; urgent: number; humanOnly: true;
  providerWrites: 0; executedRemediations: 0;
};
const priority = (row: CorrelatedSource):
  EvidenceReviewQueueItem["priority"] =>
  row.verdict === "ERROR_RECORD" || row.verdict === "CROSS_TENANT_REJECTED" ?
    "CRITICAL" : row.verdict === "CONFLICT" || row.verdict === "STALE_RECORD" ?
    "HIGH" : row.verdict === "UNKNOWN_COVERAGE" ||
    row.verdict === "MISSING_RECORD" ? "MEDIUM" : "LOW";
const time = (row: CorrelatedSource) => {
  const urgency = priority(row);
  return urgency === "CRITICAL" ? 30 : urgency === "HIGH" ? 120 :
    urgency === "MEDIUM" ? 480 : 1440;
};
export function buildIncidentEvidenceReviewQueue(
  correlation: IncidentEvidenceCorrelation,
): EvidenceReviewSummary {
  if (correlation.sourceRecords.some(x =>
      x.organizationId !== correlation.organizationId ||
      x.incidentId !== correlation.incidentId))
    throw Error("INCIDENT_EVIDENCE_REVIEW_CROSS_TENANT");
  const items: EvidenceReviewQueueItem[] = [];
  for (const row of correlation.sourceRecords) {
    if (row.verdict === "SUPPORTED_RECORD" && !row.requiredReview) continue;
    const reason = row.signals.join(", ") || "Independent action outcome is not proven";
    const requiredAction = row.verdict === "ERROR_RECORD" ?
      "Resolve source collection error and reread with original permissions" :
      row.verdict === "STALE_RECORD" ?
      "Collect a fresh timestamped observation without overwriting prior evidence" :
      row.verdict === "UNKNOWN_COVERAGE" ?
      "Check retention, license, scope and source availability" :
      row.verdict === "DECLARED_RECORD" ?
      "Obtain independent verification from a different source" :
      "Review explicit source identity and original evidence digest";
    items.push({ id: row.id, sourceId: row.sourceId,
      kind: row.kind, incidentId: correlation.incidentId,
      priority: priority(row), reason, requiredAction,
      requiredRole: row.kind === "DECISION" ? "ADMIN" : "REVIEWER",
      dueInMinutes: time(row), independentlyCorrected: false });
  }
  for (const id of correlation.missingIds) {
    items.push({
      id: "MISSING:" + id, sourceId: id, kind: "UNKNOWN",
      incidentId: correlation.incidentId, priority: "HIGH",
      reason: "Explicitly selected record did not exist in the organization",
      requiredAction: "Verify identity, retention, deletion and tenant scope; never invent a substitute",
      requiredRole: "REVIEWER", dueInMinutes: 120,
      independentlyCorrected: false,
    });
  }
  for (const step of correlation.steps) {
    if (!step.missingSources.length) continue;
    for (const name of step.missingSources) {
      items.push({ id: "SOURCE:" + step.stepId + ":" + name,
        sourceId: name, kind: "STEP_SOURCE", incidentId: correlation.incidentId,
        priority: "MEDIUM", reason: "Playbook requires a source not established in this review",
        requiredAction: "Request exact independent evidence source or explicitly mark unavailable",
        requiredRole: "REVIEWER", dueInMinutes: 480,
        independentlyCorrected: false });
    }
  }
  const weight: Record<EvidenceReviewQueueItem["priority"], number> =
    { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  items.sort((a, b) => weight[b.priority] - weight[a.priority] ||
    a.id.localeCompare(b.id));
  return { schema: "cyberpilot.incident.evidence.review-queue.v1",
    organizationId: correlation.organizationId,
    incidentId: correlation.incidentId, producedAt: correlation.generatedAt,
    items: items.slice(0, 500), queued: items.length,
    unsupported: correlation.sourceRecords.filter(x =>
      x.verdict === "DECLARED_RECORD").length,
    stale: correlation.sourceRecords.filter(x =>
      x.verdict === "STALE_RECORD").length, missing: correlation.missingIds.length,
    error: correlation.sourceRecords.filter(x =>
      x.verdict === "ERROR_RECORD").length,
    urgent: items.filter(x => x.priority === "CRITICAL").length,
    humanOnly: true, providerWrites: 0, executedRemediations: 0 };
}
export type EvidenceReviewMatrix = {
  schema: "cyberpilot.incident.evidence.matrix.v1";
  organizationId: string; incidentId: string;
  rows: Array<{ verdict: CorrelationVerdict; evidence: number;
    findings: number; decisions: number; needsReview: number }>;
  independentProofRate: number | null;
  unknownCoverageRate: number | null; total: number;
  matrixDigest: string; excludedDataKinds: string[];
  actualSecurityPostureImproved: false;
};
export function summarizeIncidentEvidenceMatrix(
  correlation: IncidentEvidenceCorrelation,
): EvidenceReviewMatrix {
  const verdicts: CorrelationVerdict[] = [
    "SUPPORTED_RECORD", "DECLARED_RECORD", "UNKNOWN_COVERAGE",
    "STALE_RECORD", "ERROR_RECORD", "CONFLICT",
    "MISSING_RECORD", "CROSS_TENANT_REJECTED",
  ];
  const rows = verdicts.map(verdict => {
    const subset = correlation.sourceRecords.filter(x => x.verdict === verdict);
    return { verdict,
      evidence: subset.filter(x => x.kind === "EVIDENCE").length,
      findings: subset.filter(x => x.kind === "FINDING").length,
      decisions: subset.filter(x => x.kind === "DECISION").length,
      needsReview: subset.filter(x => x.requiredReview).length };
  });
  const all = correlation.sourceRecords.length;
  const independent = correlation.sourceRecords.filter(x =>
    x.kind === "EVIDENCE" &&
    x.evidenceConfidence === "INDEPENDENTLY_PERSISTED").length;
  const unknown = correlation.sourceRecords.filter(x =>
    ["UNKNOWN_COVERAGE", "ERROR_RECORD", "STALE_RECORD",
      "MISSING_RECORD"].includes(x.verdict)).length;
  return { schema: "cyberpilot.incident.evidence.matrix.v1",
    organizationId: correlation.organizationId, incidentId: correlation.incidentId,
    rows, independentProofRate: all ? independent / all : null,
    unknownCoverageRate: all ? unknown / all : null,
    total: all, matrixDigest: createHash("sha256").update(JSON.stringify(rows))
      .digest("hex"),
    excludedDataKinds: ["provider live actions", "deleted message content",
      "unconsented mailbox contents", "unverified identity inference"],
    actualSecurityPostureImproved: false };
}
const csvField = (value: unknown): string => {
  const raw = String(value ?? "");
  const escaped = /^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw;
  return '"' + escaped.replaceAll('"', '""')
    .replaceAll("\n", " ").replaceAll("\r", " ") + '"';
};
export function exportIntegratedIncidentEvidence(
  correlation: IncidentEvidenceCorrelation,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  const matrix = summarizeIncidentEvidenceMatrix(correlation);
  const queue = buildIncidentEvidenceReviewQueue(correlation);
  const name = "incident-evidence-" + correlation.incidentId;
  const manifest = { schema: "cyberpilot.incident.evidence.dossier.v1",
    correlation, matrix, queue,
    independentProviderContainment: false, providerWrites: 0,
  };
  const digest = createHash("sha256").update(JSON.stringify(manifest))
    .digest("hex");
  if (format === "JSON") return { filename: name + ".json",
    mime: "application/json", digest,
    content: JSON.stringify({ ...manifest, digest }, null, 2) };
  if (format === "CSV") {
    const rows = [["kind", "sourceId", "verdict", "basis", "source",
      "confidence", "review", "observedAt"],
      ...correlation.sourceRecords.map(row => [
        row.kind, row.sourceId, row.verdict, row.basis,
        row.sourceLabel, row.evidenceConfidence,
        String(row.requiredReview), row.observedAt ?? "",
      ])];
    return { filename: name + ".csv", mime: "text/csv", digest,
      content: rows.map(row => row.map(csvField).join(",")).join("\r\n") };
  }
  if (format !== "MARKDOWN") throw Error("EVIDENCE_EXPORT_FORMAT_INVALID");
  const safe = (x: string) => x.replaceAll("|", "\\|")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  return { filename: name + ".md", mime: "text/markdown", digest,
    content: ["# Incident evidence correlation",
      "Organization: " + correlation.organizationId,
      "Incident: " + correlation.incidentId,
      "State: " + correlation.acceptance,
      "Known records: " + matrix.total,
      "Pending human reviews: " + queue.queued,
      "Provider containment verified: NO",
      "Digest: " + digest, "", "## Evidence",
      "| Type | Source | Status |",
      "|---|---|---|",
      ...correlation.sourceRecords.map(x => "| " + x.kind + " | " +
        safe(x.sourceLabel) + " | " + x.verdict + " |"), "",
      "## Human follow-up",
      ...queue.items.map(x => "- " + safe(x.requiredAction) +
        " (" + x.priority + ")"),
      "", "No source observation independently proves provider remediation.",
    ].join("\n") };
}
