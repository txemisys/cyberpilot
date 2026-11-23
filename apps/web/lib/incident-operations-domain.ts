import { createHash } from "node:crypto";
import { getIncidentPlaybook, INCIDENT_TYPES,
  type IncidentState, type IncidentType } from "./incident-playbook-catalog";
import { incidentDigest, type IncidentSnapshot, type IncidentEvent,
  type IncidentEvidence } from "./incident-case-domain";

export type IncidentPortfolio = {
  schema: "cyberpilot.incident.portfolio.v1"; organizationId: string;
  asOf: string; total: number; truncated: boolean;
  status: Record<IncidentState, number>;
  byType: Record<IncidentType, number>;
  urgent: number; unassigned: number; needsApproval: number;
  missingIndependentProof: number; reportedButNotVerified: number;
  staleOver24h: number; closedWorkflowOnly: number; missingEvidence: number;
  riskReductionProven: false; providerWrites: 0;
};
export function buildIncidentPortfolio(organizationId: string,
  rows: IncidentSnapshot[], truncated: boolean, asOf: string): IncidentPortfolio {
  if (!organizationId || rows.length > 500 || rows.some(x => x.organizationId !== organizationId) ||
      !Number.isFinite(Date.parse(asOf))) throw new Error("INCIDENT_PORTFOLIO_SCOPE_INVALID");
  const states: IncidentState[] = ["OPEN", "TRIAGE", "CONTAINMENT", "RECOVERY", "REVIEW", "CLOSED"];
  const status = Object.fromEntries(states.map(s => [s, rows.filter(r => r.status === s).length]))
    as Record<IncidentState, number>;
  const byType = Object.fromEntries(INCIDENT_TYPES.map(t =>
    [t, rows.filter(r => r.type === t).length])) as Record<IncidentType, number>;
  const age = new Date(asOf).getTime();
  const needsApproval = (x: IncidentSnapshot) => {
    const book = getIncidentPlaybook(x.type);
    return x.steps.some(p => {
      const spec = book.steps.find(s => s.id === p.stepId)!;
      return spec.requiresApproval && p.status !== "PENDING" &&
        !x.approvals.some(a => a.stepId === p.stepId &&
          new Date(a.expiresAt).getTime() > age);
    });
  };
  const missingProof = (x: IncidentSnapshot) => x.steps.some(p => {
    if (p.status === "PENDING") return false;
    const evidence = x.evidence.filter(e => p.evidenceIds.includes(e.id));
    return !evidence.some(e => e.independent && e.verdict === "OBSERVED");
  });
  return {
    schema: "cyberpilot.incident.portfolio.v1", organizationId, asOf,
    total: rows.length, truncated, status, byType,
    urgent: rows.filter(x => x.status !== "CLOSED" &&
      x.severity === "CRITICAL").length,
    unassigned: rows.filter(x => x.ownerUserId === null && x.status !== "CLOSED").length,
    needsApproval: rows.filter(needsApproval).length,
    missingIndependentProof: rows.filter(missingProof).length,
    reportedButNotVerified: rows.filter(x => x.steps.some(p => p.status === "REPORTED_DONE")).length,
    staleOver24h: rows.filter(x => x.status !== "CLOSED" &&
      age - new Date(x.updatedAt).getTime() > 86400000).length,
    closedWorkflowOnly: rows.filter(x => x.status === "CLOSED").length,
    missingEvidence: rows.filter(x => x.steps.some(s =>
      s.status !== "PENDING" && s.evidenceIds.length === 0)).length,
    riskReductionProven: false, providerWrites: 0,
  };
}
export type IncidentReadiness = {
  schema: "cyberpilot.incident.readiness.v1"; incidentId: string;
  organizationId: string; gate: "BLOCKED" | "REQUIRES_REVIEW" | "READY_FOR_MANUAL_REVIEW";
  blocking: string[]; warnings: string[];
  steps: { id: string; status: string; evidenceCount: number;
    independentObservedCount: number; missingRequiredSources: string[];
    approvalValid: boolean; capability: string; providerOutcomeProven: false }[];
  technicalContainmentEstablished: false;
};
export function evaluateIncidentReadiness(snapshot: IncidentSnapshot,
  at = new Date().toISOString()): IncidentReadiness {
  const book = getIncidentPlaybook(snapshot.type);
  const blocking: string[] = [], warnings: string[] = [];
  const steps = book.steps.map(spec => {
    const state = snapshot.steps.find(s => s.stepId === spec.id)!;
    const evidence = snapshot.evidence.filter(x => state.evidenceIds.includes(x.id));
    const observed = evidence.filter(e => e.independent && e.verdict === "OBSERVED");
    const missingRequiredSources = spec.requiredEvidence.filter(source =>
      source !== "approval" && !observed.some(x => x.source === source));
    const approvalValid = !spec.requiresApproval || snapshot.approvals.some(a =>
      a.stepId === spec.id && a.approvedAt <= at && a.expiresAt > at);
    if (state.status === "VERIFIED" && (!approvalValid ||
      missingRequiredSources.length || observed.length === 0))
      blocking.push("PROOF_INCONSISTENT:" + spec.id);
    if (state.status === "REPORTED_DONE")
      warnings.push("REPORTED_NOT_VERIFIED:" + spec.id);
    if (state.status === "BLOCKED") warnings.push("STEP_BLOCKED:" + spec.id);
    if (spec.requiresApproval && state.status !== "PENDING" && !approvalValid)
      warnings.push("APPROVAL_MISSING_OR_EXPIRED:" + spec.id);
    if (evidence.some(e => e.verdict === "UNKNOWN" || e.verdict === "ERROR"))
      warnings.push("INCOMPLETE_EVIDENCE:" + spec.id);
    return { id: spec.id, status: state.status, evidenceCount: evidence.length,
      independentObservedCount: observed.length, missingRequiredSources,
      approvalValid, capability: spec.providerCapability, providerOutcomeProven: false as const };
  });
  if (snapshot.status === "CLOSED" &&
      steps.some(s => s.status !== "VERIFIED")) blocking.push("CLOSED_WITH_OPEN_STEPS");
  if (snapshot.status === "CLOSED") warnings.push("CLOSED_NOT_PROVIDER_VERIFIED");
  return {
    schema: "cyberpilot.incident.readiness.v1", incidentId: snapshot.id,
    organizationId: snapshot.organizationId,
    gate: blocking.length ? "BLOCKED" : warnings.length ||
      steps.some(s => s.status !== "VERIFIED") ?
      "REQUIRES_REVIEW" : "READY_FOR_MANUAL_REVIEW",
    blocking, warnings, steps, technicalContainmentEstablished: false,
  };
}
function csvField(value: unknown): string {
  const s = typeof value === "string" ? value : JSON.stringify(value ?? "");
  // Prefix spreadsheet formula characters to prevent interpreted CSV formulas.
  const neutralized = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return '"' + neutralized.replaceAll('"', '""').replaceAll("\r", " ").replaceAll("\n", " ") + '"';
}
function safeMarkdown(s: string): string {
  return s.replace(/[\u0000-\u001f]/g, " ").replaceAll("|", "\\|")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}
export function exportIncidentDossier(snapshot: IncidentSnapshot,
  events: IncidentEvent[], format: "JSON" | "CSV" | "MARKDOWN") {
  if (events.some(x => x.organizationId !== snapshot.organizationId ||
    x.incidentId !== snapshot.id)) throw new Error("INCIDENT_EXPORT_CROSS_TENANT");
  if (events.length > 2000) throw new Error("INCIDENT_EXPORT_HISTORY_LIMIT");
  const readiness = evaluateIncidentReadiness(snapshot);
  const filename = "cyberpilot-incident-" + snapshot.id;
  const manifest = {
    schema: "cyberpilot.incident.dossier.v1", snapshot,
    events, readiness, exportedAt: new Date().toISOString(),
    externalActionsPerformed: 0, actualContainmentVerified: false,
    caution: "Offline guided record. Never interpret status as provider containment.",
  };
  const manifestDigest = createHash("sha256").update(JSON.stringify(manifest))
    .digest("hex");
  if (format === "JSON") {
    return { filename: filename + ".json", mime: "application/json",
      digest: manifestDigest, content: JSON.stringify({ ...manifest, manifestDigest }, null, 2) };
  }
  if (format === "CSV") {
    const columns = ["incidentId", "type", "stepId", "stepStatus",
      "evidenceId", "evidenceSource", "verdict", "independent", "observedAt"];
    const rows: string[][] = [];
    for (const step of snapshot.steps) {
      const evidence = snapshot.evidence.filter(e => e.stepId === step.stepId);
      if (!evidence.length) rows.push([
        snapshot.id, snapshot.type, step.stepId, step.status, "", "", "", "", "",
      ]);
      for (const e of evidence) rows.push([
        snapshot.id, snapshot.type, step.stepId, step.status, e.id,
        e.source, e.verdict, String(e.independent), e.observedAt ?? "",
      ]);
    }
    return { filename: filename + ".csv", mime: "text/csv",
      digest: manifestDigest, content: [
        columns.join(","), ...rows.map(row => row.map(csvField).join(",")),
      ].join("\r\n") };
  }
  if (format !== "MARKDOWN") throw new Error("INCIDENT_EXPORT_FORMAT_UNKNOWN");
  const book = getIncidentPlaybook(snapshot.type);
  return { filename: filename + ".md", mime: "text/markdown",
    digest: manifestDigest, content: [
      "# CyberPilot incident review — " + safeMarkdown(snapshot.title),
      "",
      "Incident: " + snapshot.id, "Organization: " + snapshot.organizationId,
      "Playbook: " + book.id + " / v" + book.version,
      "Status: " + snapshot.status + " (workflow only)",
      "Revision: " + snapshot.revision, "Snapshot digest: " + incidentDigest(snapshot),
      "Readiness: " + readiness.gate, "Evidence observed: " + snapshot.evidence.length,
      "Provider writes performed: 0", "Actual containment verified: NO",
      "Manifest digest: " + manifestDigest, "",
      "## Steps", ...book.steps.map(spec => {
        const state = snapshot.steps.find(x => x.stepId === spec.id)!;
        return "- **" + safeMarkdown(spec.title) + "** — " + state.status +
          " / evidence: " + state.evidenceIds.length +
          " / requires approval: " + spec.requiresApproval;
      }),
      "", "## Review warnings",
      ...readiness.blocking.map(x => "- BLOCKED: " + x),
      ...readiness.warnings.map(x => "- REVIEW: " + x),
      "", "Offline guidance is not evidence of external remediation.",
    ].join("\n") };
}
export type SourceCoverage = { source: string; observed: number; declared: number;
  unknown: number; error: number; independent: number; stale: number };
export function summarizeIncidentEvidence(snapshot: IncidentSnapshot,
  at = new Date().toISOString(), staleHours = 72) {
  if (!Number.isInteger(staleHours) || staleHours < 1 || staleHours > 8760)
    throw new Error("INCIDENT_EVIDENCE_AGE_INVALID");
  const threshold = Date.parse(at) - staleHours * 3600000;
  if (!Number.isFinite(threshold)) throw new Error("INCIDENT_EVIDENCE_TIME_INVALID");
  const sources = [...new Set(snapshot.evidence.map(x => x.source))].sort();
  const coverage: SourceCoverage[] = sources.map(source => {
    const rows = snapshot.evidence.filter(x => x.source === source);
    return { source, observed: rows.filter(x => x.verdict === "OBSERVED").length,
      declared: rows.filter(x => x.verdict === "DECLARED").length,
      unknown: rows.filter(x => x.verdict === "UNKNOWN").length,
      error: rows.filter(x => x.verdict === "ERROR").length,
      independent: rows.filter(x => x.independent && x.verdict === "OBSERVED").length,
      stale: rows.filter(x => x.observedAt === null ||
        Date.parse(x.observedAt) < threshold).length };
  });
  return { organizationId: snapshot.organizationId, incidentId: snapshot.id,
    coverage, total: snapshot.evidence.length,
    incomplete: snapshot.evidence.some(x => x.verdict !== "OBSERVED" ||
      !x.independent || x.observedAt === null ||
      Date.parse(x.observedAt) < threshold), providerProofValidated: false as const };
}
export function identifyIncidentEvidenceConflicts(evidence: IncidentEvidence[]) {
  const groups = new Map<string, IncidentEvidence[]>();
  for (const e of evidence) {
    const key = e.stepId + "::" + e.source + "::" + e.sourceReference;
    const list = groups.get(key) ?? [];
    list.push(e); groups.set(key, list);
  }
  return [...groups.entries()].flatMap(([key, list]) => {
    const verdicts = [...new Set(list.map(x => x.verdict))];
    if (verdicts.length < 2) return [];
    return [{ key, evidenceIds: list.map(x => x.id),
      verdicts, requiresHumanReconciliation: true as const }];
  });
}
