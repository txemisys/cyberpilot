import { createHash, timingSafeEqual } from "node:crypto";
import type {
  OsvForensicReport, OsvForensicNode, OsvForensicEdge,
  OsvForensicAnomaly,
} from "./assets-osv-dispatch-forensics";

/**
 * Verifies local report structure and SHA-256 consistency. SHA-256 is a
 * tamper-detection fingerprint, NOT a trusted third-party signature.
 * Cross-tenant provenance always requires independent RBAC and DB scoping.
 */
export type OsvForensicVerification = {
  schema: "cyberpilot.assets.osv.dispatch.forensic.verification.v1";
  organizationId: string;
  fingerprintValid: boolean;
  nodeDigestsValid: boolean;
  referencesValid: boolean;
  summaryValid: boolean;
  orderingValid: boolean;
  noExternalActionsClaimed: boolean;
  completeWithinWindow: boolean;
  validForInternalReview: boolean;
  checkedNodes: number;
  checkedEdges: number;
  checkedAnomalies: number;
  issues: string[];
  warnings: string[];
};
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equalHex(left: string, right: string) {
  if (!/^[a-f0-9]{64}$/.test(left) ||
      !/^[a-f0-9]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"),
    Buffer.from(right, "hex"));
}
function nodeDigest(row: OsvForensicNode) {
  return sha({
    id: row.id, type: row.type, referenceId: row.referenceId,
    scheduleId: row.scheduleId, eventAt: row.eventAt,
    state: row.state, attributes: row.attributes,
  });
}
function canonicalReport(report: OsvForensicReport) {
  return {
    schema: report.schema, organizationId: report.organizationId,
    evaluatedAt: report.evaluatedAt, windowStart: report.windowStart,
    windowEnd: report.windowEnd, input: report.input,
    complete: report.complete,
    truncatedCollections: report.truncatedCollections,
    collectionCounts: report.collectionCounts,
    nodes: report.nodes, edges: report.edges,
    anomalies: report.anomalies, summary: report.summary,
    liveProviderVerified: report.liveProviderVerified,
    changesCommitted: report.changesCommitted,
    networkRequestsMade: report.networkRequestsMade,
    findingsModified: report.findingsModified,
  };
}
function ordered<T>(values: T[], compare: (a: T, b: T) => number) {
  for (let i = 1; i < values.length; i++)
    if (compare(values[i - 1]!, values[i]!) > 0)
      return false;
  return true;
}
export function verifyOsvForensicReport(
  report: OsvForensicReport,
): OsvForensicVerification {
  const issues: string[] = [];
  const fingerprintValid = equalHex(report.reportDigest,
    sha(canonicalReport(report)));
  if (!fingerprintValid)
    issues.push("The forensic report fingerprint differs from the canonical payload.");
  const nodeIds = new Set<string>();
  const nodeDigests = new Set<string>();
  let nodeDigestsValid = true;
  for (const node of report.nodes) {
    if (nodeIds.has(node.id)) {
      nodeDigestsValid = false;
      issues.push("Duplicate forensic node ID: " + node.id);
    }
    nodeIds.add(node.id);
    if (!equalHex(node.digest, nodeDigest(node))) {
      nodeDigestsValid = false;
      issues.push("Forensic node fingerprint mismatch: " + node.id);
    }
    nodeDigests.add(node.digest);
  }
  const referencesValid = report.edges.every(edge =>
    nodeIds.has(edge.from) && nodeIds.has(edge.to) &&
    (edge.relation === "TIME_ADJACENT_ONLY" ?
      edge.confidence === "HEURISTIC" :
      edge.confidence === "EXACT_REFERENCE")) &&
    report.anomalies.every(row =>
      (row.nodeId === null || nodeIds.has(row.nodeId)) &&
      row.supportedBy.every(fingerprint =>
        nodeDigests.has(fingerprint)));
  if (!referencesValid)
    issues.push("Some forensic edges or anomaly evidence references are invalid.");
  const summary = report.summary;
  const summaryValid = summary.nodes === report.nodes.length &&
    summary.edges === report.edges.length &&
    summary.exactReferences === report.edges.filter(edge =>
      edge.confidence === "EXACT_REFERENCE").length &&
    summary.heuristicLinks === report.edges.filter(edge =>
      edge.confidence === "HEURISTIC").length &&
    summary.criticalAnomalies === report.anomalies.filter(row =>
      row.severity === "CRITICAL").length &&
    summary.warningAnomalies === report.anomalies.filter(row =>
      row.severity === "WARNING").length &&
    summary.unfinishedClaims === report.nodes.filter(row =>
      row.type === "SCHEDULE_RUN" && row.state === "CLAIMED").length &&
    summary.unknownProviderResults === report.nodes.filter(row =>
      row.type === "SCHEDULE_RUN" && row.state === "UNKNOWN").length &&
    summary.unresolvedQuotas === report.nodes.filter(row =>
      row.type === "QUOTA" && row.state === "RESERVED").length;
  if (!summaryValid)
    issues.push("Forensic graph counts or states disagree with its summary.");
  const orderingValid = ordered(report.nodes, (a, b) =>
    a.eventAt.localeCompare(b.eventAt) || a.id.localeCompare(b.id)) &&
    ordered(report.edges, (a, b) =>
      a.from.localeCompare(b.from) || a.to.localeCompare(b.to)) &&
    ordered(report.anomalies, (a, b) =>
      a.code.localeCompare(b.code) || a.id.localeCompare(b.id));
  if (!orderingValid)
    issues.push("Forensic nodes, references or anomalies are not canonically ordered.");
  const noExternalActionsClaimed =
    report.liveProviderVerified === false &&
    report.changesCommitted === false &&
    report.networkRequestsMade === 0 &&
    report.findingsModified === false;
  if (!noExternalActionsClaimed)
    issues.push("Forensic report incorrectly claims an external or mutating action.");
  const completeWithinWindow =
    report.complete && report.truncatedCollections.length === 0 &&
    (Object.keys(report.collectionCounts) as
      Array<keyof typeof report.collectionCounts>).every(key =>
      report.collectionCounts[key] === report.nodes.filter(node =>
        node.type === ({
          signatures: "SIGNATURE", runs: "SCHEDULE_RUN",
          quotas: "QUOTA", inspections: "INSPECTION",
          audits: "AUDIT",
        }[key])).length);
  if (!completeWithinWindow)
    issues.push("Forensic evidence is incomplete or collection counts do not match.");
  return {
    schema: "cyberpilot.assets.osv.dispatch.forensic.verification.v1",
    organizationId: report.organizationId,
    fingerprintValid, nodeDigestsValid, referencesValid,
    summaryValid, orderingValid,
    noExternalActionsClaimed, completeWithinWindow,
    validForInternalReview: issues.length === 0,
    checkedNodes: report.nodes.length,
    checkedEdges: report.edges.length,
    checkedAnomalies: report.anomalies.length,
    issues,
    warnings: [
      "A matching SHA-256 detects local modifications but does not authenticate the report producer.",
      "Even a structurally valid report is not evidence of OSV.dev availability, endpoint security or remediation.",
      "Completeness applies only to the requested local window and included data sources.",
    ],
  };
}
