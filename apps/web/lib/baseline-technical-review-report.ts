import { sha256V2, canonicalV2 } from "@cyberpilot/risk-engine";
import type { ReviewView } from "./baseline-technical-review-service";

/**
 * Internal A+B review summaries. Findings can request clarification
 * but never establish legal customer signoff or independent proof.
 */
export type BaselineReviewDigest = {
  schema: "cyberpilot.baseline.technical.review.report.v1";
  organizationId: string;
  createdAt: string;
  reviewCount: number;
  sourceDigests: string[];
  outcomes: {
    open: number;
    inReview: number;
    changesRequested: number;
    technicallyReviewedInternally: number;
    reopened: number;
    pendingBlockingFindings: number;
    unassignedReviewers: number;
    independentSecurityControlsVerified: 0;
    externalCustomerApprovals: 0;
  };
  sourceRevisions: Array<{
    reviewId: string;
    sourceRevision: number;
    reviewRevision: number;
    status: string;
    reportDigest: string;
    findingsDigest: string;
    issueCount: number;
    blockingIssueCount: number;
    reviewerUserId: string | null;
    technicalAcceptanceRecorded: boolean;
    legalAcceptance: false;
    approvedByCustomer: false;
  }>;
  disclaimers: string[];
  proofOfCustomerAcceptance: false;
  certifiedCisIg1: false;
  legacyCyberScoreUpdated: false;
  digest: string;
};
export type BaselineReviewExport = {
  format: "JSON" | "MARKDOWN" | "CSV";
  filename: string;
  content: string;
  mimeType: string;
  sha256: string;
  sourceDigest: string;
  customerSigned: false;
};
const sha = (x: unknown) => sha256V2(canonicalV2(x));
const csv = (x: string | number | null) => {
  const value = String(x ?? "").replace(/[\u0000-\u001f\u007f]/g, " ");
  const safe = /^[+=@-]/.test(value) ? "'" + value : value;
  return '"' + safe.replaceAll('"', '""') + '"';
};
export function buildBaselineTechnicalReviewReport(
  organizationId: string, rows: readonly ReviewView[],
  createdAt: string,
): BaselineReviewDigest {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(organizationId) ||
      !Number.isFinite(Date.parse(createdAt)) ||
      rows.length > 1000 ||
      rows.some(r =>
        r.organizationId !== organizationId ||
        r.securityControlsIndependentlyVerified !== 0 ||
        r.externalCustomerApproval !== false ||
        r.cisCertification !== false ||
        r.historicalCyberScoreModified !== false ||
        r.issueCount !== r.findings.length ||
        r.findingsDigest !== sha(r.findings)) ||
      new Set(rows.map(r => r.id)).size !== rows.length)
    throw Error("Invalid, cross-tenant or falsely approved technical review.");
  const sorted = [...rows].sort((a, b) =>
    a.sourceRevision - b.sourceRevision ||
    a.id.localeCompare(b.id));
  const canonical = {
    schema: "cyberpilot.baseline.technical.review.report.v1" as const,
    organizationId, createdAt,
    reviewCount: sorted.length,
    sourceDigests: sorted.map(x => sha({
      id: x.id, reportDigest: x.reportDigest,
      revision: x.revision, findingsDigest: x.findingsDigest,
    })),
    outcomes: {
      open: sorted.filter(x => x.state === "OPEN").length,
      inReview: sorted.filter(x => x.state === "IN_REVIEW").length,
      changesRequested: sorted.filter(x =>
        x.state === "CHANGES_REQUESTED").length,
      technicallyReviewedInternally: sorted.filter(x =>
        x.state === "TECHNICALLY_REVIEWED").length,
      reopened: sorted.filter(x => x.state === "REOPENED").length,
      pendingBlockingFindings: sorted.reduce((n, x) =>
        n + x.blockingIssueCount, 0),
      unassignedReviewers: sorted.filter(x =>
        !x.reviewerUserId).length,
      independentSecurityControlsVerified: 0 as const,
      externalCustomerApprovals: 0 as const,
    },
    sourceRevisions: sorted.map(x => ({
      reviewId: x.id,
      sourceRevision: x.sourceRevision,
      reviewRevision: x.revision,
      status: x.state,
      reportDigest: x.reportDigest,
      findingsDigest: x.findingsDigest,
      issueCount: x.issueCount,
      blockingIssueCount: x.blockingIssueCount,
      reviewerUserId: x.reviewerUserId,
      technicalAcceptanceRecorded:
        x.state === "TECHNICALLY_REVIEWED",
      legalAcceptance: false as const,
      approvedByCustomer: false as const,
    })),
    disclaimers: [
      "Internal review is not client signoff.",
      "A completed review does not certify CIS Controls compliance.",
      "Declarative responses never become independent observations.",
      "Remediation requires separate technical verification.",
      "All evidence is scoped to the organization and report revision.",
    ],
    proofOfCustomerAcceptance: false as const,
    certifiedCisIg1: false as const,
    legacyCyberScoreUpdated: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyBaselineTechnicalReviewReport(
  report: BaselineReviewDigest,
) {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  if (sha(canonical) !== digest) issues.push("DIGEST_INVALID");
  if (report.proofOfCustomerAcceptance ||
      report.certifiedCisIg1 ||
      report.legacyCyberScoreUpdated ||
      report.outcomes.externalCustomerApprovals !== 0 ||
      report.outcomes.independentSecurityControlsVerified !== 0 ||
      report.sourceRevisions.some(x =>
        x.legalAcceptance || x.approvedByCustomer))
    issues.push("FALSE_ACCEPTANCE_OR_COMPLIANCE");
  if (report.reviewCount !== report.sourceRevisions.length ||
      report.sourceDigests.length !== report.reviewCount)
    issues.push("SOURCE_COUNT_MISMATCH");
  return { valid: issues.length === 0, issues };
}
export function exportBaselineTechnicalReviewReport(
  report: BaselineReviewDigest,
  format: BaselineReviewExport["format"],
): BaselineReviewExport {
  if (!verifyBaselineTechnicalReviewReport(report).valid ||
      !["JSON","MARKDOWN","CSV"].includes(format))
    throw Error("Cannot export invalid technical acceptance report.");
  const content = format === "JSON" ?
    JSON.stringify(report, null, 2) + "\n" :
    format === "CSV" ? [
      ["sourceRevision","status","issues","blocking",
        "reportDigest","customerApproval"].map(csv).join(","),
      ...report.sourceRevisions.map(x => [
        x.sourceRevision, x.status, x.issueCount,
        x.blockingIssueCount, x.reportDigest, "false",
      ].map(csv).join(",")),
    ].join("\r\n") + "\r\n" : [
      "# CyberPilot — internal Baseline technical acceptance",
      "Organization: " + report.organizationId,
      "Generated: " + report.createdAt,
      "Customer approval: NOT ESTABLISHED",
      "CIS certification: NOT PROVIDED",
      "Internal technical reviews: " +
        report.outcomes.technicallyReviewedInternally,
      "Open blocking findings: " +
        report.outcomes.pendingBlockingFindings,
      "", "## Reviews",
      ...report.sourceRevisions.map(x =>
        "- Baseline v" + x.sourceRevision + ": " + x.status +
        ", blocking " + x.blockingIssueCount),
      "", "## Limitations",
      ...report.disclaimers.map(x => "- " + x),
    ].join("\n") + "\n";
  return {
    format,
    filename: "baseline-internal-reviews-" +
      report.createdAt.slice(0, 10) +
      (format === "JSON" ? ".json" :
        format === "CSV" ? ".csv" : ".md"),
    content,
    mimeType: format === "JSON" ? "application/json" :
      format === "CSV" ? "text/csv" : "text/markdown",
    sha256: sha256V2(content),
    sourceDigest: report.digest,
    customerSigned: false,
  };
}
