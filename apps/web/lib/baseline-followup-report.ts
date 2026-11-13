import {
  sha256V2, canonicalV2,
} from "@cyberpilot/risk-engine";
import type { BaselineFollowUpView } from
  "./baseline-followup-service";

/** Reporting of management follow-up, never independently verified fixes. */
export type BaselineFollowUpDigest = {
  schema: "cyberpilot.baseline.followup.executive.v1";
  organizationId: string;
  generatedAt: string;
  sourceCount: number;
  sourceDigests: string[];
  summary: {
    total: number; open: number;
    inProgress: number; blocked: number;
    reportedComplete: number; reopened: number;
    dueSoon: number; overdue: number;
    withoutOwner: number;
    withOpaqueEvidence: number;
    highPriority: number;
    completedTechnicallyVerified: 0;
    certifiedCompliant: false;
  };
  workstreams: Array<{
    domain: string;
    questions: string[];
    count: number;
    high: number;
    overdue: number;
    reportedComplete: number;
    needsVerification: true;
  }>;
  priorities: Array<{
    questionId: string;
    status: string;
    severity: string;
    title: string;
    owner: string | null;
    targetAt: string | null;
    evidenceReference: string | null;
    nextAction: string;
    sourceRevision: number;
    confirmedSecure: false;
    remediationVerified: false;
  }>;
  nextSteps: string[];
  noRemediationExecutedByReport: true;
  externalCustomerSignoffProven: false;
  legacyCyberScoreChanged: false;
  digest: string;
};
export type BaselineFollowUpExport = {
  schema: "cyberpilot.baseline.followup.export.v1";
  organizationId: string;
  format: "JSON" | "CSV" | "MARKDOWN";
  filename: string;
  mimeType: string;
  payload: string;
  payloadDigest: string;
  reportDigest: string;
  containsRawSensitiveNotes: false;
  customerSecurityCertified: false;
};
function sha(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function severity(value: string) {
  const order = ["CRITICAL","HIGH","MEDIUM",
    "LOW","UNKNOWN","NOT_APPLICABLE"];
  return order.indexOf(value) < 0 ? 99 : order.indexOf(value);
}
function group(question: string) {
  if (/mfa|access|account|offboarding|privilege/i.test(question))
    return "IDENTITY_AND_ACCESS";
  if (/backup|restore|recover|continuity/i.test(question))
    return "BACKUP_AND_RECOVERY";
  if (/patch|software|asset|device|endpoint/i.test(question))
    return "ASSET_AND_ENDPOINT";
  if (/incident|training|phishing|security-review/i.test(question))
    return "GOVERNANCE_AND_INCIDENTS";
  if (/email|dns|browser|network/i.test(question))
    return "EMAIL_WEB_NETWORK";
  return "OTHER_CONTROLS";
}
function csv(value: string | number | null) {
  const clean = String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ");
  const protectedText = /^[=+@-]/.test(clean) ?
    "'" + clean : clean;
  return '"' + protectedText.replaceAll('"', '""') + '"';
}
function validateRow(row: BaselineFollowUpView,
  organizationId: string) {
  return row.organizationId === organizationId &&
    row.questionnaireVersion === 1 &&
    row.independentlyVerified === false &&
    row.securityCertified === false &&
    row.historicalCyberScoreModified === false &&
    row.revision >= 1 &&
    /^[a-z][a-z0-9-]{2,79}$/.test(row.questionId) &&
    Number.isFinite(Date.parse(row.createdAt)) &&
    Number.isFinite(Date.parse(row.updatedAt));
}
export function buildBaselineFollowUpExecutive(
  organizationId: string,
  records: readonly BaselineFollowUpView[],
  generatedAt: string,
): BaselineFollowUpDigest {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(
      organizationId) ||
      !Number.isFinite(Date.parse(generatedAt)) ||
      records.length > 1000 ||
      records.some(x => !validateRow(x, organizationId)) ||
      new Set(records.map(x => x.questionId)).size !== records.length)
    throw Error("Invalid follow-up report tenant, source or timestamp.");
  const now = Date.parse(generatedAt);
  const soon = now + 7 * 86400000;
  const isClosed = (x: BaselineFollowUpView) =>
    x.status === "COMPLETED_REPORTED";
  const overdue = (x: BaselineFollowUpView) =>
    x.dueAt !== null && Date.parse(x.dueAt) < now && !isClosed(x);
  const sorted = [...records].sort((a, b) => {
    const dueA = a.dueAt ?? "9999";
    const dueB = b.dueAt ?? "9999";
    return severity(a.severity) - severity(b.severity) ||
      dueA.localeCompare(dueB) ||
      a.questionId.localeCompare(b.questionId);
  });
  const groupIds = [...new Set(records.map(x => group(x.questionId)))];
  const sourceDigests = sorted.map(x =>
    sha({
      organizationId: x.organizationId,
      questionId: x.questionId,
      revision: x.revision,
      status: x.status,
      updatedAt: x.updatedAt,
    }));
  const priorities = sorted.map(x => ({
    questionId: x.questionId,
    status: x.status, severity: x.severity,
    title: x.title, owner: x.ownerUserId,
    targetAt: x.dueAt,
    evidenceReference: x.evidenceReference,
    nextAction: x.nextAction,
    sourceRevision: x.sourceDraftRevision,
    confirmedSecure: false as const,
    remediationVerified: false as const,
  }));
  const canonical = {
    schema: "cyberpilot.baseline.followup.executive.v1" as const,
    organizationId, generatedAt,
    sourceCount: records.length, sourceDigests,
    summary: {
      total: records.length,
      open: records.filter(x => x.status === "OPEN").length,
      inProgress: records.filter(x => x.status === "IN_PROGRESS").length,
      blocked: records.filter(x => x.status === "BLOCKED").length,
      reportedComplete: records.filter(isClosed).length,
      reopened: records.filter(x => x.status === "REOPENED").length,
      dueSoon: records.filter(x =>
        x.dueAt !== null &&
        Date.parse(x.dueAt) >= now &&
        Date.parse(x.dueAt) <= soon && !isClosed(x)).length,
      overdue: records.filter(overdue).length,
      withoutOwner: records.filter(x => !x.ownerUserId).length,
      withOpaqueEvidence: records.filter(x =>
        x.evidenceReference !== null).length,
      highPriority: records.filter(x =>
        x.severity === "HIGH" || x.severity === "CRITICAL").length,
      completedTechnicallyVerified: 0 as const,
      certifiedCompliant: false as const,
    },
    workstreams: groupIds.sort().map(domain => {
      const scoped = records.filter(x =>
        group(x.questionId) === domain);
      return {
        domain, questions: scoped.map(x => x.questionId).sort(),
        count: scoped.length,
        high: scoped.filter(x =>
          x.severity === "HIGH" || x.severity === "CRITICAL").length,
        overdue: scoped.filter(overdue).length,
        reportedComplete: scoped.filter(isClosed).length,
        needsVerification: true as const,
      };
    }),
    priorities,
    nextSteps: [
      "Verify that each owner has acknowledged the action.",
      "Resolve blocked and overdue actions with documented decisions.",
      "Obtain independent technical evidence before claiming remediation.",
      "Preserve prior revisions and separate CyberScore history.",
    ],
    noRemediationExecutedByReport: true as const,
    externalCustomerSignoffProven: false as const,
    legacyCyberScoreChanged: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyBaselineFollowUpExecutive(
  report: BaselineFollowUpDigest,
  source?: readonly BaselineFollowUpView[],
) {
  const { digest, ...canonical } = report;
  const problems: string[] = [];
  if (sha(canonical) !== digest)
    problems.push("DIGEST_MISMATCH");
  if (report.summary.certifiedCompliant ||
      report.summary.completedTechnicallyVerified !== 0 ||
      !report.noRemediationExecutedByReport ||
      report.externalCustomerSignoffProven ||
      report.legacyCyberScoreChanged ||
      report.priorities.some(x =>
        x.confirmedSecure || x.remediationVerified))
    problems.push("FALSE_REMEDIATION_OR_COMPLIANCE_CLAIM");
  if (report.sourceCount !== report.priorities.length ||
      report.sourceDigests.length !== report.sourceCount)
    problems.push("SOURCE_COUNT_MISMATCH");
  if (source &&
      buildBaselineFollowUpExecutive(report.organizationId,
        source, report.generatedAt).digest !== report.digest)
    problems.push("SOURCE_REPRODUCIBILITY_FAILED");
  return { valid: problems.length === 0, problems };
}
export function exportBaselineFollowUpExecutive(
  report: BaselineFollowUpDigest,
  format: BaselineFollowUpExport["format"],
): BaselineFollowUpExport {
  if (!verifyBaselineFollowUpExecutive(report).valid)
    throw Error("Cannot export a tampered follow-up report.");
  if (!["JSON","CSV","MARKDOWN"].includes(format))
    throw Error("Unknown reporting format.");
  let payload: string;
  if (format === "JSON")
    payload = JSON.stringify(report, null, 2) + "\n";
  else if (format === "CSV") {
    const rows: Array<Array<string | number | null>> = [
      ["questionId","status","severity","owner","targetAt",
        "evidenceReference","sourceRevision","remediationVerified"],
      ...report.priorities.map(x => [
        x.questionId, x.status, x.severity, x.owner,
        x.targetAt, x.evidenceReference, x.sourceRevision, "false",
      ]),
    ];
    payload = rows.map(row => row.map(csv)
      .join(",")).join("\r\n") + "\r\n";
  } else {
    const lines = [
      "# CyberPilot Baseline — management follow-up",
      "Organization: " + report.organizationId,
      "Evaluated at: " + report.generatedAt,
      "Outstanding: " + (report.summary.total -
        report.summary.reportedComplete),
      "Overdue: " + report.summary.overdue,
      "Security certification: NONE", "",
    ];
    for (const item of report.priorities)
      lines.push("- [" + item.severity + "] " +
        item.title + ": " + item.nextAction +
        " (status: " + item.status + ")");
    lines.push("", "## Next actions",
      ...report.nextSteps.map(x => "- " + x));
    payload = lines.join("\n") + "\n";
  }
  return {
    schema: "cyberpilot.baseline.followup.export.v1",
    organizationId: report.organizationId, format,
    filename: "baseline-actions-" + report.generatedAt.slice(0, 10) +
      (format === "JSON" ? ".json" :
        format === "CSV" ? ".csv" : ".md"),
    mimeType: format === "JSON" ? "application/json" :
      format === "CSV" ? "text/csv" : "text/markdown",
    payload, payloadDigest: sha256V2(payload),
    reportDigest: report.digest,
    containsRawSensitiveNotes: false,
    customerSecurityCertified: false,
  };
}
