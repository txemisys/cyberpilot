import { sha256V2 } from "./multisource-v2-history";
import { canonicalV2 } from "./multisource-v2-contract";
import { type ExposureAssessment, type ExposureCheck,
  type ExposureFinding, verifyExposureOfflineAssessment }
  from "./exposure-offline-v2";

/** Provenance-first reporting; it does not authorize collection of any traffic. */
export type ExposureReportSection = {
  id: "SUMMARY" | "AUTHORIZATION" | "DNS" | "EMAIL" |
    "TLS" | "HTTP" | "RISKS" | "PRIORITIES" |
    "COVERAGE" | "LIMITATIONS";
  title: string; status: "EVIDENCED" | "PARTIAL" |
    "UNKNOWN" | "REQUIRES_REVIEW";
  description: string; sourceIds: string[];
  findings: string[]; missingControls: string[];
  noSecurityCertification: true;
};
export type ExposureReport = {
  schema: "cyberpilot.exposure.report.v2";
  organizationId: string; snapshotId: string;
  domain: string; generatedAt: string;
  assessmentDigest: string;
  summary: {
    findings: number; highFindings: number;
    controls: number; assessed: number;
    uncertain: number; coveragePercent: number;
    authorizationStatus: string;
    status: "UNDETERMINED" | "PARTIAL_EVIDENCE" |
      "POTENTIAL_RISK";
    securityGrade: null;
    noM365Required: true;
    noLIVEAccessPerformed: true;
  };
  sections: ExposureReportSection[];
  findings: ExposureFinding[];
  actions: Array<{
    id: string; title: string; impact: string;
    steps: string[]; severity: string;
    sourceIds: string[]; priority: number;
    executed: false; approved: false;
  }>;
  coverage: Array<{
    control: string; state: string;
    sourceIds: string[];
    observationAt: string | null;
    interpretation: string;
    uncertain: boolean;
    certifiedHealthy: false;
  }>;
  limitations: string[];
  customerApprovalVerified: false;
  externallyRevalidated: false;
  legacyCyberScoreTouched: false;
  digest: string;
};
export type ExposureReportAudit = {
  verified: boolean; issues: string[];
  assessmentMatches: boolean;
  sectionsComplete: boolean;
  findingsLinked: boolean;
  noExternalAssurance: boolean;
  localDigestValid: boolean;
  remoteValidationPerformed: false;
};
export type ExposureReportExport = {
  schema: "cyberpilot.exposure.export.v2";
  organizationId: string; snapshotId: string;
  format: "JSON" | "CSV" | "MARKDOWN";
  filename: string; mediaType: string;
  payload: string;
  reportDigest: string; payloadDigest: string;
  containsUnredactedCredentials: false;
  hasNetworkActivity: false;
  securityCertified: false;
};
export type ExposureReportDelta = {
  organizationId: string; domain: string;
  older: string; newer: string;
  chronologyValid: boolean;
  coverageDelta: number;
  newFindings: string[];
  absentFindings: string[];
  continuingFindings: string[];
  newUnknownControls: string[];
  newlyObservedControls: string[];
  independentRemediationVerified: false;
  safeToCompareAsHealthGrade: false;
};
const sectionDefinitions: Array<{
  id: ExposureReportSection["id"];
  title: string; controls: string[];
}> = [
  { id: "SUMMARY", title: "Executive overview", controls: [] },
  { id: "AUTHORIZATION", title: "Domain authorization", controls: ["DOMAIN_OWNERSHIP"] },
  { id: "DNS", title: "DNS evidence provenance", controls: ["EMAIL_SPF", "EMAIL_DMARC", "EMAIL_DKIM"] },
  { id: "EMAIL", title: "Mail authentication posture", controls: ["EMAIL_SPF", "EMAIL_DMARC", "EMAIL_DKIM"] },
  { id: "TLS", title: "TLS and certificate metadata", controls: ["WEB_TLS"] },
  { id: "HTTP", title: "HTTP security and redirects", controls: ["WEB_SECURITY_HEADERS", "WEB_REDIRECT"] },
  { id: "RISKS", title: "Potential risk findings", controls: [] },
  { id: "PRIORITIES", title: "Recommended next actions", controls: [] },
  { id: "COVERAGE", title: "Unknown, partial and inaccessible controls", controls: [] },
  { id: "LIMITATIONS", title: "Evidence and operational limitations", controls: [] },
];
const severityRank: Record<ExposureFinding["severity"], number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};
function hash(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function involved(section: typeof sectionDefinitions[number],
  checks: ExposureCheck[]) {
  if (!section.controls.length) return checks;
  return checks.filter(c => section.controls.includes(c.control));
}
function status(
  controls: ExposureCheck[],
): ExposureReportSection["status"] {
  if (!controls.length) return "UNKNOWN";
  if (controls.some(x => x.findings.length))
    return "REQUIRES_REVIEW";
  if (controls.every(x => x.state === "OBSERVED"))
    return "EVIDENCED";
  return controls.some(x => x.state === "OBSERVED") ?
    "PARTIAL" : "UNKNOWN";
}
export function buildExposureReportV2(
  assessment: ExposureAssessment,
): ExposureReport {
  if (!verifyExposureOfflineAssessment(assessment).valid)
    throw Error("Invalid or tampered Exposure assessment.");
  const sectionData: ExposureReportSection[] = sectionDefinitions.map(section => {
    const checks = involved(section, assessment.checks);
    const unknown = checks.filter(x => x.state !== "OBSERVED");
    const risks = checks.flatMap(x => x.findings);
    return {
      id: section.id, title: section.title,
      status: status(checks),
      description: unknown.length ?
        unknown.length + " controls remain unverified or unobserved." :
        "Only the supplied passive observations are described.",
      sourceIds: [...new Set(checks.flatMap(x => x.sourceIds))],
      findings: risks.map(x => x.id),
      missingControls: unknown.map(x => x.control),
      noSecurityCertification: true as const,
    };
  });
  const actions = [
    ...[...assessment.findings].sort((a, b) =>
      severityRank[b.severity] - severityRank[a.severity] ||
      a.id.localeCompare(b.id)).map(finding => ({
      id: "act-" + finding.id,
      title: finding.title,
      impact: finding.rationale,
      steps: [
        "Validate source evidence within the authorized domain.",
        finding.recommendation,
        "Record independent revalidation after applying changes.",
      ],
      severity: finding.severity,
      sourceIds: [...finding.sourceIds],
      priority: severityRank[finding.severity] * 10,
      executed: false as const, approved: false as const,
    })),
    ...assessment.checks.filter(x =>
      x.state !== "OBSERVED").map(item => ({
      id: "gap-" + item.control,
      title: "Collect evidence: " + item.control,
      impact: item.explanations.join(" "),
      steps: [
        "Confirm the authorized domain and purpose.",
        "Collect the missing observation without intrusive scanning.",
        "Reassess freshness and completeness before conclusions.",
      ],
      severity: "UNKNOWN", sourceIds: [...item.sourceIds],
      priority: 3, executed: false as const,
      approved: false as const,
    })),
  ].sort((a, b) => b.priority - a.priority ||
    a.id.localeCompare(b.id));
  const uncertain = assessment.checks.filter(x =>
    x.state !== "OBSERVED").length;
  const summaryStatus: ExposureReport["summary"]["status"] =
    assessment.findings.length ? "POTENTIAL_RISK" :
      assessment.coverage.observedControls ?
        "PARTIAL_EVIDENCE" : "UNDETERMINED";
  const canonical = {
    schema: "cyberpilot.exposure.report.v2" as const,
    organizationId: assessment.organizationId,
    snapshotId: assessment.snapshotId,
    domain: assessment.domain,
    generatedAt: assessment.assessedAt,
    assessmentDigest: assessment.digest,
    summary: {
      findings: assessment.findings.length,
      highFindings: assessment.findings.filter(x =>
        severityRank[x.severity] >= 4).length,
      controls: assessment.checks.length,
      assessed: assessment.coverage.observedControls,
      uncertain,
      coveragePercent: assessment.coverage.coveragePercent,
      authorizationStatus: assessment.authorization.status,
      status: summaryStatus, securityGrade: null,
      noM365Required: true as const, noLIVEAccessPerformed: true as const,
    },
    sections: sectionData,
    findings: [...assessment.findings],
    actions,
    coverage: assessment.checks.map(x => ({
      control: x.control, state: x.state,
      sourceIds: [...x.sourceIds],
      observationAt: x.observedAt,
      interpretation: x.interpretation,
      uncertain: x.state !== "OBSERVED",
      certifiedHealthy: false as const,
    })),
    limitations: [...assessment.limitations,
      "Passive observations cannot certify whole-domain security.",
      "External DNS or HTTP fetch was not performed by this report.",
      "Additional selectors, subdomains and services remain out of scope."],
    customerApprovalVerified: false as const,
    externallyRevalidated: false as const,
    legacyCyberScoreTouched: false as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyExposureReportV2(
  report: ExposureReport,
  assessment?: ExposureAssessment,
): ExposureReportAudit {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  const localDigestValid = digest === hash(canonical);
  if (!localDigestValid) issues.push("REPORT_DIGEST_INVALID");
  const sectionsComplete =
    sectionDefinitions.every(x =>
      report.sections.some(y => x.id === y.id)) &&
    report.sections.length === sectionDefinitions.length;
  if (!sectionsComplete) issues.push("SECTION_COVERAGE_INCOMPLETE");
  const findingIds = new Set(report.findings.map(x => x.id));
  const findingsLinked = report.actions.every(x =>
    x.id.startsWith("gap-") ||
      findingIds.has(x.id.replace(/^act-/, "")));
  if (!findingsLinked) issues.push("UNATTRIBUTED_ACTION");
  const noExternalAssurance =
    !report.customerApprovalVerified &&
    !report.externallyRevalidated &&
    !report.legacyCyberScoreTouched &&
    report.summary.securityGrade === null &&
    report.coverage.every(x => !x.certifiedHealthy);
  if (!noExternalAssurance)
    issues.push("FALSE_CUSTOMER_SECURITY_ASSURANCE");
  const assessmentMatches = !assessment ||
    verifyExposureOfflineAssessment(assessment).valid &&
    assessment.digest === report.assessmentDigest &&
    assessment.organizationId === report.organizationId &&
    assessment.snapshotId === report.snapshotId &&
    buildExposureReportV2(assessment).digest === report.digest;
  if (!assessmentMatches) issues.push("ASSESSMENT_NOT_BOUND");
  return {
    verified: issues.length === 0, issues, assessmentMatches,
    sectionsComplete, findingsLinked, noExternalAssurance,
    localDigestValid, remoteValidationPerformed: false,
  };
}
function escapeCsv(value: string | number | null) {
  const raw = String(value ?? "");
  const escaped = /^[=+@-]/.test(raw) ? "'" + raw : raw;
  return '"' + escaped.replaceAll('"', '""')
    .replace(/[\u0000-\u001f\u007f]/g, " ") + '"';
}
export function exportExposureReportV2(
  report: ExposureReport,
  format: ExposureReportExport["format"],
): ExposureReportExport {
  if (!verifyExposureReportV2(report).verified)
    throw Error("Cannot export invalid report.");
  if (!["JSON", "CSV", "MARKDOWN"].includes(format))
    throw Error("Unsupported passive evidence export.");
  let payload: string;
  if (format === "JSON")
    payload = JSON.stringify(report, null, 2) + "\n";
  else if (format === "CSV") {
    const rows: Array<Array<string | number | null>> = [
      ["control", "state", "interpretation", "evidence", "observedAt"],
      ...report.coverage.map(x => [
        x.control, x.state, x.interpretation,
        x.sourceIds.join(";"), x.observationAt,
      ]),
    ];
    payload = rows.map(x => x.map(escapeCsv)
      .join(",")).join("\r\n") + "\r\n";
  } else {
    const lines = [
      "# CyberPilot — Authorized passive Exposure report",
      "", "Organization: " + report.organizationId,
      "Domain: " + report.domain,
      "Date: " + report.generatedAt,
      "Observed coverage: " + report.summary.coveragePercent + "%",
      "Security grade: UNDETERMINED (not certified)", "",
    ];
    for (const section of report.sections)
      lines.push("## " + section.title, section.description, "");
    for (const action of report.actions)
      lines.push("- " + action.title + ": " +
        action.steps.join(" "));
    lines.push("", "## Explicit limitations",
      ...report.limitations.map(x => "- " + x));
    payload = lines.join("\n") + "\n";
  }
  const mediaType = format === "JSON" ? "application/json" :
    format === "CSV" ? "text/csv" : "text/markdown";
  return {
    schema: "cyberpilot.exposure.export.v2",
    organizationId: report.organizationId,
    snapshotId: report.snapshotId, format,
    filename: "exposure-" + report.snapshotId + "." +
      (format === "JSON" ? "json" : format === "CSV" ? "csv" : "md"),
    mediaType, payload,
    reportDigest: report.digest,
    payloadDigest: sha256V2(payload),
    containsUnredactedCredentials: false,
    hasNetworkActivity: false, securityCertified: false,
  };
}
export function compareExposureReportsV2(
  previous: ExposureReport, current: ExposureReport,
): ExposureReportDelta {
  if (!verifyExposureReportV2(previous).verified ||
      !verifyExposureReportV2(current).verified)
    throw Error("Unverified Exposure report delta.");
  if (previous.organizationId !== current.organizationId ||
      previous.domain !== current.domain ||
      previous.generatedAt >= current.generatedAt)
    throw Error("Cross-tenant, cross-domain or unordered report comparison.");
  const oldFindings = new Set(previous.findings.map(x => x.id));
  const newFindings = new Set(current.findings.map(x => x.id));
  const oldUncertain = new Set(previous.coverage.filter(x =>
    x.uncertain).map(x => x.control));
  const newUncertain = new Set(current.coverage.filter(x =>
    x.uncertain).map(x => x.control));
  return {
    organizationId: current.organizationId,
    domain: current.domain, older: previous.generatedAt,
    newer: current.generatedAt, chronologyValid: true,
    coverageDelta: current.summary.coveragePercent -
      previous.summary.coveragePercent,
    newFindings: [...newFindings].filter(x => !oldFindings.has(x)),
    absentFindings: [...oldFindings].filter(x =>
      !newFindings.has(x)),
    continuingFindings: [...newFindings].filter(x =>
      oldFindings.has(x)),
    newUnknownControls: [...newUncertain].filter(x =>
      !oldUncertain.has(x)),
    newlyObservedControls: [...oldUncertain].filter(x =>
      !newUncertain.has(x)),
    independentRemediationVerified: false,
    safeToCompareAsHealthGrade: false,
  };
}
export function exposureOfflineReleaseCheck(
  assessments: readonly ExposureAssessment[],
) {
  const failures: string[] = [];
  for (const result of assessments) {
    const report = buildExposureReportV2(result);
    const checked = verifyExposureReportV2(report, result);
    if (!checked.verified)
      failures.push(result.snapshotId + ":" + checked.issues.join(","));
    if (result.trafficGenerated !== 0 ||
        result.coverage.healthyClaimAllowed)
      failures.push(result.snapshotId + ":FALSE_LIVE_CLAIM");
  }
  return {
    mode: "SYNTHETIC_OFFLINE" as const,
    scenarios: assessments.length, failures,
    passed: failures.length === 0 && assessments.length > 0,
    tenantAuthenticatedExternally: false as const,
    customerSignedOff: false as const,
    legacyScoreModified: false as const,
  };
}
