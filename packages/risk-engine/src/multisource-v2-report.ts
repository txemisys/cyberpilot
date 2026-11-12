import {
  type V2Manifest, type V2Coverage,
  type V2Score, type V2Finding,
  type V2Domain, type V2Source,
  type V2CoverageRow, type V2Status,
  canonicalV2, validateV2Manifest,
} from "./multisource-v2-contract";
import {
  computeV2Coverage, coverageV2Gaps,
  summarizeV2CoverageExecutive,
} from "./multisource-v2-coverage";
import {
  calculateMultiSourceCyberScoreV2,
  explainV2Score, summarizeV2ScoreExecutive,
} from "./multisource-v2-score";
import { sha256V2 } from "./multisource-v2-history";

/**
 * Product-facing M365-independent report. No "healthy" inference:
 * a score remains null unless v2 attains its verified coverage gate.
 */
export type V2ReportSection = {
  id:
    "EXECUTIVE" | "SOURCES" | "COVERAGE" |
    "IDENTITY" | "EMAIL" | "WEB" |
    "ENDPOINT" | "BACKUP" | "GOVERNANCE" |
    "EXPOSURE" | "FINDINGS" |
    "ACTIONS" | "PROVENANCE" | "LIMITATIONS";
  title: string;
  subtitle: string;
  status: "EVIDENCED_WITH_LIMITS" |
    "UNKNOWN" | "REQUIRES_REVIEW";
  narrative: string;
  risks: number;
  unknownControls: number;
  sourceCount: number;
  evidenceCount: number;
  sourceDigests: string[];
  confidence: V2Score["confidence"];
  customerCertified: false;
};
export type V2ExecutiveReport = {
  schema: "cyberpilot.multisource.executive.v2";
  organizationId: string;
  snapshotId: string;
  modelId: "cyberpilot.multisource.v2";
  evaluatedAt: string;
  summary: {
    numericScore: number | null;
    scoreStatus: V2Score["status"];
    coveragePercent: number;
    requiredControls: number;
    verifiedControls: number;
    unknownControls: number;
    unsupportedFindings: number;
    riskPoints: number;
    confidence: V2Score["confidence"];
    providerCount: number;
    domainCount: number;
    liveProviderAuthenticated: boolean;
    noMicrosoft365RequiredToGenerate: true;
    certifiedHealthy: false;
    complianceCertified: false;
  };
  sources: Array<{
    source: V2Source;
    controlCount: number;
    observed: number;
    unknown: number;
    declared: number;
    errors: number;
    scopeAuthenticated: boolean;
    sourceDigests: string[];
    fullTenantSecurityProven: false;
  }>;
  sections: V2ReportSection[];
  gaps: Array<{
    controlId: string;
    domain: V2Domain;
    state: V2Status;
    weight: number;
    explanation: string[];
    sourceIds: V2Source[];
    nextAction: string;
    automaticallyFixed: false;
  }>;
  findings: Array<{
    findingId: string;
    severity: string;
    state: string;
    title: string;
    explanation: string;
    remediation: string;
    scope: string;
    source: V2Source;
    evidenceIds: string[];
    scoreEligible: boolean;
    resolved: false;
    customerSignedOff: false;
  }>;
  priorities: Array<{
    rank: number;
    code: string;
    title: string;
    reason: string;
    recommendation: string;
    source: V2Source | "MULTI_SOURCE";
    evidenceIds: string[];
    requiresLiveVerification: boolean;
    automaticallyExecuted: false;
  }>;
  provenance: {
    sourceDigests: string[];
    manifestDigest: string;
    coverageDigest: string;
    scoreDigest: string;
    modelRevision: 1;
    customerSignatureVerified: false;
    originalProviderResponseAuthenticated: false;
    legacyCyberScoreRecomputed: false;
  };
  caveats: string[];
  customerApprovalAttested: false;
  providerLIVEFullyValidated: false;
  historicalCyberScoreModified: false;
  dataExportContainsSecrets: false;
  digest: string;
};
export type V2ReportAudit = {
  schema: "cyberpilot.multisource.report.audit.v2";
  organizationId: string;
  snapshotId: string;
  verified: boolean;
  digestMatches: boolean;
  referencesConsistent: boolean;
  scoreCoverageConsistent: boolean;
  sourceScopeConsistent: boolean;
  noCustomerApprovalClaim: boolean;
  noLegacyScoreChange: boolean;
  issues: string[];
  checkedSections: number;
  checkedFindings: number;
  checkedPriorities: number;
  auditDigest: string;
};
export type V2ReportExport = {
  schema: "cyberpilot.multisource.report.export.v2";
  organizationId: string;
  format: "MARKDOWN" | "JSON" | "CSV";
  filename: string;
  mimeType: string;
  reportDigest: string;
  content: string;
  sizeBytes: number;
  includesPII: false;
  containsOauthTokens: false;
  customerCertificationClaimed: false;
  historicalV1CyberScoreModified: false;
  digest: string;
};
const domains: V2Domain[] = [
  "IDENTITY", "EMAIL", "WEB", "ENDPOINT",
  "BACKUP", "GOVERNANCE", "EXPOSURE",
];
function hash(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function section(
  id: V2ReportSection["id"], title: string,
  subtitle: string, narrative: string,
  rows: V2CoverageRow[], manifest: V2Manifest,
  score: V2Score,
): V2ReportSection {
  const controls = rows.filter(x =>
    id === "EXECUTIVE" || id === "SOURCES" ||
      id === "COVERAGE" || id === "FINDINGS" ||
      id === "ACTIONS" || id === "PROVENANCE" ||
      id === "LIMITATIONS" || x.domain === id);
  const unknown = controls.filter(x =>
    !x.verifiedForScoring).length;
  const risks = manifest.findings.filter(x =>
    controls.some(c => c.controlId === x.controlId) &&
    x.state === "POTENTIAL_RISK").length;
  const sources = [...new Set(controls.flatMap(c =>
    c.sourceIds))];
  const evidence = manifest.evidence.filter(x =>
    controls.some(c => c.controlId === x.controlId));
  return {
    id, title, subtitle,
    status: unknown > 0 ? "UNKNOWN" :
      risks > 0 ? "REQUIRES_REVIEW" :
        "EVIDENCED_WITH_LIMITS",
    narrative, risks, unknownControls: unknown,
    sourceCount: sources.length,
    evidenceCount: evidence.length,
    sourceDigests: [...new Set(evidence.map(x =>
      x.sourceDigest))],
    confidence: score.confidence,
    customerCertified: false,
  };
}
function sourceRows(
  manifest: V2Manifest, coverage: V2Coverage,
): V2ExecutiveReport["sources"] {
  return [...new Set(manifest.evidence.map(x => x.source))]
    .sort().map(source => {
    const sourceEvidence = manifest.evidence.filter(x =>
      x.source === source);
    const controlIds = [...new Set(
      sourceEvidence.map(x => x.controlId))];
    return {
      source, controlCount: controlIds.length,
      observed: sourceEvidence.filter(x =>
        x.state === "OBSERVED").length,
      unknown: sourceEvidence.filter(x =>
        x.state === "UNKNOWN").length,
      declared: sourceEvidence.filter(x =>
        x.state === "DECLARED").length,
      errors: sourceEvidence.filter(x =>
        x.state === "ERROR").length,
      scopeAuthenticated: manifest.scopes.some(s =>
        s.source === source && s.customerTenantAuthenticated &&
        s.scopeAuthenticityVerified),
      sourceDigests: [...new Set(
        sourceEvidence.map(x => x.sourceDigest))],
      fullTenantSecurityProven: false as const,
    };
  });
}
function normalizeFinding(
  finding: V2Finding,
  score: V2Score,
): V2ExecutiveReport["findings"][number] {
  return {
    findingId: finding.findingId,
    severity: finding.severity,
    state: finding.state,
    title: finding.title,
    explanation: finding.explanation,
    remediation: finding.remediation,
    scope: finding.scope,
    source: finding.source,
    evidenceIds: [...finding.evidenceIds],
    scoreEligible: score.contributions.some(x =>
      x.key === finding.findingId),
    resolved: false,
    customerSignedOff: false,
  };
}
function priorities(
  score: V2Score, coverage: V2Coverage,
): V2ExecutiveReport["priorities"] {
  const actions: V2ExecutiveReport["priorities"] = [];
  for (const item of score.topActions) {
    actions.push({
      rank: actions.length + 1,
      code: "RISK:" + item.findingId,
      title: item.title,
      reason: item.rationale,
      recommendation: item.recommendation,
      source: item.source,
      evidenceIds: [...item.evidenceIds],
      requiresLiveVerification: true,
      automaticallyExecuted: false,
    });
  }
  for (const gap of coverageV2Gaps(coverage).slice(0, 15)) {
    actions.push({
      rank: actions.length + 1,
      code: "COVERAGE:" + gap.controlId,
      title: "Obtain evidence for " + gap.controlId,
      reason: gap.uncertainty.join(" "),
      recommendation:
        "Confirm authorization, scope and observation recency before assessing.",
      source: gap.sourcesAttempted[0] ?? "MULTI_SOURCE",
      evidenceIds: [...gap.evidenceIds],
      requiresLiveVerification: true,
      automaticallyExecuted: false,
    });
  }
  return actions;
}
export function buildV2ExecutiveReport(
  manifest: V2Manifest,
): V2ExecutiveReport {
  if (!validateV2Manifest(manifest).valid)
    throw new Error("Refusing report for invalid or cross-tenant source.");
  const coverage = computeV2Coverage(manifest);
  const score = calculateMultiSourceCyberScoreV2(manifest);
  const coverageSummary = summarizeV2CoverageExecutive(coverage);
  const scoreSummary = summarizeV2ScoreExecutive(score, coverage);
  const breakdown = explainV2Score(score, coverage);
  const sourceInfo = sourceRows(manifest, coverage);
  const sectionDefinitions: Array<{
    id: V2ReportSection["id"]; title: string;
    subtitle: string; narrative: string;
  }> = [
    {
      id: "EXECUTIVE", title: "Executive risk posture",
      subtitle: "What can be concluded from the available evidence",
      narrative: scoreSummary.message,
    },
    {
      id: "SOURCES", title: "Connected and observed sources",
      subtitle: "M365, Google, Exposure, Baseline and Assets",
      narrative: sourceInfo.length +
        " sources contributed data. This does not certify tenant completeness.",
    },
    {
      id: "COVERAGE", title: "Required control coverage",
      subtitle: "Coverage is distinct from the absence of findings",
      narrative: coverage.verifiedControls +
        " of " + coverage.totalControls + " required controls supported.",
    },
    ...domains.map(domain => {
      const metric = breakdown.find(x => x.domain === domain);
      return {
        id: domain as V2ReportSection["id"],
        title: domain.toLowerCase() + " controls",
        subtitle: "Known, missing and conflicting signals",
        narrative: metric?.recommendedAction ??
          "No scoped evidence is available for this domain.",
      };
    }),
    {
      id: "FINDINGS", title: "Potential risks",
      subtitle: "Proposed findings, not automatically resolved incidents",
      narrative: manifest.findings.length +
        " source-attributed findings; unverified links do not enter scoring.",
    },
    {
      id: "ACTIONS", title: "Prioritized next actions",
      subtitle: "Guidance only; no account writes are performed",
      narrative: "Review highest risk and highest-value coverage gaps first.",
    },
    {
      id: "PROVENANCE", title: "Evidence provenance",
      subtitle: "Local deterministic verification, not external signatures",
      narrative: "Source digests, scopes, model and timestamps are preserved.",
    },
    {
      id: "LIMITATIONS", title: "Limitations",
      subtitle: "Unknown does not mean safe",
      narrative: score.limitations.join(" "),
    },
  ];
  const gaps = coverageV2Gaps(coverage).map(g => ({
    controlId: g.controlId, domain: g.domain,
    state: g.code, weight: g.weight,
    explanation: [...g.uncertainty],
    sourceIds: [...g.sourcesAttempted],
    nextAction: g.shouldRecheck ?
      "Verify source integrity and refresh observation." :
      "Request authorized scoped control evidence.",
    automaticallyFixed: false as const,
  }));
  const canonical = {
    schema: "cyberpilot.multisource.executive.v2" as const,
    organizationId: manifest.organizationId,
    snapshotId: manifest.snapshotId,
    modelId: "cyberpilot.multisource.v2" as const,
    evaluatedAt: manifest.evaluatedAt,
    summary: {
      numericScore: score.score,
      scoreStatus: score.status,
      coveragePercent: coverage.coveragePercent,
      requiredControls: coverage.totalControls,
      verifiedControls: coverage.verifiedControls,
      unknownControls: score.unknownControls.length,
      unsupportedFindings: score.unsupportedFindings.length,
      riskPoints: score.riskPoints,
      confidence: score.confidence,
      providerCount: sourceInfo.length,
      domainCount: coverage.domains.length,
      liveProviderAuthenticated: coverage.liveProviderAuthenticated,
      noMicrosoft365RequiredToGenerate: true as const,
      certifiedHealthy: false as const,
      complianceCertified: false as const,
    },
    sources: sourceInfo,
    sections: sectionDefinitions.map(def =>
      section(def.id, def.title, def.subtitle,
        def.narrative, coverage.controls, manifest, score)),
    gaps, findings: manifest.findings.map(f =>
      normalizeFinding(f, score)),
    priorities: priorities(score, coverage),
    provenance: {
      sourceDigests: [...manifest.sourceDigests],
      manifestDigest: hash(manifest),
      coverageDigest: hash(coverage),
      scoreDigest: hash(score),
      modelRevision: 1 as const,
      customerSignatureVerified: false as const,
      originalProviderResponseAuthenticated: false as const,
      legacyCyberScoreRecomputed: false as const,
    },
    caveats: [...new Set([
      ...coverageSummary.topUnknowns.slice(0, 3)
        .flatMap(x => x.uncertainty),
      ...score.limitations,
      "A v2 risk estimate is not comparable to historical v1 CyberScore.",
      "No customer operational approval is inferred by automated tests.",
    ])],
    customerApprovalAttested: false as const,
    providerLIVEFullyValidated: false as const,
    historicalCyberScoreModified: false as const,
    dataExportContainsSecrets: false as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyV2ExecutiveReport(
  report: V2ExecutiveReport,
  manifest?: V2Manifest,
): V2ReportAudit {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  if (hash(canonical) !== digest)
    issues.push("REPORT_DIGEST_INVALID");
  if (report.schema !== "cyberpilot.multisource.executive.v2" ||
      report.modelId !== "cyberpilot.multisource.v2")
    issues.push("REPORT_MODEL_UNSUPPORTED");
  if (report.customerApprovalAttested ||
      report.providerLIVEFullyValidated ||
      report.historicalCyberScoreModified ||
      report.dataExportContainsSecrets ||
      report.summary.certifiedHealthy ||
      report.summary.complianceCertified)
    issues.push("UNSUPPORTED_CUSTOMER_OR_LEGACY_ASSURANCE");
  const referencesConsistent = report.findings.every(f =>
    f.evidenceIds.length > 0 &&
    f.source.length > 0 && !f.resolved &&
    !f.customerSignedOff);
  if (!referencesConsistent)
    issues.push("FINDING_REFERENCE_OR_APPROVAL_INVALID");
  const scoreCoverageConsistent =
    report.summary.numericScore === null ||
      report.summary.coveragePercent >= 60 &&
      report.summary.verifiedControls >= 5;
  if (!scoreCoverageConsistent)
    issues.push("SCORE_WITHOUT_COVERAGE");
  const sourceScopeConsistent = report.sources.every(x =>
    !x.fullTenantSecurityProven);
  if (!sourceScopeConsistent)
    issues.push("SOURCE_FALSE_SECURITY_CLAIM");
  if (manifest) {
    if (manifest.organizationId !== report.organizationId ||
        manifest.snapshotId !== report.snapshotId ||
        hash(manifest) !== report.provenance.manifestDigest)
      issues.push("MISMATCHED_SOURCE_MANIFEST");
    else {
      const recalculated = buildV2ExecutiveReport(manifest);
      if (recalculated.digest !== report.digest)
        issues.push("REPORT_NOT_REPRODUCIBLE");
    }
  }
  const result = {
    schema: "cyberpilot.multisource.report.audit.v2" as const,
    organizationId: report.organizationId,
    snapshotId: report.snapshotId,
    verified: issues.length === 0,
    digestMatches: !issues.includes("REPORT_DIGEST_INVALID"),
    referencesConsistent, scoreCoverageConsistent,
    sourceScopeConsistent,
    noCustomerApprovalClaim:
      !report.customerApprovalAttested,
    noLegacyScoreChange:
      !report.historicalCyberScoreModified,
    issues, checkedSections: report.sections.length,
    checkedFindings: report.findings.length,
    checkedPriorities: report.priorities.length,
  };
  return { ...result, auditDigest: hash(result) };
}
function csvCell(value: string) {
  const normalized = /^[=+@-]/.test(value) ? "'" + value : value;
  return '"' + normalized.replaceAll('"', '""')
    .replace(/[\r\n\u0000-\u001f\u007f]/g, " ") + '"';
}
export function exportV2Report(
  report: V2ExecutiveReport,
  format: V2ReportExport["format"],
): V2ReportExport {
  if (!verifyV2ExecutiveReport(report).verified)
    throw new Error("Cannot export invalid multitenant report.");
  if (!["MARKDOWN", "JSON", "CSV"].includes(format))
    throw new Error("Unsupported report format.");
  let content: string;
  if (format === "JSON") {
    content = JSON.stringify(report, null, 2) + "\n";
  } else if (format === "CSV") {
    const rows: string[][] = [
      ["source", "domain", "control", "state",
        "evidence", "nextAction"],
    ];
    for (const gap of report.gaps)
      rows.push([
        gap.sourceIds.join("+"), gap.domain,
        gap.controlId, gap.state,
        gap.explanation.join(" "),
        gap.nextAction,
      ]);
    content = rows.map(row => row.map(csvCell)
      .join(",")).join("\r\n") + "\r\n";
  } else {
    const lines = [
      "# CyberPilot — Multi-source security assessment v2",
      "",
      "Organization: " + report.organizationId,
      "Date: " + report.evaluatedAt,
      "Model: " + report.modelId,
      "Score: " + (report.summary.numericScore ?? "UNDETERMINED"),
      "Verified coverage: " + report.summary.coveragePercent + "%",
      "",
      "This is a cautious risk estimate, not a security certification.",
    ];
    for (const section of report.sections) {
      lines.push("", "## " + section.title,
        section.narrative,
        "Source count: " + section.sourceCount,
        "Unknown controls: " + section.unknownControls);
    }
    lines.push("", "## Priority actions");
    for (const action of report.priorities)
      lines.push("- " + action.title + ": " +
        action.recommendation);
    lines.push("", "## Limitations", ...report.caveats.map(x =>
      "- " + x));
    content = lines.join("\n") + "\n";
  }
  const canonical = {
    schema: "cyberpilot.multisource.report.export.v2" as const,
    organizationId: report.organizationId, format,
    filename: "cyberpilot-v2-" + report.snapshotId + "." +
      (format === "MARKDOWN" ? "md" :
        format === "CSV" ? "csv" : "json"),
    mimeType: format === "MARKDOWN" ?
      "text/markdown" : format === "CSV" ?
        "text/csv" : "application/json",
    reportDigest: report.digest, content,
    sizeBytes: new TextEncoder().encode(content).length,
    includesPII: false as const,
    containsOauthTokens: false as const,
    customerCertificationClaimed: false as const,
    historicalV1CyberScoreModified: false as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyV2ReportExport(
  exported: V2ReportExport,
) {
  const { digest, ...canonical } = exported;
  const issues: string[] = [];
  if (hash(canonical) !== digest)
    issues.push("EXPORT_DIGEST_CHANGED");
  if (exported.includesPII ||
      exported.containsOauthTokens ||
      exported.customerCertificationClaimed ||
      exported.historicalV1CyberScoreModified)
    issues.push("EXPORT_FALSE_ASSURANCE_OR_PERSONAL_DATA");
  if (!["JSON", "CSV", "MARKDOWN"].includes(exported.format))
    issues.push("EXPORT_FORMAT_UNKNOWN");
  if (!exported.reportDigest ||
      !/^[a-f0-9]{64}$/.test(exported.reportDigest))
    issues.push("EXPORT_REPORT_DIGEST_INVALID");
  if (new TextEncoder().encode(exported.content).length !==
      exported.sizeBytes)
    issues.push("EXPORT_CONTENT_SIZE_MISMATCH");
  return { valid: issues.length === 0, issues };
}
export function compareV2ExecutiveReports(
  previous: V2ExecutiveReport,
  current: V2ExecutiveReport,
) {
  if (!verifyV2ExecutiveReport(previous).verified ||
      !verifyV2ExecutiveReport(current).verified)
    throw new Error("Cannot compare invalid v2 reports.");
  if (previous.organizationId !== current.organizationId ||
      previous.modelId !== current.modelId ||
      previous.evaluatedAt > current.evaluatedAt)
    throw new Error("Report comparison crosses tenant, model or time.");
  const oldKeys = new Set(previous.findings.map(x =>
    x.findingId));
  const newKeys = new Set(current.findings.map(x =>
    x.findingId));
  const oldGaps = new Set(previous.gaps.map(x =>
    x.controlId));
  const newGaps = new Set(current.gaps.map(x =>
    x.controlId));
  const comparable = previous.summary.numericScore !== null &&
    current.summary.numericScore !== null;
  return {
    schema: "cyberpilot.multisource.report.comparison.v2" as const,
    organizationId: current.organizationId,
    previousReportDigest: previous.digest,
    currentReportDigest: current.digest,
    from: previous.evaluatedAt, to: current.evaluatedAt,
    oldScore: previous.summary.numericScore,
    newScore: current.summary.numericScore,
    scoreDelta: comparable ?
      current.summary.numericScore! -
        previous.summary.numericScore! : null,
    scoreComparable: comparable,
    coverageDelta: current.summary.coveragePercent -
      previous.summary.coveragePercent,
    addedFindings: [...newKeys].filter(x => !oldKeys.has(x)),
    disappearedFindings: [...oldKeys].filter(x =>
      !newKeys.has(x)),
    newlyUnknownControls: [...newGaps].filter(x =>
      !oldGaps.has(x)),
    newlyObservedControls: [...oldGaps].filter(x =>
      !newGaps.has(x)),
    remediationVerified: false as const,
    providerReauthenticated: false as const,
    historicalV1ScoreChanged: false as const,
    limitations: [
      "A missing finding can reflect a coverage loss, not remediation.",
      "Model v2 coverage and score must be interpreted together.",
      "No automatic customer certification is issued.",
    ],
  };
}
