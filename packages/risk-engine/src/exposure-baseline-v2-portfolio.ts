import {
  type ExposureAssessment, type ExposureOfflineEnvelope,
  assessExposureOffline, verifyExposureOfflineAssessment,
} from "./exposure-offline-v2";
import {
  type ExposureReport, buildExposureReportV2,
  verifyExposureReportV2,
} from "./exposure-offline-report-v2";
import {
  type BaselineV2Assessment,
  type BaselineV2AssessmentOptions,
  assessBaselineOfflineV2, verifyBaselineOfflineV2,
} from "./baseline-offline-v2";
import {
  type BaselineReportV2,
  buildBaselineReportV2, verifyBaselineReportV2,
  buildBaselineActionPlanV2,
} from "./baseline-offline-report-v2";
import type { BaselineSubmission } from "./baseline-questions";
import { type V2BridgeProjection,
  buildExposureBaselineV2Bridge,
  exposureBaselineV2CrossSignals,
  verifyExposureBaselineV2Bridge,
} from "./exposure-baseline-v2-bridge";
import { canonicalV2 } from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";

/**
 * Unified no-M365 offline workflow. Source validation precedes
 * any analysis; a declaration is never converted to a LIVE tenant.
 */
export type Phase2PortfolioInput = {
  schema: "cyberpilot.phase2.portfolio.input.v1";
  organizationId: string;
  snapshotId: string;
  evaluatedAt: string;
  actorId: string;
  exposure: ExposureOfflineEnvelope[];
  baseline: BaselineSubmission | null;
  sourceMode: "OFFLINE_ONLY";
  liveNetworkRequestsAllowed: false;
  oauthTokensProvided: false;
  authorizedLiveTenantClaimed: false;
  maximumActions: number;
};
export type Phase2PortfolioPriority = {
  id: string;
  source: "EXPOSURE" | "BASELINE" | "CROSS_SOURCE" |
    "COVERAGE";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" |
    "UNKNOWN";
  title: string;
  rationale: string;
  recommendation: string;
  evidenceDigests: string[];
  evidenceIds: string[];
  rank: number;
  confidence: "DECLARED" | "OFFLINE_OBSERVED" |
    "NOT_DETERMINED";
  approvedByCustomer: false;
  executed: false;
  closed: false;
  independentlyValidated: false;
};
export type Phase2PortfolioDomain = {
  domain: string;
  exposureControls: number;
  baselineQuestions: number;
  observedOffline: number;
  declared: number;
  unknown: number;
  candidateRisks: number;
  conclusion: "PARTIAL_EVIDENCE" | "UNKNOWN" |
    "REVIEW_REQUIRED";
  securityHealthy: false;
  certificationValid: false;
};
export type Phase2Portfolio = {
  schema: "cyberpilot.phase2.portfolio.v1";
  organizationId: string;
  snapshotId: string;
  evaluatedAt: string;
  sourceMode: "OFFLINE_ONLY";
  sourceDigests: string[];
  sources: Array<{
    kind: "EXPOSURE" | "BASELINE";
    digest: string;
    snapshotId: string;
    domain: string | null;
    status: "DECLARED" | "OFFLINE_OBSERVED";
    realThirdPartyVerification: false;
  }>;
  exposureReports: ExposureReport[];
  baselineReport: BaselineReportV2 | null;
  bridge: V2BridgeProjection;
  priorities: Phase2PortfolioPriority[];
  domains: Phase2PortfolioDomain[];
  overview: {
    domains: number;
    exposureDomains: number;
    baselineQuestions: number;
    unknownControls: number;
    potentialRiskCount: number;
    recommendedActions: number;
    technicalCoveragePercent: number;
    score: null;
    label: "UNDETERMINED";
    sourceCount: number;
    noM365Required: true;
    containsLiveSecurityEvaluation: false;
    autoRemediationCount: 0;
  };
  limitations: string[];
  links: Array<{
    from: string; to: string;
    relation: "SAME_DOMAIN" | "SHARED_CONTROL" |
      "EVIDENCE_REQUIRED";
    semanticallyEquivalent: false;
    proofOfRemediation: false;
  }>;
  localIntegrityVerified: true;
  realProviderConsentVerified: false;
  customerApprovedDeployment: false;
  historicalCyberScoreUpdated: false;
  digest: string;
};
export type Phase2PortfolioVerification = {
  valid: boolean; issues: string[];
  localDigestVerified: boolean;
  sourcesBound: boolean;
  tenantScoped: boolean;
  hasNoFalseScore: boolean;
  hasNoLiveActivity: boolean;
  independentExternalAuditPerformed: false;
};
export type Phase2PortfolioDelta = {
  organizationId: string;
  olderSnapshot: string;
  newerSnapshot: string;
  coverageDelta: number;
  sourceCountDelta: number;
  newActions: string[];
  absentActions: string[];
  newUnknownDomains: string[];
  apparentlyImprovedDomains: string[];
  remediationProof: false;
  riskReductionExternallyValidated: false;
  legacyCyberScoreChanged: false;
};
const priorityValue: Record<Phase2PortfolioPriority["severity"], number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3,
  LOW: 2, UNKNOWN: 1,
};
function hash(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function validId(s: string) {
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
}
function rankPriorities(
  values: Phase2PortfolioPriority[],
): Phase2PortfolioPriority[] {
  const deduped = new Map<string, Phase2PortfolioPriority>();
  for (const item of values) {
    const key = [item.source, item.id].join("|");
    if (!deduped.has(key)) deduped.set(key, item);
  }
  const sorted = [...deduped.values()].sort((a, b) =>
    priorityValue[b.severity] - priorityValue[a.severity] ||
      a.id.localeCompare(b.id));
  return sorted.map((item, index) => ({
    ...item, rank: index + 1,
  }));
}
function domains(
  exposure: ExposureAssessment[],
  baseline: BaselineV2Assessment | null,
): Phase2PortfolioDomain[] {
  const names = new Set<string>([
    ...exposure.flatMap(x => x.checks.map(y =>
      y.control.startsWith("EMAIL") ? "EMAIL" : "WEB")),
    ...baseline?.domains.map(x => x.domain) ?? [],
  ]);
  return [...names].sort().map(name => {
    const controls = exposure.flatMap(x => x.checks)
      .filter(x => (x.control.startsWith("EMAIL") ?
        "EMAIL" : "WEB") === name);
    const answers = baseline?.evidence.filter(x =>
      x.domain === name) ?? [];
    const unknown = controls.filter(x =>
      x.state !== "OBSERVED").length +
      answers.filter(x => x.answer === "UNANSWERED" ||
        x.answer === "UNKNOWN").length;
    const risks = controls.flatMap(x => x.findings).length +
      answers.filter(x => x.answer === "NO" ||
        x.answer === "PARTIAL").length;
    const observedOffline = controls.filter(x =>
      x.state === "OBSERVED").length;
    return {
      domain: name,
      exposureControls: controls.length,
      baselineQuestions: answers.length,
      observedOffline,
      declared: answers.filter(x =>
        x.answer === "YES" || x.answer === "PARTIAL" ||
        x.answer === "NO").length,
      unknown, candidateRisks: risks,
      conclusion: risks ? "REVIEW_REQUIRED" as const :
        observedOffline ? "PARTIAL_EVIDENCE" as const :
        "UNKNOWN" as const,
      securityHealthy: false as const,
      certificationValid: false as const,
    };
  });
}
function actionsFromExposure(
  report: ExposureReport,
): Phase2PortfolioPriority[] {
  return report.actions.map(x => ({
    id: x.id, source: "EXPOSURE" as const,
    severity: x.severity === "CRITICAL" ||
      x.severity === "HIGH" ||
      x.severity === "MEDIUM" ||
      x.severity === "LOW" ?
        x.severity : "UNKNOWN" as const,
    title: x.title,
    rationale: x.impact,
    recommendation: x.steps.join(" "),
    evidenceDigests: [report.assessmentDigest],
    evidenceIds: [...x.sourceIds],
    rank: 0, confidence: "OFFLINE_OBSERVED" as const,
    approvedByCustomer: false as const,
    executed: false as const, closed: false as const,
    independentlyValidated: false as const,
  }));
}
function actionsFromBaseline(
  report: BaselineReportV2,
): Phase2PortfolioPriority[] {
  return report.actions.map(x => ({
    id: x.id, source: "BASELINE" as const,
    severity: x.priority === "CRITICAL" ||
      x.priority === "HIGH" ||
      x.priority === "MEDIUM" ||
      x.priority === "LOW" ? x.priority : "UNKNOWN" as const,
    title: x.title, rationale: x.reason,
    recommendation: x.steps.join(" "),
    evidenceDigests: [report.sourceDigest],
    evidenceIds: x.evidenceReference ?
      [x.evidenceReference] : [],
    rank: 0, confidence: "DECLARED" as const,
    approvedByCustomer: false as const,
    executed: false as const, closed: false as const,
    independentlyValidated: false as const,
  }));
}
function linkSources(
  exposure: ExposureAssessment[],
  baseline: BaselineV2Assessment | null,
) {
  const links: Phase2Portfolio["links"] = [];
  if (!baseline) return links;
  const baselineDomains = new Set(baseline.domains.map(x => x.domain));
  for (const assessment of exposure) {
    for (const item of assessment.checks) {
      const target = item.control.startsWith("EMAIL") ?
        "EMAIL_WEB" : "APPLICATIONS";
      if (!baselineDomains.has(target)) continue;
      links.push({
        from: assessment.snapshotId + ":" + item.control,
        to: baseline.snapshotId + ":" + target,
        relation: "SAME_DOMAIN",
        semanticallyEquivalent: false,
        proofOfRemediation: false,
      });
    }
  }
  return links;
}
export function buildPhase2OfflinePortfolio(
  input: Phase2PortfolioInput,
): Phase2Portfolio {
  if (input.schema !== "cyberpilot.phase2.portfolio.input.v1" ||
      !validId(input.organizationId) ||
      !validId(input.snapshotId) ||
      !validId(input.actorId) ||
      !Number.isFinite(Date.parse(input.evaluatedAt)) ||
      input.sourceMode !== "OFFLINE_ONLY" ||
      input.liveNetworkRequestsAllowed ||
      input.oauthTokensProvided ||
      input.authorizedLiveTenantClaimed ||
      !Number.isSafeInteger(input.maximumActions) ||
      input.maximumActions < 1 || input.maximumActions > 200 ||
      !Array.isArray(input.exposure) ||
      input.exposure.length > 20 ||
      (!input.baseline && !input.exposure.length))
    throw Error("Invalid Phase 2 offline portfolio input.");
  const observedDomains = new Set<string>();
  const assessments = input.exposure.map(source => {
    if (source.organizationId !== input.organizationId ||
        source.assessedAt > input.evaluatedAt ||
        observedDomains.has(source.domain))
      throw Error("Cross-tenant, duplicate or future Exposure data.");
    observedDomains.add(source.domain);
    const assessment = assessExposureOffline(source);
    if (!verifyExposureOfflineAssessment(assessment, source).valid)
      throw Error("Exposure source invalid for portfolio.");
    return assessment;
  });
  let baseline: BaselineV2Assessment | null = null;
  if (input.baseline) {
    if (input.baseline.organizationId !== input.organizationId ||
        input.baseline.submittedAt > input.evaluatedAt)
      throw Error("Cross-tenant or future Baseline source.");
    const opts: BaselineV2AssessmentOptions = {
      organizationId: input.organizationId,
      snapshotId: "baseline-" + hash({
        organizationId: input.organizationId,
        source: input.baseline,
      }).slice(0, 32),
      evaluatedAt: input.evaluatedAt,
      completedBy: input.actorId,
      notePolicy: "DISCARD_CONTENT",
      referencePolicy: "OPAQUE_IDENTIFIERS_ONLY",
      maxActions: 100,
    };
    baseline = assessBaselineOfflineV2(input.baseline, opts);
  }
  const exposureReports = assessments.map(buildExposureReportV2);
  const baselineReport = baseline ?
    buildBaselineReportV2(baseline) : null;
  const bridge = buildExposureBaselineV2Bridge({
    organizationId: input.organizationId,
    snapshotId: input.snapshotId,
    evaluatedAt: input.evaluatedAt,
  }, assessments, baseline);
  if (!verifyExposureBaselineV2Bridge(bridge).valid)
    throw Error("Multi-source bridging failed acceptance.");
  const signals = exposureBaselineV2CrossSignals(bridge);
  const candidates = [
    ...exposureReports.flatMap(actionsFromExposure),
    ...baselineReport ? actionsFromBaseline(baselineReport) : [],
    ...signals.map(signal => ({
      id: signal.id, source: "CROSS_SOURCE" as const,
      severity: "UNKNOWN" as const, title: signal.category,
      rationale: signal.explanation,
      recommendation: "Compare scope and collect independently verified evidence.",
      evidenceDigests: [bridge.digest],
      evidenceIds: [...signal.sourceEvidenceIds],
      rank: 0, confidence: "NOT_DETERMINED" as const,
      approvedByCustomer: false as const,
      executed: false as const, closed: false as const,
      independentlyValidated: false as const,
    })),
  ];
  const priorities = rankPriorities(candidates)
    .slice(0, input.maximumActions);
  const domainRows = domains(assessments, baseline);
  const sources: Phase2Portfolio["sources"] = [
    ...assessments.map(x => ({
      kind: "EXPOSURE" as const, digest: x.digest,
      snapshotId: x.snapshotId, domain: x.domain,
      status: "OFFLINE_OBSERVED" as const,
      realThirdPartyVerification: false as const,
    })),
    ...baseline ? [{
      kind: "BASELINE" as const, digest: baseline.digest,
      snapshotId: baseline.snapshotId, domain: null,
      status: "DECLARED" as const,
      realThirdPartyVerification: false as const,
    }] : [],
  ];
  const canonical = {
    schema: "cyberpilot.phase2.portfolio.v1" as const,
    organizationId: input.organizationId,
    snapshotId: input.snapshotId,
    evaluatedAt: input.evaluatedAt,
    sourceMode: "OFFLINE_ONLY" as const,
    sourceDigests: sources.map(x => x.digest),
    sources, exposureReports, baselineReport,
    bridge, priorities, domains: domainRows,
    overview: {
      domains: domainRows.length,
      exposureDomains: assessments.length,
      baselineQuestions: baseline?.expectedQuestions ?? 0,
      unknownControls: bridge.coverage.missingControls,
      potentialRiskCount: bridge.totalFindings,
      recommendedActions: priorities.length,
      technicalCoveragePercent: bridge.coverage.coveragePercent,
      score: null, label: "UNDETERMINED" as const,
      sourceCount: sources.length,
      noM365Required: true as const,
      containsLiveSecurityEvaluation: false as const,
      autoRemediationCount: 0 as const,
    },
    limitations: [
      "The portfolio operates only on caller-provided offline evidence.",
      "Third-party authorization is not independently established by the report.",
      "Baseline is a declarative questionnaire, not CIS certification.",
      "Missing sources and missing controls are UNKNOWN.",
      "No LIVE CyberScore or historical score is updated.",
      "Apparent remediation needs separate authorized verification.",
    ],
    links: linkSources(assessments, baseline),
    localIntegrityVerified: true as const,
    realProviderConsentVerified: false as const,
    customerApprovedDeployment: false as const,
    historicalCyberScoreUpdated: false as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyPhase2OfflinePortfolio(
  portfolio: Phase2Portfolio,
): Phase2PortfolioVerification {
  const { digest, ...canonical } = portfolio;
  const issues: string[] = [];
  const localDigestVerified = hash(canonical) === digest;
  if (!localDigestVerified) issues.push("PORTFOLIO_DIGEST_MISMATCH");
  const sourcesBound = portfolio.sources.every(source =>
    source.kind === "EXPOSURE" ?
      portfolio.exposureReports.some(x => x.assessmentDigest ===
        source.digest && x.snapshotId === source.snapshotId) :
      portfolio.baselineReport?.sourceDigest === source.digest &&
        portfolio.baselineReport.snapshotId === source.snapshotId);
  if (!sourcesBound) issues.push("SOURCE_PROVENANCE_MISMATCH");
  const tenantScoped = portfolio.sources.every(source =>
    source.kind === "BASELINE" ?
      portfolio.baselineReport?.organizationId ===
        portfolio.organizationId :
      portfolio.exposureReports.some(x =>
        x.snapshotId === source.snapshotId &&
        x.organizationId === portfolio.organizationId)) &&
    portfolio.bridge.organizationId === portfolio.organizationId;
  if (!tenantScoped) issues.push("TENANT_SCOPE_INVALID");
  const hasNoFalseScore =
    portfolio.overview.score === null &&
    portfolio.bridge.score.score === null &&
    portfolio.bridge.scoredFindings === 0 &&
    !portfolio.historicalCyberScoreUpdated &&
    portfolio.domains.every(d => !d.securityHealthy &&
      !d.certificationValid);
  if (!hasNoFalseScore) issues.push("FALSE_SCORE_OR_HEALTH_CLAIM");
  const hasNoLiveActivity =
    portfolio.sourceMode === "OFFLINE_ONLY" &&
    !portfolio.realProviderConsentVerified &&
    !portfolio.customerApprovedDeployment &&
    portfolio.overview.autoRemediationCount === 0 &&
    portfolio.exposureReports.every(x =>
      x.summary.noLIVEAccessPerformed);
  if (!hasNoLiveActivity) issues.push("UNSUPPORTED_LIVE_CLAIM");
  if (!verifyExposureBaselineV2Bridge(portfolio.bridge).valid)
    issues.push("MULTISOURCE_BRIDGE_INVALID");
  if (portfolio.baselineReport &&
      !verifyBaselineReportV2(portfolio.baselineReport).valid)
    issues.push("BASELINE_REPORT_INVALID");
  if (portfolio.exposureReports.some(x =>
    !verifyExposureReportV2(x).verified))
    issues.push("EXPOSURE_REPORT_INVALID");
  return {
    valid: issues.length === 0, issues,
    localDigestVerified, sourcesBound, tenantScoped,
    hasNoFalseScore, hasNoLiveActivity,
    independentExternalAuditPerformed: false,
  };
}
export function comparePhase2Portfolios(
  older: Phase2Portfolio,
  newer: Phase2Portfolio,
): Phase2PortfolioDelta {
  if (!verifyPhase2OfflinePortfolio(older).valid ||
      !verifyPhase2OfflinePortfolio(newer).valid ||
      older.organizationId !== newer.organizationId ||
      older.evaluatedAt >= newer.evaluatedAt)
    throw Error("Cannot compare cross-tenant or tampered Phase 2 portfolios.");
  const oldActions = new Set(older.priorities.map(x => x.id));
  const newActions = new Set(newer.priorities.map(x => x.id));
  const oldDomains = new Map(older.domains.map(x =>
    [x.domain, x]));
  const newDomains = new Map(newer.domains.map(x =>
    [x.domain, x]));
  return {
    organizationId: newer.organizationId,
    olderSnapshot: older.snapshotId,
    newerSnapshot: newer.snapshotId,
    coverageDelta: newer.overview.technicalCoveragePercent -
      older.overview.technicalCoveragePercent,
    sourceCountDelta: newer.sources.length - older.sources.length,
    newActions: [...newActions].filter(x =>
      !oldActions.has(x)),
    absentActions: [...oldActions].filter(x =>
      !newActions.has(x)),
    newUnknownDomains: [...newDomains].filter(([name, value]) =>
      value.unknown > (oldDomains.get(name)?.unknown ?? 0))
      .map(([name]) => name),
    apparentlyImprovedDomains: [...newDomains].filter(([name, value]) =>
      value.unknown < (oldDomains.get(name)?.unknown ?? 0))
      .map(([name]) => name),
    remediationProof: false, riskReductionExternallyValidated: false,
    legacyCyberScoreChanged: false,
  };
}
export function exportPhase2Portfolio(
  portfolio: Phase2Portfolio,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  if (!verifyPhase2OfflinePortfolio(portfolio).valid)
    throw Error("Cannot export unverifiable Phase 2 portfolio.");
  const output = format === "JSON" ?
    JSON.stringify(portfolio, null, 2) + "\n" :
    format === "CSV" ? [
      "source,priority,id,title,executed",
      ...portfolio.priorities.map(x => [
        x.source, x.severity, x.id,
        '"' + x.title.replaceAll('"', '""') + '"',
        "false",
      ].join(",")),
    ].join("\r\n") + "\r\n" :
    [
      "# CyberPilot Phase 2 — Offline Exposure and Baseline",
      "Organization: " + portfolio.organizationId,
      "Date: " + portfolio.evaluatedAt,
      "Sources: " + portfolio.overview.sourceCount,
      "CyberScore: UNDETERMINED",
      "Verified technical coverage: " +
        portfolio.overview.technicalCoveragePercent + "%",
      "",
      "## Prioritized follow-ups",
      ...portfolio.priorities.map(x =>
        "- " + x.title + ": " + x.recommendation),
      "",
      "## Limitations",
      ...portfolio.limitations.map(x => "- " + x),
    ].join("\n") + "\n";
  if (!["JSON", "CSV", "MARKDOWN"].includes(format))
    throw Error("Unsupported portfolio export format.");
  return {
    organizationId: portfolio.organizationId,
    snapshotId: portfolio.snapshotId,
    format, output,
    filename: "phase2-" + portfolio.snapshotId +
      (format === "JSON" ? ".json" :
        format === "CSV" ? ".csv" : ".md"),
    sha256: sha256V2(output),
    sourceDigest: portfolio.digest,
    certificationProvided: false as const,
    externalNetworkRequests: 0 as const,
    legacyCyberScoreWrites: 0 as const,
  };
}
