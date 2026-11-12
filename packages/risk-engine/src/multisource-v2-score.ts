import {
  type V2Coverage, type V2Finding, type V2Manifest,
  type V2RiskContribution, type V2Score,
  type V2Severity, type V2Confidence,
  type V2ControlSpec, type V2Evidence,
  defaultV2Controls, validateV2Manifest,
} from "./multisource-v2-contract";
import {
  computeV2Coverage, detectV2EvidenceConflicts,
} from "./multisource-v2-coverage";

/**
 * CyberScore v2 is a separate, explicitly versioned risk estimate.
 *
 * Core invariants:
 *   - No absent source becomes a passing control.
 *   - A synthetic fixture never results in a trusted numeric score.
 *   - Unverified and DECLARED signals never grant verified coverage.
 *   - Coverage and risk are separately visible.
 *   - No v1 stored scores are modified, read or migrated.
 *   - Unknown risk cannot inflate the security score.
 */
export type V2ModelPolicy = {
  modelId: "cyberpilot.multisource.v2";
  revision: 1;
  minimumCoveragePercent: number;
  minimumVerifiedControls: number;
  requireNonSyntheticSource: true;
  requireAuthenticatedSource: boolean;
  severityPoints: Record<V2Severity, number>;
  confidenceMultipliers: Record<V2Confidence, number>;
  domainRiskCaps: Record<string, number>;
  maximumRiskPoints: number;
  maximumPointsPerFinding: number;
  maximumFindingCount: number;
  maximumEvidenceAgeDays: number;
  missingCoverageLowerBoundMultiplier: number;
  permitHealthyBadge: false;
  changeHistoricalV1: false;
  acceptFixtureAsCustomerProof: false;
  allowUnknownAsSafe: false;
  assumeUnreportedSourcesHealthy: false;
};
export type V2ScoreEligibility = {
  schema: "cyberpilot.multisource.eligibility.v2";
  organizationId: string;
  evaluatedAt: string;
  coveragePercent: number;
  verifiedControls: number;
  minimumRequiredCoverage: number;
  enoughCoverage: boolean;
  nonSyntheticSources: string[];
  hasNonSynthetic: boolean;
  authenticatedSource: boolean;
  hasReliableControlEvidence: boolean;
  sourceConflicts: number;
  staleControls: number;
  missingControls: number;
  technicalEligible: boolean;
  issues: string[];
  warnings: string[];
  externalCustomerSignoffProven: false;
  v1ScoreRead: false;
};
export type V2FindingSelection = {
  accepted: V2Finding[];
  unsupported: V2Finding[];
  excluded: V2Finding[];
  duplicateIds: string[];
  missingEvidence: string[];
  ineligibleControls: string[];
  contradictions: string[];
  noAutomaticResolution: true;
};
export type V2ScoreDriver = {
  domain: string;
  verifiedCoverageWeight: number;
  requiredCoverageWeight: number;
  coveragePercent: number;
  risks: number;
  appliedRiskPoints: number;
  highSeverityFindings: number;
  unknownControls: number;
  missingTechnicalEvidence: number;
  certainty: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  canAssertHealthy: false;
  recommendedAction: string;
};
export type V2ScoreComparison = {
  schema: "cyberpilot.multisource.score.compare.v2";
  organizationId: string;
  modelId: "cyberpilot.multisource.v2";
  baselineDate: string;
  currentDate: string;
  previousScore: number | null;
  currentScore: number | null;
  numericDelta: number | null;
  deltaIsComparable: boolean;
  baselineCoverage: number;
  currentCoverage: number;
  coverageDelta: number;
  baselineRisk: number;
  currentRisk: number;
  newPotentialRisks: string[];
  absentFromCurrentAssessment: string[];
  persistentPotentialRisks: string[];
  newlyVerifiedControls: string[];
  newlyUncoveredControls: string[];
  explanatoryWarnings: string[];
  historicalV1ScoreTouched: false;
  remediationConfirmed: false;
  customerSecurityImprovementProven: false;
};
const severityDefault: Record<V2Severity, number> = {
  CRITICAL: 25, HIGH: 15, MEDIUM: 7,
  LOW: 3, INFO: 1, UNKNOWN: 0,
};
const confidenceDefault: Record<V2Confidence, number> = {
  HIGH: 1, MEDIUM: .75, LOW: .45, UNKNOWN: .2,
};
const domainsDefault: Record<string, number> = {
  IDENTITY: 30, EMAIL: 20, WEB: 18,
  ENDPOINT: 25, BACKUP: 25,
  GOVERNANCE: 18, EXPOSURE: 25,
};
const fixedPolicy: V2ModelPolicy = {
  modelId: "cyberpilot.multisource.v2",
  revision: 1,
  minimumCoveragePercent: 60,
  minimumVerifiedControls: 5,
  requireNonSyntheticSource: true,
  requireAuthenticatedSource: true,
  severityPoints: severityDefault,
  confidenceMultipliers: confidenceDefault,
  domainRiskCaps: domainsDefault,
  maximumRiskPoints: 100,
  maximumPointsPerFinding: 25,
  maximumFindingCount: 5000,
  maximumEvidenceAgeDays: 365,
  missingCoverageLowerBoundMultiplier: 1,
  permitHealthyBadge: false,
  changeHistoricalV1: false,
  acceptFixtureAsCustomerProof: false,
  allowUnknownAsSafe: false,
  assumeUnreportedSourcesHealthy: false,
};
export function defaultV2ModelPolicy(): V2ModelPolicy {
  return {
    ...fixedPolicy,
    severityPoints: { ...severityDefault },
    confidenceMultipliers: { ...confidenceDefault },
    domainRiskCaps: { ...domainsDefault },
  };
}
function range(value: unknown, name: string,
  min: number, max: number) {
  if (typeof value !== "number" ||
      !Number.isFinite(value) ||
      value < min || value > max)
    throw new Error("Invalid CyberScore v2 policy: " + name);
  return value;
}
function integer(value: unknown, name: string,
  min: number, max: number) {
  if (typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new Error("Invalid CyberScore v2 policy: " + name);
  return value;
}
export function parseV2ModelPolicy(
  raw: unknown = {},
): V2ModelPolicy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    throw new Error("CyberScore v2 policy must be an object.");
  const x = raw as Record<string, unknown>;
  const accepted = [
    "minimumCoveragePercent", "minimumVerifiedControls",
    "requireAuthenticatedSource", "maximumFindingCount",
  ];
  if (Object.keys(x).some(key => !accepted.includes(key)))
    throw new Error("CyberScore v2 policy override is not permitted.");
  if (x.requireAuthenticatedSource !== undefined &&
      x.requireAuthenticatedSource !== true)
    throw new Error("A real verified source is required for trusted scoring.");
  return {
    ...defaultV2ModelPolicy(),
    minimumCoveragePercent: x.minimumCoveragePercent === undefined ?
      fixedPolicy.minimumCoveragePercent :
        integer(x.minimumCoveragePercent, "minimum coverage", 60, 100),
    minimumVerifiedControls: x.minimumVerifiedControls === undefined ?
      fixedPolicy.minimumVerifiedControls :
        integer(x.minimumVerifiedControls, "minimum controls", 5, 100),
    maximumFindingCount: x.maximumFindingCount === undefined ?
      fixedPolicy.maximumFindingCount :
        integer(x.maximumFindingCount, "maximum findings", 1, 5000),
  };
}
export function v2RiskPointsForSeverity(
  severity: V2Severity,
  confidence: V2Confidence,
  policy: V2ModelPolicy = fixedPolicy,
) {
  const raw = policy.severityPoints[severity];
  const confidenceFactor = policy.confidenceMultipliers[confidence];
  if (!Number.isFinite(raw) ||
      !Number.isFinite(confidenceFactor))
    throw new Error("Cannot assign points to unknown severity.");
  return Math.round(raw * confidenceFactor * 100) / 100;
}
export function assessV2ScoreEligibility(
  manifest: V2Manifest, coverage: V2Coverage,
  policy: V2ModelPolicy = fixedPolicy,
): V2ScoreEligibility {
  if (!validateV2Manifest(manifest).valid)
    throw new Error("Score eligibility requires valid source manifest.");
  if (coverage.organizationId !== manifest.organizationId ||
      coverage.modelId !== manifest.modelId ||
      coverage.evaluatedAt !== manifest.evaluatedAt)
    throw new Error("Score eligibility source scope mismatch.");
  const nonSyntheticSources = [...new Set(manifest.evidence.filter(e =>
    e.verification !== "SYNTHETIC_FIXTURE").map(e => e.source))];
  const authenticatedSource = coverage.controls.some(c =>
    c.authenticatedLiveEvidence && c.verifiedForScoring);
  const enoughCoverage = coverage.coveragePercent >=
      policy.minimumCoveragePercent &&
    coverage.verifiedControls >= policy.minimumVerifiedControls;
  const hasReliableControlEvidence = coverage.controls.some(c =>
    c.verifiedForScoring);
  const issues: string[] = [];
  if (!enoughCoverage)
    issues.push("COVERAGE_BELOW_MINIMUM");
  if (!nonSyntheticSources.length)
    issues.push("ONLY_SYNTHETIC_OR_UNOBSERVED_EVIDENCE");
  if (!authenticatedSource)
    issues.push("NO_AUTHENTICATED_PROVIDER_EVIDENCE");
  if (!hasReliableControlEvidence)
    issues.push("NO_VERIFIED_CONTROL_EVIDENCE");
  if (coverage.conflicts)
    issues.push("SOURCE_CONFLICTS_REQUIRE_REVIEW");
  const technicalEligible = issues.length === 0;
  const warnings = [
    "An eligible v2 risk estimate is not a security certification.",
    "v2 is opt-in and never replaces stored historical v1 CyberScore.",
    "Partial coverage remains visible and unmeasured domains are UNKNOWN.",
    "A missing risk is not evidence that remediation succeeded.",
  ];
  if (coverage.coveragePercent < 100)
    warnings.push("Remaining unobserved controls reduce score confidence.");
  return {
    schema: "cyberpilot.multisource.eligibility.v2",
    organizationId: manifest.organizationId,
    evaluatedAt: manifest.evaluatedAt,
    coveragePercent: coverage.coveragePercent,
    verifiedControls: coverage.verifiedControls,
    minimumRequiredCoverage: policy.minimumCoveragePercent,
    enoughCoverage, nonSyntheticSources,
    hasNonSynthetic: nonSyntheticSources.length > 0,
    authenticatedSource,
    hasReliableControlEvidence,
    sourceConflicts: coverage.conflicts,
    staleControls: coverage.stale,
    missingControls: coverage.missingControls,
    technicalEligible, issues, warnings,
    externalCustomerSignoffProven: false,
    v1ScoreRead: false,
  };
}
function sameSubject(
  evidence: V2Evidence, finding: V2Finding,
) {
  return evidence.organizationId === finding.organizationId &&
    evidence.domain === finding.domain &&
    evidence.controlId === finding.controlId &&
    evidence.source === finding.source &&
    evidence.scope === finding.scope &&
    evidence.subjectHash === finding.subjectHash;
}
export function selectV2ScoreFindings(
  manifest: V2Manifest, coverage: V2Coverage,
  policy: V2ModelPolicy = fixedPolicy,
): V2FindingSelection {
  if (!validateV2Manifest(manifest).valid)
    throw new Error("Cannot select findings from invalid evidence.");
  const controls = new Map(coverage.controls.map(c =>
    [c.controlId, c]));
  const source = new Map(manifest.evidence.map(e =>
    [e.evidenceId, e]));
  const accepted: V2Finding[] = [];
  const unsupported: V2Finding[] = [];
  const excluded: V2Finding[] = [];
  const duplicateIds: string[] = [];
  const missingEvidence: string[] = [];
  const ineligibleControls: string[] = [];
  const contradictions: string[] = [];
  const seen = new Set<string>();
  for (const finding of manifest.findings.slice(0,
    policy.maximumFindingCount)) {
    const row = controls.get(finding.controlId);
    const key = [
      finding.ruleId, finding.domain,
      finding.controlId, finding.scope,
      finding.subjectHash,
    ].join("|");
    if (seen.has(key)) {
      duplicateIds.push(finding.findingId);
      excluded.push(finding);
      continue;
    }
    seen.add(key);
    if (finding.state !== "POTENTIAL_RISK" ||
        finding.severity === "UNKNOWN") {
      excluded.push(finding);
      continue;
    }
    if (!row || !row.verifiedForScoring) {
      ineligibleControls.push(finding.findingId);
      unsupported.push(finding);
      continue;
    }
    const linked = finding.evidenceIds.map(id =>
      source.get(id));
    if (linked.some(item => !item)) {
      missingEvidence.push(finding.findingId);
      unsupported.push(finding);
      continue;
    }
    if (linked.some(item => !sameSubject(item!, finding))) {
      contradictions.push(finding.findingId);
      unsupported.push(finding);
      continue;
    }
    if (!finding.evidenceIds.some(id =>
      row.verifiedEvidenceIds.includes(id))) {
      ineligibleControls.push(finding.findingId);
      unsupported.push(finding);
      continue;
    }
    accepted.push(finding);
  }
  if (manifest.findings.length > policy.maximumFindingCount)
    unsupported.push(...manifest.findings.slice(policy.maximumFindingCount));
  return {
    accepted, unsupported, excluded,
    duplicateIds, missingEvidence,
    ineligibleControls, contradictions,
    noAutomaticResolution: true,
  };
}
function domainCaps(policy: V2ModelPolicy) {
  return new Map(Object.entries(policy.domainRiskCaps));
}
function round(value: number) {
  return Math.round(value * 100) / 100;
}
export function calculateV2RiskContributions(
  manifest: V2Manifest, coverage: V2Coverage,
  policy: V2ModelPolicy = fixedPolicy,
): V2RiskContribution[] {
  const findings = selectV2ScoreFindings(
    manifest, coverage, policy);
  const caps = domainCaps(policy);
  const spent = new Map<string, number>();
  const controlSet = new Map(coverage.controls.map(c =>
    [c.controlId, c]));
  const ordered = findings.accepted.sort((a, b) =>
    v2RiskPointsForSeverity(b.severity, b.confidence, policy) -
      v2RiskPointsForSeverity(a.severity, a.confidence, policy) ||
    a.findingId.localeCompare(b.findingId));
  return ordered.map(finding => {
    const control = controlSet.get(finding.controlId)!;
    const riskWeight = policy.severityPoints[finding.severity];
    const confidenceMultiplier =
      policy.confidenceMultipliers[finding.confidence];
    const scopeMultiplier = control.scopeComplete ? 1 : 0;
    const rawPoints = round(Math.min(
      policy.maximumPointsPerFinding,
      riskWeight * confidenceMultiplier * scopeMultiplier));
    const cap = caps.get(finding.domain) ?? 0;
    const used = spent.get(finding.domain) ?? 0;
    const appliedPoints = round(Math.min(
      rawPoints, Math.max(0, cap - used)));
    spent.set(finding.domain, used + appliedPoints);
    const rationale = [
      "Severity " + finding.severity +
        " (" + riskWeight + " base points).",
      "Evidence confidence " + finding.confidence +
        " (" + confidenceMultiplier + " multiplier).",
      "Scoped verified control " + finding.controlId + ".",
      "Domain limit " + cap + " prevents duplicate risk inflation.",
      "Automated remediation and compliance are not inferred.",
    ].join(" ");
    return {
      key: finding.findingId, ruleId: finding.ruleId,
      severity: finding.severity, domain: finding.domain,
      source: finding.source, subjectHash: finding.subjectHash,
      evidenceIds: [...finding.evidenceIds],
      assessedControlIds: [finding.controlId],
      riskWeight, confidenceMultiplier, scopeMultiplier,
      rawPoints, appliedPoints,
      limitedByDomain: appliedPoints < rawPoints,
      confidence: finding.confidence, actionable: true,
      unverifiable: false, rationale,
    };
  });
}
function confidenceLabel(
  coverage: V2Coverage,
): V2Score["confidence"] {
  if (!coverage.verifiedControls) return "UNKNOWN";
  if (coverage.coveragePercent >= 95 &&
      coverage.conflicts === 0 &&
      coverage.errors === 0) return "HIGH";
  if (coverage.coveragePercent >= 80 &&
      coverage.conflicts === 0) return "MEDIUM";
  if (coverage.coveragePercent >= 60) return "LOW";
  return "UNKNOWN";
}
export function calculateMultiSourceCyberScoreV2(
  manifest: V2Manifest, policyRaw: unknown = {},
): V2Score {
  const modelPolicy = parseV2ModelPolicy(policyRaw);
  const validated = validateV2Manifest(manifest);
  if (!validated.valid)
    throw new Error("Refusing invalid, foreign or unsupported v2 evidence.");
  const coverage = computeV2Coverage(manifest);
  const eligibility = assessV2ScoreEligibility(
    manifest, coverage, modelPolicy);
  const selection = selectV2ScoreFindings(
    manifest, coverage, modelPolicy);
  const contributions = calculateV2RiskContributions(
    manifest, coverage, modelPolicy);
  const totalRisk = round(Math.min(
    modelPolicy.maximumRiskPoints,
    contributions.reduce((s, row) =>
      s + row.appliedPoints, 0)));
  const assessed = eligibility.technicalEligible;
  const preliminaryScore = Math.max(0,
    Math.min(100, Math.round(100 - totalRisk)));
  const unknownControls = coverage.controls.filter(c =>
    !c.verifiedForScoring).map(c => c.controlId);
  const riskOfMissingEvidence = Math.round(100 *
    (100 - coverage.coveragePercent) / 100);
  // Unknown scope cannot be counted as verified safety.
  // The interval is a communication aid, not a certification.
  const maxPossible = Math.max(0,
    preliminaryScore);
  const minPossible = Math.max(0,
    preliminaryScore - riskOfMissingEvidence);
  const status: V2Score["status"] =
    assessed ? "ASSESSED_WITH_LIMITATIONS" :
      coverage.verifiedControls === 0 ?
        "UNASSESSABLE" : "INSUFFICIENT_COVERAGE";
  const limitations = [
    ...eligibility.issues,
    ...eligibility.warnings,
    ...coverage.warnings,
  ];
  if (selection.unsupported.length)
    limitations.push("Unverified or inconsistent findings were excluded.");
  if (coverage.syntheticDataPresent)
    limitations.push("Synthetic evidence cannot score a real customer.");
  if (detectV2EvidenceConflicts(manifest).length)
    limitations.push("Conflicting sources must not be resolved automatically.");
  const topActions = selection.accepted
    .map(finding => {
      const points = contributions.find(c =>
        c.key === finding.findingId)?.appliedPoints ?? 0;
      return { finding, points };
    })
    .sort((a, b) => b.points - a.points ||
      a.finding.findingId.localeCompare(b.finding.findingId))
    .slice(0, 5)
    .map(({ finding, points }) => ({
      findingId: finding.findingId,
      title: finding.title,
      severity: finding.severity,
      rationale: finding.explanation +
        " Risk contribution: " + points + " points.",
      recommendation: finding.remediation,
      source: finding.source,
      evidenceIds: [...finding.evidenceIds],
      verifiedAction: false as const,
    }));
  return {
    schema: "cyberpilot.multisource.score.v2",
    organizationId: manifest.organizationId,
    modelId: "cyberpilot.multisource.v2",
    modelRevision: 1,
    evaluatedAt: manifest.evaluatedAt,
    score: assessed ? preliminaryScore : null,
    scoreRange: { min: minPossible, max: maxPossible },
    riskPoints: totalRisk,
    maximumRiskPoints: modelPolicy.maximumRiskPoints,
    coveragePercent: coverage.coveragePercent,
    adjustedRisk: round(totalRisk +
      modelPolicy.missingCoverageLowerBoundMultiplier *
      riskOfMissingEvidence),
    status, label: assessed ? "NOT_CERTIFIED" : "UNDETERMINED",
    confidence: confidenceLabel(coverage),
    contributions,
    unsupportedFindings: selection.unsupported.map(f =>
      f.findingId),
    unknownControls,
    excludedFindings: selection.excluded.map(f =>
      f.findingId),
    topActions,
    legacyScore: null,
    legacyCyberScoreRecomputed: false,
    eligibleForProductHealthBadge: false,
    modelMigrationCompleted: false,
    noVerifiedCustomerCompliance: true,
    limitations: [...new Set(limitations)],
  };
}
export function explainV2Score(
  score: V2Score, coverage: V2Coverage,
): V2ScoreDriver[] {
  if (score.organizationId !== coverage.organizationId ||
      score.modelId !== coverage.modelId ||
      score.evaluatedAt !== coverage.evaluatedAt)
    throw new Error("Cannot explain scoring from a different source.");
  return coverage.domains.map(domain => {
    const findings = score.contributions.filter(x =>
      x.domain === domain.domain);
    const missing = coverage.controls.filter(x =>
      x.domain === domain.domain && !x.verifiedForScoring);
    const risk = round(findings.reduce((sum, finding) =>
      sum + finding.appliedPoints, 0));
    return {
      domain: domain.domain,
      verifiedCoverageWeight: domain.verifiedWeight,
      requiredCoverageWeight: domain.weightTotal,
      coveragePercent: domain.coveragePercent,
      risks: findings.length, appliedRiskPoints: risk,
      highSeverityFindings: findings.filter(x =>
        x.severity === "CRITICAL" || x.severity === "HIGH").length,
      unknownControls: missing.length,
      missingTechnicalEvidence: missing.filter(x =>
        x.requirement === "TECHNICAL").length,
      certainty: domain.coveragePercent >= 95 &&
        !missing.length ? "HIGH" as const :
        domain.coveragePercent >= 80 ? "MEDIUM" as const :
        domain.coveragePercent >= 60 ? "LOW" as const :
        "UNKNOWN" as const,
      canAssertHealthy: false,
      recommendedAction: missing.length ?
        "Collect authorized fresh evidence for " +
          missing.map(x => x.controlId).slice(0, 3).join(", ") :
        risk > 0 ?
          "Review evidenced potential risks and validate remediation." :
          "Continue monitoring; zero findings is not security certification.",
    };
  });
}
export function compareV2Scores(
  previous: V2Score, current: V2Score,
): V2ScoreComparison {
  if (previous.organizationId !== current.organizationId ||
      previous.modelId !== current.modelId ||
      previous.modelRevision !== current.modelRevision)
    throw new Error("CyberScore v2 comparison requires same tenant and model revision.");
  if (previous.evaluatedAt > current.evaluatedAt)
    throw new Error("Cannot compare reversed score history.");
  const oldKeys = new Set(previous.contributions.map(x => x.key));
  const newKeys = new Set(current.contributions.map(x => x.key));
  const comparable = previous.score !== null &&
    current.score !== null &&
    previous.coveragePercent >= 60 &&
    current.coveragePercent >= 60;
  return {
    schema: "cyberpilot.multisource.score.compare.v2",
    organizationId: current.organizationId,
    modelId: current.modelId,
    baselineDate: previous.evaluatedAt,
    currentDate: current.evaluatedAt,
    previousScore: previous.score,
    currentScore: current.score,
    numericDelta: comparable ?
      current.score! - previous.score! : null,
    deltaIsComparable: comparable,
    baselineCoverage: previous.coveragePercent,
    currentCoverage: current.coveragePercent,
    coverageDelta: current.coveragePercent -
      previous.coveragePercent,
    baselineRisk: previous.riskPoints,
    currentRisk: current.riskPoints,
    newPotentialRisks: [...newKeys].filter(x =>
      !oldKeys.has(x)),
    absentFromCurrentAssessment: [...oldKeys].filter(x =>
      !newKeys.has(x)),
    persistentPotentialRisks: [...newKeys].filter(x =>
      oldKeys.has(x)),
    newlyVerifiedControls: [],
    newlyUncoveredControls: [],
    explanatoryWarnings: [
      "A numeric delta is not proof of remediation or improved security.",
      "Changing evidence coverage may affect numeric comparability.",
      "Historical CyberScore v1 remains intact and is not equivalent to v2.",
    ],
    historicalV1ScoreTouched: false,
    remediationConfirmed: false,
    customerSecurityImprovementProven: false,
  };
}
export function summarizeV2ScoreExecutive(
  score: V2Score, coverage: V2Coverage,
) {
  const breakdown = explainV2Score(score, coverage);
  return {
    organizationId: score.organizationId,
    model: score.modelId,
    revision: score.modelRevision,
    evaluatedAt: score.evaluatedAt,
    score: score.score,
    status: score.status,
    label: score.label,
    coveragePercent: score.coveragePercent,
    confidence: score.confidence,
    riskPoints: score.riskPoints,
    unassessedControls: score.unknownControls.length,
    topRisks: score.topActions,
    domainBreakdown: breakdown,
    caveats: [...score.limitations],
    message: score.score === null ?
      "Insufficient verified coverage to issue a v2 numeric estimate." :
      "Risk estimate with explicit coverage; it is not a certification.",
    customerComplianceCertified: false as const,
    historicalCyberScoreChanged: false as const,
    allSourcesEvaluated: false as const,
    actionableRemediationPerformed: false as const,
  };
}
