import {
  type ExposureAssessment, type ExposureControl,
  verifyExposureOfflineAssessment,
} from "./exposure-offline-v2";
import {
  type BaselineV2Assessment, verifyBaselineOfflineV2,
} from "./baseline-offline-v2";
import {
  type V2AdapterContext, type V2AdapterObservation,
  type V2AdapterBatch, type V2AdapterRawFinding,
  createV2AdapterBatch, buildV2Intake, assembleV2Intake,
} from "./multisource-v2-adapters";
import {
  type V2ControlSpec, type V2Source, type V2Domain,
  type V2Manifest, type V2Coverage, type V2Score,
  defaultV2Controls, canonicalV2,
} from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";
import { computeV2Coverage } from "./multisource-v2-coverage";
import { calculateMultiSourceCyberScoreV2 } from "./multisource-v2-score";
import {
  buildV2ExecutiveReport, type V2ExecutiveReport,
} from "./multisource-v2-report";

/**
 * Bridge from existing offline Exposure and declarative Baseline to
 * CyberScore v2. Its output is always synthetic/unverified, never a
 * claim of authenticated third-party collection or customer compliance.
 */
export type V2BridgeSource = {
  source: "EXPOSURE" | "BASELINE";
  inputDigest: string;
  inputSnapshotId: string;
  inputDate: string;
  domain: string | null;
  controlIds: string[];
  unresolvedControls: string[];
  originalFindings: number;
  projectedFindings: number;
  synthetic: boolean;
  authenticatedLIVE: false;
  promotedToVerified: false;
};
export type V2BridgeProjection = {
  schema: "cyberpilot.exposure.baseline.v2.bridge";
  organizationId: string;
  snapshotId: string;
  evaluatedAt: string;
  manifest: V2Manifest;
  coverage: V2Coverage;
  score: V2Score;
  report: V2ExecutiveReport;
  sources: V2BridgeSource[];
  limitations: string[];
  modeledExposureControls: number;
  modeledBaselineControls: number;
  pendingReviewControls: number;
  totalFindings: number;
  scoredFindings: 0;
  scoreAsRealCustomer: null;
  legacyCyberScoreModified: false;
  liveProviderAuthenticationAttempted: false;
  customerSignoffVerified: false;
  digest: string;
};
export type V2CrossSignal = {
  id: string;
  category: "CONFIRMATION_CANDIDATE" |
    "SOURCE_DISAGREEMENT" |
    "EXTERNAL_SCOPE_MISSING" | "BASELINE_SCOPE_MISSING";
  domain: V2Domain;
  controls: string[];
  sourceEvidenceIds: string[];
  sourceTypes: V2Source[];
  explanation: string;
  assessmentStatus: "REQUIRES_REVIEW";
  automaticallyReconciled: false;
  riskConfirmedByIndependentAuditor: false;
  changesCyberScore: false;
};
export type V2BridgeComparison = {
  schema: "cyberpilot.exposure.baseline.compare.v2";
  organizationId: string;
  olderId: string; newerId: string;
  sourceCountDelta: number;
  newUnassessedControls: string[];
  newPotentialFindings: string[];
  disappearedFindings: string[];
  coverageChange: number;
  scoreChange: null;
  apparentResolutionConfirmed: false;
  independentlyValidated: false;
  historicalV1Updated: false;
};
const exposureControls: Partial<Record<
  ExposureControl, string>> = {
  EMAIL_SPF: "EMAIL_SPF",
  EMAIL_DMARC: "EMAIL_DMARC",
  EMAIL_DKIM: "EMAIL_DKIM",
  WEB_TLS: "WEB_TLS",
  WEB_SECURITY_HEADERS: "WEB_SECURITY_HEADERS",
};
const baselineControlMap: Record<string, string> = {
  "inventory-hardware": "ENDPOINT_DEVICE_INVENTORY",
  "unknown-devices": "ENDPOINT_DEVICE_INVENTORY",
  "asset-owners": "ENDPOINT_DEVICE_INVENTORY",
  "account-inventory": "IDENTITY_USER_INVENTORY",
  "inactive-accounts": "IDENTITY_INACTIVE_ACCOUNTS",
  "mfa": "IDENTITY_PRIVILEGED_MFA",
  "admin-separation": "IDENTITY_PRIVILEGED_ROLES",
  "least-privilege": "GOVERNANCE_ACCESS_REVIEWS",
  "patch-inventory": "ENDPOINT_PATCH_POSTURE",
  "patch-deadlines": "ENDPOINT_PATCH_POSTURE",
  "endpoint-protection": "ENDPOINT_PROTECTION",
  "backups": "BACKUP_POLICY",
  "restore-tests": "BACKUP_RESTORE_TEST",
  "backup-protection": "BACKUP_POLICY",
  "incident-plan": "GOVERNANCE_INCIDENT_PLAN",
  "incident-exercises": "GOVERNANCE_INCIDENT_PLAN",
  "security-training": "GOVERNANCE_SECURITY_TRAINING",
  "security-reviews": "GOVERNANCE_ACCESS_REVIEWS",
  "email-protection": "EMAIL_DMARC",
  "network-inventory": "EXPOSURE_ASSET_DISCOVERY",
};
const severity: Record<string, V2AdapterRawFinding["severity"]> = {
  CRITICAL: "CRITICAL", HIGH: "HIGH",
  MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO",
  UNKNOWN: "UNKNOWN",
};
function validId(value: string) {
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function context(
  organizationId: string, snapshotId: string,
  evaluatedAt: string, source: "EXPOSURE" | "BASELINE",
  sourceDigest: string, scope: string,
  scopeKind: V2AdapterContext["scopeKind"],
  reportedCount: number,
): V2AdapterContext {
  return {
    organizationId, snapshotId, evaluatedAt,
    authority: source === "EXPOSURE" ?
      "passive-offline-evidence-import" :
      "organizational-declarative-diagnostic",
    sourceReference: source === "EXPOSURE" ?
      "exposure-offline-v2-bridge" : "baseline-offline-v2-bridge",
    sourceDigest, scope, scopeKind,
    expectedSubjects: null,
    observedSubjects: reportedCount,
    expectedPages: null, pagesRead: null,
    status: "UNASSESSED",
    providerAuthenticated: false,
    scopeAuthenticityVerified: false,
    sourceIsSynthetic: true,
    allowTechnicalProof: false,
    maxAgeDays: source === "EXPOSURE" ? 14 : 90,
  };
}
function observation(
  externalId: string, subjectId: string,
  control: V2ControlSpec, state: V2AdapterObservation["state"],
  evaluatedAt: string, scope: string,
  details: Record<string, string | number | boolean | null>,
  provenance: string,
): V2AdapterObservation {
  return {
    schema: "cyberpilot.multisource.adapter.observation.v2",
    externalId, subjectId, controlId: control.id,
    domain: control.domain, state,
    confidence: state === "OBSERVED" ?
      "LOW" : "UNKNOWN",
    observedAt: state === "OBSERVED" ? evaluatedAt : null,
    checkedAt: evaluatedAt, scope,
    details, provenance,
  };
}
function exposureBatch(
  result: ExposureAssessment, snapshotId: string,
  evaluatedAt: string, controls: V2ControlSpec[],
): { batch: V2AdapterBatch; summary: V2BridgeSource } {
  const eligibleControls = new Map(controls.filter(c =>
    c.acceptedSources.includes("EXPOSURE") &&
    c.scope === "DOMAIN").map(c => [c.id, c]));
  const contextData = context(
    result.organizationId, snapshotId, evaluatedAt,
    "EXPOSURE", result.digest, result.domain, "DOMAIN",
    result.checks.length);
  const observed: V2AdapterObservation[] = [];
  const findings: V2AdapterRawFinding[] = [];
  const missing: string[] = [];
  for (const check of result.checks) {
    const targetId = exposureControls[check.control];
    const target = targetId ? eligibleControls.get(targetId) : null;
    if (!target) {
      missing.push(check.control);
      continue;
    }
    // No unsupported or raw external identity is embedded.
    const externalId = "exp-" + sha256V2(
      result.organizationId + result.snapshotId +
      check.control).slice(0, 20);
    const state: V2AdapterObservation["state"] =
      check.state === "OBSERVED" ? "OBSERVED" :
      check.state === "ERROR" ? "ERROR" : "UNKNOWN";
    observed.push(observation(
      externalId, "domain-" + sha256V2(result.domain).slice(0, 16),
      target, state, evaluatedAt, result.domain, {
        importedOffline: true,
        sourceCount: check.sourceIds.length,
        observedButNotLive: check.state === "OBSERVED",
        candidateRiskCount: check.findings.length,
        sourceAuthenticityUnverified: true,
      }, "passive-offline-evidence-candidate"));
    for (const finding of check.findings) {
      findings.push({
        id: finding.id.replace(/[^A-Za-z0-9_.:-]/g, "_"),
        ruleId: "EXPOSURE_" + check.control,
        controlId: target.id, domain: target.domain,
        severity: severity[finding.severity] ?? "UNKNOWN",
        state: "POTENTIAL_RISK",
        title: finding.title,
        explanation: finding.rationale ||
          "Potential offline exposure requires external revalidation.",
        remediation: finding.recommendation,
        sourceId: externalId,
        subjectId: "domain-" + sha256V2(result.domain).slice(0, 16),
        observedAt: evaluatedAt, confidence: "LOW",
      });
    }
  }
  const batch = createV2AdapterBatch(
    "EXPOSURE", contextData, observed, findings);
  return {
    batch,
    summary: {
      source: "EXPOSURE", inputDigest: result.digest,
      inputSnapshotId: result.snapshotId,
      inputDate: result.assessedAt, domain: result.domain,
      controlIds: [...new Set(observed.map(x =>
        x.controlId))], unresolvedControls: missing,
      originalFindings: result.findings.length,
      projectedFindings: findings.length,
      synthetic: true, authenticatedLIVE: false,
      promotedToVerified: false,
    },
  };
}
function baselineBatch(
  result: BaselineV2Assessment, snapshotId: string,
  evaluatedAt: string, controls: V2ControlSpec[],
): { batch: V2AdapterBatch; summary: V2BridgeSource } {
  const eligible = new Map(controls.filter(c =>
    c.acceptedSources.includes("BASELINE") &&
    c.scope === "ORGANIZATION").map(c => [c.id, c]));
  const ctx = context(result.organizationId,
    snapshotId, evaluatedAt, "BASELINE",
    result.digest, "organization", "ORGANIZATION",
    result.evidence.length);
  const observations: V2AdapterObservation[] = [];
  const findings: V2AdapterRawFinding[] = [];
  const missing: string[] = [];
  const seen = new Set<string>();
  for (const answer of result.evidence) {
    const mapped = baselineControlMap[answer.questionId];
    const control = mapped ? eligible.get(mapped) : null;
    if (!control) {
      if (answer.answer !== "UNANSWERED") missing.push(answer.questionId);
      continue;
    }
    const externalId = "base-" + sha256V2(
      result.organizationId + result.snapshotId +
      answer.questionId).slice(0, 20);
    const state: V2AdapterObservation["state"] =
      answer.answer === "UNANSWERED" ||
      answer.answer === "UNKNOWN" ||
      answer.answer === "NOT_APPLICABLE" ?
        "UNKNOWN" : "DECLARED";
    const subject = "org-" + sha256V2(
      result.organizationId).slice(0, 16);
    observations.push(observation(
      externalId, subject, control, state,
      evaluatedAt, "organization", {
        selfDeclared: true,
        explicitNo: answer.answer === "NO",
        partial: answer.answer === "PARTIAL",
        positiveDeclaration: answer.answer === "YES",
        applicabilityUnverified: answer.answer === "NOT_APPLICABLE",
      }, "self-declaration-unverified"));
    seen.add(control.id);
    if (answer.answer === "NO" ||
        answer.answer === "PARTIAL") {
      findings.push({
        id: "declared-" + answer.questionId,
        ruleId: "BASELINE_DECLARED_" + answer.questionId.replace(
          /-/g, "_").toUpperCase(),
        controlId: control.id, domain: control.domain,
        severity: answer.priority === "CRITICAL" ?
          "CRITICAL" : answer.priority === "HIGH" ?
            "HIGH" : "MEDIUM",
        state: "REQUIRES_REVIEW",
        title: "Declared gap: " + answer.questionId,
        explanation: "Self-reported gap; technical status is not determined.",
        remediation: answer.guidance,
        sourceId: externalId, subjectId: subject,
        observedAt: evaluatedAt, confidence: "LOW",
      });
    }
  }
  const batch = createV2AdapterBatch(
    "BASELINE", ctx, observations, findings);
  return {
    batch,
    summary: {
      source: "BASELINE", inputDigest: result.digest,
      inputSnapshotId: result.snapshotId,
      inputDate: result.evaluatedAt, domain: null,
      controlIds: [...seen], unresolvedControls: missing,
      originalFindings: result.actions.filter(x =>
        x.priority !== "UNKNOWN").length,
      projectedFindings: findings.length,
      synthetic: true, authenticatedLIVE: false,
      promotedToVerified: false,
    },
  };
}
export function buildExposureBaselineV2Bridge(
  scope: { organizationId: string; snapshotId: string;
    evaluatedAt: string },
  exposure: readonly ExposureAssessment[],
  baseline: BaselineV2Assessment | null,
  controls: V2ControlSpec[] = defaultV2Controls(),
): V2BridgeProjection {
  if (!validId(scope.organizationId) ||
      !validId(scope.snapshotId) ||
      !Number.isFinite(Date.parse(scope.evaluatedAt)) ||
      exposure.length > 30)
    throw Error("Invalid or excessive bridge scope.");
  if (!exposure.length && !baseline)
    throw Error("At least one source is required for this bridge.");
  const batches: V2AdapterBatch[] = [];
  const sources: V2BridgeSource[] = [];
  const seenDomains = new Set<string>();
  for (const input of exposure) {
    if (!verifyExposureOfflineAssessment(input).valid ||
        input.organizationId !== scope.organizationId ||
        input.assessedAt > scope.evaluatedAt ||
        seenDomains.has(input.domain))
      throw Error("Invalid, foreign or duplicate Exposure source.");
    seenDomains.add(input.domain);
    const converted = exposureBatch(
      input, scope.snapshotId, scope.evaluatedAt, controls);
    batches.push(converted.batch);
    sources.push(converted.summary);
  }
  if (baseline) {
    if (!verifyBaselineOfflineV2(baseline).valid ||
        baseline.organizationId !== scope.organizationId ||
        baseline.evaluatedAt > scope.evaluatedAt)
      throw Error("Invalid or foreign Baseline source.");
    const converted = baselineBatch(
      baseline, scope.snapshotId, scope.evaluatedAt, controls);
    batches.push(converted.batch);
    sources.push(converted.summary);
  }
  const input = buildV2Intake({
    organizationId: scope.organizationId,
    snapshotId: scope.snapshotId,
    evaluatedAt: scope.evaluatedAt,
    authority: "phase2-offline-cross-source-bridge",
    sourceReference: "explicit-manifest",
    sourceDigest: sha256V2(
      sources.map(s => s.inputDigest).join("|")),
    scope: "organization", scopeKind: "ORGANIZATION",
    expectedSubjects: null, observedSubjects: null,
    expectedPages: null, pagesRead: null,
    status: "UNASSESSED",
    providerAuthenticated: false,
    scopeAuthenticityVerified: false,
    sourceIsSynthetic: true,
    allowTechnicalProof: false, maxAgeDays: 30,
  }, batches, controls);
  const intake = assembleV2Intake(input);
  const manifest = intake.manifest;
  const coverage = computeV2Coverage(manifest);
  const score = calculateMultiSourceCyberScoreV2(manifest);
  const report = buildV2ExecutiveReport(manifest);
  if (score.score !== null || coverage.verifiedControls !== 0 ||
      manifest.evidence.some(e =>
        e.verification === "TECHNICALLY_VERIFIED"))
    throw Error("Offline bridge must never promote evidence to LIVE.");
  const canonical = {
    schema: "cyberpilot.exposure.baseline.v2.bridge" as const,
    organizationId: scope.organizationId,
    snapshotId: scope.snapshotId,
    evaluatedAt: scope.evaluatedAt,
    manifest, coverage, score, report, sources,
    limitations: [
      "Exposure and Baseline were imported from offline inputs.",
      "A declared control or synthetic observation is not LIVE proof.",
      "Cross-source similarities do not certify remediation.",
      "The historical CyberScore v1 remains untouched.",
    ],
    modeledExposureControls: sources.filter(x =>
      x.source === "EXPOSURE").reduce((n, x) =>
      n + x.controlIds.length, 0),
    modeledBaselineControls: sources.filter(x =>
      x.source === "BASELINE").reduce((n, x) =>
      n + x.controlIds.length, 0),
    pendingReviewControls: coverage.missingControls,
    totalFindings: manifest.findings.length,
    scoredFindings: 0 as const, scoreAsRealCustomer: null,
    legacyCyberScoreModified: false as const,
    liveProviderAuthenticationAttempted: false as const,
    customerSignoffVerified: false as const,
  };
  return { ...canonical,
    digest: sha256V2(canonicalV2(canonical)) };
}
export function verifyExposureBaselineV2Bridge(
  output: V2BridgeProjection,
) {
  const { digest, ...canonical } = output;
  const issues: string[] = [];
  if (sha256V2(canonicalV2(canonical)) !== digest)
    issues.push("BRIDGE_DIGEST_MISMATCH");
  if (output.score.score !== null ||
      output.coverage.verifiedControls !== 0 ||
      output.scoredFindings !== 0 ||
      output.legacyCyberScoreModified ||
      output.liveProviderAuthenticationAttempted ||
      output.customerSignoffVerified)
    issues.push("FALSE_LIVE_OR_HISTORICAL_SCORE_CLAIM");
  if (output.sources.some(x =>
    x.promotedToVerified || x.authenticatedLIVE))
    issues.push("SOURCE_FALSIFIED");
  if (output.manifest.organizationId !== output.organizationId ||
      output.report.organizationId !== output.organizationId ||
      output.score.organizationId !== output.organizationId)
    issues.push("CROSS_TENANT_OUTPUT");
  return { valid: issues.length === 0, issues };
}
export function compareExposureBaselineV2Bridges(
  older: V2BridgeProjection, newer: V2BridgeProjection,
): V2BridgeComparison {
  if (!verifyExposureBaselineV2Bridge(older).valid ||
      !verifyExposureBaselineV2Bridge(newer).valid ||
      older.organizationId !== newer.organizationId ||
      older.evaluatedAt >= newer.evaluatedAt)
    throw Error("Invalid or cross-tenant bridge trend.");
  const before = new Set(older.manifest.findings.map(x =>
    x.findingId));
  const after = new Set(newer.manifest.findings.map(x =>
    x.findingId));
  const priorUnknown = new Set(older.coverage.controls.filter(x =>
    !x.verifiedForScoring).map(x => x.controlId));
  const nextUnknown = new Set(newer.coverage.controls.filter(x =>
    !x.verifiedForScoring).map(x => x.controlId));
  return {
    schema: "cyberpilot.exposure.baseline.compare.v2",
    organizationId: newer.organizationId,
    olderId: older.snapshotId, newerId: newer.snapshotId,
    sourceCountDelta: newer.sources.length - older.sources.length,
    newUnassessedControls: [...nextUnknown].filter(x =>
      !priorUnknown.has(x)),
    newPotentialFindings: [...after].filter(x => !before.has(x)),
    disappearedFindings: [...before].filter(x => !after.has(x)),
    coverageChange: newer.coverage.coveragePercent -
      older.coverage.coveragePercent,
    scoreChange: null, apparentResolutionConfirmed: false,
    independentlyValidated: false, historicalV1Updated: false,
  };
}
export function exposureBaselineV2CrossSignals(
  result: V2BridgeProjection,
): V2CrossSignal[] {
  if (!verifyExposureBaselineV2Bridge(result).valid)
    throw Error("Invalid cross-source bridge input.");
  const output: V2CrossSignal[] = [];
  const byControl = new Map<string, Set<V2Source>>();
  for (const observation of result.manifest.evidence) {
    const set = byControl.get(observation.controlId) ??
      new Set<V2Source>();
    set.add(observation.source);
    byControl.set(observation.controlId, set);
  }
  for (const [controlId, sourceIds] of byControl.entries()) {
    if (sourceIds.size < 2) continue;
    const evidence = result.manifest.evidence.filter(x =>
      x.controlId === controlId);
    const hasUnknown = evidence.some(e =>
      e.state === "UNKNOWN" || e.state === "ERROR");
    output.push({
      id: "cross-" + sha256V2(result.snapshotId +
        controlId).slice(0, 18),
      category: hasUnknown ? "SOURCE_DISAGREEMENT" :
        "CONFIRMATION_CANDIDATE",
      domain: evidence[0]!.domain, controls: [controlId],
      sourceEvidenceIds: evidence.map(x => x.evidenceId),
      sourceTypes: [...sourceIds],
      explanation: hasUnknown ?
        "One source has incomplete signals; compare scope and provenance." :
        "Multiple offline sources mention this control but do not verify it.",
      assessmentStatus: "REQUIRES_REVIEW",
      automaticallyReconciled: false,
      riskConfirmedByIndependentAuditor: false,
      changesCyberScore: false,
    });
  }
  return output;
}
