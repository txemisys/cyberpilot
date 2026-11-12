import { canonicalGoogleHash } from "./canonical-json";
import {
  runGooglePhase5AcceptanceMatrix,
  verifyGooglePhase5Matrix,
  summarizeGooglePhase5Acceptance,
  type Phase5AcceptanceMatrix,
  type Phase5AcceptanceDimension,
} from "./phase5-acceptance-matrix";
import { GOOGLE_LAB_SCENARIOS } from "./lab-scenarios";

/**
 * Technical A/B release decision is deliberately NOT customer acceptance.
 * It does not authorize merge, run external Google OAuth or update CyberScore.
 */
export type Phase5GateCode =
  "SCENARIO_MATRIX_COMPLETE" | "EVERY_CASE_TECHNICALLY_VALID" |
  "NO_BLOCKING_FINDINGS" | "REQUIRED_DIMENSIONS_COVERED" |
  "DIRECTORY_FIXTURE_FUNCTIONAL" | "REPORTS_FIXTURE_FUNCTIONAL" |
  "PERMISSION_DENIAL_CONSERVATIVE" | "QUOTA_BOUNDED" |
  "PAGINATION_TRUNCATION_EXPLICIT" | "MFA_AND_ADMIN_COVERAGE" |
  "DOMAIN_SIGNAL_PRESENT" | "PRIVACY_NOT_OVERRIDDEN" |
  "NO_EXTERNAL_GOOGLE_PROVIDER_CLAIM" | "NO_CUSTOMER_SIGNOFF" |
  "CANONICAL_CYBERSCORE_UNCHANGED" | "PROVENANCE_CHAIN_COMPLETE" |
  "TENANT_ISOLATION_MODELED" | "NO_ACCOUNT_MUTATIONS" |
  "NO_PROVIDER_SECRETS" | "REPORTS_NEUTRALIZED" |
  "HUMAN_APPROVAL_NOT_REQUIRED_FOR_DEVELOPMENT";
export type Phase5GateFinding = {
  code: Phase5GateCode;
  category: "AUTOMATED_ACCEPTANCE" |
    "SAFE_BOUNDARY" | "EVIDENCE_PROVENANCE" |
    "FEATURE_COMPLETENESS";
  state: "PASS" | "BLOCK" | "REVIEW";
  explanation: string;
  expected: string;
  actual: string;
  linkedDigests: string[];
  automaticallyAssessed: true;
  externalProviderAuthenticated: false;
};
export type Phase5GateSection = {
  id: "COLLECTION" | "SOURCE_SCOPE" | "RISK" |
    "REPORTING" | "CONSENT_BOUNDS" | "SECURITY" |
    "TECHNICAL_ACCEPTANCE" | "GITHUB_DECISION";
  title: string;
  state: "PASS" | "BLOCK" | "REVIEW";
  gateCodes: Phase5GateCode[];
  passing: number;
  blocking: number;
  review: number;
  explanation: string;
  owner: "AUTOMATED_TESTS" | "PROJECT" |
    "CUSTOMER_OPERATIONS";
  evidenceDigest: string;
  humanSignatureRequiredForOfflineDevelopment: false;
  customerOperationalSignoffProven: false;
};
export type Phase5DevelopmentGate = {
  schema: "cyberpilot.google.phase5.development.gate.v1";
  organizationId: string;
  generatedAt: string;
  evidenceMatrixDigest: string;
  requiredScenarioCount: number;
  executedScenarioCount: number;
  referenceScenarioIds: string[];
  sections: Phase5GateSection[];
  gates: Phase5GateFinding[];
  coverageSummary: {
    checks: number;
    passed: number;
    failed: number;
    review: number;
    dimensionsComplete: number;
    dimensionsRequired: number;
    testCasesComplete: number;
    testCasesRequired: number;
    sourceIsSynthetic: true;
    googleLiveChecksPerformed: 0;
    customerAccountChanges: 0;
    officialProviderClaims: 0;
  };
  outstanding: Array<{
    gateCode: Phase5GateCode;
    level: "BLOCK" | "REVIEW";
    description: string;
    nextAction: string;
    requiresRealTenantToCloseOfflineDevelopment: false;
  }>;
  developmentVerdict: "OFFLINE_A_B_PASS" |
    "OFFLINE_A_B_BLOCKED";
  offlineReadyToConsiderMerge: boolean;
  mergeAuthorizedAutomatically: false;
  mergePerformed: false;
  issueClosedAutomatically: false;
  customerDeploymentAccepted: false;
  externalGoogleVerified: false;
  oauthAdministratorConsentVerified: false;
  legalComplianceCertified: false;
  productionReadyClaimed: false;
  canonicalCyberScoreChanged: false;
  digest: string;
};
export type Phase5ReleaseManifest = {
  schema: "cyberpilot.google.phase5.release.manifest.v1";
  organizationId: string;
  generatedAt: string;
  matrixDigest: string;
  gateDigest: string;
  source: "AUTOMATED_OFFLINE_SYNTHETIC";
  scenarioIds: string[];
  totalAcceptanceChecks: number;
  failedAcceptanceChecks: number;
  technicalGatePassed: boolean;
  obligationsDeferredToLive: string[];
  evidenceIntegrityLocallyVerified: boolean;
  googleApiAuthenticated: false;
  googleAdminConsentReceived: false;
  humanRequiredToSignOffDevelopment: false;
  clientApprovalInvented: false;
  mergeAuthorizationGranted: false;
  deploymentToClientAuthorized: false;
  manifestDigest: string;
};
const categories: Record<Phase5GateSection["id"],
  Phase5GateCode[]> = {
  COLLECTION: [
    "DIRECTORY_FIXTURE_FUNCTIONAL",
    "REPORTS_FIXTURE_FUNCTIONAL",
    "QUOTA_BOUNDED",
    "PAGINATION_TRUNCATION_EXPLICIT",
  ],
  SOURCE_SCOPE: [
    "NO_EXTERNAL_GOOGLE_PROVIDER_CLAIM",
    "PERMISSION_DENIAL_CONSERVATIVE",
    "TENANT_ISOLATION_MODELED",
  ],
  RISK: [
    "MFA_AND_ADMIN_COVERAGE",
    "DOMAIN_SIGNAL_PRESENT",
    "CANONICAL_CYBERSCORE_UNCHANGED",
  ],
  REPORTING: [
    "REPORTS_NEUTRALIZED",
    "PRIVACY_NOT_OVERRIDDEN",
    "PROVENANCE_CHAIN_COMPLETE",
  ],
  CONSENT_BOUNDS: [
    "NO_CUSTOMER_SIGNOFF",
    "NO_PROVIDER_SECRETS",
    "NO_ACCOUNT_MUTATIONS",
  ],
  SECURITY: [
    "NO_EXTERNAL_GOOGLE_PROVIDER_CLAIM",
    "NO_PROVIDER_SECRETS",
    "CANONICAL_CYBERSCORE_UNCHANGED",
  ],
  TECHNICAL_ACCEPTANCE: [
    "SCENARIO_MATRIX_COMPLETE",
    "EVERY_CASE_TECHNICALLY_VALID",
    "NO_BLOCKING_FINDINGS",
    "REQUIRED_DIMENSIONS_COVERED",
    "HUMAN_APPROVAL_NOT_REQUIRED_FOR_DEVELOPMENT",
  ],
  GITHUB_DECISION: [
    "HUMAN_APPROVAL_NOT_REQUIRED_FOR_DEVELOPMENT",
    "NO_CUSTOMER_SIGNOFF",
    "NO_EXTERNAL_GOOGLE_PROVIDER_CLAIM",
  ],
};
const titles: Record<Phase5GateSection["id"], string> = {
  COLLECTION: "Directory and Reports offline execution",
  SOURCE_SCOPE: "Provider and organization boundaries",
  RISK: "Conservative risk and MFA interpretation",
  REPORTING: "Traceable executive and neutral evidence",
  CONSENT_BOUNDS: "Synthetic consent and account safety",
  SECURITY: "Security and secrets assertions",
  TECHNICAL_ACCEPTANCE: "Automated A/B development acceptance",
  GITHUB_DECISION: "Merge readiness distinct from product approval",
};
function gate(
  code: Phase5GateCode, ok: boolean,
  explanation: string, observed: unknown,
  matrix: Phase5AcceptanceMatrix,
  category: Phase5GateFinding["category"] =
    "AUTOMATED_ACCEPTANCE",
): Phase5GateFinding {
  return {
    code, category, state: ok ? "PASS" : "BLOCK",
    explanation, expected: "true",
    actual: String(observed),
    linkedDigests: [matrix.digest],
    automaticallyAssessed: true,
    externalProviderAuthenticated: false,
  };
}
function scenario(matrix: Phase5AcceptanceMatrix,
  name: string, requiredCheck?: string) {
  const item = matrix.cases.find(c => c.scenario === name);
  return !!item && item.technicalPassed &&
    (!requiredCheck || item.checks.some(g =>
      g.id === requiredCheck && g.state === "PASS"));
}
function dimension(matrix: Phase5AcceptanceMatrix,
  key: Phase5AcceptanceDimension) {
  return !!matrix.dimensions.find(d =>
    d.dimension === key && d.complete);
}
function sourceSet(matrix: Phase5AcceptanceMatrix) {
  return new Set(matrix.cases.map(c => c.scenario));
}
export function buildPhase5DevelopmentGate(
  matrix: Phase5AcceptanceMatrix,
): Phase5DevelopmentGate {
  if (!verifyGooglePhase5Matrix(matrix).valid)
    throw new Error("Phase 5 release gate requires authentic matrix evidence.");
  const unique = sourceSet(matrix);
  const expected = GOOGLE_LAB_SCENARIOS.map(s => s.id);
  const sourceValid = matrix.cases.every(c =>
    c.testedWithSyntheticProvider &&
    !c.independentLiveVerification &&
    c.writeOperations === 0 &&
    !c.bearerTokensStored &&
    !c.canonicalScoreModified);
  const gates: Phase5GateFinding[] = [
    gate("SCENARIO_MATRIX_COMPLETE",
      expected.every(id => unique.has(id)) &&
      matrix.scenarioCount === expected.length &&
      matrix.duplicateScenarios.length === 0,
      "All 17 separate provider failure modes are assessed.",
      matrix.scenarioCount, matrix, "FEATURE_COMPLETENESS"),
    gate("EVERY_CASE_TECHNICALLY_VALID",
      matrix.cases.every(c => c.technicalPassed),
      "Every fixture case passed its independently evaluated technical assertions.",
      matrix.cases.filter(c => c.technicalPassed).length, matrix),
    gate("NO_BLOCKING_FINDINGS",
      matrix.blockingFailures.length === 0 &&
      matrix.failed === 0,
      "A/B cannot close while a blocking test assertion is failing.",
      matrix.blockingFailures.length, matrix),
    gate("REQUIRED_DIMENSIONS_COVERED",
      matrix.dimensions.length === 15 &&
      matrix.dimensions.every(d => d.complete),
      "All required acceptance dimensions have positive evidence.",
      matrix.dimensions.filter(d => d.complete).length, matrix),
    gate("DIRECTORY_FIXTURE_FUNCTIONAL",
      scenario(matrix, "HEALTHY_REFERENCE",
        "REFERENCE_DIRECTORY") &&
      scenario(matrix, "PAGINATED_DIRECTORY",
        "PAGINATION_MULTI_PAGE"),
      "Directory synthetic users are collected and paginated correctly.",
      matrix.coverage.transport && matrix.coverage.pagination,
      matrix, "FEATURE_COMPLETENESS"),
    gate("REPORTS_FIXTURE_FUNCTIONAL",
      scenario(matrix, "HEALTHY_REFERENCE",
        "REFERENCE_REPORTS") &&
      scenario(matrix, "REPORTS_PARTIAL",
        "REPORTS_TRUNCATED"),
      "Login/Admin activity and partial report limitations are covered.",
      matrix.coverage.reports, matrix, "FEATURE_COMPLETENESS"),
    gate("PERMISSION_DENIAL_CONSERVATIVE",
      scenario(matrix, "PERMISSION_DENIED",
        "PERMISSION_403") &&
      scenario(matrix, "REPORTS_UNAVAILABLE",
        "REPORTS_403"),
      "Denied permissions become UNKNOWN or permission-required, never healthy.",
      matrix.coverage.permissions, matrix, "SAFE_BOUNDARY"),
    gate("QUOTA_BOUNDED",
      scenario(matrix, "QUOTA_THEN_RECOVER",
        "QUOTA_RETRY_RECOVERY") &&
      scenario(matrix, "QUOTA_EXHAUSTED",
        "QUOTA_EXHAUSTION") &&
      scenario(matrix, "TRANSPORT_TIMEOUT",
        "TRANSPORT_BOUNDED"),
      "Retries and quota exhaustion are bounded and conservatively recorded.",
      matrix.coverage.quota, matrix, "FEATURE_COMPLETENESS"),
    gate("PAGINATION_TRUNCATION_EXPLICIT",
      scenario(matrix, "PARTIAL_DIRECTORY",
        "PARTIAL_PAGE") &&
      scenario(matrix, "REPEATED_PAGE",
        "PAGE_CYCLE") &&
      scenario(matrix, "MALFORMED_PAGE",
        "MALFORMED_JSON"),
      "Cycles, truncation and malformed response are never silently accepted.",
      matrix.coverage.pagination, matrix, "SAFE_BOUNDARY"),
    gate("MFA_AND_ADMIN_COVERAGE",
      scenario(matrix, "MFA_GAPS",
        "MFA_OBSERVED_GAP") &&
      scenario(matrix, "UNKNOWN_MFA",
        "UNKNOWN_MFA_FIELDS") &&
      scenario(matrix, "SUSPENDED_ADMIN",
        "SUSPENDED_SUPERUSER") &&
      scenario(matrix, "ADMIN_RISK",
        "ADMIN_SUPERUSER_RISK"),
      "Privileged and MFA attributes are assessed without automatic remediation.",
      matrix.coverage.mfa && matrix.coverage.risk,
      matrix, "FEATURE_COMPLETENESS"),
    gate("DOMAIN_SIGNAL_PRESENT",
      scenario(matrix, "DOMAIN_UNVERIFIED",
        "DOMAIN_VERIFICATION"),
      "Directory domain verification is a candidate risk, not DNS certification.",
      matrix.coverage.risk, matrix, "FEATURE_COMPLETENESS"),
    gate("PRIVACY_NOT_OVERRIDDEN",
      dimension(matrix, "PRIVACY") && sourceValid,
      "No raw user emails, provider bearer tokens or IPs are exported as security evidence.",
      dimension(matrix, "PRIVACY"), matrix, "SAFE_BOUNDARY"),
    gate("NO_EXTERNAL_GOOGLE_PROVIDER_CLAIM",
      !matrix.realGoogleProviderValidated &&
      matrix.source === "SYNTHETIC_FIXTURE" &&
      matrix.cases.every(c => !c.independentLiveVerification),
      "Fixture tests cannot demonstrate real Google OAuth/API access.",
      matrix.realGoogleProviderValidated, matrix, "SAFE_BOUNDARY"),
    gate("NO_CUSTOMER_SIGNOFF",
      !matrix.customerOperationalApproval &&
      !matrix.legalCertificationPassed,
      "No business or legal approval may be inferred from CI.",
      matrix.customerOperationalApproval, matrix, "SAFE_BOUNDARY"),
    gate("CANONICAL_CYBERSCORE_UNCHANGED",
      !matrix.canonicalCyberScoreChanged &&
      matrix.cases.every(c => !c.canonicalScoreModified),
      "The Google preview never mutates historical CyberScore.",
      matrix.canonicalCyberScoreChanged, matrix, "SAFE_BOUNDARY"),
    gate("PROVENANCE_CHAIN_COMPLETE",
      dimension(matrix, "PROVENANCE") &&
      matrix.cases.every(c => c.sourceDigest.length === 64 &&
        c.journeyDigest.length === 64 && c.digest.length === 64),
      "Local source, journey and technical acceptance digests must exist.",
      dimension(matrix, "PROVENANCE"), matrix, "EVIDENCE_PROVENANCE"),
    gate("TENANT_ISOLATION_MODELED",
      dimension(matrix, "ISOLATION") &&
      matrix.coverage.tenantIsolation,
      "Source and normalized evidence remain scoped by organization.",
      matrix.coverage.tenantIsolation, matrix, "SAFE_BOUNDARY"),
    gate("NO_ACCOUNT_MUTATIONS",
      matrix.coverage.noAccountMutation &&
      matrix.cases.every(c => c.writeOperations === 0),
      "No customer account or Google API permission is modified.",
      matrix.coverage.noAccountMutation, matrix, "SAFE_BOUNDARY"),
    gate("NO_PROVIDER_SECRETS",
      !matrix.oauthTokensPersisted &&
      matrix.cases.every(c => !c.bearerTokensStored),
      "LAB mock credentials are never treated as provider secrets.",
      matrix.oauthTokensPersisted, matrix, "SAFE_BOUNDARY"),
    gate("REPORTS_NEUTRALIZED",
      matrix.coverage.executiveReport &&
      matrix.coverage.neutralEvidence &&
      dimension(matrix, "REPORT"),
      "Executive reporting and neutral controls are available without canonical scoring.",
      matrix.coverage.neutralEvidence, matrix, "FEATURE_COMPLETENESS"),
    gate("HUMAN_APPROVAL_NOT_REQUIRED_FOR_DEVELOPMENT",
      true, "A/B relies on automated technical evidence; customer approvals remain operational.",
      true, matrix, "SAFE_BOUNDARY"),
  ];
  const sections: Phase5GateSection[] = (
    Object.keys(categories) as Phase5GateSection["id"][]
  ).map(id => {
    const codes = categories[id];
    const checks = gates.filter(g => codes.includes(g.code));
    const blocking = checks.filter(c => c.state === "BLOCK").length;
    const review = checks.filter(c => c.state === "REVIEW").length;
    const canonical = {
      id, title: titles[id],
      state: blocking ? "BLOCK" as const :
        review ? "REVIEW" as const : "PASS" as const,
      gateCodes: codes, passing: checks.filter(c =>
        c.state === "PASS").length,
      blocking, review,
      explanation: blocking ?
        "Automated development acceptance has blocking evidence gaps." :
        "All local automated evidence checks in this section passed.",
      owner: id === "GITHUB_DECISION" ?
        "PROJECT" as const : "AUTOMATED_TESTS" as const,
      evidenceDigest: matrix.digest,
      humanSignatureRequiredForOfflineDevelopment: false as const,
      customerOperationalSignoffProven: false as const,
    };
    return canonical;
  });
  const outstanding = gates.filter(g =>
    g.state !== "PASS").map(g => ({
    gateCode: g.code,
    level: g.state === "BLOCK" ? "BLOCK" as const :
      "REVIEW" as const,
    description: g.explanation,
    nextAction: "Repair the failing fixture assertion and re-run the entire A/B matrix.",
    requiresRealTenantToCloseOfflineDevelopment: false as const,
  }));
  const pass = matrix.verdict === "OFFLINE_A_B_PASS" &&
    gates.every(g => g.state === "PASS");
  const canonical = {
    schema: "cyberpilot.google.phase5.development.gate.v1" as const,
    organizationId: matrix.organizationId,
    generatedAt: matrix.evaluatedAt,
    evidenceMatrixDigest: matrix.digest,
    requiredScenarioCount: expected.length,
    executedScenarioCount: matrix.cases.length,
    referenceScenarioIds: expected,
    sections, gates,
    coverageSummary: {
      checks: matrix.checks, passed: matrix.passed,
      failed: matrix.failed, review: matrix.review,
      dimensionsComplete: matrix.dimensions.filter(d =>
        d.complete).length,
      dimensionsRequired: matrix.dimensions.length,
      testCasesComplete: matrix.cases.filter(c =>
        c.technicalPassed).length,
      testCasesRequired: expected.length,
      sourceIsSynthetic: true as const,
      googleLiveChecksPerformed: 0 as const,
      customerAccountChanges: 0 as const,
      officialProviderClaims: 0 as const,
    },
    outstanding,
    developmentVerdict: pass ?
      "OFFLINE_A_B_PASS" as const : "OFFLINE_A_B_BLOCKED" as const,
    offlineReadyToConsiderMerge: pass,
    mergeAuthorizedAutomatically: false as const,
    mergePerformed: false as const,
    issueClosedAutomatically: false as const,
    customerDeploymentAccepted: false as const,
    externalGoogleVerified: false as const,
    oauthAdministratorConsentVerified: false as const,
    legalComplianceCertified: false as const,
    productionReadyClaimed: false as const,
    canonicalCyberScoreChanged: false as const,
  };
  return { ...canonical, digest: canonicalGoogleHash(canonical) };
}
export function verifyPhase5DevelopmentGate(
  report: Phase5DevelopmentGate,
  matrix?: Phase5AcceptanceMatrix,
) {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  if (canonicalGoogleHash(canonical) !== digest)
    issues.push("DEVELOPMENT_GATE_DIGEST_MISMATCH");
  if (report.developmentVerdict === "OFFLINE_A_B_PASS" &&
      (report.outstanding.length !== 0 ||
       report.coverageSummary.failed !== 0 ||
       report.gates.some(g => g.state !== "PASS")))
    issues.push("DEVELOPMENT_ACCEPTANCE_FALSE_POSITIVE");
  if (report.mergeAuthorizedAutomatically ||
      report.mergePerformed ||
      report.issueClosedAutomatically ||
      report.customerDeploymentAccepted ||
      report.externalGoogleVerified ||
      report.oauthAdministratorConsentVerified ||
      report.legalComplianceCertified ||
      report.productionReadyClaimed ||
      report.canonicalCyberScoreChanged)
    issues.push("UNAUTHORIZED_RELEASE_OR_CUSTOMER_ASSURANCE_CLAIM");
  if (report.coverageSummary.googleLiveChecksPerformed !== 0 ||
      report.coverageSummary.customerAccountChanges !== 0 ||
      !report.coverageSummary.sourceIsSynthetic)
    issues.push("TECHNICAL_GATE_CLAIMS_REAL_PROVIDER_ACTIONS");
  if (matrix && (!verifyGooglePhase5Matrix(matrix).valid ||
      matrix.digest !== report.evidenceMatrixDigest ||
      matrix.organizationId !== report.organizationId))
    issues.push("MATRIX_NOT_BOUND_TO_RELEASE_GATE");
  if (report.sections.length !== Object.keys(categories).length ||
      report.gates.length !== 21)
    issues.push("REQUIRED_GATE_SECTIONS_NOT_PRESENT");
  return { valid: issues.length === 0, issues };
}
export function phase5ReleaseManifest(
  report: Phase5DevelopmentGate,
): Phase5ReleaseManifest {
  if (!verifyPhase5DevelopmentGate(report).valid)
    throw new Error("Cannot produce manifest for invalid Phase5 release gate.");
  const canonical = {
    schema: "cyberpilot.google.phase5.release.manifest.v1" as const,
    organizationId: report.organizationId,
    generatedAt: report.generatedAt,
    matrixDigest: report.evidenceMatrixDigest,
    gateDigest: report.digest,
    source: "AUTOMATED_OFFLINE_SYNTHETIC" as const,
    scenarioIds: [...report.referenceScenarioIds],
    totalAcceptanceChecks: report.coverageSummary.checks,
    failedAcceptanceChecks: report.coverageSummary.failed,
    technicalGatePassed: report.offlineReadyToConsiderMerge,
    obligationsDeferredToLive: [
      "Real Google Workspace administrator OAuth consent",
      "Customer tenant membership and security permissions",
      "Edition-specific Reports, MFA and Directory availability",
      "External API quota, retention and service-level behavior",
      "Customer privacy, deletion, backup and legal obligations",
      "Formal product deployment readiness",
    ],
    evidenceIntegrityLocallyVerified: true,
    googleApiAuthenticated: false as const,
    googleAdminConsentReceived: false as const,
    humanRequiredToSignOffDevelopment: false as const,
    clientApprovalInvented: false as const,
    mergeAuthorizationGranted: false as const,
    deploymentToClientAuthorized: false as const,
  };
  return { ...canonical, manifestDigest:
    canonicalGoogleHash(canonical) };
}
export function verifyPhase5ReleaseManifest(
  manifest: Phase5ReleaseManifest,
  gate?: Phase5DevelopmentGate,
) {
  const { manifestDigest, ...canonical } = manifest;
  const issues: string[] = [];
  if (canonicalGoogleHash(canonical) !== manifestDigest)
    issues.push("RELEASE_MANIFEST_CONTENT_CHANGED");
  if (manifest.googleApiAuthenticated ||
      manifest.googleAdminConsentReceived ||
      manifest.clientApprovalInvented ||
      manifest.mergeAuthorizationGranted ||
      manifest.deploymentToClientAuthorized)
    issues.push("RELEASE_MANIFEST_FALSE_CUSTOMER_ASSURANCE");
  if (gate && (manifest.gateDigest !== gate.digest ||
      manifest.matrixDigest !== gate.evidenceMatrixDigest ||
      manifest.technicalGatePassed !==
        gate.offlineReadyToConsiderMerge))
    issues.push("RELEASE_MANIFEST_GATE_BINDING_INVALID");
  return { valid: issues.length === 0, issues };
}
export async function runPhase5DevelopmentAcceptance(
  raw: unknown = {},
) {
  const matrix = await runGooglePhase5AcceptanceMatrix(raw);
  const gate = buildPhase5DevelopmentGate(matrix);
  const manifest = phase5ReleaseManifest(gate);
  const verified =
    verifyGooglePhase5Matrix(matrix).valid &&
    verifyPhase5DevelopmentGate(gate, matrix).valid &&
    verifyPhase5ReleaseManifest(manifest, gate).valid;
  if (!verified)
    throw new Error("Google Phase5 technical A/B report is inconsistent.");
  return {
    matrix, gate, manifest,
    summary: summarizeGooglePhase5Acceptance(matrix),
    verified, technicalPass:
      gate.developmentVerdict === "OFFLINE_A_B_PASS",
    googleLiveAuthenticated: false as const,
    customerApproved: false as const,
    mergeAuthorized: false as const,
  };
}
