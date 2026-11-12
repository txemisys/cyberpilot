import { canonicalGoogleHash } from "./canonical-json";
import {
  GOOGLE_LAB_SCENARIOS,
  type GoogleLabScenarioName,
} from "./lab-scenarios";
import {
  runGoogleLabJourney, inspectGoogleLabJourney,
  googleLabJourneySummary,
  type GoogleLabJourneyResult,
} from "./lab-journey";

/**
 * Phase 5 A/B is technical, synthetic, repeatable and tenant neutral.
 * It does not fabricate customer consent, LIVE Google verification or
 * legal signoff. A failed matrix blocks A/B closure.
 */
export type Phase5AcceptanceDimension =
  "CONNECTOR" | "PAGINATION" | "QUOTA" |
  "PERMISSION" | "PARTIAL" | "MFA" |
  "ADMIN" | "AUDIT" | "DOMAIN" |
  "PRIVACY" | "REPORT" | "PROVENANCE" |
  "ISOLATION" | "SCORE" | "SAFETY";
export type Phase5AcceptanceLevel =
  "PASS" | "FAIL" | "REVIEW" | "EXCLUDED";
export type Phase5AcceptanceCheck = {
  id: string;
  dimension: Phase5AcceptanceDimension;
  state: Phase5AcceptanceLevel;
  description: string;
  observed: string;
  expected: string;
  sourceDigest: string;
  blocking: boolean;
  externallyAttested: false;
};
export type Phase5ScenarioAcceptance = {
  schema: "cyberpilot.google.phase5.scenario.acceptance.v1";
  organizationId: string;
  scenario: GoogleLabScenarioName;
  sourceDigest: string;
  journeyDigest: string;
  checkedAt: string;
  technicalPassed: boolean;
  testedWithSyntheticProvider: true;
  independentLiveVerification: false;
  writeOperations: 0;
  bearerTokensStored: false;
  canonicalScoreModified: false;
  capabilitiesIncomplete: number;
  possibleRisks: number;
  unknowns: number;
  requests: number;
  checks: Phase5AcceptanceCheck[];
  blockingFailures: string[];
  warnings: string[];
  digest: string;
};
export type Phase5AcceptanceMatrix = {
  schema: "cyberpilot.google.phase5.matrix.v1";
  organizationId: string;
  evaluatedAt: string;
  scenarioCount: number;
  cases: Phase5ScenarioAcceptance[];
  dimensions: Array<{
    dimension: Phase5AcceptanceDimension;
    total: number;
    passed: number;
    failed: number;
    review: number;
    excluded: number;
    complete: boolean;
    sourceDigests: string[];
  }>;
  checks: number;
  passed: number;
  failed: number;
  review: number;
  excluded: number;
  blockingFailures: string[];
  missingScenarios: GoogleLabScenarioName[];
  duplicateScenarios: string[];
  coverage: {
    transport: boolean;
    pagination: boolean;
    quota: boolean;
    permissions: boolean;
    mfa: boolean;
    reports: boolean;
    risk: boolean;
    executiveReport: boolean;
    neutralEvidence: boolean;
    tenantIsolation: boolean;
    noAccountMutation: boolean;
    noLiveProviderClaim: boolean;
  };
  verdict: "OFFLINE_A_B_PASS" | "OFFLINE_A_B_BLOCKED";
  source: "SYNTHETIC_FIXTURE";
  realGoogleProviderValidated: false;
  customerOperationalApproval: false;
  legalCertificationPassed: false;
  canonicalCyberScoreChanged: false;
  oauthTokensPersisted: false;
  digest: string;
};
const mandatory: Phase5AcceptanceDimension[] = [
  "CONNECTOR", "PAGINATION", "QUOTA", "PERMISSION",
  "PARTIAL", "MFA", "ADMIN", "AUDIT", "DOMAIN",
  "PRIVACY", "REPORT", "PROVENANCE", "ISOLATION",
  "SCORE", "SAFETY",
];
function check(
  scenario: GoogleLabJourneyResult,
  id: string,
  dimension: Phase5AcceptanceDimension,
  passed: boolean,
  description: string,
  observed: string,
  expected: string,
  blocking = true,
): Phase5AcceptanceCheck {
  return {
    id, dimension, state: passed ? "PASS" :
      blocking ? "FAIL" : "REVIEW",
    description, observed, expected,
    sourceDigest: scenario.digest,
    blocking,
    externallyAttested: false,
  };
}
function allObserved(run: GoogleLabJourneyResult,
  resource: string) {
  return run.collection.resourceCollections.find(x =>
    x.resource === resource);
}
function failure(run: GoogleLabJourneyResult,
  category: string, resource?: string) {
  return run.collection.failures.some(x =>
    x.category === category &&
    (!resource || x.resource === resource));
}
function flag(run: GoogleLabJourneyResult,
  name: string) {
  return run.assessment.findings.some(x =>
    x.ruleId === name);
}
function enough(run: GoogleLabJourneyResult) {
  return run.neutral.controls.length > 0 &&
    run.report.sections.length === 11 &&
    run.assessment.evidence.length > 0;
}
function scenarioSpecific(
  run: GoogleLabJourneyResult,
): Phase5AcceptanceCheck[] {
  const out: Phase5AcceptanceCheck[] = [];
  const add = (id: string, dimension: Phase5AcceptanceDimension,
    passed: boolean, description: string,
    observed: string, expected: string) =>
    out.push(check(run, id, dimension, passed,
      description, observed, expected));
  const users = run.collection.observation.users.length;
  const directory = allObserved(run, "USERS");
  const login = allObserved(run, "LOGIN_AUDIT");
  const admin = allObserved(run, "ADMIN_AUDIT");
  switch (run.scenario) {
    case "HEALTHY_REFERENCE":
      add("REFERENCE_DIRECTORY", "CONNECTOR",
        users === 3 && !directory?.truncated,
        "Complete reference fixture returns three synthetic users.",
        String(users), "3");
      add("REFERENCE_REPORTS", "AUDIT",
        run.collection.observation.reports.length === 3 &&
        login?.permissionAvailable === true &&
        admin?.permissionAvailable === true,
        "Both Reports resources expose synthetic events.",
        String(run.collection.observation.reports.length), "3");
      add("REFERENCE_NO_FALSE_SCORE", "SCORE",
        run.assessment.score.score === null,
        "Synthetic evidence cannot produce a canonical or trusted score.",
        String(run.assessment.score.score), "null");
      break;
    case "MFA_GAPS":
      add("MFA_OBSERVED_GAP", "MFA",
        flag(run, "SUPERADMIN_2SV_NOT_ENROLLED"),
        "Observed missing superadmin enrollment is a potential risk.",
        String(flag(run, "SUPERADMIN_2SV_NOT_ENROLLED")), "true");
      add("MFA_NO_ACTION", "SAFETY",
        run.assessment.accountWrites === 0,
        "Risk analysis never changes MFA state.",
        String(run.assessment.accountWrites), "0");
      break;
    case "ADMIN_RISK":
      add("ADMIN_SUPERUSER_RISK", "ADMIN",
        flag(run, "SUPERADMIN_2SV_NOT_ENROLLED") &&
        flag(run, "SUPERADMIN_2SV_NOT_ENFORCED"),
        "Superadministrator risk uses observed 2SV flags.",
        String(run.assessment.counts.possibleRisks),
        "At least two privileged signals");
      add("ADMIN_OLD_LOGIN", "ADMIN",
        flag(run, "STALE_ACTIVE_IDENTITY"),
        "Old login is signaled without claiming compromise.",
        String(flag(run, "STALE_ACTIVE_IDENTITY")), "true");
      break;
    case "PAGINATED_DIRECTORY":
      add("PAGINATION_MULTI_PAGE", "PAGINATION",
        (directory?.pagesRead ?? 0) >= 4 &&
        users === 9 && !directory?.truncated,
        "Paged users collection must be bounded and complete.",
        String(directory?.pagesRead ?? 0) + " pages " + users + " users",
        ">=4 pages, 9 users");
      add("PAGINATION_NO_DUPLICATE", "PAGINATION",
        new Set(run.collection.observation.users.map(x => x.id))
          .size === users,
        "Repeated user identifiers may not pass ingestion.",
        String(users), "unique");
      break;
    case "PERMISSION_DENIED":
      add("PERMISSION_403", "PERMISSION",
        failure(run, "PERMISSION", "USERS") &&
        run.collection.observation.coverage.DIRECTORY_USERS ===
          "REQUIRES_PERMISSION",
        "403 must become an explicit permission gap.",
        run.collection.observation.coverage.DIRECTORY_USERS,
        "REQUIRES_PERMISSION");
      add("PERMISSION_NO_HEALTH", "SCORE",
        run.assessment.score.score === null,
        "Denied Directory is not a healthy posture.",
        String(run.assessment.score.score), "null");
      break;
    case "QUOTA_THEN_RECOVER":
      add("QUOTA_RETRY_RECOVERY", "QUOTA",
        run.fixtureTrace.some(x => x.status === 429) &&
        users === 3 && !directory?.truncated,
        "A bounded 429 must recover when the fixture becomes available.",
        String(run.fixtureTrace.filter(x => x.status === 429).length),
        ">=1 retry and complete users");
      break;
    case "QUOTA_EXHAUSTED":
      add("QUOTA_EXHAUSTION", "QUOTA",
        failure(run, "QUOTA", "USERS") &&
        run.collection.observation.unknownCapabilities
          .includes("DIRECTORY_USERS"),
        "Repeated 429 must preserve UNKNOWN coverage.",
        String(run.collection.observation.unknownCapabilities
          .includes("DIRECTORY_USERS")), "true");
      break;
    case "PARTIAL_DIRECTORY":
      add("PARTIAL_PAGE", "PARTIAL",
        (directory?.pagesRead ?? 0) >= 1 &&
        directory?.truncated === true,
        "A second-page error must not erase first-page evidence.",
        String(directory?.pagesRead ?? 0), ">=1 with truncation");
      break;
    case "REPORTS_UNAVAILABLE":
      add("REPORTS_403", "AUDIT",
        failure(run, "PERMISSION", "LOGIN_AUDIT") &&
        failure(run, "PERMISSION", "ADMIN_AUDIT"),
        "Reports API permissions are independently assessed.",
        String(run.collection.failures.length),
        "Login and Admin 403");
      add("REPORTS_KEEP_USERS", "CONNECTOR",
        users === 3,
        "Reports refusal must not erase valid Directory users.",
        String(users), "3");
      break;
    case "REPORTS_PARTIAL":
      add("REPORTS_TRUNCATED", "AUDIT",
        login?.truncated === true &&
        (login.pagesRead ?? 0) >= 1,
        "A partial activity feed is not fully observed.",
        String(login?.truncated), "true");
      break;
    case "UNKNOWN_MFA":
      add("UNKNOWN_MFA_FIELDS", "MFA",
        flag(run, "UNKNOWN_MFA_SIGNAL") &&
        run.assessment.counts.usersWithUnknownMfa > 0,
        "Missing MFA attributes are UNKNOWN rather than healthy.",
        String(run.assessment.counts.usersWithUnknownMfa), ">0");
      break;
    case "SUSPENDED_ADMIN":
      add("SUSPENDED_SUPERUSER", "ADMIN",
        flag(run, "SUPERADMIN_SUSPENDED_CONFLICT") &&
        !flag(run, "SUPERADMIN_2SV_NOT_ENROLLED"),
        "Suspended superadmin requires review, not active account action.",
        String(flag(run, "SUPERADMIN_SUSPENDED_CONFLICT")), "true");
      break;
    case "NO_IDENTITIES":
      add("EMPTY_POPULATION", "PARTIAL",
        users === 0 &&
        run.assessment.score.score === null,
        "No returned users does not prove the tenant has no identities.",
        String(users), "0, score null");
      break;
    case "MALFORMED_PAGE":
      add("MALFORMED_JSON", "PARTIAL",
        failure(run, "MALFORMED", "USERS") &&
        directory?.truncated === true,
        "Malformed page must be rejected without claiming coverage.",
        String(failure(run, "MALFORMED", "USERS")), "true");
      break;
    case "REPEATED_PAGE":
      add("PAGE_CYCLE", "PAGINATION",
        failure(run, "PARTIAL", "USERS") &&
        directory?.truncated === true,
        "Repeated page token must stop with partial coverage.",
        String(directory?.truncated), "true");
      break;
    case "TRANSPORT_TIMEOUT":
      add("TRANSPORT_BOUNDED", "QUOTA",
        failure(run, "TRANSPORT", "USERS") &&
        run.fixtureTrace.filter(t => t.resource === "USERS")
          .length <= run.transportPolicy.maxRetriesPerPage + 1,
        "Transient failures must obey retry budget.",
        String(run.fixtureTrace.length), "<= bounded");
      break;
    case "DOMAIN_UNVERIFIED":
      add("DOMAIN_VERIFICATION", "DOMAIN",
        flag(run, "DOMAIN_UNVERIFIED"),
        "Google Directory unverified domain flag is a potential risk.",
        String(flag(run, "DOMAIN_UNVERIFIED")), "true");
      break;
  }
  return out;
}
export function evaluateGoogleScenarioAcceptance(
  run: GoogleLabJourneyResult,
): Phase5ScenarioAcceptance {
  const checks: Phase5AcceptanceCheck[] = [];
  const add = (id: string, dimension: Phase5AcceptanceDimension,
    passed: boolean, description: string, observed: string,
    expected: string, blocking = true) =>
    checks.push(check(run, id, dimension, passed,
      description, observed, expected, blocking));
  add("JOURNEY_INTEGRITY", "PROVENANCE",
    inspectGoogleLabJourney(run).valid,
    "Recompute digest and verify assessment/report/neutral source.",
    String(inspectGoogleLabJourney(run).valid), "true");
  add("SOURCE_TENANT", "ISOLATION",
    run.organizationId === run.collection.organizationId &&
    run.neutral.organizationId === run.organizationId,
    "All data must belong to a single requested organization.",
    run.organizationId, "matching organization");
  add("PROVIDER_NEVER_CONTACTED", "SAFETY",
    !run.collection.providerContacted &&
    run.diagnostics.externalApiRequests === 0,
    "Fixture never reaches the Google Admin SDK.",
    String(run.collection.providerContacted), "false");
  add("NO_ACCOUNT_ACTION", "SAFETY",
    run.assessment.accountWrites === 0 &&
    run.collection.accountWrites === 0,
    "No account mutation can be performed by a mock.",
    String(run.collection.accountWrites), "0");
  add("NO_CUSTOMER_CLAIM", "SAFETY",
    !run.report.customerCertified &&
    !run.assessment.customerLegalApproval &&
    !run.neutral.exportRestrictions.customerAcceptanceVerified,
    "Offline software cannot replace customer acceptance.",
    String(run.report.customerCertified), "false");
  add("NO_CANONICAL_CYBERSCORE", "SCORE",
    run.assessment.score.score === null &&
    !run.assessment.score.cyberScoreUpdated &&
    !run.neutral.summary.canonicalScoreUpdated,
    "Fixture posture score remains unset and CyberScore unchanged.",
    String(run.assessment.score.score), "null");
  add("SOURCE_CLASS_FIXTURE", "PROVENANCE",
    run.collection.observation.source === "SYNTHETIC_FIXTURE" &&
    run.neutral.sourceClass === "SYNTHETIC_FIXTURE",
    "Google fixtures remain separate from LIVE M365 and Google.",
    run.collection.observation.source, "SYNTHETIC_FIXTURE");
  add("RISK_REPORT_COMPLETE", "REPORT",
    enough(run) && run.report.summary.previewScore === null,
    "Create a report and neutral controls without claiming health.",
    String(run.report.sections.length), "11 sections");
  add("NO_PII_IN_REPORT", "PRIVACY",
    !run.report.sourceEmailsExported &&
    !run.report.sourceTokensExported &&
    !run.neutral.exportRestrictions.rawEmailIncluded &&
    !run.neutral.exportRestrictions.oauthCredentialIncluded,
    "No raw identities or credentials in the exported report.",
    "all false", "all false");
  add("BOUNDED_TRANSPORT", "QUOTA",
    run.fixtureTrace.length <=
      run.transportPolicy.maxTotalRequests,
    "The request budget bounds synthetic transport.",
    String(run.fixtureTrace.length),
    String(run.transportPolicy.maxTotalRequests));
  add("UNCERTAINTY_PRESERVED", "PARTIAL",
    run.collection.observation.unknownCapabilities.every(c =>
      run.assessment.coverage.some(x => x.capability === c &&
        !x.scoreEligible)),
    "Partial provider capabilities cannot yield a trusted assessment.",
    String(run.collection.observation.unknownCapabilities.length),
    "no eligible UNKNOWN capabilities");
  add("TRACE_REDACTED", "PRIVACY",
    run.fixtureTrace.every(x => !x.bearerTokenLogged &&
      !x.rawAuthorizationHeadersLogged),
    "No Authorization credentials can appear in fixture traces.",
    "all redacted", "all redacted");
  checks.push(...scenarioSpecific(run));
  const blockingFailures = checks.filter(x =>
    x.blocking && x.state === "FAIL").map(x => x.id);
  const canonical = {
    schema: "cyberpilot.google.phase5.scenario.acceptance.v1" as const,
    organizationId: run.organizationId,
    scenario: run.scenario, sourceDigest: run.sourceDigest,
    journeyDigest: run.digest, checkedAt: run.checkedAt,
    technicalPassed: blockingFailures.length === 0,
    testedWithSyntheticProvider: true as const,
    independentLiveVerification: false as const,
    writeOperations: 0 as const,
    bearerTokensStored: false as const,
    canonicalScoreModified: false as const,
    capabilitiesIncomplete:
      run.diagnostics.partialCapabilities,
    possibleRisks: run.diagnostics.potentialRisks,
    unknowns: run.assessment.counts.unknownFindings,
    requests: run.diagnostics.requests, checks,
    blockingFailures,
    warnings: [
      "All observations originate from synthetic fixture data.",
      "A/B closure verifies development only, not customer deployment.",
      "Google Workspace OAuth consent and actual API behavior were not exercised.",
    ],
  };
  return { ...canonical, digest: canonicalGoogleHash(canonical) };
}
export function verifyGoogleScenarioAcceptance(
  report: Phase5ScenarioAcceptance,
) {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  if (canonicalGoogleHash(canonical) !== digest)
    issues.push("SCENARIO_ACCEPTANCE_DIGEST_MISMATCH");
  if (!report.testedWithSyntheticProvider ||
      report.independentLiveVerification ||
      report.writeOperations !== 0 ||
      report.bearerTokensStored ||
      report.canonicalScoreModified)
    issues.push("FALSE_LIVE_OR_CREDENTIAL_ASSURANCE");
  if (report.technicalPassed !==
      !report.checks.some(c => c.blocking && c.state === "FAIL"))
    issues.push("SCENARIO_VERDICT_MISMATCH");
  if (report.checks.some(c =>
    c.sourceDigest !== report.journeyDigest ||
    c.externallyAttested))
    issues.push("SCENARIO_GATE_UNTRUSTED_REFERENCE");
  if (report.blockingFailures.join("|") !==
      report.checks.filter(c => c.blocking &&
        c.state === "FAIL").map(c => c.id).join("|"))
    issues.push("SCENARIO_FAILURE_REGISTER_MISMATCH");
  return { valid: issues.length === 0, issues };
}
export function buildGooglePhase5Matrix(
  organizationId: string,
  at: string, cases: Phase5ScenarioAcceptance[],
): Phase5AcceptanceMatrix {
  if (!Array.isArray(cases) || cases.length > 40)
    throw new Error("Phase 5 acceptance scenario count out of range.");
  if (cases.some(c => c.organizationId !== organizationId ||
      !verifyGoogleScenarioAcceptance(c).valid))
    throw new Error("Invalid or cross-tenant Google acceptance case.");
  const actual = new Set(cases.map(c => c.scenario));
  const missingScenarios = GOOGLE_LAB_SCENARIOS.filter(c =>
    !actual.has(c.id)).map(c => c.id);
  const duplicates = cases.map(c => c.scenario).filter(
    (scenario, index, all) => all.indexOf(scenario) !== index);
  const dimensions = mandatory.map(dimension => {
    const checks = cases.flatMap(c => c.checks).filter(c =>
      c.dimension === dimension);
    const passed = checks.filter(c => c.state === "PASS").length;
    const failed = checks.filter(c => c.state === "FAIL").length;
    const review = checks.filter(c => c.state === "REVIEW").length;
    const excluded = checks.filter(c => c.state === "EXCLUDED").length;
    return {
      dimension, total: checks.length,
      passed, failed, review, excluded,
      complete: checks.length > 0 && failed === 0,
      sourceDigests: [...new Set(checks.map(c =>
        c.sourceDigest))],
    };
  });
  const checks = cases.flatMap(c => c.checks);
  const blockingFailures = cases.flatMap(c =>
    c.blockingFailures.map(issue => c.scenario + ":" + issue));
  const ready = missingScenarios.length === 0 &&
    duplicates.length === 0 &&
    blockingFailures.length === 0 &&
    dimensions.every(d => d.complete) &&
    cases.every(c => c.technicalPassed);
  const capability = (
    scenario: GoogleLabScenarioName,
  ) => cases.some(c => c.scenario === scenario && c.technicalPassed);
  const coverage = {
    transport: capability("HEALTHY_REFERENCE"),
    pagination: capability("PAGINATED_DIRECTORY") &&
      capability("REPEATED_PAGE"),
    quota: capability("QUOTA_THEN_RECOVER") &&
      capability("QUOTA_EXHAUSTED"),
    permissions: capability("PERMISSION_DENIED") &&
      capability("REPORTS_UNAVAILABLE"),
    mfa: capability("MFA_GAPS") &&
      capability("UNKNOWN_MFA"),
    reports: capability("REPORTS_PARTIAL") &&
      capability("HEALTHY_REFERENCE"),
    risk: capability("ADMIN_RISK") &&
      capability("DOMAIN_UNVERIFIED"),
    executiveReport: cases.every(c => c.checks.some(x =>
      x.id === "RISK_REPORT_COMPLETE" && x.state === "PASS")),
    neutralEvidence: cases.every(c => c.checks.some(x =>
      x.id === "RISK_REPORT_COMPLETE" && x.state === "PASS")),
    tenantIsolation: cases.every(c => c.checks.some(x =>
      x.id === "SOURCE_TENANT" && x.state === "PASS")),
    noAccountMutation: cases.every(c => c.writeOperations === 0),
    noLiveProviderClaim: cases.every(c =>
      !c.independentLiveVerification),
  };
  const canonical = {
    schema: "cyberpilot.google.phase5.matrix.v1" as const,
    organizationId, evaluatedAt: at,
    scenarioCount: cases.length, cases, dimensions,
    checks: checks.length,
    passed: checks.filter(c => c.state === "PASS").length,
    failed: checks.filter(c => c.state === "FAIL").length,
    review: checks.filter(c => c.state === "REVIEW").length,
    excluded: checks.filter(c => c.state === "EXCLUDED").length,
    blockingFailures, missingScenarios,
    duplicateScenarios: duplicates, coverage,
    verdict: ready && Object.values(coverage).every(Boolean) ?
      "OFFLINE_A_B_PASS" as const : "OFFLINE_A_B_BLOCKED" as const,
    source: "SYNTHETIC_FIXTURE" as const,
    realGoogleProviderValidated: false as const,
    customerOperationalApproval: false as const,
    legalCertificationPassed: false as const,
    canonicalCyberScoreChanged: false as const,
    oauthTokensPersisted: false as const,
  };
  return { ...canonical, digest: canonicalGoogleHash(canonical) };
}
export function verifyGooglePhase5Matrix(matrix: Phase5AcceptanceMatrix) {
  const { digest, ...canonical } = matrix;
  const issues: string[] = [];
  if (canonicalGoogleHash(canonical) !== digest)
    issues.push("MATRIX_DIGEST_MISMATCH");
  if (matrix.realGoogleProviderValidated ||
      matrix.customerOperationalApproval ||
      matrix.legalCertificationPassed ||
      matrix.canonicalCyberScoreChanged ||
      matrix.oauthTokensPersisted ||
      matrix.source !== "SYNTHETIC_FIXTURE")
    issues.push("MATRIX_FALSE_LIVE_CLAIM");
  if (matrix.scenarioCount !== matrix.cases.length ||
      matrix.dimensions.length !== mandatory.length ||
      matrix.cases.some(c => !verifyGoogleScenarioAcceptance(c).valid))
    issues.push("MATRIX_INCOMPLETE_CASE_REGISTER");
  const ready = matrix.missingScenarios.length === 0 &&
    matrix.duplicateScenarios.length === 0 &&
    matrix.blockingFailures.length === 0 &&
    matrix.dimensions.every(d => d.complete) &&
    Object.values(matrix.coverage).every(Boolean);
  if ((matrix.verdict === "OFFLINE_A_B_PASS") !== ready)
    issues.push("MATRIX_VERDICT_NOT_SUPPORTED");
  return { valid: issues.length === 0, issues };
}
export async function runGooglePhase5AcceptanceMatrix(
  raw: unknown = {},
): Promise<Phase5AcceptanceMatrix> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    throw new Error("Matrix input must be a bounded record.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(key => ![
    "organizationId", "checkedAt", "scenarios",
  ].includes(key)))
    throw new Error("Unexpected matrix parameter.");
  const organizationId = x.organizationId ??
    "phase5-acceptance-fixture";
  const checkedAt = x.checkedAt ??
    "2026-11-12T10:00:00.000Z";
  if (typeof organizationId !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(organizationId))
    throw new Error("Invalid phase5 matrix organization ID.");
  if (typeof checkedAt !== "string" ||
      !Number.isFinite(Date.parse(checkedAt)))
    throw new Error("Invalid phase5 acceptance clock.");
  let scenarios = GOOGLE_LAB_SCENARIOS.map(c => c.id);
  if (x.scenarios !== undefined) {
    if (!Array.isArray(x.scenarios) ||
        x.scenarios.length > 40 ||
        x.scenarios.some(s => typeof s !== "string" ||
          !GOOGLE_LAB_SCENARIOS.some(c => c.id === s)))
      throw new Error("Invalid phase5 matrix scenarios.");
    scenarios = x.scenarios as GoogleLabScenarioName[];
  }
  const reports: Phase5ScenarioAcceptance[] = [];
  for (const scenario of scenarios) {
    const journey = await runGoogleLabJourney({
      organizationId, checkedAt, scenario,
    });
    reports.push(evaluateGoogleScenarioAcceptance(journey));
  }
  const matrix = buildGooglePhase5Matrix(
    organizationId, new Date(checkedAt).toISOString(),
    reports);
  if (!verifyGooglePhase5Matrix(matrix).valid)
    throw new Error("Generated Google Phase5 acceptance matrix invalid.");
  return matrix;
}
export function summarizeGooglePhase5Acceptance(
  matrix: Phase5AcceptanceMatrix,
) {
  if (!verifyGooglePhase5Matrix(matrix).valid)
    throw new Error("Cannot summarize corrupted Google acceptance matrix.");
  return {
    phase: 5,
    scope: "GOOGLE_WORKSPACE_OFFLINE",
    organizationId: matrix.organizationId,
    evaluatedAt: matrix.evaluatedAt,
    scenariosRequired: GOOGLE_LAB_SCENARIOS.length,
    scenariosChecked: matrix.scenarioCount,
    controlsChecked: matrix.checks,
    controlsPassed: matrix.passed,
    blockingFailures: matrix.blockingFailures.length,
    missingScenarios: matrix.missingScenarios,
    dimensions: matrix.dimensions.map(d => ({
      code: d.dimension, pass: d.complete,
      checks: d.total, failed: d.failed,
    })),
    technicalDevelopmentAccepted:
      matrix.verdict === "OFFLINE_A_B_PASS",
    requiresHumanSignatureForDevelopment: false as const,
    customerTenantConnected: false as const,
    providerLiveValidated: false as const,
    customerLegalAcceptanceVerified: false as const,
    githubMergeAuthorizedByEvidence: false as const,
    referenceDigest: matrix.digest,
  };
}
