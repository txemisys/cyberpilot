import { canonicalGoogleHash } from "./canonical-json";
import {
  collectGoogleWorkspace,
  type GoogleCollectionResult,
  type GoogleTransportPolicy,
} from "./transport";
import {
  assessGoogleWorkspace, verifyGoogleRiskAssessment,
  type GoogleRiskAssessment,
} from "./risk-assessment";
import {
  buildGoogleExecutiveReport,
  verifyGoogleExecutiveReport,
  exportGoogleReportMarkdown,
  type GoogleReportExport,
} from "./assessment-report";
import {
  buildNeutralGoogleBundle,
  verifyNeutralGoogleBundle,
  type NeutralGoogleBundle,
} from "./neutral-evidence";
import {
  buildGoogleLabSimulation, makeGoogleLabScenario,
  defaultScenarioPolicy, validateGoogleMockTrace,
  GOOGLE_LAB_SCENARIOS, type GoogleLabScenarioName,
  type GoogleLabMockTrace,
} from "./lab-scenarios";

export type LabJourneyInput = {
  organizationId: string;
  scenario: GoogleLabScenarioName;
  checkedAt: string;
  userCount?: number;
  pageSize?: number;
  maxPages?: number;
  maxRetries?: number;
  includeReports?: boolean;
  requireCompleteCoverage?: boolean;
};
export type LabJourneyGate = {
  code:
    "SOURCE_VALID" | "ZERO_EXTERNAL_TRAFFIC" |
    "NO_GOOGLE_CREDENTIALS" | "NO_ACCOUNT_WRITES" |
    "RISK_ENGINE_VALID" | "REPORT_VALID" |
    "NEUTRAL_BUNDLE_VALID" | "TRACE_VALID" |
    "SCOPE_MATCH" | "PERMISSIONS_CONSERVATIVE" |
    "NO_CANONICAL_SCORE" | "NO_CUSTOMER_APPROVAL" |
    "PRIVACY_REDACTED" | "BOUNDED_REQUEST_COUNT";
  passed: boolean;
  severity: "BLOCK" | "REVIEW";
  description: string;
  evidenceDigest: string | null;
};
export type GoogleLabJourneyResult = {
  schema: "cyberpilot.google.lab.journey.v1";
  organizationId: string;
  scenario: GoogleLabScenarioName;
  checkedAt: string;
  sourceDigest: string;
  transportPolicy: GoogleTransportPolicy;
  collection: GoogleCollectionResult;
  assessment: GoogleRiskAssessment;
  report: GoogleReportExport;
  neutral: NeutralGoogleBundle;
  fixtureTrace: GoogleLabMockTrace[];
  diagnostics: {
    requests: number;
    successfulPages: number;
    failedPages: number;
    retriesObserved: number;
    partialCapabilities: number;
    permissionFailures: number;
    rateLimitFailures: number;
    transportFailures: number;
    unknownMfaUsers: number;
    potentialRisks: number;
    reportSections: number;
    reportMarkdownBytes: number;
    sourceDigestValidated: boolean;
    externalApiRequests: 0;
    accountWrites: 0;
    rawEmailsExported: false;
    historicalCyberScoreMutated: false;
    customerApprovalAttested: false;
    providerLiveValidated: false;
  };
  gates: LabJourneyGate[];
  acceptedForOfflineDevelopment: boolean;
  acceptedForCustomerOperations: false;
  cryptographicallySignedByGoogle: false;
  digest: string;
};
const rules = [
  "A synthetic fixture can support offline development only.",
  "Directory and Reports API access remain unverified until an authorized LIVE integration.",
  "A non-null preview score is not the canonical CyberScore.",
  "Missing Reports, MFA, or pagination cannot be interpreted as healthy.",
  "No customer administrator consent is conveyed by a fixture.",
  "No account, credential or OAuth setting is modified.",
] as const;
function id(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(value))
    throw new Error("Invalid Google LAB journey " + label + ".");
  return value;
}
function number(value: unknown, label: string,
  low: number, high: number) {
  if (typeof value !== "number" ||
      !Number.isSafeInteger(value) || value < low || value > high)
    throw new Error("Invalid LAB journey " + label + ".");
  return value;
}
export function parseGoogleLabJourneyInput(
  raw: unknown,
): LabJourneyInput {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    throw new Error("LAB journey input must be a record.");
  const x = raw as Record<string, unknown>;
  const allowed = [
    "organizationId", "scenario", "checkedAt",
    "userCount", "pageSize", "maxPages", "maxRetries",
    "includeReports", "requireCompleteCoverage",
  ];
  if (Object.keys(x).some(key => !allowed.includes(key)))
    throw new Error("Unknown LAB journey option.");
  const organizationId = id(x.organizationId, "organization");
  if (typeof x.scenario !== "string" ||
      !GOOGLE_LAB_SCENARIOS.some(s => s.id === x.scenario))
    throw new Error("Unknown LAB journey scenario.");
  if (typeof x.checkedAt !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(x.checkedAt) ||
      !Number.isFinite(Date.parse(x.checkedAt)))
    throw new Error("Invalid LAB journey clock.");
  for (const key of ["includeReports", "requireCompleteCoverage"])
    if (x[key] !== undefined && typeof x[key] !== "boolean")
      throw new Error("Invalid LAB flag " + key + ".");
  return {
    organizationId,
    scenario: x.scenario as GoogleLabScenarioName,
    checkedAt: new Date(x.checkedAt).toISOString(),
    ...(x.userCount !== undefined ?
      { userCount: number(x.userCount, "user count", 0, 120) } : {}),
    ...(x.pageSize !== undefined ?
      { pageSize: number(x.pageSize, "page size", 1, 500) } : {}),
    ...(x.maxPages !== undefined ?
      { maxPages: number(x.maxPages, "max pages", 1, 30) } : {}),
    ...(x.maxRetries !== undefined ?
      { maxRetries: number(x.maxRetries, "max retries", 0, 6) } : {}),
    ...(x.includeReports !== undefined ?
      { includeReports: x.includeReports as boolean } : {}),
    ...(x.requireCompleteCoverage !== undefined ?
      { requireCompleteCoverage:
        x.requireCompleteCoverage as boolean } : {}),
  };
}
function permitted(policy: GoogleTransportPolicy,
  scenario: LabJourneyInput) {
  const pages = scenario.maxPages ??
    policy.maxPagesPerResource;
  const pageSize = scenario.pageSize ?? policy.pageSize;
  const retries = scenario.maxRetries ??
    policy.maxRetriesPerPage;
  return {
    ...policy, maxPagesPerResource: pages,
    pageSize, maxRetriesPerPage: retries,
    includeReports: scenario.includeReports ??
      policy.includeReports,
  };
}
export async function runGoogleLabJourney(
  raw: unknown,
): Promise<GoogleLabJourneyResult> {
  const input = parseGoogleLabJourneyInput(raw);
  const source = makeGoogleLabScenario(input);
  const policy = permitted(defaultScenarioPolicy(source), input);
  const sim = buildGoogleLabSimulation(source, policy);
  const clock = Date.parse(input.checkedAt);
  const collection = await collectGoogleWorkspace({
    environment: {
      organizationId: input.organizationId,
      customerId: "my_customer",
      checkedAt: input.checkedAt,
      source: "SYNTHETIC_FIXTURE",
      token: "offline-fixture-only-no-provider-credential",
      consentVerifiedByCaller: true,
      liveProviderAllowedByCaller: false,
    },
    policy, fetcher: sim.fetcher,
    sleep: async () => {},
    clock: () => clock,
  });
  const assessment = assessGoogleWorkspace(
    collection.observation, { referenceDate: input.checkedAt },
    new Date(input.checkedAt));
  if (!verifyGoogleRiskAssessment(assessment).valid)
    throw new Error("LAB risk assessment is inconsistent.");
  const report = buildGoogleExecutiveReport(assessment);
  if (!verifyGoogleExecutiveReport(report).valid)
    throw new Error("LAB executive report is inconsistent.");
  const neutral = buildNeutralGoogleBundle(assessment);
  if (!verifyNeutralGoogleBundle(neutral).valid)
    throw new Error("LAB neutral bundle is inconsistent.");
  const transcript = sim.inspect();
  const traceCheck = validateGoogleMockTrace(
    source, sim.transcript);
  const reportMarkdown = exportGoogleReportMarkdown(report);
  const diagnostics = {
    requests: transcript.requests,
    successfulPages: transcript.pages,
    failedPages: transcript.failures,
    retriesObserved: Math.max(0,
      sim.transcript.length -
      new Set(sim.transcript.map(t =>
        t.resource + ":" + t.page)).size),
    partialCapabilities:
      collection.observation.unknownCapabilities.length,
    permissionFailures: collection.failures.filter(f =>
      f.category === "PERMISSION").length,
    rateLimitFailures: collection.failures.filter(f =>
      f.category === "QUOTA").length,
    transportFailures: collection.failures.filter(f =>
      f.category === "TRANSPORT").length,
    unknownMfaUsers: assessment.counts.usersWithUnknownMfa,
    potentialRisks: assessment.counts.possibleRisks,
    reportSections: report.sections.length,
    reportMarkdownBytes: Buffer.byteLength(reportMarkdown),
    sourceDigestValidated: traceCheck.valid,
    externalApiRequests: 0 as const,
    accountWrites: 0 as const,
    rawEmailsExported: false as const,
    historicalCyberScoreMutated: false as const,
    customerApprovalAttested: false as const,
    providerLiveValidated: false as const,
  };
  const gate = (
    code: LabJourneyGate["code"],
    passed: boolean, description: string,
    severity: LabJourneyGate["severity"] = "BLOCK",
    digest: string | null = null,
  ): LabJourneyGate => ({
    code, passed, description, severity, evidenceDigest: digest,
  });
  const gates: LabJourneyGate[] = [
    gate("SOURCE_VALID",
      collection.observation.digest.length === 64 &&
      collection.observation.organizationId ===
        input.organizationId,
      "Snapshot must be structurally valid and scoped to the requested tenant.",
      "BLOCK", collection.observation.digest),
    gate("ZERO_EXTERNAL_TRAFFIC",
      !collection.providerContacted && transcript.liveRequests === 0,
      "No fixture run may call an external Google endpoint.",
      "BLOCK", transcript.transcriptDigest),
    gate("NO_GOOGLE_CREDENTIALS",
      collection.tokenRetained === false &&
      transcript.credentialLeaks === 0,
      "No Google token can be stored, exported or logged."),
    gate("NO_ACCOUNT_WRITES",
      collection.accountWrites === 0 &&
      assessment.accountWrites === 0,
      "The connector never updates Google identities."),
    gate("RISK_ENGINE_VALID",
      verifyGoogleRiskAssessment(assessment).valid,
      "The cautious risk assessment must verify locally.",
      "BLOCK", assessment.digest),
    gate("REPORT_VALID",
      verifyGoogleExecutiveReport(report).valid,
      "The executive report must match its source.",
      "BLOCK", report.machineReadableJsonDigest),
    gate("NEUTRAL_BUNDLE_VALID",
      verifyNeutralGoogleBundle(neutral).valid,
      "The normalized controls must retain evidence provenance.",
      "BLOCK", neutral.digest),
    gate("TRACE_VALID", traceCheck.valid,
      "Mock trace must be tenant scoped and contain no secrets.",
      "BLOCK", traceCheck.requestDigest),
    gate("SCOPE_MATCH",
      neutral.organizationId === input.organizationId &&
      report.organizationId === input.organizationId &&
      assessment.organizationId === input.organizationId,
      "Every derived result must remain tenant-scoped."),
    gate("PERMISSIONS_CONSERVATIVE",
      collection.observation.unknownCapabilities.every(c =>
        assessment.coverage.some(row => row.capability === c &&
          !row.scoreEligible)),
      "Unavailable or partial capabilities cannot enter a posture score."),
    gate("NO_CANONICAL_SCORE",
      !assessment.score.cyberScoreUpdated &&
      !neutral.summary.canonicalScoreUpdated &&
      assessment.score.score === null,
      "Offline fixtures cannot generate canonical security scores."),
    gate("NO_CUSTOMER_APPROVAL",
      !assessment.customerLegalApproval &&
      !report.customerCertified &&
      !neutral.exportRestrictions.customerAcceptanceVerified,
      "LAB execution never replaces customer operational approval."),
    gate("PRIVACY_REDACTED",
      !report.sourceEmailsExported &&
      !report.sourceTokensExported &&
      !neutral.exportRestrictions.rawEmailIncluded &&
      !neutral.exportRestrictions.oauthCredentialIncluded,
      "Report and neutral output exclude raw provider identity and token fields."),
    gate("BOUNDED_REQUEST_COUNT",
      diagnostics.requests <= policy.maxTotalRequests,
      "Mock transport must respect the request budget."),
  ];
  if (input.requireCompleteCoverage &&
      collection.evidenceIncomplete)
    gates.push(gate("PERMISSIONS_CONSERVATIVE", false,
      "Requested complete coverage is not available.",
      "REVIEW"));
  const acceptedForOfflineDevelopment =
    gates.every(g => g.passed || g.severity === "REVIEW");
  const canonical = {
    schema: "cyberpilot.google.lab.journey.v1" as const,
    organizationId: input.organizationId,
    scenario: input.scenario,
    checkedAt: input.checkedAt,
    sourceDigest: source.sourceDigest,
    transportPolicy: policy,
    collection, assessment, report, neutral,
    fixtureTrace: [...sim.transcript],
    diagnostics, gates, acceptedForOfflineDevelopment,
    acceptedForCustomerOperations: false as const,
    cryptographicallySignedByGoogle: false as const,
  };
  return { ...canonical,
    digest: canonicalGoogleHash(canonical) };
}
export function inspectGoogleLabJourney(
  run: GoogleLabJourneyResult,
) {
  const { digest, ...canonical } = run;
  const issues: string[] = [];
  if (canonicalGoogleHash(canonical) !== digest)
    issues.push("JOURNEY_DIGEST_MISMATCH");
  if (run.gates.length < 14 ||
      run.gates.some(g => g.severity === "BLOCK" &&
        !g.passed) && run.acceptedForOfflineDevelopment)
    issues.push("JOURNEY_GATES_INCONSISTENT");
  if (run.collection.providerContacted ||
      run.acceptedForCustomerOperations ||
      run.cryptographicallySignedByGoogle ||
      run.diagnostics.externalApiRequests ||
      run.diagnostics.accountWrites ||
      run.diagnostics.rawEmailsExported ||
      run.diagnostics.historicalCyberScoreMutated ||
      run.diagnostics.customerApprovalAttested ||
      run.diagnostics.providerLiveValidated)
    issues.push("JOURNEY_FALSE_PROVIDER_OR_APPROVAL_CLAIM");
  if (run.collection.organizationId !== run.organizationId ||
      run.assessment.organizationId !== run.organizationId ||
      run.neutral.organizationId !== run.organizationId)
    issues.push("JOURNEY_CROSS_TENANT_DATA");
  if (!verifyGoogleRiskAssessment(run.assessment).valid ||
      !verifyGoogleExecutiveReport(run.report).valid ||
      !verifyNeutralGoogleBundle(run.neutral).valid)
    issues.push("JOURNEY_DERIVED_EVIDENCE_INVALID");
  if (run.fixtureTrace.some(t =>
    t.organizationId !== run.organizationId ||
    !t.usedFixtureOnly || t.bearerTokenLogged ||
    t.rawAuthorizationHeadersLogged))
    issues.push("JOURNEY_TRACE_HAS_EXTERNAL_OR_PII_CLAIM");
  return { valid: issues.length === 0, issues };
}
export function googleLabJourneySummary(
  journey: GoogleLabJourneyResult,
) {
  if (!inspectGoogleLabJourney(journey).valid)
    throw new Error("Cannot summarize tampered LAB journey.");
  const gates = journey.gates;
  const blocking = gates.filter(g =>
    g.severity === "BLOCK" && !g.passed);
  const review = gates.filter(g =>
    g.severity === "REVIEW" && !g.passed);
  return {
    organizationId: journey.organizationId,
    scenario: journey.scenario,
    checkedAt: journey.checkedAt,
    sourceDigest: journey.sourceDigest,
    journeyDigest: journey.digest,
    steps: gates.length,
    passed: gates.filter(g => g.passed).length,
    blocked: blocking.length, review: review.length,
    totalRequests: journey.diagnostics.requests,
    partialCapabilities:
      journey.diagnostics.partialCapabilities,
    possibleRiskFindings: journey.diagnostics.potentialRisks,
    reportSections: journey.diagnostics.reportSections,
    localAcceptance: blocking.length === 0,
    customerApproval: false as const,
    externalProviderValidated: false as const,
    risksFullyResolved: false as const,
    warnings: [...rules],
  };
}
export function googleLabJourneyOperatorActions(
  journey: GoogleLabJourneyResult,
) {
  if (!inspectGoogleLabJourney(journey).valid)
    throw new Error("Invalid LAB journey for operator action plan.");
  const actions: Array<{
    rank: number; category: string; title: string;
    description: string; evidence: string[];
    executed: false; realProviderRequired: boolean;
  }> = [];
  const add = (category: string, title: string,
    description: string, evidence: string[] = [],
    realProviderRequired = false) => actions.push({
    rank: actions.length + 1,
    category, title, description, evidence,
    executed: false, realProviderRequired,
  });
  for (const gate of journey.gates.filter(g => !g.passed))
    add("LOCAL_GATE", gate.code, gate.description,
      gate.evidenceDigest ? [gate.evidenceDigest] : []);
  for (const failure of journey.collection.failures.slice(0, 25))
    add("PROVIDER_VISIBILITY", failure.category +
      " on " + failure.resource,
    failure.summary, [], false);
  for (const action of journey.assessment.topActions.slice(0, 25))
    add("SECURITY_REVIEW", action.description, action.nextStep,
      [action.findingId], true);
  if (journey.collection.evidenceIncomplete)
    add("COVERAGE", "Incomplete Google capability coverage",
      "Review permissions, licensing, resource-specific errors and pagination.",
      [journey.collection.observation.digest], true);
  if (journey.diagnostics.requests > 0)
    add("DEVELOPMENT", "Replay synthetic API collection",
      "Reproduce the local fixture with the same scenario and timestamp.",
      [journey.digest]);
  return actions;
}
