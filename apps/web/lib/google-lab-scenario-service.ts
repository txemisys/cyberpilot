import { db } from "@cyberpilot/database";
import {
  GoogleLabError, GoogleLabOnboardingService,
  GOOGLE_LAB_SCENARIOS, runGoogleLabJourney,
  inspectGoogleLabJourney, googleLabJourneySummary,
  googleLabJourneyOperatorActions,
  verifyNeutralGoogleBundle,
  type GoogleLabScope, type GoogleLabScenarioName,
  type GoogleLabJourneyResult,
  type GoogleCapability,
} from "@cyberpilot/integrations/google-workspace";
import { PrismaGoogleLabRepository } from
  "./google-lab-prisma-repository";
import {
  persistGoogleOfflineSnapshot, type GoogleSnapshotSummary,
} from "./google-offline-snapshot-service";

/**
 * LAB-only tenant-scoped synthetic provider journey. No user data is accepted
 * from a browser, all raw identities remain in the ephemeral runner, and
 * only reports, risk outputs and hashes may be returned to the UI.
 */
export type ScenarioRunCommand = {
  connectionId: string;
  expectedConnectionRevision: number;
  scenario: GoogleLabScenarioName;
  checkedAt: string;
  retentionDays: number;
  persist: boolean;
  includeAuditTrace: boolean;
  pageSize: number | null;
  maxRetries: number | null;
  maxPages: number | null;
  requireCompleteCoverage: boolean;
};
export type ScenarioGateSummary = {
  code: string;
  passed: boolean;
  severity: "BLOCK" | "REVIEW";
  explanation: string;
  reference: string | null;
};
export type ScenarioRunResult = {
  schema: "cyberpilot.google.lab.scenario.run.v1";
  organizationId: string;
  scenario: GoogleLabScenarioName;
  connectionId: string;
  connectionRevision: number;
  checkedAt: string;
  sourceClass: "SYNTHETIC_FIXTURE";
  workflow: {
    started: true;
    collectionPerformed: boolean;
    reportCreated: boolean;
    neutralEvidenceCreated: boolean;
    saved: boolean;
    blockingGateCount: number;
    reviewGateCount: number;
    passedGateCount: number;
    totalGateCount: number;
    localDevelopmentAccepted: boolean;
    customerDeploymentAccepted: false;
    providerAuthenticationVerified: false;
  };
  snapshot: GoogleSnapshotSummary | null;
  report: {
    digest: string;
    sections: Array<{
      id: string;
      title: string;
      state: string;
      summary: string;
      risks: number;
      unknown: number;
    }>;
    summary: {
      usersObserved: number;
      adminsObserved: number;
      potentialRisks: number;
      unresolvedUnknowns: number;
      incompleteCapabilities: number;
      previewScore: number | null;
      customerSecurityStatus: "NOT_DETERMINED";
    };
    caveats: string[];
  };
  coverage: Array<{
    capability: GoogleCapability;
    status: string;
    observed: number;
    unknown: number;
    sourceCount: number;
    verifiedExternally: false;
  }>;
  findings: Array<{
    id: string;
    ruleId: string;
    status: string;
    severity: string;
    title: string;
    remediation: string;
    evidenceDigest: string;
    autoRemediated: false;
  }>;
  trace: Array<{
    resource: string;
    page: number;
    status: number;
    attempt: number;
    digest: string;
  }>;
  failures: Array<{
    category: string;
    resource: string;
    requestCount: number;
    pagesRead: number;
    explanation: string;
  }>;
  operatorActions: Array<{
    rank: number;
    title: string;
    category: string;
    description: string;
    requiresLiveValidation: boolean;
    executed: false;
  }>;
  gates: ScenarioGateSummary[];
  sourceDigest: string;
  assessmentDigest: string;
  reportDigest: string;
  neutralDigest: string;
  warnings: string[];
  googleApiRequests: 0;
  googleAccountWrites: 0;
  rawEmailsInResponse: false;
  tokensInResponse: false;
  realAdministratorConsentVerified: false;
  canonicalCyberScoreModified: false;
};
const adminRoles = new Set(["OWNER", "ADMIN"]);
const MAX_OUTPUT_FINDINGS = 250;
const MAX_TRACE = 150;
const MAX_OUTPUT_ACTIONS = 50;
const supported = new Set(GOOGLE_LAB_SCENARIOS.map(s => s.id));
const relevantCapabilities: GoogleCapability[] = [
  "DIRECTORY_USERS", "DIRECTORY_DOMAINS",
  "DIRECTORY_ORGANIZATION_UNITS",
];
function fail(code: GoogleLabError["code"], message: string): never {
  throw new GoogleLabError(code, message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Scenario command must be JSON object.");
  return value as Record<string, unknown>;
}
function text(value: unknown, label: string, max = 128) {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,128}$/.test(value) ||
      value.length > max)
    fail("INVALID", "Invalid " + label + ".");
  return value;
}
function date(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    fail("INVALID", "Invalid scenario UTC timestamp.");
  return new Date(value).toISOString();
}
function integer(v: unknown, label: string,
  low: number, high: number) {
  if (typeof v !== "number" ||
      !Number.isSafeInteger(v) || v < low || v > high)
    fail("INVALID", "Invalid " + label + ".");
  return v;
}
function bool(v: unknown, label: string) {
  if (typeof v !== "boolean")
    fail("INVALID", "Invalid boolean " + label + ".");
  return v;
}
export function parseScenarioRunCommand(raw: unknown): ScenarioRunCommand {
  const v = object(raw);
  const fields = [
    "connectionId", "expectedConnectionRevision",
    "scenario", "checkedAt", "retentionDays",
    "persist", "includeAuditTrace", "pageSize",
    "maxRetries", "maxPages", "requireCompleteCoverage",
  ];
  if (Object.keys(v).some(key => !fields.includes(key)))
    fail("INVALID", "Unexpected scenario input key.");
  if (typeof v.scenario !== "string" ||
      !supported.has(v.scenario as GoogleLabScenarioName))
    fail("INVALID", "Unknown Google fixture scenario.");
  const pageSize = v.pageSize === undefined || v.pageSize === null ?
    null : integer(v.pageSize, "page size", 1, 500);
  const maxRetries = v.maxRetries === undefined ||
    v.maxRetries === null ? null :
      integer(v.maxRetries, "retry count", 0, 6);
  const maxPages = v.maxPages === undefined ||
    v.maxPages === null ? null :
      integer(v.maxPages, "max pages", 1, 30);
  return {
    connectionId: text(v.connectionId, "LAB connection ID"),
    expectedConnectionRevision: integer(
      v.expectedConnectionRevision, "connection revision", 1, 10000),
    scenario: v.scenario as GoogleLabScenarioName,
    checkedAt: date(v.checkedAt),
    retentionDays: integer(v.retentionDays ?? 30,
      "retention", 1, 365),
    persist: v.persist === undefined ?
      false : bool(v.persist, "persist"),
    includeAuditTrace: v.includeAuditTrace === undefined ?
      true : bool(v.includeAuditTrace, "includeAuditTrace"),
    pageSize, maxRetries, maxPages,
    requireCompleteCoverage:
      v.requireCompleteCoverage === undefined ? false :
        bool(v.requireCompleteCoverage, "requireCompleteCoverage"),
  };
}
async function currentMembership(
  scope: GoogleLabScope, requiredManager = false,
) {
  if (!scope || !scope.organizationId || !scope.actorUserId ||
      !["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role))
    fail("FORBIDDEN", "Invalid Google fixture identity scope.");
  const row = await db.membership.findFirst({
    where: {
      organizationId: scope.organizationId,
      userId: scope.actorUserId,
    }, select: { id: true, role: true },
  });
  if (!row || row.role !== scope.role)
    fail("FORBIDDEN", "Google fixture requires active membership.");
  if (requiredManager && !adminRoles.has(row.role))
    fail("FORBIDDEN",
      "Only administrators may persist synthetic provider evidence.");
}
export function googleScenarioCatalog() {
  return GOOGLE_LAB_SCENARIOS.map((scenario, index) => ({
    id: scenario.id, sequence: index + 1,
    title: scenario.title, purpose: scenario.purpose,
    expectedRisk: scenario.expectedRisk,
    expectedCoverage: scenario.expectedCoverage,
    gates: [...scenario.gates],
    needsRealGoogleTenant: false as const,
    producesProviderRequests: false as const,
    containsCustomerData: false as const,
    externalGoogleConsentSatisfied: false as const,
    canModifyGoogleAccounts: false as const,
  }));
}
export function sanitizeGoogleScenarioJourney(
  journey: GoogleLabJourneyResult,
  command: ScenarioRunCommand,
  snapshot: GoogleSnapshotSummary | null,
): ScenarioRunResult {
  if (!inspectGoogleLabJourney(journey).valid)
    fail("CONFLICT", "Cannot expose tampered fixture journey.");
  if (!verifyNeutralGoogleBundle(journey.neutral).valid ||
      journey.organizationId !==
        journey.collection.observation.organizationId)
    fail("CONFLICT", "Provider source is inconsistent.");
  const gates = journey.gates.map(gate => ({
    code: gate.code, passed: gate.passed,
    severity: gate.severity, explanation: gate.description,
    reference: gate.evidenceDigest,
  }));
  const blocking = gates.filter(g =>
    g.severity === "BLOCK" && !g.passed).length;
  const review = gates.filter(g =>
    g.severity === "REVIEW" && !g.passed).length;
  const source = journey.collection.observation;
  const actions = googleLabJourneyOperatorActions(journey)
    .slice(0, MAX_OUTPUT_ACTIONS).map(item => ({
      rank: item.rank, title: item.title,
      category: item.category, description: item.description,
      requiresLiveValidation: item.realProviderRequired,
      executed: false as const,
    }));
  const rawFindings = journey.assessment.findings;
  if (rawFindings.length > MAX_OUTPUT_FINDINGS)
    fail("INVALID", "Too many fixture findings to expose.");
  const reportSummary = journey.report.summary;
  const result: ScenarioRunResult = {
    schema: "cyberpilot.google.lab.scenario.run.v1",
    organizationId: journey.organizationId,
    scenario: command.scenario,
    connectionId: command.connectionId,
    connectionRevision: command.expectedConnectionRevision,
    checkedAt: journey.checkedAt,
    sourceClass: "SYNTHETIC_FIXTURE",
    workflow: {
      started: true,
      collectionPerformed: journey.diagnostics.requests > 0,
      reportCreated: journey.report.sections.length > 0,
      neutralEvidenceCreated: journey.neutral.controls.length > 0,
      saved: snapshot !== null,
      blockingGateCount: blocking,
      reviewGateCount: review,
      passedGateCount: gates.filter(g => g.passed).length,
      totalGateCount: gates.length,
      localDevelopmentAccepted: blocking === 0,
      customerDeploymentAccepted: false,
      providerAuthenticationVerified: false,
    },
    snapshot,
    report: {
      digest: journey.report.machineReadableJsonDigest,
      sections: journey.report.sections.map(section => ({
        id: section.id, title: section.title,
        state: section.state, summary: section.headline,
        risks: section.potentialRisks,
        unknown: section.unknownItems,
      })),
      summary: {
        usersObserved: reportSummary.usersObserved,
        adminsObserved: reportSummary.adminsObserved,
        potentialRisks: reportSummary.potentialRisks,
        unresolvedUnknowns: reportSummary.unresolvedUnknowns,
        incompleteCapabilities: reportSummary.incompleteCapabilities,
        previewScore: reportSummary.previewScore,
        customerSecurityStatus: "NOT_DETERMINED",
      },
      caveats: [...journey.report.caveats],
    },
    coverage: journey.neutral.coverage.capabilities.map(cap => ({
      capability: cap.capability, status: cap.status,
      observed: cap.observed, unknown: cap.unknown,
      sourceCount: cap.controlRows,
      verifiedExternally: false,
    })),
    findings: rawFindings.map(finding => ({
      id: finding.id, ruleId: finding.ruleId,
      status: finding.status, severity: finding.severity,
      title: finding.title, remediation: finding.remediation,
      evidenceDigest: finding.sourceDigest,
      autoRemediated: false,
    })),
    trace: command.includeAuditTrace ?
      journey.fixtureTrace.slice(0, MAX_TRACE).map(item => ({
        resource: item.resource,
        page: item.page, status: item.status,
        attempt: item.attempt, digest: item.responseDigest,
      })) : [],
    failures: journey.collection.failures.map(failure => ({
      category: failure.category,
      resource: failure.resource,
      requestCount: failure.requestCount,
      pagesRead: failure.pagesRead,
      explanation: failure.summary,
    })),
    operatorActions: actions,
    gates,
    sourceDigest: source.digest,
    assessmentDigest: journey.assessment.digest,
    reportDigest: journey.report.machineReadableJsonDigest,
    neutralDigest: journey.neutral.digest,
    warnings: [
      "Synthetic LAB results are not authenticated Google Workspace data.",
      "Provider permissions and licensing have not been confirmed LIVE.",
      "No canonical CyberScore was recalculated.",
      "No customer approval, remediation or account modification occurred.",
    ],
    googleApiRequests: 0,
    googleAccountWrites: 0,
    rawEmailsInResponse: false,
    tokensInResponse: false,
    realAdministratorConsentVerified: false,
    canonicalCyberScoreModified: false,
  };
  if (JSON.stringify(result).includes("@") &&
      JSON.stringify(result).includes("example.invalid"))
    fail("CONFLICT", "Synthetic raw identities leaked into UI payload.");
  return result;
}
export async function executeGoogleScenarioRun(
  scope: GoogleLabScope,
  raw: unknown,
): Promise<ScenarioRunResult> {
  const command = parseScenarioRunCommand(raw);
  await currentMembership(scope, command.persist);
  const repository = new PrismaGoogleLabRepository();
  const lab = new GoogleLabOnboardingService(repository);
  const connection = await repository.getByOrganization(
    scope.organizationId, command.connectionId);
  if (!connection)
    fail("MISSING", "LAB connection unavailable in this tenant.");
  if (connection.revision !== command.expectedConnectionRevision)
    fail("CONFLICT", "LAB connection revision has changed.");
  const required: GoogleCapability[] = [...relevantCapabilities];
  const scenario = GOOGLE_LAB_SCENARIOS.find(s =>
    s.id === command.scenario)!;
  if (scenario.requiredResources.includes("LOGIN_AUDIT"))
    required.push("REPORTS_LOGIN");
  if (scenario.requiredResources.includes("ADMIN_AUDIT"))
    required.push("REPORTS_ADMIN");
  const eligibility = await lab.eligibility(
    scope, command.connectionId, command.checkedAt,
    required);
  if (!eligibility.eligible)
    fail("FORBIDDEN",
      "LAB connection not active or required fixture capabilities denied.");
  if (command.checkedAt < connection.updatedAt)
    fail("CONFLICT", "Scenario clock predates LAB state transition.");
  const journey = await runGoogleLabJourney({
    organizationId: scope.organizationId,
    scenario: command.scenario,
    checkedAt: command.checkedAt,
    ...(command.pageSize === null ? {} :
      { pageSize: command.pageSize }),
    ...(command.maxRetries === null ? {} :
      { maxRetries: command.maxRetries }),
    ...(command.maxPages === null ? {} :
      { maxPages: command.maxPages }),
    requireCompleteCoverage: command.requireCompleteCoverage,
  });
  if (!inspectGoogleLabJourney(journey).valid)
    fail("CONFLICT", "Google LAB journey could not be verified.");
  let snapshot: GoogleSnapshotSummary | null = null;
  if (command.persist) {
    if (!journey.acceptedForOfflineDevelopment)
      fail("CONFLICT", "Cannot persist a failed fixture scenario.");
    const stored = await persistGoogleOfflineSnapshot(scope, {
      connectionId: command.connectionId,
      expectedConnectionRevision: command.expectedConnectionRevision,
      createdAt: command.checkedAt,
      retentionDays: command.retentionDays,
      observation: journey.collection.observation,
    });
    snapshot = stored.summary;
  }
  return sanitizeGoogleScenarioJourney(
    journey, command, snapshot);
}
export function inspectSanitizedGoogleRun(
  result: ScenarioRunResult,
) {
  const issues: string[] = [];
  if (result.sourceClass !== "SYNTHETIC_FIXTURE" ||
      result.googleApiRequests !== 0 ||
      result.googleAccountWrites !== 0 ||
      result.rawEmailsInResponse ||
      result.tokensInResponse ||
      result.realAdministratorConsentVerified ||
      result.canonicalCyberScoreModified)
    issues.push("FALSE_LIVE_OR_PII_CLAIM");
  if (result.workflow.providerAuthenticationVerified ||
      result.workflow.customerDeploymentAccepted)
    issues.push("UNSUPPORTED_BUSINESS_APPROVAL");
  if (result.workflow.blockingGateCount !==
      result.gates.filter(g => !g.passed &&
        g.severity === "BLOCK").length)
    issues.push("INCORRECT_GATE_COUNT");
  if (result.workflow.saved !== (result.snapshot !== null))
    issues.push("SNAPSHOT_PERSISTENCE_STATUS_INVALID");
  if (result.coverage.some(c => c.verifiedExternally) ||
      result.findings.some(f => f.autoRemediated))
    issues.push("FALSE_FINDING_OR_COVERAGE_ASSURANCE");
  if (result.trace.some(t => t.page < 0 ||
      ![200, 403, 429, 503].includes(t.status)))
    issues.push("UNEXPECTED_SIMULATION_TRACE");
  return { valid: issues.length === 0, issues };
}
