import { createHash, timingSafeEqual } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";
import {
  buildAssetAdviceRows, summarizeAssetAdvice,
} from "./assets-action-guidance";
import type {
  AdviceSnapshot, AssetAdviceRow, AssetAdviceStatus,
} from "./assets-action-guidance";
import type { PackageBinding } from "./assets-osv-correlation";
import {
  evaluateAssetOfflineAcceptance,
  parseAcceptancePolicy,
} from "./assets-offline-acceptance";
import type {
  AcceptanceDataset, AcceptancePolicy,
  AcceptanceReport,
} from "./assets-offline-acceptance";
import {
  verifyOfflineAcceptanceReport,
} from "./assets-offline-acceptance-verification";
import type { CaseRow } from "./assets-action-case-service";

/**
 * Operator-facing regression matrix for the complete offline assets
 * decision pipeline. These synthetic inputs never substitute for customer
 * inventory, third-party OSV validation or signed manual acceptance.
 */
export type ScenarioCategory =
  "CLEAN_REVIEW" | "NO_REVIEW" | "AMBIGUOUS_VERSION" |
  "MISSING_MAPPING" | "INCOMPLETE_PROVIDER" |
  "MISSING_AUDIT" | "ALTERED_FINGERPRINT" |
  "STALE_OBSERVATION" | "FOREIGN_TENANT" |
  "INCOMPLETE_SNAPSHOT" | "DUPLICATE_CASE" |
  "INVALID_CHECKLIST" | "UNRESOLVED_PROVIDER";
export type ScenarioExpectation = {
  id: ScenarioCategory;
  expectedAccepted: boolean;
  expectedBlockedGateIds: string[];
  expectedAdvisoryGateIds: string[];
  expectedAdviceStatuses: AssetAdviceStatus[];
  shouldThrow: boolean;
};
export type ScenarioResult = {
  id: ScenarioCategory;
  label: string;
  passed: boolean;
  expectedAccepted: boolean;
  observedAccepted: boolean | null;
  expectedException: boolean;
  observedException: boolean;
  errorCode: string | null;
  expectedBlockers: string[];
  actualBlockers: string[];
  unexpectedBlockers: string[];
  missingBlockers: string[];
  expectedAdvisories: string[];
  missingAdvisories: string[];
  adviceStatuses: AssetAdviceStatus[];
  missingAdviceStatuses: AssetAdviceStatus[];
  sourceImportId: string;
  sourceInspectionId: string;
  candidateCount: number;
  reviewCaseCount: number;
  validatedReport: boolean;
  reportFingerprint: string | null;
  concerns: string[];
};
export type ScenarioMatrixOptions = {
  scenarios: ScenarioCategory[];
  maximumScenarios: number;
  maximumInventoryAgeDays: number;
  minimumMappedPercent: number;
  requireCaseAudit: boolean;
  requireAllCandidateReviews: boolean;
};
export type ScenarioMatrixReport = {
  schema: "cyberpilot.assets.offline.scenario.matrix.v1";
  generatedAt: string;
  synthetic: true;
  source: "BUILT_IN_SYNTHETIC_FIXTURES";
  organizationId: string;
  options: ScenarioMatrixOptions;
  totalRequested: number;
  totalExecuted: number;
  passed: number;
  failed: number;
  results: ScenarioResult[];
  resultsDigest: string;
  fixtureVersion: 1;
  externalProviderContacted: false;
  customerDatabaseRead: false;
  customerDatabaseWritten: false;
  userActionRecorded: false;
  releaseAutomaticallyApproved: false;
  warnings: string[];
};
export const SCENARIO_IDS: ScenarioCategory[] = [
  "CLEAN_REVIEW", "NO_REVIEW", "AMBIGUOUS_VERSION",
  "MISSING_MAPPING", "INCOMPLETE_PROVIDER",
  "MISSING_AUDIT", "ALTERED_FINGERPRINT",
  "STALE_OBSERVATION", "FOREIGN_TENANT",
  "INCOMPLETE_SNAPSHOT", "DUPLICATE_CASE",
  "INVALID_CHECKLIST", "UNRESOLVED_PROVIDER",
];
const descriptions: Record<ScenarioCategory, string> = {
  CLEAN_REVIEW: "Fully documented candidate with explicit human review",
  NO_REVIEW: "Positive provider ID has no human review case",
  AMBIGUOUS_VERSION: "Declared software lacks an exact installed version",
  MISSING_MAPPING: "Declared product has no publisher mapping",
  INCOMPLETE_PROVIDER: "Provider inspection returned partial evidence",
  MISSING_AUDIT: "Human case exists without original opening audit",
  ALTERED_FINGERPRINT: "Stored case fingerprint was modified",
  STALE_OBSERVATION: "Inventory observation falls outside freshness window",
  FOREIGN_TENANT: "Case belongs to a different organization",
  INCOMPLETE_SNAPSHOT: "Stored inventory count exceeds fetched records",
  DUPLICATE_CASE: "Two case records assert the same asset/product identity",
  INVALID_CHECKLIST: "Completed human review still has pending steps",
  UNRESOLVED_PROVIDER: "Provider-only vulnerability is not a verified match",
};
const expectations: Record<ScenarioCategory, ScenarioExpectation> = {
  CLEAN_REVIEW: {
    id: "CLEAN_REVIEW", expectedAccepted: true,
    expectedBlockedGateIds: [], expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  NO_REVIEW: {
    id: "NO_REVIEW", expectedAccepted: false,
    expectedBlockedGateIds: ["UNKNOWN_EVIDENCE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  AMBIGUOUS_VERSION: {
    id: "AMBIGUOUS_VERSION", expectedAccepted: true,
    expectedBlockedGateIds: [], expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_UNKNOWN_VERSION"],
    shouldThrow: false,
  },
  MISSING_MAPPING: {
    id: "MISSING_MAPPING", expectedAccepted: false,
    expectedBlockedGateIds: ["MAPPING_COVERAGE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_MISSING_MAPPING"],
    shouldThrow: false,
  },
  INCOMPLETE_PROVIDER: {
    id: "INCOMPLETE_PROVIDER", expectedAccepted: false,
    expectedBlockedGateIds: ["INSPECTION_COMPLETE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_SOURCE_INTEGRITY"],
    shouldThrow: false,
  },
  MISSING_AUDIT: {
    id: "MISSING_AUDIT", expectedAccepted: false,
    expectedBlockedGateIds: ["AUDIT_COVERAGE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  ALTERED_FINGERPRINT: {
    id: "ALTERED_FINGERPRINT", expectedAccepted: false,
    expectedBlockedGateIds: ["CANDIDATE_PROVENANCE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  STALE_OBSERVATION: {
    id: "STALE_OBSERVATION", expectedAccepted: true,
    expectedBlockedGateIds: [],
    expectedAdvisoryGateIds: ["AGE_POLICY"],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  FOREIGN_TENANT: {
    id: "FOREIGN_TENANT", expectedAccepted: false,
    expectedBlockedGateIds: ["TENANT_ISOLATION", "CANDIDATE_PROVENANCE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  INCOMPLETE_SNAPSHOT: {
    id: "INCOMPLETE_SNAPSHOT", expectedAccepted: false,
    expectedBlockedGateIds: [],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: [],
    shouldThrow: true,
  },
  DUPLICATE_CASE: {
    id: "DUPLICATE_CASE", expectedAccepted: false,
    expectedBlockedGateIds: ["REVIEW_CASE_PROVENANCE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  INVALID_CHECKLIST: {
    id: "INVALID_CHECKLIST", expectedAccepted: false,
    expectedBlockedGateIds: ["CASE_LIFECYCLE"],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_POSSIBLE_ADVISORY"],
    shouldThrow: false,
  },
  UNRESOLVED_PROVIDER: {
    id: "UNRESOLVED_PROVIDER", expectedAccepted: true,
    expectedBlockedGateIds: [],
    expectedAdvisoryGateIds: [],
    expectedAdviceStatuses: ["REVIEW_PROVIDER_UNCERTAINTY"],
    shouldThrow: false,
  },
};
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function problem(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    problem("Scenario matrix options must be an object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    problem("Scenario matrix " + label + " exceeds its bound.");
  return value;
}
function bool(value: unknown, label: string, fallback: boolean) {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean")
    problem("Scenario matrix " + label + " must be boolean.");
  return value;
}
export function parseScenarioMatrixOptions(raw: unknown = {}):
  ScenarioMatrixOptions {
  const source = object(raw);
  const allowed = [
    "scenarios", "maximumScenarios", "maximumInventoryAgeDays",
    "minimumMappedPercent", "requireCaseAudit",
    "requireAllCandidateReviews",
  ];
  if (Object.keys(source).some(key => !allowed.includes(key)))
    problem("Unexpected offline scenario matrix field.");
  const rawNames = source.scenarios ?? SCENARIO_IDS;
  if (!Array.isArray(rawNames) || rawNames.length === 0 ||
      rawNames.length > SCENARIO_IDS.length)
    problem("Scenario list is empty or exceeds available scenarios.");
  const ids = rawNames.map(value => {
    if (typeof value !== "string" ||
        !SCENARIO_IDS.includes(value as ScenarioCategory))
      problem("Unknown offline acceptance scenario.");
    return value as ScenarioCategory;
  });
  if (new Set(ids).size !== ids.length)
    problem("Scenario identifiers must be unique.");
  const maximumScenarios = integer(source.maximumScenarios ??
    SCENARIO_IDS.length, "capacity", 1, SCENARIO_IDS.length);
  if (ids.length > maximumScenarios)
    problem("Selected scenarios exceed the configured capacity.");
  return {
    scenarios: ids,
    maximumScenarios,
    maximumInventoryAgeDays: integer(source.maximumInventoryAgeDays ??
      30, "inventory age", 1, 365),
    minimumMappedPercent: integer(source.minimumMappedPercent ??
      100, "mapped percent", 0, 100),
    requireCaseAudit: bool(source.requireCaseAudit,
      "requireCaseAudit", true),
    requireAllCandidateReviews: bool(source.requireAllCandidateReviews,
      "requireAllCandidateReviews", true),
  };
}
export function fixtureForScenario(
  id: ScenarioCategory, evaluatedAt: Date,
): AcceptanceDataset {
  if (!Number.isFinite(evaluatedAt.getTime()))
    problem("Invalid fixture evaluation date.");
  if (!SCENARIO_IDS.includes(id))
    problem("Unknown fixture identifier.");
  const org = "synthetic-assets-acceptance";
  const inventory = "synthetic-import-2026";
  const inspection = "synthetic-inspection-2026";
  const packageBindings: PackageBinding[] = [{
    inventoryProduct: "Example Package",
    ecosystem: "npm", packageName: "example-package",
    expectedPurl: null,
  }];
  const recently = new Date(evaluatedAt.getTime() - 86400000);
  const snapshot: AdviceSnapshot = {
    importId: inventory, inspectionId: inspection,
    inspectionDigest: "a".repeat(64),
    inventoryDigest: "b".repeat(64),
    inspectionStatus: "COMPLETE",
    inspectionCompletedAt: recently,
    importedCount: 1,
    devices: [{
      externalId: "synthetic-asset-001",
      softwareName: "Example Package",
      softwareVersion: "1.2.3",
      normalizedProductKey: "example package",
      versionStatus: "EXACT", freshnessStatus: "FRESH",
      observedAt: recently,
      sourceRow: 2,
    }],
    queries: [{
      ecosystem: "npm", packageName: "example-package",
      version: "1.2.3",
      providerStatus: "COMPLETE",
      possibleIds: ["GHSA-aaaa-bbbb-cccc"],
      providerOnlyIds: [], unresolvedIds: [], withdrawnIds: [],
    }],
  };
  if (id === "AMBIGUOUS_VERSION") {
    snapshot.devices[0]!.versionStatus = "AMBIGUOUS";
    snapshot.devices[0]!.softwareVersion = null;
  }
  if (id === "INCOMPLETE_PROVIDER")
    snapshot.inspectionStatus = "PARTIAL";
  if (id === "STALE_OBSERVATION")
    snapshot.devices[0]!.observedAt = new Date(
      evaluatedAt.getTime() - 120 * 86400000);
  if (id === "INCOMPLETE_SNAPSHOT")
    snapshot.importedCount = 2;
  if (id === "UNRESOLVED_PROVIDER") {
    snapshot.queries[0]!.possibleIds = [];
    snapshot.queries[0]!.providerOnlyIds = ["CVE-2026-12345"];
  }
  const bindings = id === "MISSING_MAPPING" ? [] : packageBindings;
  const advice = id === "INCOMPLETE_SNAPSHOT" ? [] :
    buildAssetAdviceRows(snapshot, bindings, 30, evaluatedAt);
  const candidate = advice[0];
  const caseRow: CaseRow | null =
    id === "NO_REVIEW" || id === "AMBIGUOUS_VERSION" ||
    id === "MISSING_MAPPING" || id === "INCOMPLETE_PROVIDER" ||
    id === "INCOMPLETE_SNAPSHOT" || id === "UNRESOLVED_PROVIDER"
      ? null : candidate ? {
      id: "synthetic-review-case-001",
      organizationId: org,
      importId: inventory, inspectionId: inspection,
      evidenceFingerprint: candidate.evidenceFingerprint,
      inventoryDigest: snapshot.inventoryDigest,
      inspectionDigest: snapshot.inspectionDigest,
      externalId: candidate.assetId,
      normalizedProductKey: candidate.normalizedProductKey,
      softwareVersion: candidate.version,
      status: "IN_REVIEW",
      category: candidate.status, priority: candidate.priority,
      revision: 2, title: "Synthetic human review",
      rationale: { reasons: candidate.reasons },
      actions: candidate.actions, advisoryIds: candidate.possibleIds,
      openedAt: recently.toISOString(),
      lastDecisionAt: recently.toISOString(),
      lastDecisionReason: "Synthetic human review for regression only.",
      lastDecisionUserId: "synthetic-operator",
      steps: candidate.actions.map((action, index) => ({
        id: "synthetic-step-" + index,
        actionCode: action.code, status: "TODO", revision: 1,
        note: null, completedAt: null, completedByUserId: null,
      })),
    } : null;
  if (caseRow && id === "MISSING_AUDIT") {
    // The audit list is empty below; do not invent an audit record.
  }
  if (caseRow && id === "ALTERED_FINGERPRINT")
    caseRow.evidenceFingerprint = "f".repeat(64);
  if (caseRow && id === "FOREIGN_TENANT")
    caseRow.organizationId = "synthetic-foreign-tenant";
  if (caseRow && id === "INVALID_CHECKLIST")
    caseRow.status = "WORK_COMPLETED";
  const cases = caseRow ? [caseRow] : [];
  if (caseRow && id === "DUPLICATE_CASE")
    cases.push({ ...caseRow, id: "synthetic-review-case-002" });
  return {
    organizationId: org, checkedAt: evaluatedAt,
    snapshot, bindings, cases,
    auditCaseIds: id === "MISSING_AUDIT" ? [] :
      cases.map(row => row.id),
  };
}
function matrixPolicy(options: ScenarioMatrixOptions): AcceptancePolicy {
  return parseAcceptancePolicy({
    maximumInventoryAgeDays: options.maximumInventoryAgeDays,
    minimumMappedPercent: options.minimumMappedPercent,
    requireCaseAudit: options.requireCaseAudit,
    requireAllCandidateReviews: options.requireAllCandidateReviews,
  });
}
function failureCode(cause: unknown): string {
  if (cause instanceof WorkInputError) return cause.code;
  return "UNEXPECTED";
}
function runScenario(id: ScenarioCategory,
  now: Date, options: ScenarioMatrixOptions): ScenarioResult {
  const expected = expectations[id];
  const data = fixtureForScenario(id, now);
  const issues: string[] = [];
  let report: AcceptanceReport | null = null;
  let actualStatuses: AssetAdviceStatus[] = [];
  let observedException = false;
  let code: string | null = null;
  let verified = false;
  try {
    const rows = buildAssetAdviceRows(data.snapshot,
      data.bindings, options.maximumInventoryAgeDays, now);
    actualStatuses = [...new Set(rows.map(row => row.status))];
    report = evaluateAssetOfflineAcceptance(data, matrixPolicy(options));
    const verdict = verifyOfflineAcceptanceReport(report);
    verified = verdict.valid;
    if (!verdict.valid)
      issues.push("Offline acceptance report failed independent integrity checks.");
  } catch (cause) {
    observedException = true;
    code = failureCode(cause);
    if (code === "UNEXPECTED")
      issues.push("A scenario raised an unexpected error type.");
  }
  const actualBlocked = report?.gates.filter(gate =>
    gate.level === "BLOCK").map(gate => gate.id) ?? [];
  const actualAdvisory = report?.gates.filter(gate =>
    gate.level === "ADVISORY").map(gate => gate.id) ?? [];
  const blockedIds = new Set<string>(actualBlocked);
  const advisoryIds = new Set<string>(actualAdvisory);
  const missingBlockers = expected.expectedBlockedGateIds.filter(gate =>
    !blockedIds.has(gate));
  const unexpectedBlockers = actualBlocked.filter(gate =>
    !expected.expectedBlockedGateIds.includes(gate));
  const missingAdvisories = expected.expectedAdvisoryGateIds.filter(gate =>
    !advisoryIds.has(gate));
  const missingAdviceStatuses = expected.expectedAdviceStatuses.filter(status =>
    !actualStatuses.includes(status));
  if (expected.shouldThrow !== observedException)
    issues.push("The scenario did not follow its declared error boundary.");
  if (!expected.shouldThrow && report &&
      report.acceptanceEligible !== expected.expectedAccepted)
    issues.push("The acceptance eligibility differs from the reference case.");
  if (missingBlockers.length)
    issues.push("Expected mandatory gates failed to block.");
  if (unexpectedBlockers.length)
    issues.push("Unexpected mandatory gates blocked the scenario.");
  if (missingAdvisories.length)
    issues.push("Expected advisory gates were not observed.");
  if (missingAdviceStatuses.length && !expected.shouldThrow)
    issues.push("Expected conservative evidence category was not observed.");
  if (report && !verified)
    issues.push("The scenario's evidence fingerprint failed verification.");
  return {
    id, label: descriptions[id],
    passed: issues.length === 0,
    expectedAccepted: expected.expectedAccepted,
    observedAccepted: report?.acceptanceEligible ?? null,
    expectedException: expected.shouldThrow,
    observedException, errorCode: code,
    expectedBlockers: expected.expectedBlockedGateIds,
    actualBlockers: actualBlocked,
    unexpectedBlockers, missingBlockers,
    expectedAdvisories: expected.expectedAdvisoryGateIds,
    missingAdvisories, adviceStatuses: actualStatuses,
    missingAdviceStatuses,
    sourceImportId: data.snapshot.importId,
    sourceInspectionId: data.snapshot.inspectionId,
    candidateCount: report?.source.positiveCandidateCount ?? 0,
    reviewCaseCount: report?.source.reviewCaseCount ?? 0,
    validatedReport: verified,
    reportFingerprint: report?.reportDigest ?? null,
    concerns: issues,
  };
}
export function runOfflineScenarioMatrix(
  options: ScenarioMatrixOptions, now = new Date(),
): ScenarioMatrixReport {
  if (!Number.isFinite(now.getTime()))
    problem("Invalid matrix execution timestamp.");
  const results = options.scenarios.map(id =>
    runScenario(id, now, options));
  const canonical = {
    schema: "cyberpilot.assets.offline.scenario.matrix.v1" as const,
    generatedAt: now.toISOString(),
    synthetic: true as const,
    source: "BUILT_IN_SYNTHETIC_FIXTURES" as const,
    organizationId: "synthetic-assets-acceptance",
    options, totalRequested: options.scenarios.length,
    totalExecuted: results.length,
    passed: results.filter(item => item.passed).length,
    failed: results.filter(item => !item.passed).length,
    results, fixtureVersion: 1 as const,
    externalProviderContacted: false as const,
    customerDatabaseRead: false as const,
    customerDatabaseWritten: false as const,
    userActionRecorded: false as const,
    releaseAutomaticallyApproved: false as const,
  };
  return {
    ...canonical, resultsDigest: digest(canonical),
    warnings: [
      "All fixture packages, hosts, advisories, timestamps and human cases are synthetic.",
      "This matrix exercises the production acceptance algorithm without querying any customer data.",
      "Passing every reference fixture does not mean a production inventory or live provider has been accepted.",
      "No tenant was accessed, no finding created and no approval or security assurance was issued.",
    ],
  };
}
export function verifyOfflineScenarioMatrix(report: ScenarioMatrixReport): {
  valid: boolean;
  digestValid: boolean;
  resultCountValid: boolean;
  noSideEffects: boolean;
  scenarioCoverageValid: boolean;
  reasons: string[];
} {
  const { resultsDigest, warnings, ...canonical } = report;
  const expected = digest(canonical);
  const digestValid = /^[a-f0-9]{64}$/.test(resultsDigest) &&
    timingSafeEqual(Buffer.from(resultsDigest, "hex"),
      Buffer.from(expected, "hex"));
  const resultCountValid =
    report.results.length === report.totalExecuted &&
    report.results.length === report.totalRequested &&
    report.passed === report.results.filter(x => x.passed).length &&
    report.failed === report.results.filter(x => !x.passed).length;
  const noSideEffects =
    report.externalProviderContacted === false &&
    report.customerDatabaseRead === false &&
    report.customerDatabaseWritten === false &&
    report.userActionRecorded === false &&
    report.releaseAutomaticallyApproved === false;
  const scenarioCoverageValid =
    report.results.every(item => SCENARIO_IDS.includes(item.id)) &&
    new Set(report.results.map(item => item.id)).size ===
      report.results.length &&
    report.results.map(item => item.id).join("|") ===
      report.options.scenarios.join("|");
  const reasons = [
    ...(!digestValid ? ["Scenario report fingerprint mismatch."] : []),
    ...(!resultCountValid ? ["Scenario counts disagree."] : []),
    ...(!noSideEffects ? ["Unexpected side effect declared."] : []),
    ...(!scenarioCoverageValid ? ["Scenario coverage differs from request."] : []),
  ];
  return {
    valid: reasons.length === 0,
    digestValid, resultCountValid,
    noSideEffects, scenarioCoverageValid, reasons,
  };
}

/**
 * Independently correlate matrix outcomes with their configured safety gates.
 * A suite that only executes "clean" fixtures cannot establish fail-closed
 * behavior, even if every executed fixture succeeds.
 */
export type ScenarioMatrixCoverage = {
  referenceCount: number;
  requiredFailureReferences: number;
  executedFailureReferences: number;
  executedPassingReferences: number;
  exceptionCases: number;
  advisoryCases: number;
  protectedGateIds: string[];
  untestedGateIds: string[];
  unexpectedlyEligible: string[];
  unexpectedlyBlocked: string[];
  verdict: "COMPLETE_REFERENCE_SET" | "PARTIAL_REFERENCE_SET" | "FAILED";
  reasons: string[];
};
export function inspectScenarioMatrixCoverage(
  report: ScenarioMatrixReport,
): ScenarioMatrixCoverage {
  const required = SCENARIO_IDS.filter(id =>
    !expectations[id].expectedAccepted);
  const passing = report.results.filter(row => row.expectedAccepted);
  const failure = report.results.filter(row => !row.expectedAccepted);
  const mandatory = new Set<string>();
  const exercised = new Set<string>();
  for (const id of SCENARIO_IDS) {
    for (const gate of expectations[id].expectedBlockedGateIds)
      mandatory.add(gate);
  }
  for (const result of report.results) {
    if (!result.passed) continue;
    for (const gate of result.actualBlockers)
      exercised.add(gate);
  }
  const unexpectedlyEligible = report.results.filter(result =>
    !result.expectedAccepted && result.observedAccepted === true)
    .map(result => result.id);
  const unexpectedlyBlocked = report.results.filter(result =>
    result.expectedAccepted && result.observedAccepted === false)
    .map(result => result.id);
  const untestedGateIds = [...mandatory].filter(gate =>
    !exercised.has(gate)).sort();
  const reasons: string[] = [];
  if (!verifyOfflineScenarioMatrix(report).valid)
    reasons.push("The scenario report's canonical provenance failed verification.");
  if (report.failed > 0)
    reasons.push("One or more selected acceptance fixtures failed.");
  if (unexpectedlyEligible.length)
    reasons.push("A mandatory negative case was incorrectly release eligible.");
  if (unexpectedlyBlocked.length)
    reasons.push("A reference positive scenario was unexpectedly blocked.");
  const complete = report.results.length === SCENARIO_IDS.length &&
    report.results.every(result => SCENARIO_IDS.includes(result.id)) &&
    untestedGateIds.length === 0;
  if (!complete)
    reasons.push("The executed matrix does not cover every declared reference case and safety gate.");
  return {
    referenceCount: SCENARIO_IDS.length,
    requiredFailureReferences: required.length,
    executedFailureReferences: failure.length,
    executedPassingReferences: passing.length,
    exceptionCases: report.results.filter(row =>
      row.observedException).length,
    advisoryCases: report.results.filter(row =>
      row.expectedAdvisories.length).length,
    protectedGateIds: [...exercised].sort(),
    untestedGateIds,
    unexpectedlyEligible, unexpectedlyBlocked,
    verdict: reasons.length === 0 ? "COMPLETE_REFERENCE_SET" :
      report.failed > 0 || unexpectedlyEligible.length > 0 ?
        "FAILED" : "PARTIAL_REFERENCE_SET",
    reasons,
  };
}
