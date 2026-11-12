import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";
import { buildAssetAdviceRows } from "./assets-action-guidance";
import { normalizeInventoryProduct } from "./assets-csv-inventory";
import type { AdviceSnapshot } from "./assets-action-guidance";
import type { PackageBinding } from "./assets-osv-correlation";
import type { CaseRow } from "./assets-action-case-service";

export type AcceptanceGateId =
  "INVENTORY_COMPLETE" | "INSPECTION_COMPLETE" |
  "MAPPING_COVERAGE" | "NO_IMPLICIT_SAFE" |
  "CANDIDATE_PROVENANCE" | "REVIEW_CASE_PROVENANCE" |
  "CASE_LIFECYCLE" | "CHECKLIST_INTEGRITY" |
  "TENANT_ISOLATION" | "AUDIT_COVERAGE" |
  "UNKNOWN_EVIDENCE" | "AGE_POLICY";
export type AcceptanceLevel = "PASS" | "BLOCK" | "ADVISORY";
export type AcceptanceGate = {
  id: AcceptanceGateId;
  level: AcceptanceLevel;
  description: string;
  actual: number;
  expected: number | null;
  affectedCaseIds: string[];
  affectedAssetIds: string[];
  explanation: string;
};
export type AcceptancePolicy = {
  maximumInventoryAgeDays: number;
  minimumMappedPercent: number;
  allowIncompleteInspections: boolean;
  requireCaseAudit: boolean;
  requireAllCandidateReviews: boolean;
  maximumCaseAgeDays: number;
  maxCases: number;
};
export type AcceptanceDataset = {
  snapshot: AdviceSnapshot;
  bindings: PackageBinding[];
  cases: CaseRow[];
  auditCaseIds: string[];
  organizationId: string;
  checkedAt: Date;
};
export type AcceptanceCaseAssessment = {
  caseId: string;
  assetId: string;
  productKey: string;
  category: string;
  status: string;
  revision: number;
  fingerprintsMatch: boolean;
  sourceConsistent: boolean;
  workflowConsistent: boolean;
  stepCodesMatch: boolean;
  auditObserved: boolean;
  stale: boolean;
  issues: string[];
  proposedNextActions: string[];
};
export type AcceptanceReport = {
  schema: "cyberpilot.assets.offline.acceptance.v1";
  organizationId: string;
  importId: string;
  inspectionId: string;
  evaluatedAt: string;
  policy: AcceptancePolicy;
  source: {
    origin: "CUSTOMER_DECLARED_CSV";
    inspectionOrigin: "STORED_OSV_LEDGER";
    inventoryDigest: string;
    inspectionDigest: string;
    deviceCount: number;
    queryCount: number;
    reviewCaseCount: number;
    auditCount: number;
    positiveCandidateCount: number;
    unknownEvidenceCount: number;
    completeWithinSnapshot: boolean;
  };
  gates: AcceptanceGate[];
  cases: AcceptanceCaseAssessment[];
  scorecard: {
    passed: number;
    blocked: number;
    advisory: number;
    casesEvaluated: number;
    casesWithIssues: number;
    possibleCandidatesWithoutReview: number;
    mappedPercent: number;
    totalIssues: number;
  };
  acceptanceEligible: boolean;
  manualAcceptanceStillRequired: true;
  noExternalTenantsRequired: true;
  databaseWrites: 0;
  providerRequests: 0;
  findingsModified: false;
  cyberScoreModified: false;
  reportDigest: string;
  warnings: string[];
};
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function hash(input: unknown) {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
function object(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    invalid("Offline acceptance configuration must be an object.");
  return input as Record<string, unknown>;
}
function integer(value: unknown, key: string, low: number, high: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < low || value > high) invalid("Invalid acceptance policy " + key + ".");
  return value;
}
function flag(input: Record<string, unknown>, key: string, fallback: boolean) {
  if (input[key] === undefined) return fallback;
  if (typeof input[key] !== "boolean")
    invalid("Invalid acceptance policy flag " + key + ".");
  return input[key] as boolean;
}
export function parseAcceptancePolicy(input: unknown = {}): AcceptancePolicy {
  const raw = object(input);
  const allowed = ["maximumInventoryAgeDays", "minimumMappedPercent",
    "allowIncompleteInspections", "requireCaseAudit",
    "requireAllCandidateReviews", "maximumCaseAgeDays", "maxCases"];
  if (Object.keys(raw).some(key => !allowed.includes(key)))
    invalid("Unknown acceptance policy field.");
  return {
    maximumInventoryAgeDays: integer(raw.maximumInventoryAgeDays ?? 30,
      "inventory age", 1, 365),
    minimumMappedPercent: integer(raw.minimumMappedPercent ?? 80,
      "mapping coverage", 0, 100),
    allowIncompleteInspections: flag(raw, "allowIncompleteInspections", false),
    requireCaseAudit: flag(raw, "requireCaseAudit", true),
    requireAllCandidateReviews: flag(raw, "requireAllCandidateReviews", true),
    maximumCaseAgeDays: integer(raw.maximumCaseAgeDays ?? 90,
      "case age", 1, 365),
    maxCases: integer(raw.maxCases ?? 500,
      "case count", 1, 1000),
  };
}
function gate(id: AcceptanceGateId, ok: boolean, description: string,
  actual: number, expected: number | null, explanation: string,
  affectedCaseIds: string[] = [], affectedAssetIds: string[] = [],
  mandatory = true): AcceptanceGate {
  return {
    id, level: ok ? "PASS" : mandatory ? "BLOCK" : "ADVISORY",
    description, actual, expected, explanation,
    affectedCaseIds: [...new Set(affectedCaseIds)].sort(),
    affectedAssetIds: [...new Set(affectedAssetIds)].sort(),
  };
}
const allowedStatuses = new Set([
  "OPEN", "IN_REVIEW", "DISMISSED", "WORK_COMPLETED",
]);
const allowedSteps = new Set(["TODO", "IN_PROGRESS", "BLOCKED", "DONE"]);
function evaluateCase(row: CaseRow, evidence: ReturnType<
  typeof buildAssetAdviceRows>[number] | undefined,
  dataset: AcceptanceDataset, policy: AcceptancePolicy):
  AcceptanceCaseAssessment {
  const issues: string[] = [];
  const next: string[] = [];
  const fingerprintsMatch = !!evidence &&
    row.evidenceFingerprint === evidence.evidenceFingerprint &&
    row.category === evidence.status &&
    row.priority === evidence.priority &&
    row.softwareVersion === evidence.version;
  const sourceConsistent =
    row.organizationId === dataset.organizationId &&
    row.importId === dataset.snapshot.importId &&
    row.inspectionId === dataset.snapshot.inspectionId &&
    row.inventoryDigest === dataset.snapshot.inventoryDigest &&
    row.inspectionDigest === dataset.snapshot.inspectionDigest;
  const codes = evidence?.actions.map(action => action.code) ?? [];
  const actualCodes = row.steps.map(step => step.actionCode);
  const stepCodesMatch = !!evidence &&
    codes.length === actualCodes.length &&
    new Set(actualCodes).size === actualCodes.length &&
    codes.every(code => actualCodes.includes(code));
  let workflowConsistent = allowedStatuses.has(row.status) &&
    Number.isSafeInteger(row.revision) && row.revision > 0 &&
    row.steps.every(step =>
      allowedSteps.has(step.status) && Number.isSafeInteger(step.revision) &&
      step.revision > 0 &&
      (step.status !== "DONE" || !!step.completedAt)) &&
    (row.status !== "WORK_COMPLETED" ||
      (row.steps.length > 0 &&
        row.steps.every(step => step.status === "DONE"))) &&
    (row.status !== "DISMISSED" || !!row.lastDecisionReason);
  if (row.category === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION")
    workflowConsistent = false;
  const age = dataset.checkedAt.getTime() -
    new Date(row.openedAt).getTime();
  const stale = !Number.isFinite(age) || age < 0 ||
    age > policy.maximumCaseAgeDays * 86400000;
  const auditObserved = dataset.auditCaseIds.includes(row.id);
  if (!fingerprintsMatch) {
    issues.push("Saved case evidence no longer matches the selected inspection.");
    next.push("Review source inspection and open a fresh independent case if required.");
  }
  if (!sourceConsistent) {
    issues.push("Case source IDs or digests do not match the selected tenant evidence.");
    next.push("Investigate tenant and source provenance before continuing.");
  }
  if (!stepCodesMatch) {
    issues.push("Case checklist differs from its evidence-derived recommended actions.");
    next.push("Inspect historic checklist creation and evidence changes.");
  }
  if (!workflowConsistent) {
    issues.push("Human review lifecycle and checklist state disagree.");
    next.push("Reconcile the audited decision and checklist history.");
  }
  if (!auditObserved && policy.requireCaseAudit) {
    issues.push("No audit record was found for this case in the selected tenant.");
    next.push("Inspect retention and audit write integrity; do not reconstruct fictitious events.");
  }
  if (stale) {
    issues.push("Case age exceeds the acceptance policy.");
    next.push("Reassess current inventory and original advisory before updating work.");
  }
  if (issues.length === 0)
    next.push("Proceed to independent operator acceptance; never infer verified remediation.");
  return {
    caseId: row.id, assetId: row.externalId,
    productKey: row.normalizedProductKey, category: row.category,
    status: row.status, revision: row.revision,
    fingerprintsMatch, sourceConsistent, workflowConsistent,
    stepCodesMatch, auditObserved, stale, issues,
    proposedNextActions: next,
  };
}
export function evaluateAssetOfflineAcceptance(
  dataset: AcceptanceDataset, policy: AcceptancePolicy,
): AcceptanceReport {
  if (!Number.isFinite(dataset.checkedAt.getTime()))
    invalid("Invalid acceptance evaluation time.");
  if (dataset.cases.length > policy.maxCases)
    throw new WorkInputError("CONFLICT",
      "Acceptance case collection exceeded its configured bound.");
  const { snapshot, organizationId, checkedAt } = dataset;
  const recommendations = buildAssetAdviceRows(snapshot,
    dataset.bindings, policy.maximumInventoryAgeDays, checkedAt);
  const byIdentity = new Map(recommendations.map(row =>
    [row.assetId + "\u0000" + row.normalizedProductKey, row]));
  const caseKeys = new Set<string>();
  const duplicates: string[] = [];
  for (const row of dataset.cases) {
    const key = row.externalId + "\u0000" + row.normalizedProductKey;
    if (caseKeys.has(key)) duplicates.push(row.id);
    caseKeys.add(key);
  }
  const assessments = dataset.cases.map(row =>
    evaluateCase(row, byIdentity.get(
      row.externalId + "\u0000" + row.normalizedProductKey),
      dataset, policy));
  const possible = recommendations.filter(row =>
    row.status === "REVIEW_POSSIBLE_ADVISORY");
  const withoutReview = possible.filter(row =>
    !caseKeys.has(row.assetId + "\u0000" + row.normalizedProductKey));
  const mappedProducts = new Set(dataset.bindings.map(binding =>
    normalizeInventoryProduct(binding.inventoryProduct)));
  const unmapped = recommendations.filter(row =>
    !mappedProducts.has(row.normalizedProductKey));
  const unknown = recommendations.filter(row =>
    !["REVIEW_POSSIBLE_ADVISORY",
      "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION"].includes(row.status));
  const mappedPercent = recommendations.length === 0 ? 0 :
    Math.floor((recommendations.length - unmapped.length) * 100 /
      recommendations.length);
  const completeSource = snapshot.inspectionStatus === "COMPLETE" &&
    snapshot.importedCount === snapshot.devices.length &&
    snapshot.inspectionCompletedAt.getTime() <= checkedAt.getTime();
  const aged = recommendations.filter(row => {
    const age = checkedAt.getTime() -
      new Date(row.observedAt).getTime();
    return age < 0 || age >
      policy.maximumInventoryAgeDays * 86400000;
  });
  const mismatched = assessments.filter(row =>
    !row.fingerprintsMatch || !row.sourceConsistent);
  const badWorkflow = assessments.filter(row =>
    !row.workflowConsistent || !row.stepCodesMatch);
  const unaudited = assessments.filter(row => !row.auditObserved);
  const staleCases = assessments.filter(row => row.stale);
  const foreign = dataset.cases.filter(row =>
    row.organizationId !== organizationId);
  const gates: AcceptanceGate[] = [
    gate("INVENTORY_COMPLETE",
      snapshot.importedCount === snapshot.devices.length,
      "All saved inventory observations were read before computing a summary.",
      snapshot.devices.length, snapshot.importedCount,
      "A partial snapshot cannot be certified as complete."),
    gate("INSPECTION_COMPLETE", completeSource,
      "The provider inspection is stored and complete within the requested time.",
      completeSource ? 1 : 0, 1,
      "Incomplete provider replies and future-dated checks cannot establish coverage.",
      [], [], !policy.allowIncompleteInspections),
    gate("MAPPING_COVERAGE",
      mappedPercent >= policy.minimumMappedPercent,
      "Declared product-to-package mapping meets the configured threshold.",
      mappedPercent, policy.minimumMappedPercent,
      "Unmapped software must remain UNKNOWN, not safe.",
      [], unmapped.map(row => row.assetId)),
    gate("NO_IMPLICIT_SAFE",
      recommendations.every(row =>
        row.confidence !== "NO_POSITIVE_MATCH_IN_SCOPE" ||
        row.status === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION"),
      "No negative provider result has been promoted to verified endpoint safety.",
      recommendations.filter(row =>
        row.confidence === "NO_POSITIVE_MATCH_IN_SCOPE").length,
      null, "A bounded no-match is only an observation in this inspection."),
    gate("CANDIDATE_PROVENANCE", mismatched.length === 0,
      "Review cases retain the selected source's exact fingerprint and digests.",
      mismatched.length, 0, "Case provenance mismatches block acceptance.",
      mismatched.map(row => row.caseId)),
    gate("REVIEW_CASE_PROVENANCE", duplicates.length === 0,
      "Each asset and product has at most one case in the inspected source.",
      duplicates.length, 0,
      "Duplicate cases would misrepresent review coverage.", duplicates),
    gate("CASE_LIFECYCLE", badWorkflow.length === 0,
      "Case state and human checklist are internally consistent.",
      badWorkflow.length, 0,
      "Completed human work never proves an endpoint was remediated.",
      badWorkflow.map(row => row.caseId)),
    gate("CHECKLIST_INTEGRITY", assessments.every(row =>
      row.stepCodesMatch),
      "Saved checklist codes correspond to the selected evidence-derived actions.",
      badWorkflow.filter(row => !row.stepCodesMatch).length, 0,
      "An unexpected or missing action needs independent investigation.",
      badWorkflow.filter(row => !row.stepCodesMatch)
        .map(row => row.caseId)),
    gate("TENANT_ISOLATION", foreign.length === 0,
      "Every included review case belongs to this organization.",
      foreign.length, 0,
      "No cross-tenant case may be included in a local acceptance assessment.",
      foreign.map(row => row.id)),
    gate("AUDIT_COVERAGE", unaudited.length === 0,
      "Each selected review case has at least one local audit event.",
      unaudited.length, 0,
      "Absence of an audit row requires investigation.",
      unaudited.map(row => row.caseId), [], policy.requireCaseAudit),
    gate("UNKNOWN_EVIDENCE", withoutReview.length === 0,
      "Potential advisory associations have a traceable human review case.",
      withoutReview.length, 0,
      "Unreviewed candidates remain open questions, not verified exposures.",
      [], withoutReview.map(row => row.assetId),
      policy.requireAllCandidateReviews),
    gate("AGE_POLICY", aged.length === 0 && staleCases.length === 0,
      "Inventory and case ages are within configured assessment windows.",
      aged.length + staleCases.length, 0,
      "Aged observations must be refreshed or explicitly accepted as a limitation.",
      staleCases.map(row => row.caseId), aged.map(row => row.assetId),
      false),
  ];
  const scorecard = {
    passed: gates.filter(row => row.level === "PASS").length,
    blocked: gates.filter(row => row.level === "BLOCK").length,
    advisory: gates.filter(row => row.level === "ADVISORY").length,
    casesEvaluated: assessments.length,
    casesWithIssues: assessments.filter(row => row.issues.length).length,
    possibleCandidatesWithoutReview: withoutReview.length,
    mappedPercent,
    totalIssues: assessments.reduce((n, row) => n + row.issues.length, 0),
  };
  const canonical = {
    schema: "cyberpilot.assets.offline.acceptance.v1" as const,
    organizationId, importId: snapshot.importId,
    inspectionId: snapshot.inspectionId,
    evaluatedAt: checkedAt.toISOString(), policy,
    source: {
      origin: "CUSTOMER_DECLARED_CSV" as const,
      inspectionOrigin: "STORED_OSV_LEDGER" as const,
      inventoryDigest: snapshot.inventoryDigest,
      inspectionDigest: snapshot.inspectionDigest,
      deviceCount: snapshot.devices.length,
      queryCount: snapshot.queries.length,
      reviewCaseCount: dataset.cases.length,
      auditCount: dataset.auditCaseIds.length,
      positiveCandidateCount: possible.length,
      unknownEvidenceCount: unknown.length,
      completeWithinSnapshot: completeSource,
    },
    gates, cases: assessments, scorecard,
    acceptanceEligible: scorecard.blocked === 0,
    manualAcceptanceStillRequired: true as const,
    noExternalTenantsRequired: true as const,
    databaseWrites: 0 as const, providerRequests: 0 as const,
    findingsModified: false as const, cyberScoreModified: false as const,
  };
  return {
    ...canonical, reportDigest: hash(canonical),
    warnings: [
      "Eligibility is a local point-in-time assessment and is not a final release approval.",
      "An OSV query record does not prove installed software, exposure, exploitation or remediation.",
      "Human checklist completion and dismissal never update verified security findings.",
      "No tenant provider, outbound request, data mutation or scheduled worker is required.",
      "Manual acceptance, privacy retention policy and LIVE limitations remain separate gates.",
    ],
  };
}
