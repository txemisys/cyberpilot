import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import { inspectAssetOfflineAcceptance } from "./assets-offline-acceptance-service";
import { verifyOfflineAcceptanceReport } from "./assets-offline-acceptance-verification";
import { inspectAssetPrivacyReadiness } from "./assets-privacy-readiness-service";
import { verifyPersistedAssetReleaseReview,
  decodeReleaseSnapshot } from "./assets-release-review-verification";
import { parseScenarioMatrixOptions, runOfflineScenarioMatrix,
  inspectScenarioMatrixCoverage, verifyOfflineScenarioMatrix,
} from "./assets-offline-scenario-matrix";

export type ReleaseState =
  "PENDING" | "IN_REVIEW" | "ACCEPTED_OFFLINE" | "REJECTED" | "REOPENED";
export type ReleaseOperation =
  "START_REVIEW" | "ACCEPT_OFFLINE" | "REJECT" | "REOPEN";
export type ReleaseAcknowledgement =
  "OFFLINE_ONLY" | "SOURCE_LIMITATIONS" | "HUMAN_REVIEW" |
  "PRIVACY_AND_RETENTION" | "NO_VERIFIED_REMEDIATION" |
  "BACKUPS_NOT_ERASED";
export const REQUIRED_ACKNOWLEDGEMENTS: ReleaseAcknowledgement[] = [
  "OFFLINE_ONLY", "SOURCE_LIMITATIONS", "HUMAN_REVIEW",
  "PRIVACY_AND_RETENTION", "NO_VERIFIED_REMEDIATION",
  "BACKUPS_NOT_ERASED",
];
export type ReleaseCreate = {
  importId: string;
  inspectionId: string;
  bindings: unknown;
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
  reason: string;
  acknowledgements: ReleaseAcknowledgement[];
  exclusions: string[];
};
export type ReleaseTransition = {
  reviewId: string;
  expectedRevision: number;
  expectedEvidenceBundleDigest: string;
  operation: ReleaseOperation;
  reason: string;
  acknowledgements: ReleaseAcknowledgement[];
  bindings: unknown;
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
};
export type ReleaseQuery = {
  offset: number;
  limit: number;
  importId: string | null;
  inspectionId: string | null;
  state: ReleaseState | null;
};

function fail(code: "INVALID" | "FORBIDDEN" | "CONFLICT" | "MISSING",
  message: string): never {
  throw new WorkInputError(code, message);
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Release review command must be a JSON object.");
  return value as Record<string, unknown>;
}
function allowed(value: Record<string, unknown>, keys: string[]) {
  if (Object.keys(value).some(key => !keys.includes(key)))
    fail("INVALID", "Unsupported release review command property.");
}
function identifier(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid release review " + label + ".");
  return value;
}
function hash64(value: unknown, label: string) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))
    fail("INVALID", "Invalid " + label + " digest.");
  return value;
}
function explanation(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 20 ||
      value.length > 1500 || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "A meaningful operator reason of 20–1500 characters is required.");
  return value.trim();
}
function revision(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > 2147483647)
    fail("INVALID", "Expected revision must be a positive integer.");
  return value;
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equalsDigest(a: string, b: string) {
  return /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function acknowledge(value: unknown): ReleaseAcknowledgement[] {
  if (!Array.isArray(value) || value.length > REQUIRED_ACKNOWLEDGEMENTS.length ||
      value.some(x => !REQUIRED_ACKNOWLEDGEMENTS.includes(
        x as ReleaseAcknowledgement)) || new Set(value).size !== value.length)
    fail("INVALID", "Invalid or duplicated release acknowledgement.");
  return value as ReleaseAcknowledgement[];
}
function exclusions(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 20 ||
      value.some(x => typeof x !== "string" || x.length < 5 ||
        x.length > 250 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    fail("INVALID", "Invalid release exclusion declarations.");
  return value as string[];
}
function manager(scope: AssetScope) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Only organization administrators can sign release reviews.");
}
export function parseReleaseCreate(input: unknown): ReleaseCreate {
  const v = object(input);
  allowed(v, ["importId", "inspectionId", "bindings",
    "acceptancePolicy", "privacyPolicy", "reason",
    "acknowledgements", "exclusions"]);
  if (!Array.isArray(v.bindings) || v.bindings.length > 2000)
    fail("INVALID", "Explicit bounded package mappings are required.");
  return {
    importId: identifier(v.importId, "inventory ID"),
    inspectionId: identifier(v.inspectionId, "inspection ID"),
    bindings: v.bindings,
    acceptancePolicy: v.acceptancePolicy ?? {},
    privacyPolicy: v.privacyPolicy ?? {},
    reason: explanation(v.reason),
    acknowledgements: acknowledge(v.acknowledgements ?? []),
    exclusions: exclusions(v.exclusions ?? []),
  };
}
export function parseReleaseTransition(input: unknown): ReleaseTransition {
  const v = object(input);
  allowed(v, ["reviewId", "expectedRevision",
    "expectedEvidenceBundleDigest", "operation", "reason",
    "acknowledgements", "bindings", "acceptancePolicy", "privacyPolicy"]);
  if (!["START_REVIEW", "ACCEPT_OFFLINE", "REJECT", "REOPEN"]
    .includes(String(v.operation)))
    fail("INVALID", "Unsupported release review transition.");
  if (!Array.isArray(v.bindings) || v.bindings.length > 2000)
    fail("INVALID", "Release transitions require bounded source mappings.");
  return {
    reviewId: identifier(v.reviewId, "ID"),
    expectedRevision: revision(v.expectedRevision),
    expectedEvidenceBundleDigest: hash64(
      v.expectedEvidenceBundleDigest, "expected evidence bundle"),
    operation: v.operation as ReleaseOperation,
    reason: explanation(v.reason),
    acknowledgements: acknowledge(v.acknowledgements ?? []),
    bindings: v.bindings,
    acceptancePolicy: v.acceptancePolicy ?? {},
    privacyPolicy: v.privacyPolicy ?? {},
  };
}
export function parseReleaseQuery(input: unknown = {}): ReleaseQuery {
  const v = object(input);
  allowed(v, ["offset", "limit", "importId", "inspectionId", "state"]);
  const offset = v.offset ?? 0;
  const limit = v.limit ?? 25;
  if (typeof offset !== "number" || !Number.isSafeInteger(offset) ||
      offset < 0 || offset > 100000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    fail("INVALID", "Invalid release review pagination.");
  const states: ReleaseState[] = [
    "PENDING", "IN_REVIEW", "ACCEPTED_OFFLINE", "REJECTED", "REOPENED",
  ];
  if (v.state != null && !states.includes(v.state as ReleaseState))
    fail("INVALID", "Unknown release review state.");
  return {
    offset, limit,
    state: v.state == null ? null : v.state as ReleaseState,
    importId: v.importId == null ? null : identifier(v.importId, "import ID"),
    inspectionId: v.inspectionId == null ? null :
      identifier(v.inspectionId, "inspection ID"),
  };
}
export function releaseTarget(from: ReleaseState,
  operation: ReleaseOperation): ReleaseState | null {
  if ((from === "PENDING" || from === "REOPENED") &&
      operation === "START_REVIEW") return "IN_REVIEW";
  if (from === "IN_REVIEW" && operation === "ACCEPT_OFFLINE")
    return "ACCEPTED_OFFLINE";
  if ((from === "PENDING" || from === "IN_REVIEW" ||
       from === "REOPENED") && operation === "REJECT") return "REJECTED";
  if ((from === "ACCEPTED_OFFLINE" || from === "REJECTED") &&
      operation === "REOPEN") return "REOPENED";
  return null;
}
export function missingReleaseAcknowledgements(
  entries: ReleaseAcknowledgement[],
): ReleaseAcknowledgement[] {
  return REQUIRED_ACKNOWLEDGEMENTS.filter(value => !entries.includes(value));
}
type Evidence = Awaited<ReturnType<typeof collectReleaseEvidence>>;
export async function collectReleaseEvidence(scope: AssetScope,
  command: Pick<ReleaseCreate, "importId" | "inspectionId" | "bindings" |
    "acceptancePolicy" | "privacyPolicy">, now = new Date()) {
  manager(scope);
  const acceptance = await inspectAssetOfflineAcceptance(scope, {
    importId: command.importId, inspectionId: command.inspectionId,
    bindings: command.bindings, policy: command.acceptancePolicy,
  }, now);
  const verdict = verifyOfflineAcceptanceReport(acceptance);
  if (!verdict.valid)
    fail("CONFLICT", "Offline source report integrity verification failed.");
  const privacy = await inspectAssetPrivacyReadiness(scope, {
    policy: command.privacyPolicy,
  }, now);
  if (privacy.organizationId !== scope.organizationId ||
      acceptance.organizationId !== scope.organizationId)
    fail("CONFLICT", "Cross-tenant evidence cannot enter a release review.");
  const scenario = runOfflineScenarioMatrix(parseScenarioMatrixOptions(),
    now);
  const coverage = inspectScenarioMatrixCoverage(scenario);
  if (!verifyOfflineScenarioMatrix(scenario).valid)
    fail("CONFLICT", "Synthetic scenario digest verification failed.");
  const scenarioSummary = {
    schema: scenario.schema, source: scenario.source,
    totalExecuted: scenario.totalExecuted,
    passed: scenario.passed, failed: scenario.failed,
    verdict: coverage.verdict, missingGates: coverage.untestedGateIds,
    resultsDigest: scenario.resultsDigest, synthetic: true,
  };
  const policyDigest = digest({
    acceptance: acceptance.policy, privacy: privacy.policy,
  });
  const evidenceBundleDigest = digest({
    schema: "cyberpilot.assets.release.evidence.v1",
    organizationId: scope.organizationId,
    importId: command.importId, inspectionId: command.inspectionId,
    inventoryDigest: acceptance.source.inventoryDigest,
    inspectionDigest: acceptance.source.inspectionDigest,
    acceptanceDigest: acceptance.reportDigest,
    privacyDigest: privacy.digest,
    scenarioDigest: scenario.resultsDigest, policyDigest,
  });
  const blockers: string[] = [];
  if (!acceptance.acceptanceEligible ||
      acceptance.gates.some(g => g.level === "BLOCK"))
    blockers.push("OFFLINE_ACCEPTANCE_BLOCKED");
  if (!privacy.fullyExamined || privacy.readiness.blocked > 0 ||
      privacy.readiness.reviewNeeded > 0 ||
      !privacy.readiness.eligibleForPrivacySignoff)
    blockers.push("PRIVACY_REVIEW_PENDING");
  if (coverage.verdict !== "COMPLETE_REFERENCE_SET" ||
      scenario.failed > 0 || scenario.totalExecuted !== 13)
    blockers.push("SCENARIO_REFERENCE_INCOMPLETE");
  return {
    acceptance, privacy, scenarioSummary, policyDigest,
    evidenceBundleDigest, blockers,
    inventoryDigest: acceptance.source.inventoryDigest,
    inspectionDigest: acceptance.source.inspectionDigest,
    acceptanceDigest: acceptance.reportDigest,
    privacyDigest: privacy.digest,
    scenarioDigest: scenario.resultsDigest,
  };
}
function snapshotJson(value: unknown) {
  return { canonical: JSON.stringify(value) };
}
export function mayAcceptOffline(evidence: Evidence,
  acknowledgements: ReleaseAcknowledgement[]) {
  return evidence.blockers.length === 0 &&
    missingReleaseAcknowledgements(acknowledgements).length === 0;
}
function rowView(row: {
  id: string; organizationId: string; importId: string;
  inspectionId: string; inventoryDigest: string;
  inspectionDigest: string; acceptanceDigest: string;
  privacyDigest: string; scenarioDigest: string;
  evidenceBundleDigest: string; policyDigest: string;
  state: string; revision: number; operatorUserId: string;
  operatorReason: string; operatorAcknowledgements: unknown;
  exclusions: unknown; acceptanceSnapshot: unknown;
  privacySnapshot: unknown; scenarioSummary: unknown;
  createdAt: Date; updatedAt: Date; decidedAt: Date | null;
  decidedByUserId: string | null; decisionReason: string | null;
}) {
  return {
    ...row, verification: verifyPersistedAssetReleaseReview(row),
    acceptanceSnapshot: decodeReleaseSnapshot(row.acceptanceSnapshot),
    privacySnapshot: decodeReleaseSnapshot(row.privacySnapshot),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    decidedAt: row.decidedAt?.toISOString() ?? null,
    caution: "Human offline decision only; LIVE, remediation, and legal approval are not implied.",
  };
}
export async function listAssetReleaseReviews(scope: AssetScope,
  query: unknown = {}) {
  manager(scope);
  const options = parseReleaseQuery(query);
  const where = {
    organizationId: scope.organizationId,
    ...(options.importId ? { importId: options.importId } : {}),
    ...(options.inspectionId ? { inspectionId: options.inspectionId } : {}),
    ...(options.state ? { state: options.state } : {}),
  };
  const [total, rows] = await Promise.all([
    db.assetReleaseReview.count({ where }),
    db.assetReleaseReview.findMany({
      where, orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: options.offset, take: options.limit,
    }),
  ]);
  return {
    schema: "cyberpilot.assets.release.review.list.v1" as const,
    total, offset: options.offset, limit: options.limit,
    reviews: rows.map(rowView),
  };
}
export async function createAssetReleaseReview(scope: AssetScope,
  raw: unknown, now = new Date()) {
  manager(scope);
  const command = parseReleaseCreate(raw);
  const evidence = await collectReleaseEvidence(scope, command, now);
  const where = {
    organizationId: scope.organizationId,
    importId: command.importId, inspectionId: command.inspectionId,
  };
  const existing = await db.assetReleaseReview.findUnique({
    where: { organizationId_importId_inspectionId: where },
  });
  if (existing) {
    if (!equalsDigest(existing.evidenceBundleDigest, evidence.evidenceBundleDigest))
      fail("CONFLICT", "Release evidence changed; reopen and reassess the existing review.");
    return { replayed: true, review: rowView(existing),
      blockers: evidence.blockers };
  }
  try {
    const created = await db.$transaction(async tx => {
      const row = await tx.assetReleaseReview.create({ data: {
        ...where, inventoryDigest: evidence.inventoryDigest,
        inspectionDigest: evidence.inspectionDigest,
        acceptanceDigest: evidence.acceptanceDigest,
        privacyDigest: evidence.privacyDigest,
        scenarioDigest: evidence.scenarioDigest,
        evidenceBundleDigest: evidence.evidenceBundleDigest,
        policyDigest: evidence.policyDigest,
        operatorUserId: scope.userId,
        operatorReason: command.reason,
        operatorAcknowledgements: command.acknowledgements,
        exclusions: command.exclusions,
        acceptanceSnapshot: snapshotJson(evidence.acceptance),
        privacySnapshot: snapshotJson(evidence.privacy),
        scenarioSummary: snapshotJson(evidence.scenarioSummary),
      } });
      await tx.auditEvent.create({ data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assets.release.review.created",
        resourceType: "AssetReleaseReview", resourceId: row.id,
        metadata: { schema: "cyberpilot.assets.release.audit.v1",
          reason: command.reason, revision: 1, state: "PENDING",
          evidenceBundleDigest: evidence.evidenceBundleDigest,
          blockers: evidence.blockers, exclusions: command.exclusions },
      } });
      return row;
    });
    return { replayed: false, review: rowView(created),
      blockers: evidence.blockers };
  } catch (cause) {
    const previous = await db.assetReleaseReview.findUnique({
      where: { organizationId_importId_inspectionId: where },
    });
    if (previous && equalsDigest(previous.evidenceBundleDigest,
      evidence.evidenceBundleDigest))
      return { replayed: true, review: rowView(previous),
        blockers: evidence.blockers };
    if (previous)
      fail("CONFLICT", "Concurrent review has different evidence.");
    throw cause;
  }
}
export async function transitionAssetReleaseReview(scope: AssetScope,
  raw: unknown, now = new Date()) {
  manager(scope);
  const command = parseReleaseTransition(raw);
  const row = await db.assetReleaseReview.findFirst({
    where: { id: command.reviewId, organizationId: scope.organizationId },
  });
  if (!row) fail("MISSING", "Release review not found in this tenant.");
  if (!verifyPersistedAssetReleaseReview(row).verified)
    fail("CONFLICT", "Stored release review failed independent integrity verification.");
  if (row.revision !== command.expectedRevision)
    fail("CONFLICT", "Release review revision has changed.");
  if (!equalsDigest(row.evidenceBundleDigest,
    command.expectedEvidenceBundleDigest))
    fail("CONFLICT", "Release evidence fingerprint has changed.");
  const target = releaseTarget(row.state as ReleaseState, command.operation);
  if (!target)
    fail("CONFLICT", "Illegal release review lifecycle transition.");
  // Replay the original evaluation clock when checking the persisted
  // evidence identity. A new timestamp changes signed report digests even
  // when no source record changed, so the original clock is essential.
  const original = decodeReleaseSnapshot(row.acceptanceSnapshot) as {
    evaluatedAt?: unknown;
  } | null;
  if (!original || typeof original.evaluatedAt !== "string" ||
      !Number.isFinite(Date.parse(original.evaluatedAt)))
    fail("CONFLICT", "Stored acceptance evaluation clock is invalid.");
  const source = {
    importId: row.importId, inspectionId: row.inspectionId,
    bindings: command.bindings,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
  };
  const historical = await collectReleaseEvidence(
    scope, source, new Date(original.evaluatedAt));
  if (command.operation !== "REOPEN" &&
      !equalsDigest(row.evidenceBundleDigest,
        historical.evidenceBundleDigest))
    fail("CONFLICT", "Release source evidence or policy changed; reopen explicitly.");
  // Also inspect the present time: historical replay must not make a stale
  // inspection or an overdue privacy obligation appear currently eligible.
  const evidence = await collectReleaseEvidence(scope, source, now);
  if (command.operation === "ACCEPT_OFFLINE" &&
      !mayAcceptOffline(evidence, command.acknowledgements))
    fail("CONFLICT", "Mandatory current evidence blockers or acknowledgements remain.");
  if (command.operation === "ACCEPT_OFFLINE" &&
      (!equalsDigest(historical.inventoryDigest, evidence.inventoryDigest) ||
       !equalsDigest(historical.inspectionDigest, evidence.inspectionDigest)))
    fail("CONFLICT", "Inventory or inspection source changed during review.");
  const updated = await db.$transaction(async tx => {
    const result = await tx.assetReleaseReview.updateMany({
      where: {
        id: row.id, organizationId: scope.organizationId,
        revision: command.expectedRevision, state: row.state,
        evidenceBundleDigest: row.evidenceBundleDigest,
      },
      data: {
        revision: { increment: 1 }, state: target,
        evidenceBundleDigest: evidence.evidenceBundleDigest,
        inventoryDigest: evidence.inventoryDigest,
        inspectionDigest: evidence.inspectionDigest,
        acceptanceDigest: evidence.acceptanceDigest,
        privacyDigest: evidence.privacyDigest,
        scenarioDigest: evidence.scenarioDigest,
        policyDigest: evidence.policyDigest,
        acceptanceSnapshot: snapshotJson(evidence.acceptance),
        privacySnapshot: snapshotJson(evidence.privacy),
        scenarioSummary: snapshotJson(evidence.scenarioSummary),
        operatorAcknowledgements: command.acknowledgements,
        decidedAt: ["ACCEPTED_OFFLINE", "REJECTED"].includes(target)
          ? now : null,
        decidedByUserId: ["ACCEPTED_OFFLINE", "REJECTED"].includes(target)
          ? scope.userId : null,
        decisionReason: command.reason,
      },
    });
    if (result.count !== 1)
      fail("CONFLICT", "Concurrent release review transition rejected.");
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assets.release.review." + command.operation.toLowerCase(),
      resourceType: "AssetReleaseReview", resourceId: row.id,
      metadata: {
        schema: "cyberpilot.assets.release.audit.v1",
        from: row.state, to: target,
        revisionBefore: command.expectedRevision,
        revisionAfter: command.expectedRevision + 1,
        evidenceBundleDigest: evidence.evidenceBundleDigest,
        reason: command.reason,
        acknowledgements: command.acknowledgements,
        blockersAtDecision: evidence.blockers,
        manualOperatorDecision: true,
        noLiveProviderAttestation: true,
      },
    } });
    return tx.assetReleaseReview.findUniqueOrThrow({
      where: { id: row.id },
    });
  });
  return { review: rowView(updated), blockers: evidence.blockers,
    decisionRecorded: true };
}
