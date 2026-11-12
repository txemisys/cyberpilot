import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import { verifyPersistedAssetReleaseReview,
  decodeReleaseSnapshot } from "./assets-release-review-verification";

export type ReleaseAuditOperation =
  "CREATED" | "START_REVIEW" | "ACCEPT_OFFLINE" | "REJECT" | "REOPEN";
export type ReleaseAuditIssueCode =
  "MISSING_CREATION" | "DUPLICATE_CREATION" |
  "REVISION_GAP" | "REVISION_REPEATED" | "REVISION_OUT_OF_ORDER" |
  "STATE_TRANSITION_INVALID" | "STATE_MISMATCH" |
  "DIGEST_MISMATCH" | "ACTOR_MISSING" | "EVENT_METADATA_INVALID" |
  "EVENT_RESOURCE_MISMATCH" | "EVENT_CLOCK_INVALID" |
  "DECISION_WITHOUT_REASON" | "ACKNOWLEDGEMENT_MISSING" |
  "BLOCKERS_AT_ACCEPTANCE" | "AUDIT_LIMIT_EXCEEDED" |
  "REVIEW_EVIDENCE_INVALID" | "REVIEW_WITHOUT_AUDIT" |
  "UNEXPECTED_ACTION" | "TERMINAL_DECISION_MISSING";
export type ReleaseAuditIssue = {
  code: ReleaseAuditIssueCode;
  severity: "BLOCK" | "REVIEW";
  eventId: string | null;
  revision: number | null;
  detail: string;
};
export type ReleaseAuditEvent = {
  id: string;
  action: string;
  operation: ReleaseAuditOperation | null;
  occurredAt: string;
  actorUserId: string | null;
  actorType: string;
  resourceId: string | null;
  from: string | null;
  to: string | null;
  revisionBefore: number | null;
  revisionAfter: number | null;
  evidenceBundleDigest: string | null;
  reason: string | null;
  acknowledgements: string[];
  blockersAtDecision: string[];
  manualOperatorDecision: boolean | null;
  noLiveProviderAttestation: boolean | null;
  metadataSchema: string | null;
  integrity: "VALID" | "INVALID";
  issues: ReleaseAuditIssue[];
};
export type ReleaseAuditRevision = {
  revision: number;
  eventId: string;
  operation: ReleaseAuditOperation;
  from: string | null;
  to: string;
  actorUserId: string | null;
  occurredAt: string;
  evidenceBundleDigest: string;
  changeSummary: string[];
};
export type ReleaseAuditDossier = {
  schema: "cyberpilot.assets.release.audit.dossier.v1";
  organizationId: string;
  reviewId: string;
  importId: string;
  inspectionId: string;
  checkedAt: string;
  persistedState: string;
  persistedRevision: number;
  persistedBundleDigest: string;
  persistedVerification: ReturnType<typeof verifyPersistedAssetReleaseReview>;
  totalEvents: number;
  completeEventSet: boolean;
  events: ReleaseAuditEvent[];
  revisions: ReleaseAuditRevision[];
  issues: ReleaseAuditIssue[];
  blockers: number;
  reviewsNeeded: number;
  auditConsistent: boolean;
  evidenceConsistent: boolean;
  decisionComplete: boolean;
  requiresHumanReconciliation: boolean;
  acceptanceRecorded: boolean;
  signedExternalAttestation: false;
  liveProviderChecked: false;
  remediationVerified: false;
  legalSignoffVerified: false;
  mutationCount: 0;
  digest: string;
  caveats: string[];
};
export type ReleaseAuditOptions = {
  reviewId: string;
  maximumEvents: number;
  includeMetadata: boolean;
  includeDecisionReasons: boolean;
};
type AuditInputRow = {
  id: string;
  organizationId: string;
  actorType: string;
  actorUserId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  occurredAt: Date;
  metadata: unknown;
};
type ReviewInput = Parameters<typeof verifyPersistedAssetReleaseReview>[0] & {
  id: string;
  operatorUserId: string;
  operatorReason: string;
  createdAt: Date;
  updatedAt: Date;
};
const supportedOperations: Record<string, ReleaseAuditOperation> = {
  "assets.release.review.created": "CREATED",
  "assets.release.review.start_review": "START_REVIEW",
  "assets.release.review.accept_offline": "ACCEPT_OFFLINE",
  "assets.release.review.reject": "REJECT",
  "assets.release.review.reopen": "REOPEN",
};
const stateNames = ["PENDING", "IN_REVIEW", "ACCEPTED_OFFLINE",
  "REJECTED", "REOPENED"] as const;
const acknowledgementIds = [
  "OFFLINE_ONLY", "SOURCE_LIMITATIONS", "HUMAN_REVIEW",
  "PRIVACY_AND_RETENTION", "NO_VERIFIED_REMEDIATION",
  "BACKUPS_NOT_ERASED",
];
const caveats = [
  "This dossier reconstructs local database audit events, not an external signed audit log.",
  "SHA-256 checks internal consistency; it does not prove identity, non-repudiation or external origin.",
  "Absent or malformed audit events block operational acceptance and must not be reconstructed.",
  "Manual review is independent from passing fixtures, CI, privacy policy or provider results.",
  "ACCEPTED_OFFLINE is not a confirmation of LIVE OSV availability or endpoint remediation.",
  "No retention approval, backup erasure or legal signoff is inferred from a local decision.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equalDigest(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string" ||
      !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b))
    return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function object(value: unknown): Record<string, unknown> | null {
  if (!value || Array.isArray(value) || typeof value !== "object")
    return null;
  return value as Record<string, unknown>;
}
function id(value: unknown): string {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid release review identifier.");
  return value;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    fail("INVALID", "Invalid bounded release audit event limit.");
  return value;
}
export function parseReleaseAuditOptions(raw: unknown): ReleaseAuditOptions {
  const source = object(raw);
  if (!source) fail("INVALID", "Release audit input must be an object.");
  const allowed = ["reviewId", "maximumEvents", "includeMetadata",
    "includeDecisionReasons"];
  if (Object.keys(source).some(key => !allowed.includes(key)))
    fail("INVALID", "Unexpected release audit option.");
  for (const key of ["includeMetadata", "includeDecisionReasons"])
    if (source[key] !== undefined && typeof source[key] !== "boolean")
      fail("INVALID", "Release audit disclosure control must be boolean.");
  return {
    reviewId: id(source.reviewId),
    maximumEvents: source.maximumEvents === undefined ? 250 :
      integer(source.maximumEvents, 1, 1000),
    includeMetadata: source.includeMetadata === true,
    includeDecisionReasons: source.includeDecisionReasons === true,
  };
}
function issue(code: ReleaseAuditIssueCode,
  detail: string, eventId: string | null = null,
  revision: number | null = null,
  severity: "BLOCK" | "REVIEW" = "BLOCK"): ReleaseAuditIssue {
  return { code, detail, eventId, revision, severity };
}
function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
function number(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value)
    ? value : null;
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100 ||
      value.some(item => typeof item !== "string"))
    return [];
  return value as string[];
}
function fromMetadata(row: AuditInputRow,
  includeDecisionReasons: boolean): ReleaseAuditEvent {
  const meta = object(row.metadata);
  const operation = supportedOperations[row.action] ?? null;
  const before = number(meta?.revisionBefore);
  const after = number(meta?.revisionAfter);
  const created = operation === "CREATED";
  const revisionBefore = created ? 0 : before;
  const revisionAfter = created ? number(meta?.revision) : after;
  const from = created ? null : str(meta?.from);
  const to = created ? str(meta?.state) : str(meta?.to);
  const evidenceBundleDigest = str(meta?.evidenceBundleDigest);
  const reason = str(meta?.reason);
  const acknowledgements = strings(meta?.acknowledgements);
  const blockersAtDecision = strings(meta?.blockersAtDecision);
  const manualOperatorDecision =
    typeof meta?.manualOperatorDecision === "boolean"
      ? meta.manualOperatorDecision : null;
  const noLiveProviderAttestation =
    typeof meta?.noLiveProviderAttestation === "boolean"
      ? meta.noLiveProviderAttestation : null;
  const issues: ReleaseAuditIssue[] = [];
  if (!operation)
    issues.push(issue("UNEXPECTED_ACTION",
      "Unknown release event cannot be interpreted as a human decision.",
      row.id, revisionAfter));
  if (row.resourceType !== "AssetReleaseReview" ||
      !row.resourceId)
    issues.push(issue("EVENT_RESOURCE_MISMATCH",
      "Release event is not linked to an AssetReleaseReview.", row.id,
      revisionAfter));
  if (!Number.isFinite(row.occurredAt.getTime()))
    issues.push(issue("EVENT_CLOCK_INVALID",
      "Audit event timestamp is not finite.", row.id, revisionAfter));
  if (row.actorType !== "USER" || !row.actorUserId)
    issues.push(issue("ACTOR_MISSING",
      "Release decision requires an identified user actor.", row.id,
      revisionAfter));
  if (str(meta?.schema) !== "cyberpilot.assets.release.audit.v1")
    issues.push(issue("EVENT_METADATA_INVALID",
      "Audit event has an unknown schema.", row.id, revisionAfter));
  if (revisionBefore === null || revisionAfter === null ||
      revisionAfter < 1 || revisionBefore !== revisionAfter - 1)
    issues.push(issue("EVENT_METADATA_INVALID",
      "Audit CAS revision pair is absent or inconsistent.", row.id,
      revisionAfter));
  if (!to || !stateNames.includes(to as typeof stateNames[number]) ||
      (!created && (!from ||
        !stateNames.includes(from as typeof stateNames[number]))))
    issues.push(issue("EVENT_METADATA_INVALID",
      "Transition state is missing or unsupported.", row.id, revisionAfter));
  if (!equalDigest(evidenceBundleDigest, evidenceBundleDigest))
    issues.push(issue("DIGEST_MISMATCH",
      "Audit bundle digest is not a SHA-256 hexadecimal value.", row.id,
      revisionAfter));
  if (!reason || reason.trim().length < 20)
    issues.push(issue("DECISION_WITHOUT_REASON",
      "Every human audit action requires a meaningful reason.", row.id,
      revisionAfter));
  if (operation !== "CREATED" &&
      (manualOperatorDecision !== true ||
        noLiveProviderAttestation !== true))
    issues.push(issue("EVENT_METADATA_INVALID",
      "Human and non-LIVE scope flags must remain explicit.", row.id,
      revisionAfter));
  if (operation === "ACCEPT_OFFLINE" &&
      (acknowledgements.length !== acknowledgementIds.length ||
        acknowledgementIds.some(ack => !acknowledgements.includes(ack))))
    issues.push(issue("ACKNOWLEDGEMENT_MISSING",
      "Offline acceptance did not record every mandatory human acknowledgement.",
      row.id, revisionAfter));
  if (operation === "ACCEPT_OFFLINE" && blockersAtDecision.length)
    issues.push(issue("BLOCKERS_AT_ACCEPTANCE",
      "Acceptance event contains unresolved mandatory blockers.",
      row.id, revisionAfter));
  return {
    id: row.id, action: row.action,
    operation, occurredAt: Number.isFinite(row.occurredAt.getTime())
      ? row.occurredAt.toISOString() : "INVALID",
    actorUserId: row.actorUserId, actorType: row.actorType,
    resourceId: row.resourceId, from, to,
    revisionBefore, revisionAfter, evidenceBundleDigest,
    reason: includeDecisionReasons ? reason : null,
    acknowledgements, blockersAtDecision,
    manualOperatorDecision, noLiveProviderAttestation,
    metadataSchema: str(meta?.schema),
    integrity: issues.length === 0 ? "VALID" : "INVALID",
    issues,
  };
}
export function nextReleaseAuditState(from: string | null,
  operation: ReleaseAuditOperation): string | null {
  if (operation === "CREATED") return from === null ? "PENDING" : null;
  if (operation === "START_REVIEW")
    return from === "PENDING" || from === "REOPENED" ? "IN_REVIEW" : null;
  if (operation === "ACCEPT_OFFLINE")
    return from === "IN_REVIEW" ? "ACCEPTED_OFFLINE" : null;
  if (operation === "REJECT")
    return from === "PENDING" || from === "IN_REVIEW" ||
      from === "REOPENED" ? "REJECTED" : null;
  if (operation === "REOPEN")
    return from === "ACCEPTED_OFFLINE" || from === "REJECTED"
      ? "REOPENED" : null;
  return null;
}
function changes(event: ReleaseAuditEvent,
  previous: ReleaseAuditEvent | null): string[] {
  const summary: string[] = [];
  if (!previous) summary.push("INITIAL_RECORD");
  else {
    if (event.from !== previous.to) summary.push("STATE_BREAK");
    if (!equalDigest(event.evidenceBundleDigest,
      previous.evidenceBundleDigest)) summary.push("EVIDENCE_DIGEST_CHANGED");
    if (event.actorUserId !== previous.actorUserId)
      summary.push("OPERATOR_CHANGED");
  }
  if (event.operation === "ACCEPT_OFFLINE") summary.push("HUMAN_OFFLINE_ACCEPTED");
  if (event.operation === "REJECT") summary.push("HUMAN_REJECTED");
  if (event.operation === "REOPEN") summary.push("HUMAN_REOPENED");
  if (event.operation === "START_REVIEW") summary.push("REVIEW_STARTED");
  return summary;
}
export function evaluateReleaseAuditDossier(
  review: ReviewInput,
  auditRows: AuditInputRow[],
  options: ReleaseAuditOptions,
  checkedAt: Date,
  completeEventSet = true,
): ReleaseAuditDossier {
  if (!Number.isFinite(checkedAt.getTime()))
    fail("INVALID", "Audit evaluation clock is invalid.");
  if (review.id !== options.reviewId)
    fail("CONFLICT", "Audit review identity mismatch.");
  if (auditRows.length > options.maximumEvents)
    fail("CONFLICT", "Release audit event set exceeds the requested bound.");
  const sorted = [...auditRows].sort((a, b) =>
    a.occurredAt.getTime() - b.occurredAt.getTime() ||
    a.id.localeCompare(b.id));
  const events = sorted.map(row =>
    fromMetadata(row, options.includeDecisionReasons));
  const issues = events.flatMap(event => event.issues);
  const revisions: ReleaseAuditRevision[] = [];
  let previous: ReleaseAuditEvent | null = null;
  let expectedRevision = 1;
  let currentState: string | null = null;
  const seenRevisions = new Set<number>();
  let acceptedEvents = 0;
  let terminalEvents = 0;
  for (const event of events) {
    const rev = event.revisionAfter;
    if (event.resourceId !== review.id ||
        sorted.some(row => row.id === event.id &&
          row.organizationId !== review.organizationId))
      issues.push(issue("EVENT_RESOURCE_MISMATCH",
        "Event is not scoped to this exact tenant and review.",
        event.id, rev));
    if (rev !== null) {
      if (seenRevisions.has(rev))
        issues.push(issue("REVISION_REPEATED",
          "More than one audit event claims the same CAS revision.",
          event.id, rev));
      seenRevisions.add(rev);
      if (rev > expectedRevision)
        issues.push(issue("REVISION_GAP",
          "One or more audited revisions are missing.",
          event.id, rev));
      if (rev < expectedRevision)
        issues.push(issue("REVISION_OUT_OF_ORDER",
          "Audit history is not a strictly increasing CAS sequence.",
          event.id, rev));
    }
    if (event.operation) {
      const target = nextReleaseAuditState(
        currentState, event.operation);
      if (!target || target !== event.to ||
          (event.operation !== "CREATED" &&
            event.from !== currentState))
        issues.push(issue("STATE_TRANSITION_INVALID",
          "Event transition does not follow the release state machine.",
          event.id, rev));
      if (target) currentState = target;
      if (event.operation === "ACCEPT_OFFLINE") acceptedEvents++;
      if (event.operation === "REJECT" ||
          event.operation === "ACCEPT_OFFLINE") terminalEvents++;
      if (rev !== null && target && event.evidenceBundleDigest) {
        revisions.push({
          revision: rev, eventId: event.id,
          operation: event.operation,
          from: event.from, to: target,
          actorUserId: event.actorUserId,
          occurredAt: event.occurredAt,
          evidenceBundleDigest: event.evidenceBundleDigest,
          changeSummary: changes(event, previous),
        });
      }
    }
    if (rev !== null) expectedRevision = Math.max(expectedRevision, rev + 1);
    previous = event;
  }
  if (!completeEventSet)
    issues.push(issue("AUDIT_LIMIT_EXCEEDED",
      "Audit query was truncated; no acceptance is allowed."));
  if (!events.length)
    issues.push(issue("REVIEW_WITHOUT_AUDIT",
      "Review exists without a corresponding transaction audit."));
  const firstCreated = events.filter(event => event.operation === "CREATED");
  if (firstCreated.length === 0)
    issues.push(issue("MISSING_CREATION",
      "The initiating PENDING event cannot be verified."));
  if (firstCreated.length > 1)
    issues.push(issue("DUPLICATE_CREATION",
      "More than one creation audit exists for one review."));
  if (review.revision !== expectedRevision - 1)
    issues.push(issue("REVISION_GAP",
      "Persisted review revision differs from audited CAS history.",
      null, review.revision));
  if (events.length && currentState !== review.state)
    issues.push(issue("STATE_MISMATCH",
      "Persisted review state differs from reconstructed audit state."));
  if (events.length &&
      !equalDigest(events[events.length - 1]!.evidenceBundleDigest,
        review.evidenceBundleDigest))
    issues.push(issue("DIGEST_MISMATCH",
      "Final audit event digest differs from the persisted bundle."));
  if (review.state === "ACCEPTED_OFFLINE" && !acceptedEvents)
    issues.push(issue("TERMINAL_DECISION_MISSING",
      "An accepted record has no corresponding human acceptance event."));
  if (review.state === "REJECTED" &&
      (!terminalEvents || previous?.operation !== "REJECT"))
    issues.push(issue("TERMINAL_DECISION_MISSING",
      "Rejected state lacks a matching final decision audit."));
  const verification = verifyPersistedAssetReleaseReview(review);
  if (!verification.verified)
    issues.push(issue("REVIEW_EVIDENCE_INVALID",
      "Stored release evidence fails independent snapshot verification."));
  const blockers = issues.filter(row => row.severity === "BLOCK").length;
  const reviewsNeeded = issues.filter(row => row.severity === "REVIEW").length;
  const auditConsistent = blockers === 0 && completeEventSet;
  const canonical = {
    schema: "cyberpilot.assets.release.audit.dossier.v1" as const,
    organizationId: review.organizationId, reviewId: review.id,
    importId: review.importId, inspectionId: review.inspectionId,
    checkedAt: checkedAt.toISOString(),
    persistedState: review.state,
    persistedRevision: review.revision,
    persistedBundleDigest: review.evidenceBundleDigest,
    persistedVerification: verification,
    totalEvents: events.length, completeEventSet,
    events, revisions, issues, blockers, reviewsNeeded,
    auditConsistent, evidenceConsistent: verification.verified,
    decisionComplete:
      auditConsistent && verification.verified &&
      (review.state === "ACCEPTED_OFFLINE" || review.state === "REJECTED"),
    requiresHumanReconciliation: !auditConsistent || !verification.verified,
    acceptanceRecorded:
      auditConsistent && verification.verified &&
      review.state === "ACCEPTED_OFFLINE" && acceptedEvents > 0,
    signedExternalAttestation: false as const,
    liveProviderChecked: false as const,
    remediationVerified: false as const,
    legalSignoffVerified: false as const,
    mutationCount: 0 as const,
  };
  return {
    ...canonical, digest: hash(canonical), caveats,
  };
}
export function verifyReleaseAuditDossier(
  report: ReleaseAuditDossier,
): { valid: boolean; reasons: string[] } {
  const { digest, caveats: notes, ...canonical } = report;
  const reasons: string[] = [];
  if (!equalDigest(digest, hash(canonical)))
    reasons.push("Audit dossier canonical digest is altered.");
  if (report.totalEvents !== report.events.length)
    reasons.push("Audited event count does not match its items.");
  if (report.blockers !== report.issues.filter(
    row => row.severity === "BLOCK").length)
    reasons.push("Audit dossier blocker count is inconsistent.");
  if (report.revisions.some((entry, index) =>
    index > 0 && entry.revision <= report.revisions[index - 1]!.revision))
    reasons.push("Audit revisions are not strictly increasing.");
  if (report.mutationCount !== 0 ||
      report.signedExternalAttestation !== false ||
      report.liveProviderChecked !== false ||
      report.remediationVerified !== false ||
      report.legalSignoffVerified !== false)
    reasons.push("Audit dossier makes an unsupported operational claim.");
  if (!Array.isArray(notes) || notes.length < 4)
    reasons.push("Audit dossier is missing scope disclaimers.");
  return { valid: reasons.length === 0, reasons };
}
export type ReleaseAuditTrend = {
  reviewed: number;
  accepted: number;
  rejected: number;
  open: number;
  invalid: number;
  decisionsByActor: Array<{ userId: string; count: number }>;
  operations: Array<{ name: string; count: number }>;
  lastEventAt: string | null;
};
export function summarizeReleaseAuditDossiers(
  dossiers: ReleaseAuditDossier[],
): ReleaseAuditTrend {
  const actors = new Map<string, number>();
  const operations = new Map<string, number>();
  let latest = 0;
  for (const report of dossiers) {
    for (const event of report.events) {
      if (event.actorUserId)
        actors.set(event.actorUserId, (actors.get(event.actorUserId) ?? 0) + 1);
      if (event.operation)
        operations.set(event.operation,
          (operations.get(event.operation) ?? 0) + 1);
      const when = Date.parse(event.occurredAt);
      if (Number.isFinite(when)) latest = Math.max(latest, when);
    }
  }
  return {
    reviewed: dossiers.length,
    accepted: dossiers.filter(item => item.acceptanceRecorded).length,
    rejected: dossiers.filter(item =>
      item.persistedState === "REJECTED" && item.decisionComplete).length,
    open: dossiers.filter(item => !item.decisionComplete).length,
    invalid: dossiers.filter(item => !item.auditConsistent ||
      !item.evidenceConsistent).length,
    decisionsByActor: [...actors].map(([userId, count]) =>
      ({ userId, count })).sort((a, b) =>
        b.count - a.count || a.userId.localeCompare(b.userId)),
    operations: [...operations].map(([name, count]) =>
      ({ name, count })).sort((a, b) => a.name.localeCompare(b.name)),
    lastEventAt: latest ? new Date(latest).toISOString() : null,
  };
}
export async function inspectReleaseAuditDossier(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<ReleaseAuditDossier> {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Release forensic dossiers require ADMIN or OWNER.");
  const options = parseReleaseAuditOptions(input);
  const review = await db.assetReleaseReview.findFirst({
    where: { id: options.reviewId, organizationId: scope.organizationId },
  });
  if (!review) fail("MISSING", "No release review exists in this organization.");
  const where = {
    organizationId: scope.organizationId,
    resourceType: "AssetReleaseReview",
    resourceId: review.id,
  };
  const total = await db.auditEvent.count({ where });
  if (total > options.maximumEvents)
    fail("CONFLICT", "Bounded audit query cannot inspect every event.");
  const events = await db.auditEvent.findMany({
    where, orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
    take: options.maximumEvents + 1,
  });
  if (events.length !== total)
    fail("CONFLICT", "Audit event set changed during inspection.");
  const report = evaluateReleaseAuditDossier(
    review, events, options, now, true);
  if (!verifyReleaseAuditDossier(report).valid)
    fail("CONFLICT", "Generated release dossier integrity check failed.");
  return report;
}
export function formatReleaseAuditExport(report: ReleaseAuditDossier) {
  const verification = verifyReleaseAuditDossier(report);
  if (!verification.valid)
    fail("CONFLICT", "Cannot export an altered audit dossier.");
  return {
    exportSchema: "cyberpilot.assets.release.audit.export.v1" as const,
    exportedAt: report.checkedAt,
    organizationId: report.organizationId,
    reviewId: report.reviewId,
    dossier: report,
    verification,
    offlineOnly: true as const,
    publicKeySignaturePresent: false as const,
    regulatoryApprovalPresent: false as const,
  };
}
export function auditIncidentPlaybook(report: ReleaseAuditDossier) {
  const steps: Array<{ priority: "BLOCK" | "REVIEW";
    issue: string; instruction: string }> = [];
  const instruction: Record<ReleaseAuditIssueCode, string> = {
    MISSING_CREATION: "Inspect the originating transaction and backup audit history.",
    DUPLICATE_CREATION: "Investigate duplicate creation events and idempotency boundaries.",
    REVISION_GAP: "Retrieve missing CAS audit revisions before any acceptance.",
    REVISION_REPEATED: "Investigate repeated audit revisions and concurrent decisions.",
    REVISION_OUT_OF_ORDER: "Check timestamps and transaction ordering; never reorder evidence silently.",
    STATE_TRANSITION_INVALID: "Review state machine integrity and stored transition metadata.",
    STATE_MISMATCH: "Reconcile the persisted state with the entire audit history.",
    DIGEST_MISMATCH: "Compare stored evidence digests with source snapshots.",
    ACTOR_MISSING: "Identify why a human decision lacks an authenticated actor.",
    EVENT_METADATA_INVALID: "Check the versioned audit event contract and required fields.",
    EVENT_RESOURCE_MISMATCH: "Examine tenant ownership and event linkage.",
    EVENT_CLOCK_INVALID: "Inspect database timestamp integrity.",
    DECISION_WITHOUT_REASON: "Obtain a new explicit human decision, never invent a reason.",
    ACKNOWLEDGEMENT_MISSING: "Reopen and record each mandatory operator acknowledgement.",
    BLOCKERS_AT_ACCEPTANCE: "Reopen the release and remediate evidence blockers.",
    AUDIT_LIMIT_EXCEEDED: "Increase bounded capacity within policy and rerun full inspection.",
    REVIEW_EVIDENCE_INVALID: "Reassess original signed-off sources; hashes are not signatures.",
    REVIEW_WITHOUT_AUDIT: "Locate missing transaction audit without reconstructing fictitious events.",
    UNEXPECTED_ACTION: "Validate the source of an unrecognized audit operation.",
    TERMINAL_DECISION_MISSING: "Obtain an independently audited decision.",
  };
  for (const item of report.issues)
    steps.push({
      priority: item.severity, issue: item.code,
      instruction: instruction[item.code],
    });
  if (!steps.length)
    steps.push({
      priority: "REVIEW", issue: "NONE",
      instruction: "Review this dossier manually; valid local history is not external authorization.",
    });
  return steps;
}
