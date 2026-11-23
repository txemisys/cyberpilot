import { createHash, timingSafeEqual } from "node:crypto";
import type { IncidentSituation } from "./incident-situation-domain";

/**
 * Immutable review ledger for a particular situation report. This is an
 * OFFLINE operator attestation, not a provider-side remediation receipt.
 * Persistence adapters must commit the revision and appended event atomically.
 */
export type SituationReviewState =
  "OPEN" | "IN_REVIEW" | "RETURNED" | "ACKNOWLEDGED" | "SUPERSEDED";
export type SituationReviewDecision =
  "BEGIN_REVIEW" | "RECORD_FINDING" | "RETURN_FOR_EVIDENCE" |
  "ACKNOWLEDGE" | "REOPEN" | "SUPERSEDE";
export type SituationReviewRole = "OWNER" | "ADMIN" | "AUDITOR";
export type SituationReviewFinding = {
  id: string;
  concernId: string;
  conclusion: "CONFIRMED_GAP" | "NEEDS_EVIDENCE" | "NOT_APPLICABLE";
  explanation: string;
  evidenceReferences: string[];
  recordedBy: string;
  recordedAt: string;
};
export type SituationReviewSnapshot = {
  schema: "cyberpilot.incident.situation.review.v1";
  id: string;
  organizationId: string;
  incidentId: string;
  incidentRevision: number;
  incidentDigest: string;
  situationDigest: string;
  evaluatedAt: string;
  sourceDigests: Record<"EVIDENCE" | "ASSETS" | "REMEDIATION", string | null>;
  concernIds: string[];
  sourceUnavailable: boolean;
  riskBand: IncidentSituation["riskBand"];
  state: SituationReviewState;
  revision: number;
  createdAt: string;
  updatedAt: string;
  openedBy: string;
  reviewerId: string | null;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  findings: SituationReviewFinding[];
  reviewNotes: string[];
  supersededBy: string | null;
  externalWrites: 0;
  providerContainmentVerified: false;
};
export type SituationReviewEvent = {
  schema: "cyberpilot.incident.situation.review.event.v1";
  ledgerId: string;
  organizationId: string;
  incidentId: string;
  revision: number;
  decision: "CREATE" | SituationReviewDecision;
  actorId: string;
  at: string;
  previousState: SituationReviewState | null;
  nextState: SituationReviewState;
  previousDigest: string | null;
  nextDigest: string;
  eventDigest: string;
};
export type SituationReviewCommand = {
  decision: SituationReviewDecision;
  expectedRevision: number;
  actorId: string;
  role: SituationReviewRole;
  organizationId: string;
  incidentId: string;
  at: string;
  explanation?: string;
  concernId?: string;
  conclusion?: SituationReviewFinding["conclusion"];
  evidenceReferences?: string[];
  supersededBy?: string;
  expectedSituationDigest: string;
};
const idPattern = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/;
const shaPattern = /^[0-9a-f]{64}$/;
const id = (v: unknown): v is string =>
  typeof v === "string" && idPattern.test(v);
const sha = (v: unknown): v is string =>
  typeof v === "string" && shaPattern.test(v);
const iso = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v)) &&
  new Date(v).toISOString() === v;
const hash = (v: unknown) => createHash("sha256")
  .update(JSON.stringify(v)).digest("hex");
const sortedUnique = (v: string[]) => [...new Set(v)].sort();
const safeSame = (a: string, b: string) =>
  sha(a) && sha(b) && timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
function reject(code: string): never { throw Error(code); }
export function situationReviewDigest(
  snapshot: SituationReviewSnapshot,
): string { return hash(snapshot); }
export function situationReviewEventDigest(
  event: Omit<SituationReviewEvent, "eventDigest">,
): string { return hash(event); }
export function validateSituationReview(snapshot: SituationReviewSnapshot): string[] {
  const errors: string[] = [];
  if (snapshot?.schema !== "cyberpilot.incident.situation.review.v1")
    errors.push("SCHEMA_INVALID");
  if (![snapshot?.id, snapshot?.organizationId, snapshot?.incidentId,
    snapshot?.openedBy].every(id)) errors.push("IDENTIFIER_INVALID");
  if (![snapshot?.incidentDigest, snapshot?.situationDigest].every(sha))
    errors.push("DIGEST_INVALID");
  if (!Number.isSafeInteger(snapshot?.incidentRevision) ||
      snapshot.incidentRevision < 1 ||
      !Number.isSafeInteger(snapshot?.revision) || snapshot.revision < 1)
    errors.push("REVISION_INVALID");
  if (![snapshot?.createdAt, snapshot?.updatedAt, snapshot?.evaluatedAt].every(iso))
    errors.push("TIMESTAMP_INVALID");
  if (!["OPEN", "IN_REVIEW", "RETURNED", "ACKNOWLEDGED", "SUPERSEDED"]
    .includes(snapshot?.state)) errors.push("STATE_INVALID");
  if (!["P0", "P1", "P2", "P3"].includes(snapshot?.riskBand))
    errors.push("RISK_INVALID");
  if (snapshot?.externalWrites !== 0 ||
      snapshot?.providerContainmentVerified !== false)
    errors.push("PROVIDER_OUTCOME_FORGED");
  if (!snapshot?.sourceDigests ||
      Object.keys(snapshot.sourceDigests).sort().join(",") !==
      "ASSETS,EVIDENCE,REMEDIATION" ||
      Object.values(snapshot.sourceDigests).some(x => x !== null && !sha(x)))
    errors.push("SOURCE_DIGEST_INVALID");
  if (!Array.isArray(snapshot?.concernIds) ||
      snapshot.concernIds.length > 1000 ||
      snapshot.concernIds.some(x => !id(x)) ||
      sortedUnique(snapshot.concernIds).join("\0") !== snapshot.concernIds.join("\0"))
    errors.push("CONCERNS_INVALID");
  if (!Array.isArray(snapshot?.findings) || snapshot.findings.length > 1000)
    errors.push("FINDINGS_INVALID");
  else {
    const seen = new Set<string>();
    for (const finding of snapshot.findings) {
      if (!id(finding.id) || seen.has(finding.id) ||
          !snapshot.concernIds.includes(finding.concernId) ||
          !["CONFIRMED_GAP", "NEEDS_EVIDENCE", "NOT_APPLICABLE"]
            .includes(finding.conclusion) ||
          !id(finding.recordedBy) || !iso(finding.recordedAt) ||
          !finding.explanation?.trim() || finding.explanation.length > 2000 ||
          !Array.isArray(finding.evidenceReferences) ||
          finding.evidenceReferences.length > 30 ||
          finding.evidenceReferences.some(x => !id(x)))
        errors.push("FINDING_INVALID");
      seen.add(finding.id);
    }
  }
  if (!Array.isArray(snapshot?.reviewNotes) ||
      snapshot.reviewNotes.length > 100 ||
      snapshot.reviewNotes.some(x => typeof x !== "string" || x.length > 2000))
    errors.push("NOTES_INVALID");
  if (snapshot?.reviewerId !== null && !id(snapshot?.reviewerId))
    errors.push("REVIEWER_INVALID");
  if (snapshot?.acknowledgedBy !== null && !id(snapshot?.acknowledgedBy))
    errors.push("ACKNOWLEDGER_INVALID");
  if (snapshot?.acknowledgedAt !== null && !iso(snapshot?.acknowledgedAt))
    errors.push("ACKNOWLEDGMENT_TIME_INVALID");
  if ((snapshot.state === "ACKNOWLEDGED") !==
      (snapshot.acknowledgedBy !== null && snapshot.acknowledgedAt !== null))
    errors.push("ACKNOWLEDGMENT_INCONSISTENT");
  if (snapshot.state === "SUPERSEDED" && !id(snapshot.supersededBy))
    errors.push("SUPERSESSION_INVALID");
  if (snapshot.state !== "SUPERSEDED" && snapshot.supersededBy !== null)
    errors.push("UNEXPECTED_SUPERSESSION");
  return sortedUnique(errors);
}
export function createSituationReview(
  ledgerId: string, situation: IncidentSituation,
  actorId: string, role: SituationReviewRole, at: string,
): { snapshot: SituationReviewSnapshot; event: SituationReviewEvent } {
  if (!id(ledgerId) || !id(actorId) || !iso(at) ||
      !["OWNER", "ADMIN"].includes(role))
    reject("REVIEW_CREATE_ACTOR_INVALID");
  if (!id(situation.organizationId) || !id(situation.incidentId) ||
      !sha(situation.situationDigest) || !sha(situation.incidentSnapshotDigest) ||
      !Number.isSafeInteger(situation.revision) || situation.revision < 1 ||
      situation.externalWrites !== 0 || situation.actualContainmentVerified ||
      situation.sourceSummaries.length !== 3 ||
      situation.concerns.length > 1000)
    reject("REVIEW_SITUATION_UNTRUSTED");
  const sources = Object.fromEntries(situation.sourceSummaries.map(s =>
    [s.name, s.sourceDigest])) as SituationReviewSnapshot["sourceDigests"];
  if (Object.keys(sources).sort().join(",") !==
      "ASSETS,EVIDENCE,REMEDIATION") reject("REVIEW_SOURCES_INCOMPLETE");
  const snapshot: SituationReviewSnapshot = {
    schema: "cyberpilot.incident.situation.review.v1",
    id: ledgerId, organizationId: situation.organizationId,
    incidentId: situation.incidentId, incidentRevision: situation.revision,
    incidentDigest: situation.incidentSnapshotDigest,
    situationDigest: situation.situationDigest,
    evaluatedAt: situation.evaluatedAt, sourceDigests: sources,
    concernIds: sortedUnique(situation.concerns.map(c => c.id)),
    sourceUnavailable: situation.sourceSummaries.some(s =>
      s.availability !== "PRESENT"),
    riskBand: situation.riskBand, state: "OPEN", revision: 1,
    createdAt: at, updatedAt: at, openedBy: actorId,
    reviewerId: null, acknowledgedBy: null, acknowledgedAt: null,
    findings: [], reviewNotes: [], supersededBy: null,
    externalWrites: 0, providerContainmentVerified: false,
  };
  if (validateSituationReview(snapshot).length)
    reject("REVIEW_SNAPSHOT_INVALID");
  const bare = {
    schema: "cyberpilot.incident.situation.review.event.v1" as const,
    ledgerId, organizationId: situation.organizationId,
    incidentId: situation.incidentId, revision: 1,
    decision: "CREATE" as const, actorId, at,
    previousState: null, nextState: "OPEN" as const,
    previousDigest: null, nextDigest: situationReviewDigest(snapshot),
  };
  return { snapshot, event: { ...bare, eventDigest: hash(bare) } };
}
export function applySituationReview(
  previous: SituationReviewSnapshot, command: SituationReviewCommand,
): { snapshot: SituationReviewSnapshot; event: SituationReviewEvent } {
  if (validateSituationReview(previous).length)
    reject("REVIEW_PREVIOUS_STATE_CORRUPT");
  if (command.organizationId !== previous.organizationId ||
      command.incidentId !== previous.incidentId)
    reject("REVIEW_CROSS_TENANT_OR_CASE");
  if (!id(command.actorId) || !iso(command.at) ||
      command.at < previous.updatedAt ||
      !safeSame(command.expectedSituationDigest, previous.situationDigest))
    reject("REVIEW_ACTOR_TIME_OR_SOURCE_INVALID");
  if (!Number.isSafeInteger(command.expectedRevision) ||
      command.expectedRevision !== previous.revision)
    reject("REVIEW_STALE_REVISION");
  if (command.role === "AUDITOR" ||
      !["OWNER", "ADMIN"].includes(command.role))
    reject("REVIEW_ROLE_DENIED");
  if (previous.state === "SUPERSEDED")
    reject("REVIEW_ALREADY_SUPERSEDED");
  const notes = [...previous.reviewNotes];
  const next: SituationReviewSnapshot = {
    ...previous, revision: previous.revision + 1, updatedAt: command.at,
    findings: [...previous.findings], reviewNotes: notes,
  };
  if (command.decision === "BEGIN_REVIEW") {
    if (!["OPEN", "RETURNED"].includes(previous.state))
      reject("REVIEW_BEGIN_ILLEGAL_STATE");
    next.state = "IN_REVIEW";
    next.reviewerId = command.actorId;
  } else if (command.decision === "RECORD_FINDING") {
    if (previous.state !== "IN_REVIEW" ||
        previous.reviewerId !== command.actorId ||
        !id(command.concernId) ||
        !previous.concernIds.includes(command.concernId) ||
        !["CONFIRMED_GAP", "NEEDS_EVIDENCE", "NOT_APPLICABLE"]
          .includes(command.conclusion ?? ""))
      reject("REVIEW_FINDING_NOT_AUTHORIZED");
    if (!command.explanation?.trim() || command.explanation.length > 2000 ||
        !Array.isArray(command.evidenceReferences) ||
        command.evidenceReferences.length > 30 ||
        command.evidenceReferences.some(x => !id(x)))
      reject("REVIEW_FINDING_EVIDENCE_INVALID");
    const seq = next.findings.length + 1;
    next.findings.push({
      id: previous.id + ":finding:" + seq,
      concernId: command.concernId, conclusion: command.conclusion!,
      explanation: command.explanation.trim(),
      evidenceReferences: sortedUnique(command.evidenceReferences),
      recordedBy: command.actorId, recordedAt: command.at,
    });
  } else if (command.decision === "RETURN_FOR_EVIDENCE") {
    if (previous.state !== "IN_REVIEW" ||
        !command.explanation?.trim() || command.explanation.length > 2000)
      reject("REVIEW_RETURN_INVALID");
    next.state = "RETURNED";
    notes.push(command.explanation.trim());
    next.reviewerId = null;
  } else if (command.decision === "ACKNOWLEDGE") {
    if (previous.state !== "IN_REVIEW" ||
        !previous.reviewerId || previous.reviewerId === command.actorId)
      reject("REVIEW_INDEPENDENT_ACKNOWLEDGMENT_REQUIRED");
    if (previous.sourceUnavailable ||
        previous.findings.some(f => f.conclusion === "NEEDS_EVIDENCE"))
      reject("REVIEW_COVERAGE_NOT_ACKNOWLEDGEABLE");
    next.state = "ACKNOWLEDGED";
    next.acknowledgedBy = command.actorId;
    next.acknowledgedAt = command.at;
  } else if (command.decision === "REOPEN") {
    if (previous.state !== "ACKNOWLEDGED")
      reject("REVIEW_REOPEN_STATE_INVALID");
    next.state = "OPEN";
    next.reviewerId = null;
    next.acknowledgedBy = null;
    next.acknowledgedAt = null;
  } else if (command.decision === "SUPERSEDE") {
    if (!id(command.supersededBy) ||
        command.supersededBy === previous.id)
      reject("REVIEW_SUPERSESSION_REFERENCE_INVALID");
    next.state = "SUPERSEDED";
    next.supersededBy = command.supersededBy;
    next.reviewerId = null;
    next.acknowledgedBy = null;
    next.acknowledgedAt = null;
  } else reject("REVIEW_DECISION_UNKNOWN");
  if (validateSituationReview(next).length)
    reject("REVIEW_TRANSITION_INVALID");
  const bare = {
    schema: "cyberpilot.incident.situation.review.event.v1" as const,
    ledgerId: next.id, organizationId: next.organizationId,
    incidentId: next.incidentId, revision: next.revision,
    decision: command.decision, actorId: command.actorId, at: command.at,
    previousState: previous.state, nextState: next.state,
    previousDigest: situationReviewDigest(previous),
    nextDigest: situationReviewDigest(next),
  };
  return { snapshot: next, event: { ...bare, eventDigest: hash(bare) } };
}
export function validateSituationReviewHistory(
  current: SituationReviewSnapshot, events: SituationReviewEvent[],
): string[] {
  const faults: string[] = [];
  if (validateSituationReview(current).length)
    faults.push("REVIEW_HISTORY_SNAPSHOT_CORRUPT");
  if (events.length !== current.revision)
    faults.push("REVIEW_HISTORY_REVISION_GAP");
  let prior: SituationReviewEvent | null = null;
  for (const [index, event] of events.entries()) {
    const { eventDigest, ...unsigned } = event;
    if (!safeSame(eventDigest, hash(unsigned)))
      faults.push("REVIEW_HISTORY_EVENT_DIGEST_INVALID");
    if (event.organizationId !== current.organizationId ||
        event.incidentId !== current.incidentId ||
        event.ledgerId !== current.id)
      faults.push("REVIEW_HISTORY_SCOPE_INVALID");
    if (event.revision !== index + 1 ||
        (prior && (event.previousDigest !== prior.nextDigest ||
          event.previousState !== prior.nextState ||
          event.at < prior.at)))
      faults.push("REVIEW_HISTORY_CHAIN_BROKEN");
    if (!prior && (event.decision !== "CREATE" ||
        event.previousDigest !== null || event.previousState !== null))
      faults.push("REVIEW_HISTORY_GENESIS_INVALID");
    prior = event;
  }
  if (!prior || !safeSame(prior.nextDigest, situationReviewDigest(current)))
    faults.push("REVIEW_HISTORY_FINAL_DIGEST_INVALID");
  return sortedUnique(faults);
}
export function compareSituationReviewSources(
  review: SituationReviewSnapshot, current: IncidentSituation,
) {
  if (review.organizationId !== current.organizationId ||
      review.incidentId !== current.incidentId)
    reject("REVIEW_COMPARISON_SCOPE_INVALID");
  const sourceChanges = current.sourceSummaries.flatMap(source =>
    review.sourceDigests[source.name] === source.sourceDigest ? [] :
      [source.name]);
  const oldConcerns = new Set(review.concernIds);
  const nextConcerns = new Set(current.concerns.map(c => c.id));
  const addedConcerns = [...nextConcerns].filter(x => !oldConcerns.has(x)).sort();
  const removedConcerns = [...oldConcerns].filter(x => !nextConcerns.has(x)).sort();
  const caseDrift = review.incidentRevision !== current.revision ||
    review.incidentDigest !== current.incidentSnapshotDigest;
  const situationDrift = review.situationDigest !== current.situationDigest;
  return {
    caseDrift, situationDrift, sourceChanges, addedConcerns, removedConcerns,
    reviewMustBeReevaluated: caseDrift || situationDrift ||
      sourceChanges.length > 0 || addedConcerns.length > 0 ||
      removedConcerns.length > 0,
    providerActionProven: false as const,
    reconciliationRequiresOperator: true as const,
  };
}
