import { describe, expect, it } from "vitest";
import {
  parseIntegrityReviewBatchPolicy,
  evaluateIntegrityReviewBatch,
  parseIntegrityReviewBatchQuery,
  queryIntegrityReviewBatch,
} from "./work-integrity-remediation-review-batch";
import {
  parseIntegrityReviewLineagePolicy,
  buildIntegrityReviewLineage,
  parseIntegrityReviewLineageQuery,
  queryIntegrityReviewLineage,
} from "./work-integrity-remediation-review-lineage";
import {
  parseIntegrityReviewDossierPolicy,
  buildIntegrityReviewDossier,
  parseIntegrityReviewDossierQuery,
  queryIntegrityReviewDossier,
} from "./work-integrity-remediation-review-dossier";
import {
  parseIntegrityReviewEvents,
  replayIntegrityReviewEvents,
} from "./work-integrity-remediation-review-event-replay";
import {
  parseIntegrityReviewEvidenceAssociations,
  reconcileIntegrityReviewEvidence,
} from "./work-integrity-remediation-review-evidence";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
const at = "2026-11-03T00:00:00.000Z";
const queue: IntegrityCapacityReviewQueue = {
  schemaVersion: 1, captureId: "capture", evaluatedAt: at,
  tasks: [{
    taskId: "task", action: "VERIFY_ASSIGNMENT_IMPACT",
    severity: "ERROR", bundleId: "bundle",
    interventionIds: ["slots"], findingCodes: [],
    reasons: [], priority: 400, position: 1,
    reviewRequired: true, checklist: [],
    affectedCandidateIds: [], blockedBy: [],
    canBeAutoResolved: false,
  }],
  totals: {
    tasks: 1, errors: 1, warnings: 0, info: 0,
    required: 1, affectedCandidates: 0,
    byAction: {}, byBundle: {},
  },
  limitation: "Analytical",
};
const events = parseIntegrityReviewEvents([
  { eventId: "ack", taskId: "task", kind: "ACKNOWLEDGE",
    actorId: "actor", occurredAt: at, expectedVersion: 0 },
  { eventId: "start", taskId: "task", kind: "START_REVIEW",
    actorId: "actor", occurredAt: "2026-11-03T01:00:00.000Z",
    expectedVersion: 1 },
  { eventId: "resolve", taskId: "task", kind: "RESOLVE",
    actorId: "actor", occurredAt: "2026-11-03T02:00:00.000Z",
    expectedVersion: 2, reason: "Reviewed",
    evidenceRefs: ["ref"] },
]);
const replay = replayIntegrityReviewEvents(queue, events);
const evidence = reconcileIntegrityReviewEvidence(queue, replay, events,
  parseIntegrityReviewEvidenceAssociations([{
    associationId: "link", captureId: "capture",
    taskId: "task", reference: "ref",
    source: "LINK_AUDIT", recordedAt: at,
  }]));
describe("review batch validation", () => {
  it("accepts causally consistent review events with associated evidence", () => {
    const batch = evaluateIntegrityReviewBatch(queue, events, replay,
      evidence, undefined, "2026-11-03T03:00:00.000Z");
    expect(batch.status).toBe("ANALYTICALLY_CONSISTENT");
    expect(batch.totals.analyticallyAccepted).toBe(3);
  });
  it("rejects review events after evaluation time", () => {
    const batch = evaluateIntegrityReviewBatch(queue, events, replay,
      evidence, undefined, at);
    expect(batch.findings.map(x => x.code)).toContain(
      "EVENT_AFTER_EVALUATION");
  });
  it("rejects missing scoped associations", () => {
    const batch = evaluateIntegrityReviewBatch(queue, events, replay,
      null, undefined, "2026-11-03T03:00:00.000Z");
    expect(batch.findings.map(x => x.code)).toContain(
      "RESOLUTION_REFERENCE_NOT_ASSOCIATED");
  });
  it("filters validation errors by code", () => {
    const batch = evaluateIntegrityReviewBatch(queue, events, replay,
      null, undefined, "2026-11-03T03:00:00.000Z");
    const page = queryIntegrityReviewBatch(batch,
      parseIntegrityReviewBatchQuery({
        codes: ["RESOLUTION_REFERENCE_NOT_ASSOCIATED"],
      }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown policy fields", () => {
    expect(() => parseIntegrityReviewBatchPolicy({
      trustClientEvidence: true,
    })).toThrow();
  });
});
describe("review provenance lineage", () => {
  it("connects tasks, events, evidence and associations", () => {
    const lineage = buildIntegrityReviewLineage(queue, events,
      replay, evidence, null);
    expect(lineage.totals.tasks).toBe(1);
    expect(lineage.totals.events).toBe(3);
    expect(lineage.totals.evidence).toBe(1);
    expect(lineage.totals.associations).toBe(1);
    expect(lineage.edges.some(x =>
      x.kind === "EVIDENCE_ASSOCIATION")).toBe(true);
  });
  it("reports unmatched evidence", () => {
    const missing = reconcileIntegrityReviewEvidence(
      queue, replay, events, []);
    const lineage = buildIntegrityReviewLineage(queue, events,
      replay, missing, null);
    expect(lineage.totals.unmatchedReferences).toBe(1);
    expect(lineage.findings.map(x => x.code)).toContain(
      "MISSING_ASSOCIATION");
  });
  it("supports filtering graph nodes", () => {
    const lineage = buildIntegrityReviewLineage(queue, events,
      replay, evidence, null);
    const page = queryIntegrityReviewLineage(lineage,
      parseIntegrityReviewLineageQuery({ kinds: ["EVIDENCE"] }));
    expect(page.total).toBe(1);
  });
  it("rejects unsupported graph policy", () => {
    expect(() => parseIntegrityReviewLineagePolicy({
      verified: true,
    })).toThrow();
  });
});
describe("conservative review dossier", () => {
  it("reports incomplete sources conservatively", () => {
    const dossier = buildIntegrityReviewDossier(
      queue, replay, null, evidence, null, null, null);
    expect(dossier.status).toBe("INCOMPLETE");
    expect(dossier.totals.missingSources).toBe(2);
    expect(dossier.totals.independentlyVerified).toBe(0);
  });
  it("requires evidence provenance even if replay resolved", () => {
    const dossier = buildIntegrityReviewDossier(
      queue, replay, null, null, null, null, null);
    expect(dossier.tasks[0]?.analyticallyComplete).toBe(false);
    expect(dossier.tasks[0]?.blockers).toContain(
      "NO_EVIDENCE_RECONCILIATION");
  });
  it("filters incomplete review tasks", () => {
    const dossier = buildIntegrityReviewDossier(
      queue, replay, null, evidence, null, null, null);
    const page = queryIntegrityReviewDossier(dossier,
      parseIntegrityReviewDossierQuery({ onlyIncomplete: true }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown dossier fields", () => {
    expect(() => parseIntegrityReviewDossierPolicy({
      authorizeExecution: true,
    })).toThrow();
  });
});
