import { describe, expect, it } from "vitest";
import { createIncident } from "./incident-case-domain";
import { buildIncidentSituation } from "./incident-situation-domain";
import {
  applySituationReview, compareSituationReviewSources,
  createSituationReview, situationReviewDigest,
  validateSituationReview, validateSituationReviewHistory,
} from "./incident-situation-review-domain";
const t0 = "2026-11-23T10:00:00.000Z";
const t1 = "2026-11-23T10:01:00.000Z";
const t2 = "2026-11-23T10:02:00.000Z";
const situation = () => buildIncidentSituation({
  incident: createIncident({
    id: "incident-1234", organizationId: "tenant-1234",
    title: "Credential exposure", type: "COMPROMISED_ACCOUNT",
    subjectReference: "account-1234", ownerUserId: null,
    actorUserId: "admin-1234", at: t0,
  }),
  evidence: null, assets: null, remediation: null,
  sourceStates: { evidence: "ABSENT", assets: "ABSENT", remediation: "ABSENT" },
  capturedAt: t0, sourceMode: "PERSISTED_READ_ONLY",
});
const command = (digest: string, revision: number, decision:
  "BEGIN_REVIEW" | "RECORD_FINDING" | "ACKNOWLEDGE", actorId = "admin-1234") => ({
  organizationId: "tenant-1234", incidentId: "incident-1234",
  actorId, role: "ADMIN" as const, expectedRevision: revision,
  expectedSituationDigest: digest, decision, at: t1,
});
describe("tenant-safe situation review ledger", () => {
  it("creates hash-chained offline review with no external execution", () => {
    const initial = createSituationReview("review-1234", situation(),
      "admin-1234", "ADMIN", t0);
    expect(validateSituationReview(initial.snapshot)).toEqual([]);
    expect(validateSituationReviewHistory(initial.snapshot, [initial.event]))
      .toEqual([]);
    expect(initial.snapshot.externalWrites).toBe(0);
    expect(initial.snapshot.providerContainmentVerified).toBe(false);
    expect(initial.event.nextDigest).toBe(situationReviewDigest(initial.snapshot));
  });
  it("ensures CAS, tenant isolation and immutable audit continuity", () => {
    const start = createSituationReview("review-1234", situation(),
      "admin-1234", "ADMIN", t0);
    const digest = start.snapshot.situationDigest;
    const begin = applySituationReview(start.snapshot, command(digest, 1, "BEGIN_REVIEW"));
    expect(begin.snapshot.state).toBe("IN_REVIEW");
    expect(validateSituationReviewHistory(begin.snapshot,
      [start.event, begin.event])).toEqual([]);
    expect(() => applySituationReview(begin.snapshot,
      command(digest, 1, "BEGIN_REVIEW"))).toThrow("REVIEW_STALE_REVISION");
    expect(() => applySituationReview(begin.snapshot, {
      ...command(digest, 2, "ACKNOWLEDGE", "approver-1234"),
      organizationId: "tenant-other",
    })).toThrow("REVIEW_CROSS_TENANT_OR_CASE");
    expect(validateSituationReviewHistory(begin.snapshot,
      [start.event, { ...begin.event, eventDigest: "a".repeat(64) }]))
      .toContain("REVIEW_HISTORY_EVENT_DIGEST_INVALID");
  });
  it("cannot authorize or assert provider containment using absent sources", () => {
    const start = createSituationReview("review-1234", situation(),
      "admin-1234", "ADMIN", t0);
    const digest = start.snapshot.situationDigest;
    const begin = applySituationReview(start.snapshot, command(digest, 1, "BEGIN_REVIEW"));
    expect(() => applySituationReview(begin.snapshot, {
      ...command(digest, 2, "ACKNOWLEDGE", "approver-1234"), at: t2,
    })).toThrow("REVIEW_COVERAGE_NOT_ACKNOWLEDGEABLE");
    expect(() => applySituationReview(begin.snapshot, {
      ...command(digest, 2, "ACKNOWLEDGE"),
      role: "AUDITOR", at: t2,
    })).toThrow("REVIEW_ROLE_DENIED");
    expect(compareSituationReviewSources(start.snapshot, situation())
      .providerActionProven).toBe(false);
  });
  it("rejects forged provider proof and unexpected reviewer identities", () => {
    const start = createSituationReview("review-1234", situation(),
      "admin-1234", "ADMIN", t0);
    expect(validateSituationReview({ ...start.snapshot,
      providerContainmentVerified: true as false }))
      .toContain("PROVIDER_OUTCOME_FORGED");
    expect(() => createSituationReview("review-1234", situation(),
      "auditor-1234", "AUDITOR", t0)).toThrow("REVIEW_CREATE_ACTOR_INVALID");
  });
});
