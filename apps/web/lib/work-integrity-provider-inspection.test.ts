import { describe, expect, it } from "vitest";
import { inspectProviderCheckRecord } from "./work-integrity-provider-inspection";

const check = {
  id: "provider-check-12345",
  organizationId: "organization-12345",
  taskId: "review-task-12345",
  evidenceId: "evidence-item-12345",
  provider: "GOOGLE_WORKSPACE",
  controlId: "google_workspace.user_2sv",
  subject: "admin@example.invalid",
  outcome: "PASS",
  checkedAt: new Date("2026-11-03T10:00:00Z"),
  requestDigest: "a".repeat(64),
  responseDigest: "b".repeat(64),
  observationDigest: "c".repeat(64),
  requestedByUserId: "admin-user-12345",
};
const audit = {
  organizationId: check.organizationId,
  action: "integrity.provider.google_2sv.check",
  resourceId: check.id,
  actorUserId: check.requestedByUserId,
  metadata: {
    taskId: check.taskId, evidenceId: check.evidenceId,
    provider: check.provider, controlId: check.controlId,
    subject: check.subject, outcome: check.outcome,
    requestDigest: check.requestDigest,
    responseDigest: check.responseDigest,
    observationDigest: check.observationDigest,
  },
};
describe("provider check audit consistency", () => {
  it("accepts a complete matching local audit", () => {
    const result = inspectProviderCheckRecord(
      check, audit, check.observationDigest);
    expect(result.auditConsistent).toBe(true);
    expect(result.evidenceMatches).toBe(true);
    expect(result.findings).toEqual([]);
  });
  it("detects absent audit", () => {
    expect(inspectProviderCheckRecord(
      check, null, check.observationDigest,
    ).findings).toContain("MISSING_AUDIT");
  });
  it("detects cross-tenant audit", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, organizationId: "other-org",
    }, check.observationDigest).findings)
      .toContain("CROSS_TENANT_AUDIT");
  });
  it("detects mismatched resource", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, resourceId: "other-id",
    }, check.observationDigest).findings)
      .toContain("AUDIT_RESOURCE_MISMATCH");
  });
  it("detects mismatched audit actor", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, actorUserId: "other-user",
    }, check.observationDigest).findings)
      .toContain("AUDIT_ACTOR_MISMATCH");
  });
  it("detects mismatched provider subject", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, metadata: {
        ...audit.metadata, subject: "other@example.invalid",
      },
    }, check.observationDigest).findings)
      .toContain("AUDIT_SUBJECT_MISMATCH");
  });
  it("detects a tampered request digest", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, metadata: {
        ...audit.metadata, requestDigest: "d".repeat(64),
      },
    }, check.observationDigest).findings)
      .toContain("AUDIT_DIGEST_MISMATCH");
  });
  it("detects a tampered provider outcome", () => {
    expect(inspectProviderCheckRecord(check, {
      ...audit, metadata: {
        ...audit.metadata, outcome: "FAIL",
      },
    }, check.observationDigest).findings)
      .toContain("AUDIT_OUTCOME_MISMATCH");
  });
  it("detects a changed evidence snapshot", () => {
    expect(inspectProviderCheckRecord(
      check, audit, "e".repeat(64),
    ).findings).toContain("EVIDENCE_CHANGED");
  });
  it("detects missing evidence", () => {
    expect(inspectProviderCheckRecord(
      check, audit, null,
    ).findings).toContain("EVIDENCE_UNAVAILABLE");
  });
  it("rejects malformed cryptographic digest", () => {
    expect(inspectProviderCheckRecord({
      ...check, responseDigest: "malformed",
    }, audit, check.observationDigest).findings)
      .toContain("INVALID_DIGEST");
  });
});
