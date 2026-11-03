import { describe, expect, it } from "vitest";
import {
  evaluateWorkReadiness, parseReadinessInput,
} from "./work-integrity-provider-work-readiness";
import { observationSnapshot } from "./work-integrity-evidence-assessment";

const now = new Date("2026-11-03T12:00:00Z");
const evidence = {
  id: "evidence-item-12345", organizationId: "org-12345",
  source: "GOOGLE_WORKSPACE", domain: "example.invalid",
  controlId: "google_workspace.user_2sv",
  scope: "admin@example.invalid", state: "OBSERVED",
  schemaVersion: 1, observedAt: new Date("2026-11-03T11:00:00Z"),
  updatedAt: new Date("2026-11-03T11:01:00Z"),
  details: { customerId: "C123456789", subject: "admin@example.invalid" },
};
const check = {
  id: "provider-check-12345", evidenceId: evidence.id,
  provider: evidence.source, controlId: evidence.controlId,
  outcome: "PASS", checkedAt: new Date("2026-11-03T11:45:00Z"),
  observationDigest: observationSnapshot(evidence).digest,
  failureCode: null,
};
const record = {
  taskId: "review-task-12345", workItemId: "work-item-12345",
  unlinkedAt: null, reviewDisposition: "IN_REVIEW",
  workStatus: "DONE", remediationStatus: "SUCCEEDED",
  findingStatus: "OPEN", evidenceIds: [evidence.id],
};
const evaluate = (
  patch: Partial<typeof record> = {},
  checks = [check],
  evidenceRecords = [evidence],
) => evaluateWorkReadiness(
  { ...record, ...patch }, checks, evidenceRecords, now, 60);
describe("provider work readiness", () => {
  it("recognizes explicitly linked, freshly verified evidence", () => {
    const result = evaluate();
    expect(result.state).toBe("PROVIDER_VERIFIED");
    expect(result.canRequestHumanReview).toBe(true);
    expect(result.canAutoResolve).toBe(false);
    expect(result.providerVerifiedEvidenceIds).toEqual([evidence.id]);
    expect(result.blockedEvidenceIds).toEqual([]);
  });
  it("does not accept an inactive review-work link", () => {
    expect(evaluate({
      unlinkedAt: new Date("2026-11-03T11:30:00Z"),
    }).state).toBe("UNLINKED");
  });
  it("rejects cancelled work", () => {
    expect(evaluate({ workStatus: "CANCELLED" }).state)
      .toBe("WORK_CANCELLED");
  });
  it("rejects waived reviews", () => {
    expect(evaluate({ reviewDisposition: "WAIVED" }).state)
      .toBe("REVIEW_WAIVED");
  });
  it.each(["TODO", "IN_PROGRESS", "BLOCKED"])(
    "does not verify incomplete work %s", workStatus => {
      expect(evaluate({ workStatus }).state).toBe("WORK_INCOMPLETE");
    },
  );
  it("requires active work-evidence links", () => {
    expect(evaluate({ evidenceIds: [] }).state).toBe("EVIDENCE_NOT_LINKED");
  });
  it("requires a provider check for the same review", () => {
    expect(evaluate({}, []).state).toBe("NO_PROVIDER_CHECK");
  });
  it("blocks a provider FAIL", () => {
    expect(evaluate({}, [{ ...check, outcome: "FAIL" }]).state)
      .toBe("PROVIDER_FAILED");
  });
  it("blocks an expired provider check", () => {
    expect(evaluate({}, [{
      ...check, checkedAt: new Date("2026-11-03T09:00:00Z"),
    }]).state).toBe("PROVIDER_STALE");
  });
  it("blocks modified evidence", () => {
    expect(evaluate({}, [check], [{
      ...evidence, details: { customerId: "C987654321" },
    }]).state).toBe("PROVIDER_STALE");
  });
  it("blocks a second linked evidence record without verification", () => {
    const other = { ...evidence, id: "evidence-other-12345" };
    const result = evaluate({
      evidenceIds: [evidence.id, other.id],
    }, [check], [evidence, other]);
    expect(result.state).toBe("PROVIDER_STALE");
    expect(result.providerVerifiedEvidenceIds).toEqual([evidence.id]);
    expect(result.blockedEvidenceIds).toEqual([other.id]);
  });
  it("blocks provider error despite a prior PASS", () => {
    const result = evaluate({}, [
      check, {
        ...check, id: "later-check-12345",
        outcome: "PROVIDER_ERROR",
        checkedAt: new Date("2026-11-03T11:50:00Z"),
      },
    ]);
    expect(result.state).toBe("PROVIDER_STALE");
    expect(result.latestProviderCheckIds).toEqual(["later-check-12345"]);
  });
  it("does not infer finding closure from verified evidence", () => {
    const result = evaluate();
    expect(result.findingStatus).toBe("OPEN");
    expect(result.remediationStatus).toBe("SUCCEEDED");
    expect(result.canAutoResolve).toBe(false);
  });
  it("deduplicates linked evidence identifiers", () => {
    const result = evaluate({
      evidenceIds: [evidence.id, evidence.id],
    });
    expect(result.linkedEvidenceIds).toHaveLength(1);
  });
});
describe("readiness query parsing", () => {
  it("applies bounded defaults", () => {
    expect(parseReadinessInput({ taskId: record.taskId })).toEqual({
      taskId: record.taskId, maxAgeMinutes: 60,
      offset: 0, limit: 50, includeInactive: false,
    });
  });
  it.each([
    { taskId: "bad" }, { maxAgeMinutes: 0 },
    { maxAgeMinutes: 1441 }, { maxAgeMinutes: "60" },
    { offset: -1 }, { offset: "0" },
    { limit: 101 }, { includeInactive: "true" },
    { unknown: true },
  ])("rejects invalid query %j", patch => {
    expect(() => parseReadinessInput({
      taskId: record.taskId, ...patch,
    })).toThrow();
  });
});
