import { describe, expect, it } from "vitest";
import {
  classifyCaptureVerification, parseCaptureVerificationQuery,
} from "./work-integrity-provider-capture-gaps";
import { observationSnapshot } from "./work-integrity-evidence-assessment";

const now = new Date("2026-11-03T12:00:00Z");
const task = {
  id: "review-task-12345",
  externalTaskId: "google-2sv",
  title: "Verify Google Workspace 2SV",
  severity: "HIGH",
  disposition: "IN_REVIEW",
  required: true,
};
const evidence = {
  id: "evidence-12345", organizationId: "org-12345",
  source: "GOOGLE_WORKSPACE",
  domain: "example.invalid",
  controlId: "google_workspace.user_2sv",
  scope: "admin@example.invalid",
  state: "OBSERVED", schemaVersion: 1,
  observedAt: new Date("2026-11-03T11:00:00Z"),
  updatedAt: new Date("2026-11-03T11:01:00Z"),
  details: {
    customerId: "C123456789",
    subject: "admin@example.invalid",
  },
};
const check = {
  id: "provider-check-12345", taskId: task.id,
  evidenceId: evidence.id, provider: evidence.source,
  controlId: evidence.controlId, outcome: "PASS",
  checkedAt: new Date("2026-11-03T11:45:00Z"),
  observationDigest: observationSnapshot(evidence).digest,
  failureCode: null,
};
const link = {
  taskId: task.id, workItemId: "work-item-12345",
  unlinkedAt: null,
  workItem: {
    status: "DONE", remediation: { status: "SUCCEEDED" },
    finding: { status: "OPEN" },
    evidenceLinks: [{ evidenceId: evidence.id }],
  },
};
const evaluate = (
  currentCheck: typeof check | null,
  links = [link],
  currentEvidence: typeof evidence | null = evidence,
) => classifyCaptureVerification(
  task, currentCheck, currentEvidence,
  links, currentCheck ? [currentCheck] : [],
  currentEvidence ? [currentEvidence] : [], now, 60);
describe("capture verification gap classification", () => {
  it("classifies a fully verified linked work item", () => {
    const result = evaluate(check);
    expect(result.gap).toBe("PROVIDER_PASS");
    expect(result.workReadiness[0]?.canRequestHumanReview).toBe(true);
  });
  it("does not infer verification without a check", () => {
    const result = evaluate(null);
    expect(result.gap).toBe("NO_PROVIDER_CHECK");
    expect(result.providerCheckId).toBeNull();
  });
  it("distinguishes an entirely unlinked task", () => {
    expect(evaluate(null, []).gap).toBe("NO_EVIDENCE");
  });
  it("detects verified observations without operational links", () => {
    expect(evaluate(check, []).gap).toBe("WORK_NOT_LINKED");
  });
  it("reports incomplete operational work", () => {
    const result = evaluate(check, [{
      ...link, workItem: {
        ...link.workItem, status: "IN_PROGRESS",
      },
    }]);
    expect(result.gap).toBe("WORK_INCOMPLETE");
  });
  it("reports a provider failure", () => {
    expect(evaluate({ ...check, outcome: "FAIL" }).gap)
      .toBe("PROVIDER_FAILED");
  });
  it("reports provider service errors separately", () => {
    expect(evaluate({
      ...check, outcome: "PROVIDER_ERROR",
    }).gap).toBe("PROVIDER_ERROR");
  });
  it("reports inconclusive provider responses", () => {
    expect(evaluate({
      ...check, outcome: "INCONCLUSIVE",
    }).gap).toBe("PROVIDER_INCONCLUSIVE");
  });
  it("detects evidence changes", () => {
    const changed = {
      ...evidence, details: {
        customerId: "C987654321", subject: "admin@example.invalid",
      },
    };
    expect(evaluate(check, [link], changed).gap)
      .toBe("EVIDENCE_CHANGED");
  });
  it("reports expired provider checks", () => {
    expect(evaluate({
      ...check, checkedAt: new Date("2026-11-03T09:00:00Z"),
    }).gap).toBe("PROVIDER_EXPIRED");
  });
  it("does not treat linked evidence mismatch as verified work", () => {
    const result = evaluate(check, [{
      ...link, workItem: {
        ...link.workItem, evidenceLinks: [{
          evidenceId: "different-evidence-12345",
        }],
      },
    }]);
    expect(result.gap).toBe("WORK_REVIEW_REQUIRED");
  });
});
describe("capture verification pagination", () => {
  it("uses conservative defaults", () => {
    expect(parseCaptureVerificationQuery({
      captureId: "capture-12345",
    })).toEqual({
      captureId: "capture-12345",
      offset: 0, limit: 50,
      maxAgeMinutes: 60, includeResolved: false,
    });
  });
  it.each([
    { offset: -1 }, { limit: 0 }, { limit: 101 },
    { maxAgeMinutes: 0 }, { maxAgeMinutes: 1441 },
    { includeResolved: "true" }, { unknown: true },
  ])("rejects invalid filter %j", patch => {
    expect(() => parseCaptureVerificationQuery({
      captureId: "capture-12345", ...patch,
    })).toThrow();
  });
});
