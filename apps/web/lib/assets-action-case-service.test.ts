import { describe, expect, it } from "vitest";
import {
  parseCaseCreate, parseCaseTransition,
  parseStepTransition, parseCaseQuery,
  caseTransitionTarget, canCompleteCaseWork,
} from "./assets-action-case-service";

const goodCreate = {
  importId: "inventory-import-12345",
  inspectionId: "inspection-source-12345",
  evidenceFingerprint: "a".repeat(64),
  bindings: [],
  reason: "Review the actual installed software and advisory applicability.",
};
const goodTransition = {
  caseId: "review-case-12345",
  expectedRevision: 2,
  expectedEvidenceFingerprint: "b".repeat(64),
  operation: "START_REVIEW",
  reason: "The administrator has accepted this declared evidence for review.",
};
const goodStep = {
  caseId: "review-case-12345",
  actionCode: "VERIFY_INVENTORY",
  expectedCaseRevision: 3,
  expectedStepRevision: 1,
  status: "IN_PROGRESS",
  note: "Assigned an authorized administrator to inspect the installed version.",
};
describe("asset candidate review contracts", () => {
  it("requires exact source identifiers and a full evidence fingerprint", () => {
    expect(parseCaseCreate(goodCreate)).toMatchObject(goodCreate);
    expect(() => parseCaseCreate({
      ...goodCreate, evidenceFingerprint: "short",
    })).toThrow();
    expect(() => parseCaseCreate({
      ...goodCreate, bindings: "[]",
    })).toThrow();
    expect(() => parseCaseCreate({
      ...goodCreate, inspectionId: "../foreign",
    })).toThrow();
  });
  it("requires an explicit investigation rationale", () => {
    expect(() => parseCaseCreate({
      ...goodCreate, reason: "ok",
    })).toThrow();
    expect(() => parseCaseCreate({
      ...goodCreate, reason: "x".repeat(1001),
    })).toThrow();
    expect(() => parseCaseCreate({
      ...goodCreate, reason: "unsafe\u0000value".repeat(3),
    })).toThrow();
  });
  it("denies additional fields that could spoof security approval", () => {
    expect(() => parseCaseCreate({
      ...goodCreate, verifiedRemediation: true,
    })).toThrow();
    expect(() => parseCaseTransition({
      ...goodTransition, resolvedSecurityFinding: true,
    })).toThrow();
    expect(() => parseStepTransition({
      ...goodStep, cyberScoreAdjustment: 100,
    })).toThrow();
  });
  it("requires CAS revisions and exact fingerprints to change case status", () => {
    expect(parseCaseTransition(goodTransition))
      .toMatchObject(goodTransition);
    expect(() => parseCaseTransition({
      ...goodTransition, expectedRevision: 0,
    })).toThrow();
    expect(() => parseCaseTransition({
      ...goodTransition, expectedRevision: 1.5,
    })).toThrow();
    expect(() => parseCaseTransition({
      ...goodTransition, expectedEvidenceFingerprint: "bad",
    })).toThrow();
    expect(() => parseCaseTransition({
      ...goodTransition, operation: "CLOSE_SECURITY_FINDING",
    })).toThrow();
  });
  it("enforces human review lifecycle and disallows skipped steps", () => {
    expect(caseTransitionTarget("OPEN", "START_REVIEW"))
      .toBe("IN_REVIEW");
    expect(caseTransitionTarget("OPEN", "DISMISS")).toBe("DISMISSED");
    expect(caseTransitionTarget("IN_REVIEW", "COMPLETE_WORK"))
      .toBe("WORK_COMPLETED");
    expect(caseTransitionTarget("DISMISSED", "REOPEN")).toBe("OPEN");
    expect(caseTransitionTarget("WORK_COMPLETED", "REOPEN")).toBe("OPEN");
    expect(caseTransitionTarget("OPEN", "COMPLETE_WORK")).toBeNull();
    expect(caseTransitionTarget("DISMISSED", "COMPLETE_WORK")).toBeNull();
    expect(caseTransitionTarget("WORK_COMPLETED", "COMPLETE_WORK")).toBeNull();
  });
  it("never treats a bounded no-match as work completion", () => {
    expect(canCompleteCaseWork([{ status: "DONE" }],
      "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION")).toBe(false);
    expect(canCompleteCaseWork([], "REVIEW_POSSIBLE_ADVISORY"))
      .toBe(false);
    expect(canCompleteCaseWork([{ status: "TODO" }],
      "REVIEW_POSSIBLE_ADVISORY")).toBe(false);
    expect(canCompleteCaseWork([{ status: "DONE" }, { status: "DONE" }],
      "REVIEW_POSSIBLE_ADVISORY")).toBe(true);
  });
  it("requires documented checklist note before transitions", () => {
    expect(parseStepTransition(goodStep)).toMatchObject(goodStep);
    expect(() => parseStepTransition({
      ...goodStep, note: "done",
    })).toThrow();
    expect(() => parseStepTransition({
      ...goodStep, expectedStepRevision: -1,
    })).toThrow();
    expect(() => parseStepTransition({
      ...goodStep, actionCode: "action/unsafe",
    })).toThrow();
    expect(() => parseStepTransition({
      ...goodStep, status: "REMEDIATED",
    })).toThrow();
  });
  it("keeps queries bounded and scoped to explicit supported statuses", () => {
    expect(parseCaseQuery()).toEqual({
      offset: 0, limit: 25,
      status: null, importId: null, inspectionId: null,
    });
    expect(parseCaseQuery({
      status: "IN_REVIEW", offset: 100, limit: 10,
    })).toMatchObject({
      status: "IN_REVIEW", offset: 100, limit: 10,
    });
    expect(() => parseCaseQuery({ status: "VERIFIED_SAFE" })).toThrow();
    expect(() => parseCaseQuery({ limit: 101 })).toThrow();
    expect(() => parseCaseQuery({ offset: -1 })).toThrow();
    expect(() => parseCaseQuery({ organizationId: "spoof" })).toThrow();
  });
});
