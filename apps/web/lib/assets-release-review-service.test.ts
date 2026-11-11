import { describe, expect, it } from "vitest";
import {
  REQUIRED_ACKNOWLEDGEMENTS, parseReleaseCreate,
  parseReleaseTransition, parseReleaseQuery, releaseTarget,
  missingReleaseAcknowledgements, mayAcceptOffline,
} from "./assets-release-review-service";

const sha = "a".repeat(64);
const reason = "Reviewed the selected evidence and its documented limitations.";
const bindings: unknown[] = [];
function create(overrides: Record<string, unknown> = {}) {
  return {
    importId: "inventory_12345",
    inspectionId: "inspection_12345",
    bindings,
    acceptancePolicy: {},
    privacyPolicy: {},
    reason,
    acknowledgements: REQUIRED_ACKNOWLEDGEMENTS,
    exclusions: ["LIVE provider not validated"],
    ...overrides,
  };
}
function transition(overrides: Record<string, unknown> = {}) {
  return {
    reviewId: "review_12345",
    expectedRevision: 1,
    expectedEvidenceBundleDigest: sha,
    operation: "START_REVIEW",
    reason,
    acknowledgements: REQUIRED_ACKNOWLEDGEMENTS,
    bindings: [],
    acceptancePolicy: {},
    privacyPolicy: {},
    ...overrides,
  };
}
describe("Fase 4 human release decision contract", () => {
  it("parses an explicit, tenant-independent command without trusting a client tenant", () => {
    const command = parseReleaseCreate(create());
    expect(command.importId).toBe("inventory_12345");
    expect(command.inspectionId).toBe("inspection_12345");
    expect(command.acknowledgements).toEqual(REQUIRED_ACKNOWLEDGEMENTS);
    expect(command.exclusions).toEqual(["LIVE provider not validated"]);
    expect(command).not.toHaveProperty("organizationId");
    expect(command).not.toHaveProperty("operatorUserId");
  });
  it("does not require a false implicit acceptance when opening a review", () => {
    const command = parseReleaseCreate(create({
      acknowledgements: [], exclusions: [],
    }));
    expect(command.acknowledgements).toEqual([]);
    expect(command.exclusions).toEqual([]);
  });
  it.each([
    { organizationId: "other-tenant" },
    { operatorUserId: "another-user" },
    { state: "ACCEPTED_OFFLINE" },
    { revision: 9 },
    { decidedAt: "2026-11-11" },
    { evidenceBundleDigest: sha },
    { manualApproval: true },
  ])("rejects client overrides of server-owned create fields %j", extra => {
    expect(() => parseReleaseCreate(create(extra))).toThrow();
  });
  it.each([
    { importId: "" },
    { importId: "../other" },
    { inspectionId: "a" },
    { importId: 3 },
    { bindings: null },
    { bindings: "[]" },
    { bindings: Array.from({ length: 2001 }, () => ({})) },
    { reason: "ok" },
    { reason: "x".repeat(1501) },
    { reason: "a sufficiently long reason\nwith control" },
    { acknowledgements: ["NOT_A_REAL_ACK"] },
    { acknowledgements: ["OFFLINE_ONLY", "OFFLINE_ONLY"] },
    { acknowledgements: "OFFLINE_ONLY" },
    { exclusions: "nothing" },
    { exclusions: ["x"] },
    { exclusions: ["Same exclusion", "Same exclusion"] },
    { exclusions: Array.from({ length: 21 }, (_, i) => "exclusion " + i) },
  ])("rejects invalid creation payloads %j", extra => {
    expect(() => parseReleaseCreate(create(extra))).toThrow();
  });
  it("preserves revision and bundle identity on a human transition", () => {
    const command = parseReleaseTransition(transition({
      operation: "ACCEPT_OFFLINE", expectedRevision: 12,
    }));
    expect(command.expectedRevision).toBe(12);
    expect(command.expectedEvidenceBundleDigest).toBe(sha);
    expect(command.operation).toBe("ACCEPT_OFFLINE");
    expect(command).not.toHaveProperty("organizationId");
  });
  it.each([
    { expectedRevision: 0 },
    { expectedRevision: -1 },
    { expectedRevision: 2.5 },
    { expectedRevision: "1" },
    { expectedEvidenceBundleDigest: "bad" },
    { expectedEvidenceBundleDigest: "A".repeat(64) },
    { operation: "AUTO_APPROVE" },
    { operation: "ACCEPT_LIVE" },
    { operation: "DELETE" },
    { reviewId: "../other" },
    { reason: "" },
    { bindings: {} },
    { organizationId: "external" },
    { actorUserId: "someone" },
    { autoAccepted: true },
  ])("rejects unsafe transition input %j", extra => {
    expect(() => parseReleaseTransition(transition(extra))).toThrow();
  });
  it("supports a bounded tenant-scoped list query", () => {
    expect(parseReleaseQuery()).toEqual({
      offset: 0, limit: 25, importId: null,
      inspectionId: null, state: null,
    });
    expect(parseReleaseQuery({ offset: 20, limit: 5,
      importId: "inventory_12345", state: "IN_REVIEW" }))
      .toMatchObject({ offset: 20, limit: 5,
        importId: "inventory_12345", state: "IN_REVIEW" });
  });
  it.each([
    { offset: -1 },
    { offset: 100001 },
    { offset: 1.5 },
    { limit: 0 },
    { limit: 101 },
    { limit: "25" },
    { state: "ACCEPTED_LIVE" },
    { organizationId: "foreign" },
    { scope: "all" },
    { inspectionId: "../inspection" },
  ])("rejects unsafe list fields %j", extra => {
    expect(() => parseReleaseQuery(extra)).toThrow();
  });
  it("allows only explicit, audited lifecycle transitions", () => {
    const expected: Record<string, Record<string, string | null>> = {
      PENDING: {
        START_REVIEW: "IN_REVIEW", ACCEPT_OFFLINE: null,
        REJECT: "REJECTED", REOPEN: null,
      },
      IN_REVIEW: {
        START_REVIEW: null, ACCEPT_OFFLINE: "ACCEPTED_OFFLINE",
        REJECT: "REJECTED", REOPEN: null,
      },
      ACCEPTED_OFFLINE: {
        START_REVIEW: null, ACCEPT_OFFLINE: null,
        REJECT: null, REOPEN: "REOPENED",
      },
      REJECTED: {
        START_REVIEW: null, ACCEPT_OFFLINE: null,
        REJECT: null, REOPEN: "REOPENED",
      },
      REOPENED: {
        START_REVIEW: "IN_REVIEW", ACCEPT_OFFLINE: null,
        REJECT: "REJECTED", REOPEN: null,
      },
    };
    for (const [state, operations] of Object.entries(expected))
      for (const [operation, target] of Object.entries(operations))
        expect(releaseTarget(state as Parameters<typeof releaseTarget>[0],
          operation as Parameters<typeof releaseTarget>[1]))
          .toBe(target);
  });
  it("requires every non-implicit human acknowledgement", () => {
    expect(missingReleaseAcknowledgements([]))
      .toEqual(REQUIRED_ACKNOWLEDGEMENTS);
    expect(missingReleaseAcknowledgements(REQUIRED_ACKNOWLEDGEMENTS))
      .toEqual([]);
    for (const id of REQUIRED_ACKNOWLEDGEMENTS)
      expect(missingReleaseAcknowledgements(
        REQUIRED_ACKNOWLEDGEMENTS.filter(x => x !== id))).toContain(id);
  });
  it("does not accept a synthetic green matrix when other blockers persist", () => {
    const empty = { blockers: [] } as unknown as
      Parameters<typeof mayAcceptOffline>[0];
    const blocked = { blockers: ["PRIVACY_REVIEW_PENDING"] } as unknown as
      Parameters<typeof mayAcceptOffline>[0];
    expect(mayAcceptOffline(empty, [])).toBe(false);
    expect(mayAcceptOffline(blocked, REQUIRED_ACKNOWLEDGEMENTS))
      .toBe(false);
    expect(mayAcceptOffline(empty, REQUIRED_ACKNOWLEDGEMENTS))
      .toBe(true);
  });
});
