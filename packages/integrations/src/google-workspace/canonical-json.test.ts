import { describe, expect, it } from "vitest";
import {
  canonicalGoogleHash, canonicalGoogleJson,
  canonicalGoogleEqual,
} from "./canonical-json";
import {
  newGoogleLabConnection, verifyGoogleLabConnection,
  transitionGoogleLab,
} from "./onboarding-policy";
import { normalizeBatch } from "./directory-contract";
import {
  assessGoogleWorkspace, verifyGoogleRiskAssessment,
} from "./risk-assessment";
import {
  buildGoogleExecutiveReport,
  verifyGoogleExecutiveReport,
} from "./assessment-report";
import {
  buildNeutralGoogleBundle, verifyNeutralGoogleBundle,
} from "./neutral-evidence";

const reverseKeys = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).reverse()
      .map(([key, v]) => [key, reverseKeys(v)]));
  return value;
};
const roundtrip = <T>(value: T): T =>
  reverseKeys(JSON.parse(JSON.stringify(value))) as T;
describe("canonical JSONB-independent Google evidence digests", () => {
  it("maintains identical fingerprints after arbitrary nested key reordering", () => {
    const first = { z: [{ p: 1, b: { y: true, x: null } }],
      a: 4, middle: "test" };
    const second = reverseKeys(first);
    expect(canonicalGoogleJson(first)).toBe(
      canonicalGoogleJson(second));
    expect(canonicalGoogleHash(first)).toBe(
      canonicalGoogleHash(second));
    expect(canonicalGoogleEqual(canonicalGoogleHash(first),
      canonicalGoogleHash(second))).toBe(true);
  });
  it("rejects undefined, nonfinite and unsupported canonical JSON fields", () => {
    expect(() => canonicalGoogleHash({ n: undefined })).toThrow();
    expect(() => canonicalGoogleHash({ n: Number.NaN })).toThrow();
    expect(() => canonicalGoogleHash({ n: Infinity })).toThrow();
    expect(() => canonicalGoogleHash({ n: BigInt(10) })).toThrow();
  });
  it("LAB CAS connection survives JSONB-like serialization roundtrip", () => {
    const initial = newGoogleLabConnection({
      organizationId: "tenant-12345",
      actorUserId: "operator-12345",
      role: "ADMIN",
    }, "lab-connection-12345", "2026-11-12T10:00:00.000Z");
    expect(verifyGoogleLabConnection(roundtrip(initial)).valid).toBe(true);
    const transition = transitionGoogleLab(initial, {
      organizationId: "tenant-12345",
      actorUserId: "operator-12345",
      role: "ADMIN",
    }, {
      type: "ISSUE_CHALLENGE",
      connectionId: "lab-connection-12345",
      expectedRevision: 0,
      at: "2026-11-12T10:01:00.000Z",
      reason: "Simulated test challenge.",
      challengeNonce: "12345678901234567890123456789012",
      requestedCapabilities: ["DIRECTORY_USERS"],
    });
    expect(verifyGoogleLabConnection(
      roundtrip(transition.connection)).valid).toBe(true);
  });
  it("risk assessment remains verifiable when PostgreSQL reorders keys", () => {
    const source = normalizeBatch({
      organizationId: "tenant-12345",
      checkedAt: "2026-11-12T10:00:00.000Z",
      source: "SYNTHETIC_FIXTURE",
      users: [{
        id: "google-user-12345",
        primaryEmail: "test@example.invalid",
        suspended: false, isAdmin: true,
        isEnrolledIn2Sv: false,
        isEnforcedIn2Sv: false,
      }],
    });
    const assessment = assessGoogleWorkspace(source, {},
      new Date("2026-11-12T10:05:00.000Z"));
    const report = buildGoogleExecutiveReport(assessment);
    expect(verifyGoogleRiskAssessment(roundtrip(assessment)).valid)
      .toBe(true);
    expect(verifyGoogleExecutiveReport(roundtrip(report)).valid)
      .toBe(true);
    const neutral = buildNeutralGoogleBundle(roundtrip(assessment));
    expect(verifyNeutralGoogleBundle(roundtrip(neutral)).valid)
      .toBe(true);
  });
  it("tampering still fails even when keys are sorted", () => {
    const original = { a: 1, b: { c: 2 } };
    const changed = { b: { c: 3 }, a: 1 };
    expect(canonicalGoogleEqual(
      canonicalGoogleHash(original),
      canonicalGoogleHash(changed))).toBe(false);
  });
});
