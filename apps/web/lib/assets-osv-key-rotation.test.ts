import { describe, expect, it } from "vitest";
import {
  dispatchKeyPermitsRequest,
  parseDispatchKeyConfig, parseSignedDispatchIntent,
  signOsvDispatch, verifySignedDispatch,
} from "./assets-osv-signed-dispatch";
import {
  parseKeyRotationInput, parseKeyRotationPolicy,
  inspectRotationKey, inspectRotationInventory,
  evaluateRotationPlan, proposeOsvKeyRotation,
} from "./assets-osv-key-rotation";
const now = new Date("2026-11-10T12:00:00.000Z");
const tenant = "rotation-tenant-12345";
const old = {
  id: "osv-previous-key-12345",
  organizationId: tenant,
  secretHex: "a2".repeat(32),
};
const replacement = {
  id: "osv-replacement-key-12345",
  organizationId: tenant,
  secretHex: "b3".repeat(32),
};
const keys = { enabled: true, keys: [old, replacement] };
const input = {
  organizationId: tenant, retiringKeyId: old.id,
  replacingKeyId: replacement.id,
  effectiveAt: "2026-11-10T13:00:00.000Z",
  retireAt: "2026-11-10T14:00:00.000Z",
  notBefore: "2026-11-10T12:45:00.000Z",
  notAfter: "2026-12-10T14:00:00.000Z",
  policy: {
    maximumActiveKeys: 2, minimumOverlapMinutes: 15,
    maximumOverlapMinutes: 1440, warningLeadHours: 72,
    requireDistinctMaterial: true,
    requireZeroOutstandingClaims: true,
  },
};
const intent = (date: string) =>
  parseSignedDispatchIntent({
    schema: "cyberpilot.assets.osv.signed-dispatch.v1",
    organizationId: tenant, organizationSlug: "rotation-tenant",
    scheduleId: "rotation-schedule-12345", expectedRevision: 1,
    issuedAt: date,
    expiresAt: new Date(new Date(date).getTime() + 60000).toISOString(),
    nonce: "synthetic-rotation-nonce-1234567890",
    confirmDispatch: true,
  });
describe("OSV scoped HMAC key lifecycle", () => {
  it("preserves legacy secret-only configuration as ACTIVE", () => {
    const config = parseDispatchKeyConfig(
      "true", JSON.stringify([old]));
    expect(config.keys).toEqual([old]);
    expect(dispatchKeyPermitsRequest(old,
      intent("2026-11-10T11:59:00.000Z"), now)).toBe(true);
  });
  it("supports explicit activation and retirement windows", () => {
    const key = {
      ...replacement,
      notBefore: "2026-11-10T11:50:00.000Z",
      notAfter: "2026-11-10T12:10:00.000Z",
      state: "ACTIVE" as const,
    };
    const config = parseDispatchKeyConfig("true",
      JSON.stringify([key]));
    expect(config.keys[0]).toMatchObject({
      notBefore: key.notBefore, notAfter: key.notAfter,
    });
    const signed = intent("2026-11-10T11:59:00.000Z");
    expect(verifySignedDispatch(signed, key.id,
      signOsvDispatch(signed, key.secretHex),
      config, now).keyId).toBe(key.id);
  });
  it("rejects signatures issued before key activation", () => {
    const key = {
      ...old, state: "ACTIVE" as const,
      notBefore: "2026-11-10T11:59:30.000Z",
    };
    expect(dispatchKeyPermitsRequest(key,
      intent("2026-11-10T11:59:00.000Z"), now)).toBe(false);
  });
  it("rejects signatures verified after old key expiry even if issued earlier", () => {
    const key = {
      ...old, state: "RETIRING" as const,
      notAfter: "2026-11-10T11:59:59.000Z",
    };
    expect(dispatchKeyPermitsRequest(key,
      intent("2026-11-10T11:59:00.000Z"), now)).toBe(false);
  });
  it("does not permit retiring keys without a deadline", () => {
    expect(dispatchKeyPermitsRequest({
      ...old, state: "RETIRING",
    }, intent("2026-11-10T11:59:00.000Z"), now)).toBe(false);
  });
  it("rejects a revoked key immediately and fails signed authentication", () => {
    const key = { ...old, state: "REVOKED" as const };
    const signed = intent("2026-11-10T11:59:00.000Z");
    const config = { enabled: true, keys: [key] };
    expect(dispatchKeyPermitsRequest(key, signed, now)).toBe(false);
    expect(() => verifySignedDispatch(signed, key.id,
      signOsvDispatch(signed, key.secretHex), config, now)).toThrow();
  });
  it("rejects unknown lifecycle states and invalid validity windows", () => {
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...old, state: "MAYBE" },
    ]))).toThrow();
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...old, notBefore: "2026-11-11T12:00:00.000Z",
        notAfter: "2026-11-10T12:00:00.000Z" },
    ]))).toThrow();
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...old, notAfter: "tomorrow" },
    ]))).toThrow();
  });
  it("never allows one tenant's key for another tenant", () => {
    expect(dispatchKeyPermitsRequest({
      ...old, organizationId: "another-tenant-12345",
    }, intent("2026-11-10T11:59:00.000Z"), now)).toBe(false);
  });
});
describe("OSV key cutover analysis", () => {
  it("defaults to bounded overlap and fresh-claim requirements", () => {
    expect(parseKeyRotationPolicy()).toMatchObject({
      maximumActiveKeys: 2, minimumOverlapMinutes: 15,
      maximumOverlapMinutes: 1440, warningLeadHours: 72,
      requireDistinctMaterial: true,
      requireZeroOutstandingClaims: true,
    });
  });
  it.each([
    { maximumActiveKeys: 0 },
    { maximumActiveKeys: 11 },
    { minimumOverlapMinutes: 0 },
    { maximumOverlapMinutes: 0 },
    { minimumOverlapMinutes: 200, maximumOverlapMinutes: 100 },
    { warningLeadHours: 0 },
    { requireDistinctMaterial: "true" },
    { requireZeroOutstandingClaims: 1 },
    { unknown: true },
  ])("rejects invalid or ambiguous rotation policy %j", patch => {
    expect(() => parseKeyRotationPolicy(patch)).toThrow();
  });
  it("requires two distinct key IDs and coherent lifetimes", () => {
    expect(parseKeyRotationInput(input).retiringKeyId).toBe(old.id);
    expect(() => parseKeyRotationInput({
      ...input, replacingKeyId: old.id,
    })).toThrow();
    expect(() => parseKeyRotationInput({
      ...input, retireAt: input.effectiveAt,
    })).toThrow();
    expect(() => parseKeyRotationInput({
      ...input, notBefore: "2026-11-10T13:01:00.000Z",
    })).toThrow();
    expect(() => parseKeyRotationInput({
      ...input, notAfter: input.retireAt,
    })).toThrow();
  });
  it("produces a viable one-hour overlap with distinct secrets", () => {
    const plan = evaluateRotationPlan(keys,
      parseKeyRotationInput(input), now, 0, 0, 0);
    expect(plan.readyForOperatorReview).toBe(true);
    expect(plan.blockingReasons).toEqual([]);
    expect(plan.overlappingMinutes).toBe(60);
    expect(plan.activeAtEffective).toBe(2);
    expect(plan.activeAtRetirement).toBe(1);
  });
  it("does not certify a cutover while outstanding claims remain", () => {
    const plan = evaluateRotationPlan(keys,
      parseKeyRotationInput(input), now, 1, 2, 4);
    expect(plan.readyForOperatorReview).toBe(false);
    expect(plan.blockingReasons.join(" ")).toMatch(/claims/i);
    expect(plan.blockingReasons.join(" ")).toMatch(/quota/i);
  });
  it("blocks reuse of cryptographic material under distinct key IDs", () => {
    const reused = {
      enabled: true, keys: [old, {
        ...replacement, secretHex: old.secretHex,
      }],
    };
    const plan = evaluateRotationPlan(reused,
      parseKeyRotationInput(input), now, 0, 0, 0);
    expect(plan.readyForOperatorReview).toBe(false);
    expect(plan.blockingReasons.join(" ")).toMatch(/cryptographic/i);
  });
  it("blocks a rotation preview when the dispatcher is disabled", () => {
    const plan = evaluateRotationPlan({
      enabled: false, keys: [old, replacement],
    }, parseKeyRotationInput(input), now, 0, 0, 0);
    expect(plan.readyForOperatorReview).toBe(false);
  });
  it("blocks configurations with too many keys active simultaneously", () => {
    const extra = { ...replacement,
      id: "third-active-key-12345",
      secretHex: "c4".repeat(32) };
    const plan = evaluateRotationPlan({
      enabled: true, keys: [old, replacement, extra],
    }, parseKeyRotationInput(input), now, 0, 0, 0);
    expect(plan.blockingReasons.join(" ")).toMatch(/many/i);
  });
  it("blocks a proposed replacement that has not been installed", () => {
    const plan = proposeOsvKeyRotation({
      enabled: true, keys: [old],
    }, parseKeyRotationInput(input), now, 0, 0, 0);
    expect(plan.plan.readyForOperatorReview).toBe(false);
    expect(plan.plan.blockingReasons.join(" ")).toMatch(/synthetic/i);
    expect(plan.noSecretsOrConfigWritten).toBe(true);
  });
  it("returns no key material even in full JSON export of preview", () => {
    const preview = proposeOsvKeyRotation(keys,
      parseKeyRotationInput(input), now, 0, 0, 0);
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain(old.secretHex);
    expect(serialized).not.toContain(replacement.secretHex);
    expect(serialized).not.toContain("secretHex");
    expect(preview.after.keys).toHaveLength(2);
    expect(preview.rolloutStages).toHaveLength(5);
  });
  it("reports retiring and revoked keys as non-accepting when appropriate", () => {
    const result = inspectRotationKey({
      ...old, state: "REVOKED",
    }, now, parseKeyRotationPolicy());
    expect(result.currentlyAccepting).toBe(false);
    expect(result.observations.join(" ")).toMatch(/Revoked/i);
    const inventory = inspectRotationInventory({
      enabled: true, keys: [{
        ...old, state: "RETIRING",
        notAfter: "2026-11-10T11:00:00.000Z",
      }],
    }, tenant, now);
    expect(inventory.activeKeyCount).toBe(0);
    expect(inventory.retiringKeyCount).toBe(1);
  });
});
