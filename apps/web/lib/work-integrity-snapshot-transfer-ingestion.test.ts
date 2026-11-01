import { describe, expect, it } from "vitest";
import {
  createSnapshotTransferEnvelope, verifySnapshotTransferEnvelope,
  transferEnvelopeFingerprint,
} from "./work-integrity-snapshot-transfer";
import {
  planSnapshotIngestion, materializeAcceptedSnapshotBatch,
} from "./work-integrity-snapshot-ingestion";

const tenant = "tenant-a";
const secret = "very-long-private-transfer-key-for-unit-testing-2026";
const issued = "2026-10-31T12:00:00.000Z";
const expires = "2026-11-01T12:00:00.000Z";
const now = "2026-11-01T11:00:00.000Z";
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
function envelope() {
  return createSnapshotTransferEnvelope([capture(30)], tenant,
    "key-1", secret, issued, expires, "nonce-1");
}
const ingestionPolicy = {
  maxAgeDays: 90, maxFutureSkewMinutes: 5,
  maxCasesPerCapture: 100, maxCapturesPerSource: 5,
  requireComplete: true, rejectQualityBlockers: false,
  rejectQualityWarnings: false, allowedSources: null,
};
describe("authenticated snapshot transfer envelopes", () => {
  it("signs and verifies unchanged transfer material", () => {
    const transfer = envelope();
    const result = verifySnapshotTransferEnvelope(transfer, tenant, "key-1",
      secret, now);
    expect(result.verified).toBe(true);
    expect(result.captureCount).toBe(1);
  });
  it("rejects a wrong signing secret", () => {
    const result = verifySnapshotTransferEnvelope(envelope(), tenant, "key-1",
      "different-private-transfer-key-for-unit-testing", now);
    expect(result.code).toBe("INVALID_SIGNATURE");
  });
  it("rejects a changed capture", () => {
    const transfer = envelope();
    const modified = { ...transfer, captures: [capture(30, "source-a", false)] };
    expect(verifySnapshotTransferEnvelope(modified, tenant, "key-1",
      secret, now).code).toBe("INVALID_SIGNATURE");
  });
  it("rejects another tenant", () => {
    expect(verifySnapshotTransferEnvelope(envelope(), "tenant-b", "key-1",
      secret, now).code).toBe("TENANT_MISMATCH");
  });
  it("rejects a different key identifier", () => {
    expect(verifySnapshotTransferEnvelope(envelope(), tenant, "key-2",
      secret, now).code).toBe("KEY_MISMATCH");
  });
  it("rejects expired transfers", () => {
    expect(verifySnapshotTransferEnvelope(envelope(), tenant, "key-1",
      secret, "2026-11-03T12:00:00.000Z").code).toBe("EXPIRED");
  });
  it("rejects transfers issued in the future", () => {
    expect(verifySnapshotTransferEnvelope(envelope(), tenant, "key-1",
      secret, "2026-10-30T12:00:00.000Z").code).toBe("NOT_YET_VALID");
  });
  it("consults the caller's replay store", () => {
    expect(verifySnapshotTransferEnvelope(envelope(), tenant, "key-1",
      secret, now, { hasNonce: () => true }).code).toBe("REPLAY");
  });
  it("rejects transfer captures from another organization", () => {
    expect(() => createSnapshotTransferEnvelope([
      capture(30, "source-a", true, "tenant-b"),
    ], tenant, "key-1", secret, issued, expires, "nonce-1"))
      .toThrow(/Cross-organization/);
  });
  it("rejects short secrets", () => {
    expect(() => createSnapshotTransferEnvelope([capture(30)], tenant,
      "key-1", "short", issued, expires, "nonce-1")).toThrow(/32/);
  });
  it("rejects reversed expiry intervals", () => {
    expect(() => createSnapshotTransferEnvelope([capture(30)], tenant,
      "key-1", secret, expires, issued, "nonce-1")).toThrow(/lifetime/);
  });
  it("produces a stable fingerprint for identical material", () => {
    expect(transferEnvelopeFingerprint(envelope()))
      .toBe(transferEnvelopeFingerprint(envelope()));
  });
  it("produces a different fingerprint after changing the nonce", () => {
    const first = envelope();
    const second = createSnapshotTransferEnvelope([capture(30)], tenant,
      "key-1", secret, issued, expires, "nonce-2");
    expect(transferEnvelopeFingerprint(first))
      .not.toBe(transferEnvelopeFingerprint(second));
  });
});
describe("snapshot ingestion preflight", () => {
  it("accepts a fresh new capture", () => {
    const result = planSnapshotIngestion([capture(30)], [],
      tenant, now, ingestionPolicy);
    expect(result.accepted).toBe(1);
    expect(result.rejected).toBe(0);
  });
  it("skips identical existing captures", () => {
    const result = planSnapshotIngestion([capture(30)], [capture(30)],
      tenant, now, ingestionPolicy);
    expect(result.skippedIdentical).toBe(1);
  });
  it("rejects an existing identity with changed contents", () => {
    const result = planSnapshotIngestion([capture(30, "source-a", false)],
      [capture(30)], tenant, now, ingestionPolicy);
    expect(result.candidates[0]?.reasons).toContain("EXISTING_CONFLICT");
  });
  it("rejects duplicate batch identities", () => {
    const result = planSnapshotIngestion([capture(30), capture(30)], [],
      tenant, now, ingestionPolicy);
    expect(result.rejected).toBe(1);
  });
  it("rejects incomplete coverage under strict policy", () => {
    const result = planSnapshotIngestion([capture(30, "source-a", false)],
      [], tenant, now, ingestionPolicy);
    expect(result.candidates[0]?.reasons).toContain("INCOMPLETE_COVERAGE");
  });
  it("enforces allowed source lists", () => {
    const result = planSnapshotIngestion([capture(30)], [],
      tenant, now, { ...ingestionPolicy, allowedSources: ["source-b"] });
    expect(result.candidates[0]?.reasons).toContain("SOURCE_NOT_ALLOWED");
  });
  it("enforces per-source quotas", () => {
    const result = planSnapshotIngestion([capture(30)], [capture(29)],
      tenant, now, { ...ingestionPolicy, maxCapturesPerSource: 1 });
    expect(result.candidates[0]?.reasons).toContain("SOURCE_QUOTA");
  });
  it("rejects captures from another tenant", () => {
    expect(() => planSnapshotIngestion([
      capture(30, "source-a", true, "tenant-b"),
    ], [], tenant, now, ingestionPolicy)).toThrow(/Cross-organization/);
  });
  it("materializes accepted captures after rechecking hashes", () => {
    const input = [capture(30)];
    const plan = planSnapshotIngestion(input, [], tenant, now, ingestionPolicy);
    expect(materializeAcceptedSnapshotBatch(plan, input).accepted).toHaveLength(1);
  });
  it("rejects modifications between preflight and materialization", () => {
    const input = [capture(30)];
    const plan = planSnapshotIngestion(input, [], tenant, now, ingestionPolicy);
    expect(() => materializeAcceptedSnapshotBatch(plan,
      [capture(30, "source-a", false)])).toThrow(/modified/);
  });
  it("rejects missing accepted captures", () => {
    const plan = planSnapshotIngestion([capture(30)], [],
      tenant, now, ingestionPolicy);
    expect(() => materializeAcceptedSnapshotBatch(plan, [])).toThrow(/missing/);
  });
  it("rejects duplicate materialization captures", () => {
    const plan = planSnapshotIngestion([capture(30)], [],
      tenant, now, ingestionPolicy);
    expect(() => materializeAcceptedSnapshotBatch(plan,
      [capture(30), capture(30)])).toThrow(/Duplicate/);
  });
});
