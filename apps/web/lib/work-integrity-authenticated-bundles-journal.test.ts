import { describe, expect, it } from "vitest";
import {
  createAuthenticatedSnapshotBundle, verifyAuthenticatedSnapshotBundle,
  fingerprintAuthenticatedBundle, DEFAULT_BUNDLE_POLICY,
} from "./work-integrity-authenticated-bundles";
import {
  emptySnapshotJournal, appendSnapshotJournalEntry, verifySnapshotJournal,
  reconcileSnapshotJournal, planJournalAppendFromCaptures,
} from "./work-integrity-snapshot-journal";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const key = {
  id: "active-key", secret: new Uint8Array(32).fill(73),
  activeFrom: "2026-01-01T00:00:00.000Z",
  activeUntil: null, revoked: false,
};
const ring = { getKey: (_tenant: string, id: string) => id === key.id ? key : null };
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
function bundle() {
  return createAuthenticatedSnapshotBundle([capture(30)], tenant, key,
    "2026-10-31T12:00:00.000Z", "2026-11-01T13:00:00.000Z",
    "unique-nonce");
}
describe("keyring authenticated snapshot bundles", () => {
  it("verifies an unchanged bundle using the trusted keyring", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant, ring, now).verified)
      .toBe(true);
  });
  it("rejects a different organization", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), "tenant-b", ring, now).code)
      .toBe("WRONG_ORGANIZATION");
  });
  it("rejects a changed capture", () => {
    const changed = { ...bundle(), captures: [capture(30, "source-a", false)] };
    expect(verifyAuthenticatedSnapshotBundle(changed, tenant, ring, now).code)
      .toBe("INVALID_SIGNATURE");
  });
  it("rejects a changed manifest", () => {
    const original = bundle();
    const changed = { ...original, manifest: {
      ...original.manifest, rootSha256: "0".repeat(64),
    } };
    expect(verifyAuthenticatedSnapshotBundle(changed, tenant, ring, now).verified)
      .toBe(false);
  });
  it("rejects an untrusted key", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant,
      { getKey: () => null }, now).code).toBe("UNTRUSTED_KEY");
  });
  it("rejects a revoked key", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant,
      { getKey: () => ({ ...key, revoked: true }) }, now).code)
      .toBe("UNTRUSTED_KEY");
  });
  it("rejects a replayed nonce", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant, ring, now,
      { hasSeen: () => true }).code).toBe("REPLAYED");
  });
  it("rejects an expired bundle", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant, ring,
      "2026-11-03T12:00:00.000Z").code).toBe("EXPIRED");
  });
  it("rejects a bundle before its creation", () => {
    expect(verifyAuthenticatedSnapshotBundle(bundle(), tenant, ring,
      "2026-10-29T12:00:00.000Z").code).toBe("FUTURE");
  });
  it("rejects an invalid key length", () => {
    expect(() => createAuthenticatedSnapshotBundle([capture(30)],
      tenant, { ...key, secret: new Uint8Array(8) },
      "2026-10-31T12:00:00.000Z", "2026-11-01T13:00:00.000Z",
      "nonce")).toThrow(/32/);
  });
  it("rejects a revoked signing key", () => {
    expect(() => createAuthenticatedSnapshotBundle([capture(30)],
      tenant, { ...key, revoked: true },
      "2026-10-31T12:00:00.000Z", "2026-11-01T13:00:00.000Z",
      "nonce")).toThrow(/Revoked/);
  });
  it("rejects a source outside the configured allowlist", () => {
    expect(() => createAuthenticatedSnapshotBundle([capture(30)],
      tenant, key, "2026-10-31T12:00:00.000Z",
      "2026-11-01T13:00:00.000Z", "nonce",
      { ...DEFAULT_BUNDLE_POLICY, allowedSources: ["other"] }))
      .toThrow(/allowlist/);
  });
  it("rejects duplicate capture identities", () => {
    expect(() => createAuthenticatedSnapshotBundle([capture(30), capture(30)],
      tenant, key, "2026-10-31T12:00:00.000Z",
      "2026-11-01T13:00:00.000Z", "nonce"))
      .toThrow(/Duplicate/);
  });
  it("produces a stable content fingerprint", () => {
    expect(fingerprintAuthenticatedBundle(bundle()))
      .toBe(fingerprintAuthenticatedBundle(bundle()));
  });
  it("rejects incomplete captures under strict policy", () => {
    expect(() => createAuthenticatedSnapshotBundle([
      capture(30, "source-a", false),
    ], tenant, key, "2026-10-31T12:00:00.000Z",
      "2026-11-01T13:00:00.000Z", "nonce",
      { ...DEFAULT_BUNDLE_POLICY, requireCompleteCaptures: true }))
      .toThrow(/complete/);
  });
});
describe("append-only capture journal", () => {
  const digest = buildSnapshotManifest([capture(30)], tenant, now).entries[0]!.sha256;
  function append(journal = emptySnapshotJournal(tenant)) {
    return appendSnapshotJournalEntry(journal, {
      id: "entry-1", source: "source-a",
      capturedAt: capture(30).capturedAt, recordedAt: now,
      actorId: "operator-a", operation: "CAPTURE_ADDED",
      captureDigest: digest, reason: "Collected from scheduled source.",
      expectedHeadDigest: journal.headDigest,
    }, tenant).journal;
  }
  it("creates an empty journal with sequence one", () => {
    expect(emptySnapshotJournal(tenant).nextSequence).toBe(1);
  });
  it("appends an active capture", () => {
    const journal = append();
    expect(journal.captures[0]?.status).toBe("ACTIVE");
    expect(journal.entries).toHaveLength(1);
  });
  it("replays a valid journal", () => {
    expect(verifySnapshotJournal(append(), tenant).valid).toBe(true);
  });
  it("detects a modified journal digest", () => {
    const journal = append();
    const modified = { ...journal, entries: [
      { ...journal.entries[0]!, entryDigest: "0".repeat(64) },
    ] };
    expect(verifySnapshotJournal(modified, tenant).valid).toBe(false);
  });
  it("detects altered materialized capture state", () => {
    const journal = append();
    const modified = { ...journal, captures: [
      { ...journal.captures[0]!, status: "ARCHIVED" as const },
    ] };
    expect(verifySnapshotJournal(modified, tenant).valid).toBe(false);
  });
  it("rejects stale optimistic concurrency heads", () => {
    const journal = append();
    expect(() => appendSnapshotJournalEntry(journal, {
      id: "entry-2", source: "source-a",
      capturedAt: capture(30).capturedAt, recordedAt: now,
      actorId: "operator-a", operation: "CAPTURE_DUPLICATE",
      captureDigest: digest, reason: "Duplicate capture.",
      expectedHeadDigest: null,
    }, tenant)).toThrow(/concurrency/);
  });
  it("rejects cross-tenant append", () => {
    expect(() => appendSnapshotJournalEntry(emptySnapshotJournal(tenant), {
      id: "entry-1", source: "source-a",
      capturedAt: capture(30).capturedAt, recordedAt: now,
      actorId: "operator-a", operation: "CAPTURE_ADDED",
      captureDigest: digest, reason: "Collected.",
      expectedHeadDigest: null,
    }, "tenant-b")).toThrow(/Cross-organization/);
  });
  it("reconciles a matching supplied capture", () => {
    const result = reconcileSnapshotJournal(append(), [capture(30)], tenant, now);
    expect(result.contentConflicts).toHaveLength(0);
    expect(result.missingFromSupply).toHaveLength(0);
  });
  it("detects a missing supplied capture", () => {
    const result = reconcileSnapshotJournal(append(), [], tenant, now);
    expect(result.missingFromSupply).toHaveLength(1);
  });
  it("detects a modified supplied capture", () => {
    const result = reconcileSnapshotJournal(append(),
      [capture(30, "source-a", false)], tenant, now);
    expect(result.contentConflicts).toHaveLength(1);
  });
  it("builds a deterministic capture append plan", () => {
    const result = planJournalAppendFromCaptures([capture(30)],
      emptySnapshotJournal(tenant), tenant, now, "operator-a");
    expect(result.entries).toHaveLength(1);
    expect(verifySnapshotJournal(result, tenant).valid).toBe(true);
  });
  it("rejects an invalid starting journal", () => {
    const journal = append();
    expect(() => planJournalAppendFromCaptures([], {
      ...journal, headDigest: "0".repeat(64),
    }, tenant, now, "operator-a")).toThrow(/Invalid starting/);
  });
});
