import { describe, expect, it } from "vitest";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import {
  emptySnapshotJournal, planJournalAppendFromCaptures,
} from "./work-integrity-snapshot-journal";
import { planJournalArchive } from "./work-integrity-snapshot-journal-archive";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
function capture(day: number, source = "source-a", complete = true) {
  return {
    organizationId: tenant, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
const policy = {
  minimumAgeDays: 1, preserveLatestPerSource: 1,
  maximumArchiveCaptures: 100, requireComplete: false,
  requireJournalValidation: true, allowQuarantined: false,
};
function journal(input: ReturnType<typeof capture>[]) {
  return planJournalAppendFromCaptures(input, emptySnapshotJournal(tenant),
    tenant, now, "operator-a");
}
describe("journal-aware archive preflight", () => {
  it("protects the latest capture per source", () => {
    const input = [capture(28), capture(30)];
    const report = planJournalArchive(input, journal(input), tenant, now, policy);
    expect(report.eligible).toBe(1);
    expect(report.candidates.find(c => c.capturedAt === capture(30).capturedAt)
      ?.reasons).toContain("SOURCE_FLOOR");
  });
  it("does not archive a capture missing from the journal", () => {
    const report = planJournalArchive([capture(28)],
      emptySnapshotJournal(tenant), tenant, now,
      { ...policy, preserveLatestPerSource: 0 });
    expect(report.candidates[0]?.reasons).toContain("NOT_IN_JOURNAL");
  });
  it("detects changed capture contents", () => {
    const original = [capture(28)];
    const report = planJournalArchive([capture(28, "source-a", false)],
      journal(original), tenant, now,
      { ...policy, preserveLatestPerSource: 0 });
    expect(report.candidates[0]?.reasons).toContain("CONTENT_CONFLICT");
  });
  it("rejects cross-organization archive journal", () => {
    expect(() => planJournalArchive([], emptySnapshotJournal("tenant-b"),
      tenant, now, policy)).toThrow(/Cross-organization/);
  });
  it("rejects a corrupted journal", () => {
    const original = journal([capture(28)]);
    expect(() => planJournalArchive([capture(28)], {
      ...original, headDigest: "0".repeat(64),
    }, tenant, now, policy)).toThrow(/integrity/);
  });
  it("preserves all captures when floor exceeds source count", () => {
    const input = [capture(28), capture(30)];
    const report = planJournalArchive(input, journal(input), tenant, now,
      { ...policy, preserveLatestPerSource: 5 });
    expect(report.eligible).toBe(0);
  });
  it("supports empty archives without fabricated evidence", () => {
    const report = planJournalArchive([], emptySnapshotJournal(tenant),
      tenant, now, policy);
    expect(report.eligible).toBe(0);
    expect(report.eligibleBytes).toBe(0);
  });
  it("enforces archive age", () => {
    const input = [capture(30)];
    const report = planJournalArchive(input, journal(input), tenant, now,
      { ...policy, minimumAgeDays: 10, preserveLatestPerSource: 0 });
    expect(report.candidates[0]?.reasons).toContain("TOO_RECENT");
  });
  it("enforces complete coverage", () => {
    const input = [capture(28, "source-a", false)];
    const report = planJournalArchive(input, journal(input), tenant, now,
      { ...policy, requireComplete: true, preserveLatestPerSource: 0 });
    expect(report.candidates[0]?.reasons).toContain("INCOMPLETE");
  });
  it("rejects invalid age policies", () => {
    expect(() => planJournalArchive([], emptySnapshotJournal(tenant),
      tenant, now, { ...policy, minimumAgeDays: -1 })).toThrow(/Invalid/);
  });
  it("returns a bounded and explicit archive estimate", () => {
    const input = [capture(28)];
    const report = planJournalArchive(input, journal(input), tenant, now,
      { ...policy, preserveLatestPerSource: 0 });
    expect(report.eligibleBytes).toBeGreaterThan(0);
  });
});
