import { describe, expect, it } from "vitest";
import { emptySnapshotJournal, planJournalAppendFromCaptures } from "./work-integrity-snapshot-journal";
import { auditSnapshotCustody } from "./work-integrity-snapshot-custody";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const policy = {
  maxCaptures: 100, maxAgeDays: 90, maxFutureSkewMinutes: 5,
  requireCompleteActiveCaptures: true, allowedSources: null,
  includeArchived: true, includeRejected: true,
};
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
function journal(captures: ReturnType<typeof capture>[]) {
  return planJournalAppendFromCaptures(captures,
    emptySnapshotJournal(tenant), tenant, now, "operator-a");
}
describe("capture custody audit", () => {
  it("reconciles identical active capture inventories", () => {
    const captures = [capture(30)];
    const result = auditSnapshotCustody(captures, journal(captures),
      tenant, now, policy);
    expect(result.operationallyReconciled).toBe(true);
    expect(result.matchedActiveCaptures).toBe(1);
  });
  it("detects missing active captures", () => {
    const result = auditSnapshotCustody([], journal([capture(30)]),
      tenant, now, policy);
    expect(result.issues.map(item => item.kind)).toContain("CAPTURE_MISSING");
    expect(result.operationallyReconciled).toBe(false);
  });
  it("detects unregistered captures", () => {
    const result = auditSnapshotCustody([capture(30)],
      emptySnapshotJournal(tenant), tenant, now, policy);
    expect(result.issues.map(item => item.kind)).toContain("CAPTURE_UNREGISTERED");
  });
  it("detects modified capture contents", () => {
    const result = auditSnapshotCustody([capture(30, "source-a", false)],
      journal([capture(30)]), tenant, now, policy);
    expect(result.issues.map(item => item.kind)).toContain("CONTENT_MODIFIED");
  });
  it("does not accept cross-organization captures", () => {
    expect(() => auditSnapshotCustody([
      capture(30, "source-a", true, "tenant-b"),
    ], emptySnapshotJournal(tenant), tenant, now, policy))
      .toThrow(/Cross-organization/);
  });
  it("does not accept a cross-organization journal", () => {
    expect(() => auditSnapshotCustody([], emptySnapshotJournal("tenant-b"),
      tenant, now, policy)).toThrow(/Cross-organization/);
  });
  it("detects duplicate capture identities", () => {
    const result = auditSnapshotCustody([capture(30), capture(30)],
      journal([capture(30)]), tenant, now, policy);
    expect(result.issues.map(item => item.kind)).toContain("DUPLICATE_CAPTURE");
  });
  it("reports a journal integrity failure", () => {
    const valid = journal([capture(30)]);
    const result = auditSnapshotCustody([capture(30)], {
      ...valid, headDigest: "0".repeat(64),
    }, tenant, now, policy);
    expect(result.journalValid).toBe(false);
    expect(result.issues.map(item => item.kind)).toContain("JOURNAL_INVALID");
  });
  it("rejects source names outside an allowlist", () => {
    const captures = [capture(30)];
    const result = auditSnapshotCustody(captures, journal(captures),
      tenant, now, { ...policy, allowedSources: ["source-b"] });
    expect(result.issues.map(item => item.kind)).toContain("SOURCE_OUT_OF_SCOPE");
  });
  it("rejects future capture timestamps", () => {
    const future = { ...capture(30), capturedAt: "2026-11-02T12:00:00.000Z" };
    const result = auditSnapshotCustody([future], emptySnapshotJournal(tenant),
      tenant, now, policy);
    expect(result.issues.map(item => item.kind)).toContain("FUTURE_CAPTURE");
  });
  it("does not count rejected incomplete captures as active evidence", () => {
    const captures = [capture(30, "source-a", false)];
    const result = auditSnapshotCustody(captures, journal(captures),
      tenant, now, policy);
    expect(result.matchedActiveCaptures).toBe(0);
    expect(result.issues.map(item => item.kind)).toContain("CAPTURE_REJECTED");
  });
  it("rejects invalid capture cardinality policy", () => {
    expect(() => auditSnapshotCustody([], emptySnapshotJournal(tenant),
      tenant, now, { ...policy, maxCaptures: 0 })).toThrow(/Invalid/);
  });
  it("does not imply that operational reconciliation proves compliance", () => {
    const result = auditSnapshotCustody([], emptySnapshotJournal(tenant),
      tenant, now, policy);
    expect(result.limitations.some(item => item.includes("security controls")))
      .toBe(true);
  });
});
