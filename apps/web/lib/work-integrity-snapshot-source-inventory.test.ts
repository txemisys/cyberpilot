import { describe, expect, it } from "vitest";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import {
  reconcileSnapshotSourceInventory, auditInventoryAgainstManifest,
} from "./work-integrity-snapshot-source-inventory";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const schedule = {
  source: "source-a", required: true,
  expectedIntervalMinutes: 1440, maximumLagMinutes: 3000,
  minimumCases: 0, requireComplete: true, requireQualityClearance: false,
};
const policy = { rejectUnscheduledSources: true, maxSnapshots: 100, maxSources: 20 };
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
describe("scheduled capture source inventory", () => {
  it("reports a current scheduled source", () => {
    const result = reconcileSnapshotSourceInventory([capture(31)],
      tenant, now, [schedule], policy);
    expect(result.rows[0]?.health).toBe("CURRENT");
    expect(result.coverageRatio).toBe(100);
  });
  it("marks a missing required source", () => {
    const result = reconcileSnapshotSourceInventory([], tenant, now, [schedule], policy);
    expect(result.rows[0]?.health).toBe("MISSING");
    expect(result.missingRequiredSources).toBe(1);
    expect(result.coverageRatio).toBe(0);
  });
  it("distinguishes optional missing sources", () => {
    const result = reconcileSnapshotSourceInventory([], tenant, now,
      [{ ...schedule, required: false }], policy);
    expect(result.rows[0]?.health).toBe("OPTIONAL_MISSING");
    expect(result.coverageRatio).toBeNull();
  });
  it("marks stale captures as late", () => {
    const result = reconcileSnapshotSourceInventory([capture(1)],
      tenant, now, [schedule], policy);
    expect(result.rows[0]?.health).toBe("LATE");
    expect(result.lateRequiredSources).toBe(1);
  });
  it("does not treat partial coverage as current", () => {
    const result = reconcileSnapshotSourceInventory([
      capture(31, "source-a", false),
    ], tenant, now, [schedule], policy);
    expect(result.rows[0]?.health).toBe("INCOMPLETE");
  });
  it("enforces the configured minimum case count", () => {
    const result = reconcileSnapshotSourceInventory([capture(31)],
      tenant, now, [{ ...schedule, minimumCases: 1 }], policy);
    expect(result.rows[0]?.health).toBe("BELOW_MINIMUM");
  });
  it("tracks the interval between the latest captures", () => {
    const result = reconcileSnapshotSourceInventory([
      capture(30), capture(31),
    ], tenant, now, [schedule], policy);
    expect(result.rows[0]?.observedIntervalMinutes).toBe(1440);
  });
  it("calculates the next expected collection timestamp", () => {
    const result = reconcileSnapshotSourceInventory([capture(31)],
      tenant, now, [schedule], policy);
    expect(result.rows[0]?.nextExpectedAt).toBe("2026-11-01T12:00:00.000Z");
  });
  it("rejects a cross-tenant capture", () => {
    expect(() => reconcileSnapshotSourceInventory([
      capture(31, "source-a", true, "tenant-b"),
    ], tenant, now, [schedule], policy)).toThrow(/Cross-organization/);
  });
  it("rejects duplicate scheduled sources", () => {
    expect(() => reconcileSnapshotSourceInventory([], tenant, now,
      [schedule, schedule], policy)).toThrow(/Duplicate/);
  });
  it("rejects duplicate capture timestamps", () => {
    expect(() => reconcileSnapshotSourceInventory([
      capture(31), capture(31),
    ], tenant, now, [schedule], policy)).toThrow(/Duplicate/);
  });
  it("rejects unscheduled sources when configured", () => {
    expect(() => reconcileSnapshotSourceInventory([
      capture(31, "other"),
    ], tenant, now, [schedule], policy)).toThrow(/Unscheduled/);
  });
  it("reports unscheduled sources in permissive mode", () => {
    const result = reconcileSnapshotSourceInventory([
      capture(31, "other"),
    ], tenant, now, [schedule],
    { ...policy, rejectUnscheduledSources: false });
    expect(result.unscheduledSources).toEqual(["other"]);
  });
  it("rejects future captures", () => {
    const future = { ...capture(31), capturedAt: "2026-11-02T12:00:00.000Z" };
    expect(() => reconcileSnapshotSourceInventory([
      future,
    ], tenant, now, [schedule], policy)).toThrow(/Future/);
  });
  it("enforces snapshot cardinality limits", () => {
    expect(() => reconcileSnapshotSourceInventory([
      capture(30), capture(31),
    ], tenant, now, [schedule],
    { ...policy, maxSnapshots: 1 })).toThrow(/cardinality/);
  });
  it("rejects invalid schedule intervals", () => {
    expect(() => reconcileSnapshotSourceInventory([], tenant, now,
      [{ ...schedule, expectedIntervalMinutes: 0 }], policy)).toThrow(/Invalid/);
  });
  it("rejects missing tenant identity", () => {
    expect(() => reconcileSnapshotSourceInventory([], "", now,
      [schedule], policy)).toThrow(/Authenticated/);
  });
  it("matches a trusted manifest for identical capture inventory", () => {
    const captures = [capture(31)];
    const report = reconcileSnapshotSourceInventory(captures,
      tenant, now, [schedule], policy);
    const manifest = buildSnapshotManifest(captures, tenant, now);
    const audit = auditInventoryAgainstManifest(report, captures, manifest);
    expect(audit.verified).toBe(true);
    expect(audit.sourceCoverage).toBe(100);
  });
  it("detects inventory manifest drift", () => {
    const captures = [capture(31)];
    const report = reconcileSnapshotSourceInventory(captures,
      tenant, now, [schedule], policy);
    const manifest = buildSnapshotManifest(captures, tenant, now);
    const audit = auditInventoryAgainstManifest(report, [
      capture(31, "source-a", false),
    ], manifest);
    expect(audit.verified).toBe(false);
  });
  it("rejects a manifest from another tenant", () => {
    const captures = [capture(31)];
    const report = reconcileSnapshotSourceInventory(captures,
      tenant, now, [schedule], policy);
    const manifest = buildSnapshotManifest([
      capture(31, "source-a", true, "tenant-b"),
    ], "tenant-b", now);
    expect(() => auditInventoryAgainstManifest(report, captures, manifest))
      .toThrow(/Cross-organization/);
  });
});
