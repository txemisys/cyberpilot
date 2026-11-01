import { describe, expect, it } from "vitest";
import { buildSnapshotCatalog } from "./work-integrity-snapshot-catalog";
import { buildSnapshotManifest, verifySnapshotManifest } from "./work-integrity-snapshot-integrity";
import { selectSnapshotBaseline, compareLatestCapturesBySource } from "./work-integrity-snapshot-baselines";
import { buildSnapshotReviewLedger, appendSnapshotReviewEvent } from "./work-integrity-snapshot-reviews";
import { detectSnapshotIncidents } from "./work-integrity-snapshot-incidents";
import { planSnapshotArchive, partitionSnapshotArchive } from "./work-integrity-snapshot-archive";

function capture(day: number, source = "source-a", complete = true, organizationId = "tenant-a") {
  return {
    organizationId, source, capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
    complete, cases: [],
  };
}
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
describe("snapshot catalog", () => {
  it("paginates by date without losing total counts", () => {
    const catalog = buildSnapshotCatalog([capture(1), capture(2), capture(3)], tenant,
      { limit: 1, offset: 1 });
    expect(catalog.total).toBe(3);
    expect(catalog.matched).toBe(3);
    expect(catalog.entries[0]?.capturedAt).toContain("-02T");
  });
  it("filters incomplete captures", () => {
    const catalog = buildSnapshotCatalog([capture(1), capture(2, "source-a", false)],
      tenant, { completeness: "incomplete" });
    expect(catalog.matched).toBe(1);
  });
  it("does not expose another organization's snapshots", () => {
    expect(() => buildSnapshotCatalog([capture(1, "source-a", true, "tenant-b")], tenant))
      .toThrow(/Cross-organization/);
  });
  it("rejects duplicate identities", () => {
    expect(() => buildSnapshotCatalog([capture(1), capture(1)], tenant))
      .toThrow(/Duplicate/);
  });
  it("reports distinct source totals", () => {
    const catalog = buildSnapshotCatalog([capture(1), capture(2), capture(1, "source-b")], tenant);
    expect(catalog.sources).toHaveLength(2);
    expect(catalog.sources.find(s => s.source === "source-a")?.captures).toBe(2);
  });
});
describe("snapshot manifest", () => {
  it("verifies unchanged snapshots", () => {
    const input = [capture(1), capture(2)];
    const manifest = buildSnapshotManifest(input, tenant, now);
    expect(verifySnapshotManifest(manifest, input).verified).toBe(true);
  });
  it("detects missing snapshots", () => {
    const input = [capture(1), capture(2)];
    const manifest = buildSnapshotManifest(input, tenant, now);
    expect(verifySnapshotManifest(manifest, [capture(1)]).missing).toHaveLength(1);
  });
  it("detects added snapshots", () => {
    const manifest = buildSnapshotManifest([capture(1)], tenant, now);
    expect(verifySnapshotManifest(manifest, [capture(1), capture(2)]).unexpected).toHaveLength(1);
  });
  it("detects modified coverage", () => {
    const manifest = buildSnapshotManifest([capture(1)], tenant, now);
    expect(verifySnapshotManifest(manifest, [capture(1, "source-a", false)]).modified)
      .toHaveLength(1);
  });
  it("rejects cross-tenant manifest construction", () => {
    expect(() => buildSnapshotManifest([capture(1, "source-a", true, "tenant-b")],
      tenant, now)).toThrow(/Cross-organization/);
  });
});
describe("baseline selection and batch comparisons", () => {
  const policy = {
    requireComplete: true, requireQualityClearance: false,
    maxAgeDays: 30, minimumCases: 0, preferSameSource: true,
  };
  it("selects latest eligible historical baseline", () => {
    const result = selectSnapshotBaseline([capture(1), capture(2), capture(3)],
      capture(4), tenant, policy);
    expect(result.selected?.capturedAt).toContain("-03T");
  });
  it("rejects incomplete baseline", () => {
    const result = selectSnapshotBaseline([capture(1, "source-a", false)],
      capture(2), tenant, policy);
    expect(result.selected).toBeNull();
  });
  it("rejects candidate from another tenant", () => {
    expect(() => selectSnapshotBaseline([capture(1, "source-a", true, "tenant-b")],
      capture(2), tenant, policy)).toThrow(/Cross-organization/);
  });
  it("compares latest captures independently per source", () => {
    const result = compareLatestCapturesBySource([
      capture(1), capture(2), capture(1, "source-b"),
    ], tenant);
    expect(result.compared).toBe(1);
    expect(result.skipped).toBe(1);
  });
});
describe("snapshot review ledger", () => {
  const event = {
    id: "review-1", organizationId: tenant, source: "source-a",
    capturedAt: capture(1).capturedAt, reviewerId: "reviewer-a",
    reviewedAt: "2026-10-02T12:00:00.000Z", status: "ACCEPTED" as const,
    rationale: "Capture reviewed for structural consistency.",
    reference: null, expectedPreviousEventId: null,
  };
  it("reconstructs a reviewed capture", () => {
    const ledger = buildSnapshotReviewLedger([capture(1)], [event], tenant);
    expect(ledger.states[0]?.status).toBe("ACCEPTED");
    expect(ledger.eventCount).toBe(1);
  });
  it("rejects stale event revision", () => {
    const ledger = buildSnapshotReviewLedger([capture(1)], [event], tenant);
    expect(() => appendSnapshotReviewEvent(ledger, {
      ...event, id: "review-2", status: "REJECTED",
    })).toThrow(/Stale/);
  });
  it("appends a valid decision without mutating prior state", () => {
    const ledger = buildSnapshotReviewLedger([capture(1)], [event], tenant);
    const next = appendSnapshotReviewEvent(ledger, {
      ...event, id: "review-2", status: "NEEDS_RECAPTURE",
      expectedPreviousEventId: "review-1",
    });
    expect(next.states[0]?.status).toBe("NEEDS_RECAPTURE");
    expect(ledger.states[0]?.status).toBe("ACCEPTED");
  });
  it("rejects unknown capture references", () => {
    expect(() => buildSnapshotReviewLedger([], [event], tenant)).toThrow(/unknown capture/);
  });
});
describe("incident detection", () => {
  const policy = {
    maxCaptureGapDays: 1, criticalIncreaseThreshold: 1,
    reviewBacklogIncreaseThreshold: 1, reportDisappearance: true,
  };
  it("reports coverage regression", () => {
    const result = detectSnapshotIncidents([capture(1), capture(2, "source-a", false)],
      tenant, policy);
    expect(result.incidents.some(i => i.kind === "COVERAGE_REGRESSION")).toBe(true);
  });
  it("reports capture scheduling gaps", () => {
    const result = detectSnapshotIncidents([capture(1), capture(4)], tenant, policy);
    expect(result.incidents.some(i => i.kind === "SOURCE_GAP")).toBe(true);
  });
  it("does not compare unrelated sources", () => {
    const result = detectSnapshotIncidents([capture(1), capture(2, "source-b")],
      tenant, policy);
    expect(result.sourcesCompared).toBe(0);
    expect(result.sourcesWithoutBaseline).toHaveLength(2);
  });
});
describe("archive planning", () => {
  const policy = {
    retention: {
      maxAgeDays: 1, minRecentCaptures: 1, maxRetainedCaptures: 1,
      preserveMonthlyBaselines: false, preserveFirstComplete: false,
    },
    requireQualityClearance: false, rejectFutureCaptures: true,
    maxArchiveBytes: 100000, maxCaptures: 100,
  };
  it("proposes older unprotected captures without deleting them", () => {
    const result = planSnapshotArchive([capture(1), capture(2), capture(3)],
      tenant, now, policy);
    expect(result.archiveCandidates).toBe(2);
    expect(result.blockedCandidates).toBe(1);
  });
  it("enforces tenant isolation", () => {
    expect(() => planSnapshotArchive([capture(1, "source-a", true, "tenant-b")],
      tenant, now, policy)).toThrow(/Cross-organization/);
  });
  it("partitions by source and month", () => {
    const result = partitionSnapshotArchive([
      capture(1), capture(2), capture(1, "source-b"),
    ], tenant);
    expect(result).toHaveLength(2);
  });
  it("rejects invalid partition size", () => {
    expect(() => partitionSnapshotArchive([], tenant, 100)).toThrow(/partition/);
  });
});
