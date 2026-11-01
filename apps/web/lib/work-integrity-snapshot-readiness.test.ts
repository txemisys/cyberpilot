import { describe, expect, it } from "vitest";
import { emptySnapshotJournal, planJournalAppendFromCaptures } from "./work-integrity-snapshot-journal";
import { assessSnapshotOperationalReadiness, type ReadinessPolicy } from "./work-integrity-snapshot-readiness";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
const schedule = [{
  source: "source-a", required: true, expectedIntervalMinutes: 1440,
  maximumLagMinutes: 10000, minimumCases: 0,
  requireComplete: true, requireQualityClearance: false,
}];
const policy: ReadinessPolicy = {
  custody: {
    maxCaptures: 100, maxAgeDays: 90, maxFutureSkewMinutes: 5,
    requireCompleteActiveCaptures: true, allowedSources: null,
    includeArchived: true, includeRejected: true,
  },
  inventory: {
    rejectUnscheduledSources: false, maxSnapshots: 100, maxSources: 20,
  },
  incidents: {
    maxCaptureGapDays: 30, criticalIncreaseThreshold: 1,
    reviewBacklogIncreaseThreshold: 1, reportDisappearance: true,
  },
  ingestion: {
    maxAgeDays: 90, maxFutureSkewMinutes: 5,
    maxCasesPerCapture: 1000, maxCapturesPerSource: 100,
    requireComplete: true, rejectQualityBlockers: true,
    rejectQualityWarnings: false, allowedSources: null,
  },
  minimumHistoryPerRequiredSource: 1,
  minimumRequiredCoverageRatio: 1,
  maximumWarningIncidents: 0, maximumUnscheduledSources: 0,
  maximumIngestionRejections: 0, blockOnIncompleteCaptures: true,
  blockOnUnverifiedJournal: true, blockOnCustodyWarnings: false,
  requireAtLeastOneRequiredSource: true,
};
function journal(captures: ReturnType<typeof capture>[]) {
  return planJournalAppendFromCaptures(captures,
    emptySnapshotJournal(tenant), tenant, now, "operator-a");
}
function report(
  captures: ReturnType<typeof capture>[],
  incoming: ReturnType<typeof capture>[] = [],
  customPolicy: ReadinessPolicy = policy,
  customSchedule = schedule,
) {
  return assessSnapshotOperationalReadiness(captures, incoming,
    journal(captures), tenant, now, customSchedule, customPolicy);
}
describe("integrated snapshot readiness gate", () => {
  it("provides a complete traceable set of operational checks", () => {
    const result = report([capture(30)]);
    expect(result.checks.map(item => item.id)).toContain("CUSTODY_RECONCILIATION");
    expect(result.checks.map(item => item.id)).toContain("SOURCE_COVERAGE");
    expect(result.checks.map(item => item.id)).toContain("INGESTION_REJECTIONS");
    expect(result.checks.map(item => item.id)).toContain("MANIFEST_CONSISTENCY");
  });
  it("does not mistake empty evidence for operational readiness", () => {
    const result = report([]);
    expect(result.summary.decision).toBe("BLOCK");
    expect(result.summary.readyRequiredSources).toBe(0);
  });
  it("rejects an empty required-source schedule", () => {
    const result = report([], [], policy, []);
    expect(result.summary.decision).toBe("BLOCK");
    expect(result.checks.find(item => item.id === "SOURCE_COVERAGE")
      ?.decision).toBe("BLOCK");
  });
  it("blocks an untrusted journal head", () => {
    const captures = [capture(30)];
    const valid = journal(captures);
    const result = assessSnapshotOperationalReadiness(captures, [], {
      ...valid, headDigest: "0".repeat(64),
    }, tenant, now, schedule, policy);
    expect(result.summary.decision).toBe("BLOCK");
    expect(result.custody.journalValid).toBe(false);
  });
  it("blocks incomplete source coverage", () => {
    const result = report([capture(30, "source-a", false)]);
    expect(result.summary.decision).toBe("BLOCK");
    expect(result.checks.find(item => item.id === "CAPTURE_COMPLETENESS")
      ?.decision).toBe("BLOCK");
  });
  it("blocks missing journal evidence even with source captures", () => {
    const captures = [capture(30)];
    const result = assessSnapshotOperationalReadiness(captures, [],
      emptySnapshotJournal(tenant), tenant, now, schedule, policy);
    expect(result.custody.blockers).toBeGreaterThan(0);
    expect(result.summary.decision).toBe("BLOCK");
  });
  it("preserves tenant isolation for capture inputs", () => {
    expect(() => report([capture(30, "source-a", true, "tenant-b")]))
      .toThrow(/Cross-organization/);
  });
  it("preserves tenant isolation for incoming captures", () => {
    expect(() => report([capture(30)], [
      capture(29, "source-a", true, "tenant-b"),
    ])).toThrow(/Cross-organization/);
  });
  it("reports unscheduled sources as an explicit decision", () => {
    const result = report([capture(30), capture(30, "other")]);
    expect(result.inventory.unscheduledSources).toContain("other");
    expect(result.checks.find(item => item.id === "UNSCHEDULED_SOURCES")
      ?.decision).toBe("BLOCK");
  });
  it("blocks duplicate capture identities", () => {
    expect(() => report([capture(30), capture(30)]))
      .toThrow(/Duplicate (?:readiness|manifest capture identity)/);
  });
  it("blocks duplicate incoming identities", () => {
    expect(() => report([capture(30)], [capture(29), capture(29)]))
      .toThrow(/Duplicate (?:readiness|manifest capture identity)/);
  });
  it("returns a canonical manifest with the actual capture count", () => {
    const result = report([capture(30)]);
    expect(result.manifest.entries).toHaveLength(1);
    expect(result.summary.observedCaptures).toBe(1);
  });
  it("never claims compliance from an operational gate", () => {
    const result = report([capture(30)]);
    expect(result.limitations.some(item => item.includes("regulatory compliance")))
      .toBe(true);
  });
  it("provides prioritized actions for blocked sources", () => {
    const result = report([]);
    expect(result.nextActions.length).toBeGreaterThan(0);
    expect(result.nextActions[0]?.priority).toBe("IMMEDIATE");
  });
  it("rejects invalid coverage thresholds", () => {
    expect(() => report([], [], {
      ...policy, minimumRequiredCoverageRatio: 1.5,
    })).toThrow(/Invalid readiness/);
  });
  it("rejects negative history floors", () => {
    expect(() => report([], [], {
      ...policy, minimumHistoryPerRequiredSource: -1,
    })).toThrow(/Invalid readiness/);
  });
  it("does not mark missing required sources ready", () => {
    const result = report([]);
    expect(result.sources.find(item => item.source === "source-a")?.decision)
      .toBe("BLOCK");
  });
});
