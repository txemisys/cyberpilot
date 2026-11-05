import { describe, expect, it } from "vitest";
import {
  compareAssetObservations, buildAssetComparisonReport,
  parseAssetComparisonQuery, summarizeAssetComparison,
} from "./assets-inventory-comparison";
import type { AssetObservation } from "./assets-inventory-comparison";
import {
  parseAssetRetentionPolicy, parseAssetPurgeCommand,
  buildAssetRetentionReport, purgePreview, replayedPurge,
  purgeFingerprint, retentionCandidate,
} from "./assets-inventory-retention";
const now = new Date("2026-11-05T12:00:00.000Z");
const earlier = new Date("2026-10-01T12:00:00.000Z");
const older = new Date("2026-09-01T12:00:00.000Z");
const base: AssetObservation = {
  externalId: "device-one", normalizedProductKey: "browser",
  platform: "WINDOWS", osName: "Windows",
  osVersion: "22H2", softwareName: "Browser",
  softwareVersion: "2.0.0",
  versionStatus: "EXACT", freshnessStatus: "FRESH",
  advisoryStatus: "UNKNOWN", advisoryIds: [],
  observedAt: earlier, sourceRow: 2,
};
const reportParams = {
  previousImportId: "previous-import-12345",
  currentImportId: "current-import-12345",
  offset: 0, limit: 50, includeUnchanged: false,
};
const previousImport = {
  id: reportParams.previousImportId,
  state: "COMMITTED" as const,
  sourceLabel: "Earlier export",
  importedCount: 1, declaredCount: 1,
  duplicateCount: 0, createdAt: older,
};
const currentImport = {
  ...previousImport,
  id: reportParams.currentImportId,
  sourceLabel: "Later export", createdAt: now,
};
const scope = {
  organizationId: "org-12345", userId: "admin-12345",
  role: "ADMIN" as const,
};
const candidate = {
  importId: "import-12345", state: "RETIRED" as const,
  sourceLabel: "Old inventory",
  createdAt: new Date("2025-01-01T12:00:00.000Z"),
  retiredAt: new Date("2026-09-01T12:00:00.000Z"),
  importedCount: 10,
  payloadDigest: "a".repeat(64),
};
const purge = {
  importId: candidate.importId, expectedDigest: candidate.payloadDigest,
  confirmImportId: candidate.importId, confirmPurge: true,
  minimumRetiredDays: 30, reason: "Permanently remove obsolete customer data.",
  dryRun: true, idempotencyKey: "purge-key-12345",
};
describe("asset comparison validation", () => {
  it("requires two different valid snapshot IDs", () => {
    expect(parseAssetComparisonQuery(reportParams)).toEqual(reportParams);
    expect(() => parseAssetComparisonQuery({
      ...reportParams, currentImportId: reportParams.previousImportId,
    })).toThrow();
    expect(() => parseAssetComparisonQuery({})).toThrow();
  });
  it.each([
    { limit: 0 }, { limit: 101 }, { offset: -1 },
    { category: "PATCHED" }, { includeUnchanged: "yes" },
    { unknown: 1 },
  ])("rejects invalid comparisons %j", patch => {
    expect(() => parseAssetComparisonQuery({ ...reportParams, ...patch }))
      .toThrow();
  });
  it("reports exact unchanged rows conservatively", () => {
    const rows = compareAssetObservations([base], [{ ...base }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.category).toBe("UNCHANGED");
    expect(rows[0]?.significant).toBe(false);
  });
  it("distinguishes missing from export from removed devices", () => {
    const rows = compareAssetObservations([base], []);
    expect(rows[0]?.category).toBe("MISSING_FROM_EXPORT");
    expect(rows[0]?.explanations.join(" ")).toMatch(/not proof/i);
  });
  it("tracks newly appearing device identifiers", () => {
    const rows = compareAssetObservations([], [base]);
    expect(rows[0]?.category).toBe("NEW_ASSET");
  });
  it("tracks product delta without calling it a new device", () => {
    const added = { ...base, normalizedProductKey: "editor",
      softwareName: "Editor" };
    const rows = compareAssetObservations([base], [base, added]);
    expect(rows.map(x => x.category)).toEqual(["NEW_PRODUCT", "UNCHANGED"]);
  });
  it("distinguishes missing products when a device remains", () => {
    const extra = { ...base, normalizedProductKey: "editor",
      softwareName: "Editor" };
    const rows = compareAssetObservations([base, extra], [base]);
    expect(rows.map(x => x.category)).toContain("PRODUCT_NOT_IN_EXPORT");
    expect(rows.map(x => x.category)).not.toContain("MISSING_FROM_EXPORT");
  });
  it("identifies simultaneous OS, platform and version changes", () => {
    const changed = {
      ...base, platform: "LINUX", osName: "Ubuntu",
      osVersion: "24.04", softwareVersion: "3.0.0",
    };
    const rows = compareAssetObservations([base], [changed]);
    expect(rows.map(x => x.category)).toEqual([
      "OS_CHANGED", "VERSION_CHANGED", "PLATFORM_CHANGED",
    ].sort((a, b) => {
      const order = ["PLATFORM_CHANGED", "OS_CHANGED", "VERSION_CHANGED"];
      return order.indexOf(a) - order.indexOf(b);
    }));
  });
  it("detects change in advisory associations without asserting exposure", () => {
    const rows = compareAssetObservations([base], [{
      ...base, advisoryStatus: "POSSIBLE_MATCH",
      advisoryIds: ["CVE-2026-12345"],
    }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.category).toBe("ADVISORY_CHANGED");
    expect(rows[0]?.explanations.join(" ")).toMatch(/may reflect/i);
  });
  it("treats timestamp-only updates as non-significant", () => {
    const rows = compareAssetObservations([base], [{
      ...base, observedAt: now,
    }]);
    expect(rows[0]?.category).toBe("OBSERVATION_UPDATED");
    expect(rows[0]?.significant).toBe(false);
  });
  it("returns stable digests and page-scoped comparisons", () => {
    const rows = compareAssetObservations([base], []);
    const a = buildAssetComparisonReport(scope.organizationId,
      previousImport, currentImport, [base], [], reportParams, now);
    const b = buildAssetComparisonReport(scope.organizationId,
      previousImport, currentImport, [base], [], reportParams, now);
    expect(a.digest).toBe(b.digest);
    expect(a.summary.missingFromExport).toBe(1);
    expect(a.coverage).toBe("DECLARED_SCOPE_UNKNOWN");
    expect(summarizeAssetComparison([base], [], rows).changed).toBe(1);
  });
  it("exposes incomplete pagination rather than a misleading aggregate", () => {
    const a = buildAssetComparisonReport(scope.organizationId,
      previousImport, currentImport,
      [base, { ...base, externalId: "device-two" }], [],
      { ...reportParams, limit: 1 }, now);
    expect(a.totalDifferences).toBe(2);
    expect(a.hasMore).toBe(true);
    expect(a.complete).toBe(false);
    expect(a.summary.missingFromExport).toBe(2);
  });
});
describe("asset retention policy and purge command", () => {
  it("defaults to a minimum thirty-day retirement hold", () => {
    expect(parseAssetRetentionPolicy({})).toMatchObject({
      minimumRetiredDays: 30, maximumCandidateAgeDays: 365,
      limit: 50, offset: 0,
    });
  });
  it.each([
    { minimumRetiredDays: 0 }, { maximumCandidateAgeDays: -1 },
    { limit: 0 }, { limit: 150 }, { unexpected: true },
  ])("rejects invalid policy values %j", value => {
    expect(() => parseAssetRetentionPolicy(value)).toThrow();
  });
  it("demands a matching ID, long reason and explicit confirmation", () => {
    expect(parseAssetPurgeCommand(purge).confirmPurge).toBe(true);
    expect(() => parseAssetPurgeCommand({
      ...purge, confirmImportId: "wrong-import-12345",
    })).toThrow();
    expect(() => parseAssetPurgeCommand({
      ...purge, confirmPurge: false,
    })).toThrow();
    expect(() => parseAssetPurgeCommand({
      ...purge, reason: "short",
    })).toThrow();
    expect(() => parseAssetPurgeCommand({
      ...purge, expectedDigest: "not-a-digest",
    })).toThrow();
  });
  it("only considers old, retired snapshots after holding period", () => {
    const policy = parseAssetRetentionPolicy({});
    const eligible = retentionCandidate(candidate, now, policy);
    expect(eligible.eligible).toBe(true);
    const active = retentionCandidate({
      ...candidate, state: "COMMITTED", retiredAt: null,
    }, now, policy);
    expect(active.eligible).toBe(false);
    const recent = retentionCandidate({
      ...candidate, retiredAt: new Date("2026-11-01T12:00:00.000Z"),
    }, now, policy);
    expect(recent.eligible).toBe(false);
  });
  it("does not delete on preview and displays full blast radius", () => {
    const result = purgePreview(scope, purge, candidate, now);
    expect(result).toMatchObject({
      status: "PREVIEW", dryRun: true,
      devicesAffected: 10,
    });
    expect(result.warnings.join(" ")).toMatch(/backup/i);
  });
  it("rejects changed digest or incomplete retirement", () => {
    expect(() => purgePreview(scope, purge, {
      ...candidate, payloadDigest: "b".repeat(64),
    }, now)).toThrow();
    expect(() => purgePreview(scope, purge, {
      ...candidate, state: "COMMITTED",
    }, now)).toThrow();
  });
  it("refuses purge before holding days have elapsed", () => {
    expect(() => purgePreview(scope, purge, {
      ...candidate, retiredAt: new Date("2026-11-04T12:00:00.000Z"),
    }, now)).toThrow();
  });
  it("builds conservative bounded retention reports", () => {
    const policy = parseAssetRetentionPolicy({ limit: 1 });
    const result = buildAssetRetentionReport(scope.organizationId,
      policy, [candidate], 2, now);
    expect(result.eligibleOnPage).toBe(1);
    expect(result.hasMore).toBe(true);
    expect(result.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("accepts exact idempotent replay and rejects conflicting reuse", () => {
    const fingerprint = purgeFingerprint(scope, purge);
    const previous = {
      id: "audit-12345", action: "assets.csv.import.purged",
      resourceId: candidate.importId,
      metadata: {
        fingerprint, deletedRows: 10,
        snapshotDigest: candidate.payloadDigest,
      },
    };
    const result = replayedPurge(scope, purge, previous);
    expect(result?.status).toBe("REPLAYED");
    expect(result?.devicesAffected).toBe(10);
    expect(() => replayedPurge(scope, {
      ...purge, reason: "Different incompatible destruction reason.",
    }, previous)).toThrow();
  });
});
