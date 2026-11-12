import { describe, expect, it } from "vitest";
import {
  parseRefreshPolicy, refreshPackageKey, latestPackageResults,
  classifyPackageRefresh, computeRefreshBudget, planOsvRefresh,
  compareOsvPackageHistory, buildOsvHistoryDelta,
} from "./assets-osv-refresh-policy";
import type {
  RefreshHistory, RefreshPackageState,
} from "./assets-osv-refresh-policy";

const now = new Date("2026-11-05T12:00:00.000Z");
const hour = 60 * 60 * 1000;
const historical = (beforeHours = 1, patch: Partial<RefreshPackageState> = {}):
  RefreshPackageState => ({
    ecosystem: "npm", packageName: "example-package", version: "1.2.3",
    providerStatus: "COMPLETE",
    checkedAt: new Date(now.getTime() - beforeHours * hour),
    observationCount: 2, inspectionId: "inspection-first-12345",
    queryKey: "a".repeat(64),
    possibleIds: ["GHSA-aaaa-1111-2222"],
    providerOnlyIds: [], unresolvedIds: [], withdrawnIds: [],
    ...patch,
  });
const policy = parseRefreshPolicy({});
const inspection = (beforeHours = 1, count = 1): RefreshHistory => ({
  inspectionId: "inspection-first-12345",
  completedAt: new Date(now.getTime() - beforeHours * hour),
  queryCount: count, completedCount: count, status: "COMPLETE",
});
describe("OSV refresh policy validation", () => {
  it("defaults to finite freshness, cooldown and daily advisory budgets", () => {
    expect(policy).toMatchObject({
      freshnessMinutes: 1440,
      minimumRetryMinutes: 60,
      maximumQueriesPerDay: 200,
      maximumInspectionsPerDay: 20,
      maximumPackagesPerRun: 10,
      historyWindowDays: 90,
      includeIncomplete: true,
    });
  });
  it.each([
    { freshnessMinutes: 1 }, { freshnessMinutes: 999999 },
    { minimumRetryMinutes: 0 },
    { maximumQueriesPerDay: 0 }, { maximumQueriesPerDay: 10001 },
    { maximumInspectionsPerDay: 0 },
    { maximumPackagesPerRun: 21 }, { historyWindowDays: 0 },
    { includeIncomplete: "yes" }, { maliciousField: "ignored" },
  ])("rejects unsafe policy parameters %j", patch => {
    expect(() => parseRefreshPolicy({ ...policy, ...patch })).toThrow();
  });
  it("uses safe stable package identities with exact version", () => {
    const key = refreshPackageKey(historical());
    expect(key).toBe(JSON.stringify(["npm", "example-package", "1.2.3"]));
    expect(key).not.toContain("\u0000");
  });
  it("selects most recent result per package identity", () => {
    const current = historical(1, { inspectionId: "newer-12345" });
    const old = historical(2, { inspectionId: "older-12345" });
    const rows = latestPackageResults([current, old]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.inspectionId).toBe("newer-12345");
  });
  it("does not replace a later record with a stale historical one", () => {
    const result = latestPackageResults([
      historical(12), historical(20), historical(24),
    ]);
    expect(result[0]?.checkedAt).toEqual(
      new Date(now.getTime() - 12 * hour));
  });
  it("recommends refresh after the freshness threshold", () => {
    const row = classifyPackageRefresh(historical(25), policy, now);
    expect(row.state).toBe("STALE");
    expect(row.shouldRefresh).toBe(true);
    expect(row.ageMinutes).toBe(1500);
  });
  it("keeps fresh complete packages out of the refresh list", () => {
    const row = classifyPackageRefresh(historical(1), policy, now);
    expect(row.state).toBe("FRESH_COMPLETE");
    expect(row.shouldRefresh).toBe(false);
    expect(row.dueAt).not.toBeNull();
  });
  it("marks provider retries as deferred during cooldown", () => {
    const result = classifyPackageRefresh(historical(0.25, {
      providerStatus: "UPSTREAM_ERROR",
    }), policy, now);
    expect(result.state).toBe("RETRY_DEFERRED");
    expect(result.shouldRefresh).toBe(false);
  });
  it("allows later investigation of failed or incomplete queries", () => {
    const result = classifyPackageRefresh(historical(2, {
      providerStatus: "TRUNCATED",
    }), policy, now);
    expect(result.state).toBe("INCOMPLETE");
    expect(result.shouldRefresh).toBe(true);
    const disabled = classifyPackageRefresh(historical(2, {
      providerStatus: "UPSTREAM_ERROR",
    }), { ...policy, includeIncomplete: false }, now);
    expect(disabled.shouldRefresh).toBe(false);
  });
  it("detects future-dated timestamps rather than silently accepting them", () => {
    const future = classifyPackageRefresh(historical(-24), policy, now);
    expect(future.state).toBe("CLOCK_INVALID");
    expect(future.shouldRefresh).toBe(false);
  });
  it("treats missing provider checkedAt as unknown and eligible for checking", () => {
    const result = classifyPackageRefresh(historical(0, {
      checkedAt: null,
    }), policy, now);
    expect(result.state).toBe("NEVER_CHECKED");
    expect(result.shouldRefresh).toBe(true);
  });
  it("computes UTC budget from all organization inspections", () => {
    const active = inspection(1, 7);
    const old = inspection(48, 99);
    const budget = computeRefreshBudget([active, old], policy, now);
    expect(budget.inspectionCountToday).toBe(1);
    expect(budget.queryCountToday).toBe(7);
    expect(budget.queryBudgetRemaining).toBe(193);
    expect(budget.inspectionBudgetRemaining).toBe(19);
  });
  it("blocks advisory selections when the inspection budget is exhausted", () => {
    const budget = computeRefreshBudget([inspection(1, 7)],
      { ...policy, maximumInspectionsPerDay: 1 }, now);
    expect(budget.blockedByInspectionBudget).toBe(true);
    expect(budget.allowedPackageQueries).toBe(0);
  });
  it("caps selected packages without claiming a real atomic reservation", () => {
    const products = Array.from({ length: 5 }, (_, i) =>
      historical(48 + i, {
        packageName: "package-" + i,
      }));
    const report = planOsvRefresh("org-12345", {
      packages: products,
      history: [inspection(1, 3)],
      policy: { ...policy, maximumPackagesPerRun: 2 },
      now, offset: 0, limit: 20,
    });
    expect(report.dueCount).toBe(5);
    expect(report.selectedCount).toBe(2);
    expect(report.excludedDueToBudget).toBe(3);
    expect(report.warnings.join(" ")).toMatch(/not an atomic/i);
  });
  it("paginates per-package details without truncating summary", () => {
    const products = Array.from({ length: 4 }, (_, i) =>
      historical(30, { packageName: "pkg-" + i }));
    const report = planOsvRefresh("org-12345", {
      packages: products, history: [], policy, now,
      offset: 0, limit: 1,
    });
    expect(report.totalHistoricalPackages).toBe(4);
    expect(report.candidates).toHaveLength(1);
    expect(report.hasMore).toBe(true);
    expect(report.selectedCount).toBe(4);
  });
});
describe("OSV longitudinal provider differences", () => {
  it("matches exact ecosystem/package/version keys only", () => {
    const a = historical();
    const b = historical(0, { version: "2.0.0" });
    const result = compareOsvPackageHistory([a], [b]);
    expect(result.compared).toBe(0);
    expect(result.excluded).toBe(2);
  });
  it("detects newly reported literal associations", () => {
    const first = historical();
    const later = historical(0, {
      possibleIds: [
        "GHSA-aaaa-1111-2222", "GHSA-bbbb-3333-4444",
      ],
    });
    const result = compareOsvPackageHistory([first], [later]);
    expect(result.compared).toBe(1);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]?.kind).toBe("POSSIBLE_ID_ADDED");
    expect(result.rows[0]?.advisoryId).toBe("GHSA-bbbb-3333-4444");
  });
  it("does not call disappeared CVEs remediated", () => {
    const first = historical();
    const later = historical(0, { possibleIds: [] });
    const result = compareOsvPackageHistory([first], [later]);
    expect(result.rows[0]?.kind).toBe("POSSIBLE_ID_NOT_LISTED");
    expect(result.rows[0]?.explanation).toMatch(/not proof of remediation/i);
  });
  it("distinguishes provider-only results and withdrawn records", () => {
    const prior = historical();
    const next = historical(0, {
      providerOnlyIds: ["GHSA-cccc-2222-1111"],
      withdrawnIds: ["GHSA-dddd-1111-2222"],
    });
    const result = compareOsvPackageHistory([prior], [next]);
    expect(result.rows.map(x => x.kind)).toEqual([
      "PROVIDER_ONLY_ADDED", "WITHDRAWN_ADDED",
    ]);
  });
  it("marks altered upstream completion as a data quality change", () => {
    const result = compareOsvPackageHistory([
      historical(),
    ], [historical(0, { providerStatus: "TRUNCATED" })]);
    expect(result.rows[0]?.kind).toBe("PROVIDER_STATUS_CHANGED");
  });
  it("produces an unchanged record for identical provider status and IDs", () => {
    const result = compareOsvPackageHistory([
      historical(),
    ], [historical(0)]);
    expect(result.rows[0]?.kind).toBe("UNCHANGED");
  });
  it("marks reports partial if package coverage differs", () => {
    const prior = [historical(), historical(0, { packageName: "other" })];
    const current = [historical(0)];
    const result = buildOsvHistoryDelta("org-12345",
      "inspection-older-12345", "inspection-newer-12345",
      prior, current, true, true, 0, 50);
    expect(result.completeComparison).toBe(false);
    expect(result.summary.excludedPackages).toBe(1);
    expect(result.summary.comparedPackages).toBe(1);
  });
  it("reports complete only when full package sets and provider status agree", () => {
    const result = buildOsvHistoryDelta("org-12345",
      "inspection-older-12345", "inspection-newer-12345",
      [historical()], [historical(0)], true, true, 0, 50);
    expect(result.completeComparison).toBe(true);
    expect(result.summary.unchanged).toBe(1);
    expect(result.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("retains complete summary across pages and verifies unique inspection IDs", () => {
    const first = historical();
    const current = historical(0, {
      providerOnlyIds: ["GHSA-cccc-2222-1111"],
      withdrawnIds: ["GHSA-dddd-1111-2222"],
    });
    const report = buildOsvHistoryDelta("org-12345",
      "inspection-older-12345", "inspection-newer-12345",
      [first], [current], true, true, 0, 1);
    expect(report.summary.total).toBe(2);
    expect(report.hasMore).toBe(true);
    expect(() => buildOsvHistoryDelta("org-12345",
      "same", "same", [first], [current],
      true, true, 0, 50)).toThrow();
  });
});
