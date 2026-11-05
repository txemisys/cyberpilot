import { describe, expect, it } from "vitest";
import {
  parseOsvLedgerCommand, parseOsvLedgerQuery,
  osvInspectionFingerprint, osvInspectionLedgerKey,
  assertLedgerReport, replayOsvLedger, buildOsvLedgerCommit,
} from "./assets-osv-inspection-ledger";
import {
  buildOfficialOsvInspectionReport, parseOfficialOsvInspection,
  planOfficialOsvInspection,
} from "./assets-osv-official-service";
import type { AssetScope } from "./assets-inventory-service";
const scope: AssetScope = {
  organizationId: "org-ledger-12345",
  userId: "user-ledger-12345",
  role: "ADMIN",
};
const now = new Date("2026-11-05T13:00:00.000Z");
const request = {
  requestKey: "osv-ledger-unique-request-key",
  inspection: {
    importId: "import-ledger-12345",
    packageBindings: [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }],
    limitPackages: 5, maxPagesPerPackage: 2,
    maxRecordsPerPackage: 50, maxAgeMinutes: 60,
    dryRun: false,
  },
};
const devices = [{
  externalId: "asset-ledger-1",
  softwareName: "Example Package", softwareVersion: "1.0.0",
  versionStatus: "EXACT", normalizedProductKey: "example package",
}];
function fixture() {
  const command = parseOsvLedgerCommand(request);
  const plan = planOfficialOsvInspection(command.inspection.importId,
    devices, command.inspection.packageBindings, command.inspection.limitPackages);
  const work = plan.work[0]!;
  const result = {
    key: work.key,
    ecosystem: work.ecosystem,
    name: work.name, version: work.version,
    observationCount: 1, status: "COMPLETE",
    checkedAt: now.toISOString(),
    digest: "c".repeat(64),
    possibleIds: ["GHSA-aaaa-bbbb-cccc"],
    providerOnlyIds: [], withdrawnIds: [],
    unresolvedIds: [], queriedPages: 1,
    warnings: [],
  };
  const report = buildOfficialOsvInspectionReport(scope,
    command.inspection, plan, [result], now);
  return { command, report, result };
}
describe("OSV inspection ledger command validation", () => {
  it("demands a non-preview authorized command with a stable request key", () => {
    const parsed = parseOsvLedgerCommand(request);
    expect(parsed.requestKey).toBe(request.requestKey);
    expect(parsed.inspection.dryRun).toBe(false);
    expect(() => parseOsvLedgerCommand({
      ...request, inspection: {
        ...request.inspection, dryRun: true,
      },
    })).toThrow();
  });
  it.each([
    { requestKey: "short" },
    { requestKey: "" },
    { requestKey: "abc\n123456789012" },
    { unexpected: true },
    { inspection: {} },
  ])("rejects invalid or unknown save parameters %j", patch => {
    expect(() => parseOsvLedgerCommand({
      ...request, ...patch,
    })).toThrow();
  });
  it("parses bounded history pages", () => {
    expect(parseOsvLedgerQuery({})).toEqual({
      offset: 0, limit: 50,
    });
    expect(parseOsvLedgerQuery({
      importId: "import-ledger-12345",
      inspectionId: "inspection-ledger-12345",
      status: "COMPLETE", limit: 10, offset: 20,
    })).toMatchObject({
      importId: "import-ledger-12345",
      status: "COMPLETE", limit: 10, offset: 20,
    });
  });
  it.each([
    { limit: 0 }, { limit: 101 }, { offset: -1 },
    { status: "SAFE" }, { unknown: true },
    { status: "COMPLETE\nERROR" },
  ])("rejects unbounded history filters %j", query => {
    expect(() => parseOsvLedgerQuery(query)).toThrow();
  });
  it("generates stable tenant-scoped request digests", () => {
    const { command } = fixture();
    const first = osvInspectionFingerprint(scope, command);
    const again = osvInspectionFingerprint(scope, command);
    expect(first).toBe(again);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(osvInspectionFingerprint({
      ...scope, organizationId: "other-ledger-org",
    }, command)).not.toBe(first);
  });
  it("does not make reviewed binding input order significant", () => {
    const command = parseOsvLedgerCommand({
      ...request,
      inspection: {
        ...request.inspection,
        packageBindings: [
          ...request.inspection.packageBindings,
          { inventoryProduct: "Different Product",
            ecosystem: "PyPI", packageName: "different-package" },
        ],
      },
    });
    const reordered = {
      ...command,
      inspection: {
        ...command.inspection,
        packageBindings: [...command.inspection.packageBindings].reverse(),
      },
    };
    expect(osvInspectionFingerprint(scope, command)).toBe(
      osvInspectionFingerprint(scope, reordered));
  });
});
describe("OSV inspection ledger integrity and replay invariants", () => {
  it("builds stable query hashes", () => {
    const { result } = fixture();
    expect(osvInspectionLedgerKey(result)).toMatch(/^[a-f0-9]{64}$/);
    expect(osvInspectionLedgerKey(result)).toBe(
      osvInspectionLedgerKey({ ...result }));
  });
  it("accepts only a correctly attributed complete report", () => {
    const { command, report } = fixture();
    expect(() => assertLedgerReport(scope, command, report)).not.toThrow();
  });
  it("rejects cross-tenant or altered report attribution", () => {
    const { command, report } = fixture();
    expect(() => assertLedgerReport(scope, command, {
      ...report, organizationId: "foreign-org",
    })).toThrow();
    expect(() => assertLedgerReport(scope, command, {
      ...report, importId: "foreign-import",
    })).toThrow();
  });
  it("refuses to persist a preview or mismatched result count", () => {
    const { command, report } = fixture();
    expect(() => assertLedgerReport(scope, command, {
      ...report, dryRun: true,
    })).toThrow();
    expect(() => assertLedgerReport(scope, command, {
      ...report, queriesAttempted: 2,
    })).toThrow();
  });
  it("rejects results that do not belong to the planned package set", () => {
    const { command, report } = fixture();
    expect(() => assertLedgerReport(scope, command, {
      ...report,
      results: [{ ...report.results[0]!,
        key: "forged-key", ecosystem: "PyPI" }],
    })).toThrow();
  });
  it("rejects identical duplicate package-result keys", () => {
    const { command, report } = fixture();
    expect(() => assertLedgerReport(scope, command, {
      ...report,
      results: [report.results[0]!, report.results[0]!],
      queriesAttempted: 2,
    })).toThrow();
  });
  it("commits results with a matching fingerprint", () => {
    const { command, report } = fixture();
    const result = buildOsvLedgerCommit(scope, command,
      report, "inspection-12345");
    expect(result).toMatchObject({
      inspectionId: "inspection-12345",
      replayed: false, status: "COMPLETE",
      queryCount: 1, reportDigest: report.reportDigest,
    });
  });
  it("replays stored reports instead of recomputing new source results", () => {
    const { command, report } = fixture();
    const fingerprint = osvInspectionFingerprint(scope, command);
    const result = replayOsvLedger(scope, command, {
      id: "inspection-12345", requestDigest: fingerprint,
      reportDigest: report.reportDigest,
      status: "COMPLETE", queryCount: 1,
      report,
    });
    expect(result.replayed).toBe(true);
    expect(result.report).toEqual(report);
    expect(result.warnings.join(" ")).toMatch(/no OSV API query ran/i);
  });
  it("conflicts on reused keys with altered command payloads", () => {
    const { command, report } = fixture();
    const original = {
      id: "inspection-12345",
      requestDigest: osvInspectionFingerprint(scope, command),
      reportDigest: report.reportDigest,
      report, status: report.status, queryCount: 1,
    };
    expect(() => replayOsvLedger(scope, {
      ...command, inspection: {
        ...command.inspection, maxAgeMinutes: 120,
      },
    }, original)).toThrow();
  });
  it("detects corrupted or mismatched persisted report metadata", () => {
    const { command, report } = fixture();
    const original = {
      id: "inspection-12345",
      requestDigest: osvInspectionFingerprint(scope, command),
      reportDigest: "b".repeat(64),
      report, status: report.status, queryCount: 1,
    };
    expect(() => replayOsvLedger(scope, command, original)).toThrow();
  });
});
