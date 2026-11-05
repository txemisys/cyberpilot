import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory, retireAssetInventory } from "./assets-inventory-service";
import { inspectOfficialOsv, parseOfficialOsvInspection,
  planOfficialOsvInspection, buildOfficialOsvInspectionReport,
} from "./assets-osv-official-service";
import type { AssetScope } from "./assets-inventory-service";
import type { LiveOsvQueryResult } from "./assets-osv-official-client";

const now = new Date("2026-11-05T12:00:00.000Z");
const mappings = [{
  inventoryProduct: "Example Package",
  ecosystem: "npm", packageName: "example-package",
}];
const rows = [
  { externalId: "device-a", softwareName: "Example Package",
    softwareVersion: "1.2.3", versionStatus: "EXACT",
    normalizedProductKey: "example package" },
  { externalId: "device-b", softwareName: "Example Package",
    softwareVersion: "1.2.3", versionStatus: "EXACT",
    normalizedProductKey: "example package" },
  { externalId: "device-c", softwareName: "Example Package",
    softwareVersion: "latest", versionStatus: "AMBIGUOUS",
    normalizedProductKey: "example package" },
  { externalId: "device-d", softwareName: "Other Software",
    softwareVersion: "1.0.0", versionStatus: "EXACT",
    normalizedProductKey: "other software" },
];
const scope: AssetScope = {
  organizationId: "test-org-12345",
  userId: "test-admin-12345",
  role: "ADMIN",
};
const payload = {
  importId: "import-12345",
  packageBindings: mappings,
  limitPackages: 10,
  maxPagesPerPackage: 2,
  maxRecordsPerPackage: 20,
  maxAgeMinutes: 60,
  dryRun: true,
};
const official = (patch?: Partial<LiveOsvQueryResult>): LiveOsvQueryResult => ({
  schema: "cyberpilot.assets.osv.live.query.v1",
  endpoint: "https://api.osv.dev",
  package: { ecosystem: "npm", name: "example-package", version: "1.2.3" },
  checkedAt: now.toISOString(), provider: "OSV_DEV_API",
  transport: "HTTPS_FIXED_ENDPOINT", status: "COMPLETE",
  queriedPages: 1, responseBytes: 300,
  vulnerabilities: [{
    id: "GHSA-abcd-1234-5678", modified: now.toISOString(),
    withdrawn: null, aliases: ["CVE-2026-12345"],
    exactVersionListed: true, packageIdentityListed: true,
    rangesPresent: false, fingerprint: "a".repeat(64),
  }],
  providerReportedCount: 1, exactEnumeratedCount: 1,
  nonEnumeratedCount: 0, withdrawnCount: 0, warnings: [],
  digest: "b".repeat(64),
  ...patch,
});
describe("official OSV provider planning", () => {
  it("parses bounded defaults and rejects unknown request fields", () => {
    expect(parseOfficialOsvInspection({
      importId: payload.importId, packageBindings: mappings,
    })).toMatchObject({
      dryRun: true, limitPackages: 10, maxPagesPerPackage: 2,
    });
    expect(() => parseOfficialOsvInspection({
      ...payload, endpoint: "https://attacker.invalid",
    })).toThrow();
  });
  it.each([
    { limitPackages: 21 },
    { limitPackages: 0 },
    { maxPagesPerPackage: 4 },
    { maxRecordsPerPackage: 0 },
    { maxAgeMinutes: 0 },
    { dryRun: "false" },
    { packageBindings: "bad" },
  ])("rejects invalid provider request budget %j", patch => {
    expect(() => parseOfficialOsvInspection({
      ...payload, ...patch,
    })).toThrow();
  });
  it("deduplicates identical package-version requests without losing observation counts", () => {
    const plan = planOfficialOsvInspection(payload.importId, rows,
      parseOfficialOsvInspection(payload).packageBindings, 10);
    expect(plan.inventoryRows).toBe(4);
    expect(plan.mappedRows).toBe(3);
    expect(plan.unmappedRows).toBe(1);
    expect(plan.invalidVersionRows).toBe(1);
    expect(plan.actionablePackages).toBe(1);
    expect(plan.selectedPackages).toBe(1);
    expect(plan.work[0]?.observationCount).toBe(2);
  });
  it("sorts frequent queries ahead of rare packages", () => {
    const extra = { ...rows[0]!,
      externalId: "device-e", normalizedProductKey: "other software",
      softwareName: "Other Software", softwareVersion: "3.0.0",
    };
    const expanded = [...rows, extra];
    const plan = planOfficialOsvInspection(payload.importId, expanded, [
      ...mappings, { inventoryProduct: "Other Software",
        ecosystem: "PyPI", packageName: "different-package",
        expectedPurl: null },
    ].map(binding => ({ expectedPurl: null, ...binding })), 1);
    expect(plan.selectedPackages).toBe(1);
    expect(plan.skippedPackages).toBe(2);
    expect(plan.work[0]?.observationCount).toBe(2);
  });
  it("refuses to call complete on partial coverage or invalid versions", () => {
    const command = parseOfficialOsvInspection(payload);
    const plan = planOfficialOsvInspection(command.importId, rows,
      command.packageBindings, 10);
    const report = buildOfficialOsvInspectionReport(scope,
      { ...command, dryRun: false }, plan, [], now);
    expect(report.status).toBe("INCOMPLETE");
    expect(report.coverage).toBe("DECLARED_NOT_VERIFIED");
  });
  it("marks upstream provider errors and stale responses independently", () => {
    const command = parseOfficialOsvInspection(payload);
    const plan = planOfficialOsvInspection(command.importId, rows,
      command.packageBindings, 10);
    const result = {
      key: plan.work[0]!.key,
      ecosystem: "npm", name: "example-package", version: "1.2.3",
      observationCount: 2, status: "UPSTREAM_ERROR",
      checkedAt: now.toISOString(), digest: "x",
      possibleIds: [], providerOnlyIds: [], withdrawnIds: [],
      unresolvedIds: [], queriedPages: 0, warnings: ["provider failed"],
    };
    const report = buildOfficialOsvInspectionReport(scope,
      { ...command, dryRun: false }, plan, [result], now);
    expect(report.status).toBe("ERROR");
    expect(report.queriesCompleted).toBe(0);
  });
});
describe.skipIf(!process.env.DATABASE_URL)(
  "official OSV live service PostgreSQL isolation and no-write semantics", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 15);
    const organizationId = "official-osv-" + nonce;
    const outsiderOrg = "official-osv-foreign-" + nonce;
    const userId = "official-osv-admin-" + nonce;
    const memberId = "official-osv-member-" + nonce;
    const outsiderId = "official-osv-outsider-" + nonce;
    const administrator: AssetScope = {
      organizationId, userId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: outsiderOrg, userId: outsiderId, role: "ADMIN",
    };
    const header = [
      "asset_id,hostname,owner,platform,os_name,os_version,",
      "software_name,software_version,observed_at",
    ].join("");
    const csv = [
      header,
      "device-001,workstation-a,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
      "device-002,workstation-b,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
      "device-003,workstation-c,,LINUX,Ubuntu,22.04,Other Software,latest,2026-11-01T12:00:00.000Z",
    ].join("\n") + "\n";
    let importId = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: userId, name: "OSV admin", email: "osv-official-admin-" + nonce + "@example.invalid" },
        { id: memberId, name: "OSV member", email: "osv-official-member-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "OSV outsider", email: "osv-official-other-" + nonce + "@example.invalid" },
      ]});
      await db.organization.createMany({ data: [
        { id: organizationId, slug: "official-osv-" + nonce,
          name: "Official OSV tests" },
        { id: outsiderOrg, slug: "official-osv-foreign-" + nonce,
          name: "Other official OSV tests" },
      ]});
      await db.membership.createMany({ data: [
        { organizationId, userId, role: "ADMIN" },
        { organizationId, userId: memberId, role: "MEMBER" },
        { organizationId: outsiderOrg, userId: outsiderId, role: "ADMIN" },
      ]});
      const created = await importAssetInventory(administrator, {
        sourceLabel: "Official OSV synthetic inventory",
        idempotencyKey: "official-osv-" + nonce,
        csv, dryRun: false,
      }, now);
      importId = created.importId!;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, outsiderOrg] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, memberId, outsiderId] } },
      });
    });
    const query = vi.fn(async () => official());
    it("blocks non-admin users before a provider call", async () => {
      query.mockClear();
      await expect(inspectOfficialOsv(member, {
        ...payload, importId, dryRun: false,
      }, { query, now: () => now })).rejects
        .toMatchObject({ code: "FORBIDDEN" });
      expect(query).not.toHaveBeenCalled();
    });
    it("does not reveal cross-tenant inventories or query a provider", async () => {
      query.mockClear();
      await expect(inspectOfficialOsv(outsider, {
        ...payload, importId, dryRun: false,
      }, { query, now: () => now })).rejects
        .toMatchObject({ code: "MISSING" });
      expect(query).not.toHaveBeenCalled();
    });
    it("plans queries in preview without contacting external endpoints", async () => {
      query.mockClear();
      const report = await inspectOfficialOsv(administrator, {
        ...payload, importId, dryRun: true,
      }, { query, now: () => now });
      expect(report.status).toBe("PREVIEW");
      expect(report.plan.inventoryRows).toBe(3);
      expect(report.plan.selectedPackages).toBe(1);
      expect(report.plan.work[0]?.observationCount).toBe(2);
      expect(query).not.toHaveBeenCalled();
    });
    it("runs only deduplicated package queries and returns conservative associations", async () => {
      query.mockClear();
      const before = await db.assetInventoryDevice.findMany({
        where: { organizationId, importId },
      });
      const report = await inspectOfficialOsv(administrator, {
        ...payload, importId, dryRun: false,
      }, { query, now: () => now });
      expect(query).toHaveBeenCalledTimes(1);
      expect(query).toHaveBeenCalledWith({
        ecosystem: "npm", name: "example-package",
        version: "1.2.3", expectedPurl: null,
      }, expect.any(Object));
      expect(report.totalPossibleAssociations).toBe(1);
      expect(report.results[0]?.observationCount).toBe(2);
      expect(report.status).toBe("PARTIAL");
      const after = await db.assetInventoryDevice.findMany({
        where: { organizationId, importId },
      });
      expect(after).toEqual(before);
    });
    it("refuses to query retired inventory snapshots", async () => {
      query.mockClear();
      await retireAssetInventory(administrator, {
        importId, reason: "Synthetic inventory superseded for retirement.",
        expectedState: "COMMITTED",
      }, now);
      await expect(inspectOfficialOsv(administrator, {
        ...payload, importId, dryRun: false,
      }, { query, now: () => now })).rejects
        .toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
    });
  },
);
