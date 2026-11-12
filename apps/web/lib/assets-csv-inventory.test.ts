import { describe, expect, it } from "vitest";
import {
  INVENTORY_COLUMNS, decodeInventoryCsv, analyzeCsvInventory,
  correlateAdvisories, normalizeInventoryProduct,
  classifyInventoryFreshness, classifyInventoryVersion,
  inventoryHash, parseInventoryTimestamp, validateAdvisoryFeed,
} from "./assets-csv-inventory";
import {
  parseAssetImport, parseAssetQuery, parseInventoryRetirement,
  assetImportFingerprint,
} from "./assets-inventory-service";

const now = new Date("2026-11-05T12:00:00.000Z");
const header = INVENTORY_COLUMNS.join(",");
const observed = "2026-11-04T12:00:00.000Z";
const row = (asset="asset-12345", owner="Jane Smith",
  product="Example Browser", version="4.0.2") =>
  [asset,"host-001",owner,"WINDOWS","Windows 11","23H2",
    product,version,observed].join(",");
const csv = header + "\n" + row() + "\n";
const opts = { sourceLabel: "MDM export", organizationId: "org-12345", now };
const advisory = {
  id: "CVE-2026-12345",
  product: "Example Browser",
  affectedVersion: "4.0.2",
  feed: "customer-provided-test-fixture",
  feedVersion: "fixture-v1",
  observedAt: "2026-11-04T12:00:00.000Z",
};
describe("assets CSV strict parser", () => {
  it("decodes quoted delimiter, escaped quotes and multiline fields", () => {
    const decoded = decodeInventoryCsv(
      'a,b,c\r\n"x,y","say ""hi""","line\ncontinued"\r\n');
    expect(decoded).toEqual([
      ["a", "b", "c"],
      ["x,y", 'say "hi"', "line\ncontinued"],
    ]);
  });
  it("allows BOM only in the first position", () => {
    expect(decodeInventoryCsv("\uFEFF" + csv)[0]).toEqual([...INVENTORY_COLUMNS]);
    expect(() => decodeInventoryCsv(header + "\n\uFEFF" + row())).toThrow();
  });
  it.each([
    'a,b\n"unterminated,row',
    'a,b\nx,y,z',
    'a,b\nx"bad",y',
    'a,b\n"x"z,y',
    'a,b\nx,y\r',
    'a,b\nx,\u0000',
  ])("rejects malformed CSV %j", source => {
    expect(() => decodeInventoryCsv(source)).toThrow();
  });
  it("bounds CSV bytes and records", () => {
    expect(() => decodeInventoryCsv(csv, 10)).toThrow();
    expect(() => decodeInventoryCsv(csv + row("asset-67890"), 262144, 1)).toThrow();
    expect(() => decodeInventoryCsv("")).toThrow();
  });
  it("rejects missing, duplicate and unknown header fields", () => {
    expect(() => analyzeCsvInventory(
      header.replace("owner", "someone") + "\n" + row(), opts)).toThrow();
    expect(() => analyzeCsvInventory(
      header.replace("owner", "asset_id") + "\n" + row(), opts)).toThrow();
  });
  it.each([
    "=HYPERLINK(1)", "+SUM(1)", "@fetch", "-cmd", "\t=2",
  ])("rejects formula-like content %j", malicious => {
    expect(() => analyzeCsvInventory(
      header + "\n" + row("asset-12345", malicious), opts)).toThrow();
  });
  it("requires complete canonical UTC timestamp", () => {
    expect(parseInventoryTimestamp(observed).toISOString()).toBe(observed);
    expect(() => parseInventoryTimestamp("2026-11-04")).toThrow();
    expect(() => parseInventoryTimestamp("2026-02-30T00:00:00.000Z")).toThrow();
  });
  it("normalizes product identifiers deterministically", () => {
    expect(normalizeInventoryProduct(" EXAMPLE  Browser™ "))
      .toBe("example browser");
    expect(inventoryHash({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });
  it("marks version ranges and unspecified versions as unknown", () => {
    expect(classifyInventoryVersion(null)).toBe("MISSING");
    expect(classifyInventoryVersion("1.0.*")).toBe("AMBIGUOUS");
    expect(classifyInventoryVersion("latest")).toBe("AMBIGUOUS");
    expect(classifyInventoryVersion("4.0.2")).toBe("EXACT");
  });
  it("classifies future and stale timestamps without claiming exposure", () => {
    expect(classifyInventoryFreshness(new Date(
      "2026-11-06T00:00:00.000Z"), now)).toBe("FUTURE");
    expect(classifyInventoryFreshness(new Date(
      "2026-01-01T00:00:00.000Z"), now)).toBe("STALE");
  });
});
describe("assets ingestion and provenance", () => {
  it("returns an explicit customer-declared report", () => {
    const report = analyzeCsvInventory(csv, opts);
    expect(report).toMatchObject({
      source: "CUSTOMER_DECLARED_CSV",
      declaredCount: 1, importedCount: 1,
      duplicateCount: 0, possibleAdvisoryCount: 0,
    });
    expect(report.rows[0]?.ownerHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(report)).not.toContain("Jane Smith");
    expect(report.rows[0]?.advisoryStatus).toBe("UNKNOWN");
  });
  it("deduplicates repeated asset and product without fabricating coverage", () => {
    const report = analyzeCsvInventory(header + "\n" +
      row() + "\n" + row() + "\n", opts);
    expect(report.importedCount).toBe(1);
    expect(report.duplicateCount).toBe(1);
    expect(report.declaredCount).toBe(2);
  });
  it("preserves distinct software on one asset", () => {
    const report = analyzeCsvInventory(header + "\n" + row() +
      "\n" + row("asset-12345", "", "Example Database", "7.1") + "\n", opts);
    expect(report.importedCount).toBe(2);
    expect(report.duplicateCount).toBe(0);
  });
  it("matches only exact declared product and version to fixture advisory", () => {
    const report = analyzeCsvInventory(csv, {
      ...opts, advisories: [advisory],
    });
    expect(report.possibleAdvisoryCount).toBe(1);
    expect(report.rows[0]?.advisoryIds).toEqual(["CVE-2026-12345"]);
    expect(report.rows[0]?.advisoryStatus).toBe("POSSIBLE_MATCH");
    expect(report.warnings.join(" ")).toMatch(/not prove exploitation/i);
  });
  it("never marks unknown versions as no vulnerability", () => {
    const report = analyzeCsvInventory(header + "\n" +
      row("asset-12345", "", "Example Browser", "latest") + "\n", {
        ...opts, advisories: [advisory],
      });
    expect(report.rows[0]?.advisoryStatus).toBe("UNKNOWN");
    expect(report.rows[0]?.versionStatus).toBe("AMBIGUOUS");
  });
  it("does not infer a CVE match from approximate product name", () => {
    const report = analyzeCsvInventory(csv, {
      ...opts, advisories: [{ ...advisory, product: "Different Browser" }],
    });
    expect(report.rows[0]?.advisoryStatus).toBe("NO_MATCH");
    expect(report.possibleAdvisoryCount).toBe(0);
  });
  it("rejects ranges and duplicate records in a supplied advisory fixture", () => {
    expect(() => validateAdvisoryFeed([
      { ...advisory, affectedVersion: "4.*" },
    ])).toThrow();
    expect(() => validateAdvisoryFeed([advisory, advisory])).toThrow();
  });
  it("keeps owner pseudonym tenant-specific", () => {
    const first = analyzeCsvInventory(csv, opts).rows[0]?.ownerHash;
    const second = analyzeCsvInventory(csv, {
      ...opts, organizationId: "org-67890",
    }).rows[0]?.ownerHash;
    expect(first).not.toBe(second);
  });
});
describe("assets service validation and replay identity", () => {
  it("requires valid role-ready import properties", () => {
    expect(parseAssetImport({
      sourceLabel: "MDM export", idempotencyKey: "key-12345",
      csv,
    })).toMatchObject({ dryRun: true, advisories: [] });
  });
  it.each([
    { sourceLabel: "", idempotencyKey: "key-12345", csv },
    { sourceLabel: "MDM export", idempotencyKey: "", csv },
    { sourceLabel: "MDM export", idempotencyKey: "key-12345", csv: 5 },
    { sourceLabel: "MDM export", idempotencyKey: "key-12345", csv, dryRun: "false" },
    { sourceLabel: "MDM export", idempotencyKey: "key-12345", csv, unknown: 1 },
  ])("rejects malformed import request", input => {
    expect(() => parseAssetImport(input)).toThrow();
  });
  it("provides stable fingerprint across identical submission", () => {
    const input = parseAssetImport({
      sourceLabel: "MDM export", idempotencyKey: "key-12345", csv,
    });
    const report = analyzeCsvInventory(csv, opts);
    expect(assetImportFingerprint(input, report)).toBe(
      assetImportFingerprint(input, report));
    expect(assetImportFingerprint({ ...input, csv: csv + "\n" }, report))
      .not.toBe(assetImportFingerprint(input, report));
  });
  it("validates paginated scoped queries", () => {
    expect(parseAssetQuery({})).toMatchObject({
      offset: 0, limit: 50, includeRetired: false,
    });
    expect(parseAssetQuery({ versionStatus: "missing" }).versionStatus)
      .toBe("MISSING");
    for (const invalid of [
      { limit: 101 }, { offset: -1 }, { includeRetired: "true" },
      { advisoryStatus: "PASS" }, { unexpected: true },
    ]) expect(() => parseAssetQuery(invalid)).toThrow();
  });
  it("retirement demands an explicit reason and expected state", () => {
    expect(parseInventoryRetirement({
      importId: "import-12345", reason: "Superseded inventory snapshot.",
      expectedState: "COMMITTED",
    }).importId).toBe("import-12345");
    expect(() => parseInventoryRetirement({
      importId: "import-12345", reason: "short",
      expectedState: "COMMITTED",
    })).toThrow();
  });
});
