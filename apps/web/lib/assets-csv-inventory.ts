import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";

export const INVENTORY_COLUMNS = [
  "asset_id", "hostname", "owner", "platform", "os_name",
  "os_version", "software_name", "software_version", "observed_at",
] as const;
export type InventoryColumn = typeof INVENTORY_COLUMNS[number];
export type InventoryPlatform =
  "WINDOWS" | "MACOS" | "LINUX" | "ANDROID" | "IOS" | "OTHER" | "UNKNOWN";
export type InventoryVersionStatus = "EXACT" | "MISSING" | "AMBIGUOUS";
export type InventoryFreshness = "FRESH" | "AGING" | "STALE" | "FUTURE";
export type InventoryAdvisoryStatus = "UNKNOWN" | "NO_MATCH" | "POSSIBLE_MATCH";
export type InventoryConfidence = "DECLARED_EXACT" | "DECLARED_PARTIAL";
export type InventoryCsvRow = {
  assetId: string;
  hostname: string | null;
  ownerHash: string | null;
  platform: InventoryPlatform;
  osName: string;
  osVersion: string | null;
  softwareName: string;
  softwareVersion: string | null;
  observedAt: Date;
  sourceRow: number;
  normalizedProductKey: string;
  versionStatus: InventoryVersionStatus;
  freshnessStatus: InventoryFreshness;
  advisoryStatus: InventoryAdvisoryStatus;
  advisoryIds: string[];
  confidence: InventoryConfidence;
};
export type InventoryImportReport = {
  schema: "cyberpilot.assets.csv.import.v1";
  source: "CUSTOMER_DECLARED_CSV";
  sourceLabel: string;
  declaredCount: number;
  importedCount: number;
  duplicateCount: number;
  unknownVersionCount: number;
  staleCount: number;
  futureCount: number;
  possibleAdvisoryCount: number;
  warnings: string[];
  rows: InventoryCsvRow[];
  digest: string;
};
export type InventoryCsvOptions = {
  sourceLabel: string;
  organizationId: string;
  now: Date;
  maxBytes?: number;
  maxRows?: number;
  maxAgeDays?: number;
  advisories?: InventoryAdvisory[];
};
export type InventoryAdvisory = {
  id: string;
  product: string;
  affectedVersion: string;
  feed: string;
  feedVersion: string;
  observedAt: string;
};
const platforms = new Set<InventoryPlatform>([
  "WINDOWS", "MACOS", "LINUX", "ANDROID", "IOS", "OTHER", "UNKNOWN",
]);
const suspicious = /^[\s]*[=+@\-]/;
const forbiddenControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function scalar(
  value: unknown, field: string, maximum: number,
  required = false,
): string {
  if (typeof value !== "string" || value.length > maximum ||
      forbiddenControls.test(value) || suspicious.test(value))
    invalid("Invalid inventory " + field + ".");
  const trimmed = value.trim().normalize("NFKC");
  if (required && !trimmed)
    invalid("Inventory " + field + " is required.");
  return trimmed;
}
function safeString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length > maximum || forbiddenControls.test(value))
    invalid("Invalid " + field + ".");
  return value;
}
export function inventoryHash(value: unknown): string {
  return createHash("sha256").update(
    typeof value === "string" ? value : JSON.stringify(value),
  ).digest("hex");
}
export function normalizeInventoryProduct(value: string): string {
  return value.normalize("NFKC").toLowerCase().trim()
    .replace(/\s+/g, " ")
    .replace(/[®™]/g, "");
}
export function classifyInventoryVersion(
  value: string | null,
): InventoryVersionStatus {
  if (!value) return "MISSING";
  if (value.length > 80 || /[<>*?~^|]/.test(value) ||
      /\b(latest|unknown|current|any|varies|multiple|all|n\/a)\b/i.test(value))
    return "AMBIGUOUS";
  if (!/^[a-z0-9][a-z0-9._+\- ]{0,79}$/i.test(value))
    return "AMBIGUOUS";
  return "EXACT";
}
export function classifyInventoryFreshness(
  observedAt: Date, now: Date, maxAgeDays = 30,
): InventoryFreshness {
  const delta = now.getTime() - observedAt.getTime();
  if (delta < -5 * 60 * 1000) return "FUTURE";
  if (delta > maxAgeDays * 2 * 86400000) return "STALE";
  if (delta > maxAgeDays * 86400000) return "AGING";
  return "FRESH";
}
export function parseInventoryTimestamp(value: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    invalid("Inventory observation timestamp must be UTC ISO8601 milliseconds.");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value)
    invalid("Inventory observation date is invalid.");
  return parsed;
}
export function inventoryPlatform(value: string): InventoryPlatform {
  const platform = value.toUpperCase().replace(/[ -]/g, "_");
  if (!platforms.has(platform as InventoryPlatform))
    invalid("Unsupported inventory platform.");
  return platform as InventoryPlatform;
}
/**
 * Strict bounded RFC4180 CSV reader: quoted delimiters, escaped quotes,
 * CRLF and quoted line breaks. Reject malformed Unicode, BOM in non-header
 * positions, unclosed quotes and shape mismatches before any writes.
 */
export function decodeInventoryCsv(
  source: string, maxBytes = 262144, maxRows = 1000,
): string[][] {
  if (typeof source !== "string" || Buffer.byteLength(source, "utf8") > maxBytes)
    invalid("Inventory CSV exceeds maximum size.");
  if (!source || source.includes("\uFFFD"))
    invalid("Inventory CSV is empty or contains replacement characters.");
  const content = source.startsWith("\uFEFF") ? source.slice(1) : source;
  if (content.includes("\uFEFF"))
    invalid("Inventory contains an unexpected byte-order mark.");
  const records: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  let justClosed = false;
  let starting = true;
  let physicalLine = 1;
  const acceptField = () => {
    if (row.length >= 16)
      invalid("Inventory CSV contains too many columns.");
    row.push(field);
    field = "";
    justClosed = false;
    starting = true;
  };
  const acceptRow = () => {
    acceptField();
    if (row.some(x => x.trim() !== ""))
      records.push(row);
    row = [];
    if (records.length > maxRows + 1)
      invalid("Inventory CSV exceeds maximum rows.");
  };
  for (let index = 0; index < content.length; index++) {
    const char = content[index]!;
    if (char === "\u0000")
      invalid("Inventory CSV contains NUL.");
    if (char === "\n") physicalLine++;
    if (quoted) {
      if (char === '"') {
        if (content[index + 1] === '"') {
          field += '"';
          index++;
        } else {
          quoted = false;
          justClosed = true;
        }
      } else {
        field += char;
      }
      if (field.length > 4096)
        invalid("Inventory CSV field too long.");
      continue;
    }
    if (justClosed && char !== "," && char !== "\r" && char !== "\n")
      invalid("Unexpected character after closing CSV quote.");
    if (char === '"') {
      if (!starting) invalid("Unexpected quote in CSV field.");
      quoted = true;
      starting = false;
      continue;
    }
    if (char === ",") {
      acceptField();
      continue;
    }
    if (char === "\r") {
      if (content[index + 1] !== "\n")
        invalid("Bare carriage return in inventory CSV.");
      index++;
      physicalLine++;
      acceptRow();
      continue;
    }
    if (char === "\n") {
      acceptRow();
      continue;
    }
    field += char;
    starting = false;
    if (field.length > 4096)
      invalid("Inventory CSV field too long.");
  }
  if (quoted) invalid("Unclosed CSV quote.");
  if (field.length || row.length || justClosed)
    acceptRow();
  if (records.length < 2)
    invalid("Inventory CSV requires a header and at least one data row.");
  if (records.length > maxRows + 1)
    invalid("Inventory CSV exceeds maximum rows.");
  const width = records[0]!.length;
  for (const record of records)
    if (record.length !== width)
      invalid("Inventory CSV row has inconsistent number of columns.");
  return records;
}
function validateHeader(header: string[]): Record<InventoryColumn, number> {
  const names = header.map(x => x.trim().toLowerCase());
  if (names.length !== INVENTORY_COLUMNS.length ||
      new Set(names).size !== names.length ||
      INVENTORY_COLUMNS.some(name => !names.includes(name)))
    invalid("Inventory CSV header must exactly match the documented nine columns.");
  return Object.fromEntries(
    INVENTORY_COLUMNS.map(name => [name, names.indexOf(name)]),
  ) as Record<InventoryColumn, number>;
}
function stringField(
  record: string[], header: Record<InventoryColumn, number>,
  field: InventoryColumn,
  max: number, required = false,
): string {
  return scalar(record[header[field]], field, max, required);
}
export function validateAdvisoryFeed(
  advisories: InventoryAdvisory[] | undefined,
): InventoryAdvisory[] {
  if (advisories === undefined) return [];
  if (!Array.isArray(advisories) || advisories.length > 500)
    invalid("Advisory feed must contain at most 500 entries.");
  const seen = new Set<string>();
  return advisories.map(value => {
    if (!value || typeof value !== "object")
      invalid("Invalid advisory source entry.");
    const id = safeString(value.id, "advisory identifier", 100);
    if (!/^CVE-\d{4}-\d{4,}$/.test(id))
      invalid("Advisory identifier must be a CVE.");
    const product = scalar(value.product, "advisory product", 160, true);
    const affectedVersion = scalar(
      value.affectedVersion, "advisory affected version", 80, true);
    if (classifyInventoryVersion(affectedVersion) !== "EXACT")
      invalid("Advisories must declare one unambiguous exact version.");
    const feed = scalar(value.feed, "advisory feed", 100, true);
    const feedVersion = scalar(
      value.feedVersion, "advisory feed version", 100, true);
    parseInventoryTimestamp(value.observedAt);
    const key = id + ":" + normalizeInventoryProduct(product) + ":" + affectedVersion;
    if (seen.has(key)) invalid("Duplicate advisory feed record.");
    seen.add(key);
    return { id, product, affectedVersion, feed, feedVersion, observedAt: value.observedAt };
  });
}
export function correlateAdvisories(
  row: Pick<InventoryCsvRow,
    "softwareName" | "softwareVersion" | "versionStatus">,
  advisories: InventoryAdvisory[],
): { status: InventoryAdvisoryStatus; advisoryIds: string[] } {
  if (!advisories.length || !row.softwareName ||
      row.versionStatus !== "EXACT" || !row.softwareVersion)
    return { status: "UNKNOWN", advisoryIds: [] };
  const matching = advisories.filter(item =>
    normalizeInventoryProduct(item.product) ===
      normalizeInventoryProduct(row.softwareName) &&
    item.affectedVersion === row.softwareVersion);
  if (matching.length === 0)
    return { status: "NO_MATCH", advisoryIds: [] };
  return {
    status: "POSSIBLE_MATCH",
    advisoryIds: [...new Set(matching.map(item => item.id))].sort(),
  };
}
export function analyzeCsvInventory(
  source: string, options: InventoryCsvOptions,
): InventoryImportReport {
  const sourceLabel = scalar(options.sourceLabel, "source label", 120, true);
  const organizationId = scalar(options.organizationId, "organization ID", 120, true);
  const maxRows = options.maxRows ?? 1000;
  const maxBytes = options.maxBytes ?? 262144;
  const maxAgeDays = options.maxAgeDays ?? 30;
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 10000 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 128 || maxBytes > 1048576 ||
      !Number.isSafeInteger(maxAgeDays) || maxAgeDays < 1 || maxAgeDays > 365)
    invalid("Invalid inventory import limits.");
  if (!Number.isFinite(options.now.getTime()))
    invalid("Invalid inventory current time.");
  const input = decodeInventoryCsv(source, maxBytes, maxRows);
  const header = validateHeader(input[0]!);
  const advisories = validateAdvisoryFeed(options.advisories);
  const rows: InventoryCsvRow[] = [];
  const seen = new Set<string>();
  let duplicateCount = 0;
  let unknownVersionCount = 0;
  let staleCount = 0;
  let futureCount = 0;
  let possibleAdvisoryCount = 0;
  for (const [index, record] of input.slice(1).entries()) {
    const assetId = stringField(record, header, "asset_id", 100, true);
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,99}$/.test(assetId))
      invalid("Invalid asset identifier on CSV row " + (index + 2));
    const hostname = stringField(record, header, "hostname", 200);
    const owner = stringField(record, header, "owner", 200);
    const platform = inventoryPlatform(
      stringField(record, header, "platform", 40, true));
    const osName = stringField(record, header, "os_name", 160, true);
    const osVersion = stringField(record, header, "os_version", 80);
    const softwareName = stringField(record, header, "software_name", 160);
    const softwareVersion = stringField(record, header, "software_version", 80);
    const observedAt = parseInventoryTimestamp(
      stringField(record, header, "observed_at", 40, true));
    if ((softwareName && !softwareVersion) ||
        (!softwareName && softwareVersion))
      unknownVersionCount++;
    const normalizedProductKey = normalizeInventoryProduct(softwareName);
    const uniqueKey = assetId + "\u0000" + normalizedProductKey;
    if (seen.has(uniqueKey)) {
      duplicateCount++;
      continue;
    }
    seen.add(uniqueKey);
    const versionStatus = classifyInventoryVersion(
      softwareName ? softwareVersion || null : osVersion || null);
    if (versionStatus !== "EXACT" && softwareName && softwareVersion)
      unknownVersionCount++;
    const freshnessStatus = classifyInventoryFreshness(
      observedAt, options.now, maxAgeDays);
    if (freshnessStatus === "STALE") staleCount++;
    if (freshnessStatus === "FUTURE") futureCount++;
    const row: InventoryCsvRow = {
      assetId,
      hostname: hostname || null,
      ownerHash: owner ? inventoryHash(organizationId + ":" + owner.toLowerCase()) : null,
      platform, osName,
      osVersion: osVersion || null, softwareName,
      softwareVersion: softwareVersion || null, observedAt,
      sourceRow: index + 2, normalizedProductKey,
      versionStatus, freshnessStatus,
      advisoryStatus: "UNKNOWN", advisoryIds: [],
      confidence: versionStatus === "EXACT" ? "DECLARED_EXACT" : "DECLARED_PARTIAL",
    };
    const match = correlateAdvisories(row, advisories);
    row.advisoryStatus = match.status;
    row.advisoryIds = match.advisoryIds;
    if (match.status === "POSSIBLE_MATCH") possibleAdvisoryCount++;
    rows.push(row);
  }
  if (!rows.length) invalid("All inventory CSV rows were duplicates or invalid.");
  const canonical = {
    schema: "cyberpilot.assets.csv.import.v1" as const,
    source: "CUSTOMER_DECLARED_CSV" as const,
    sourceLabel, declaredCount: input.length - 1,
    importedCount: rows.length, duplicateCount,
    unknownVersionCount, staleCount, futureCount,
    possibleAdvisoryCount,
    rows: rows.map(row => ({
      ...row, observedAt: row.observedAt.toISOString(),
    })),
  };
  return {
    ...canonical,
    rows, digest: inventoryHash(canonical),
    warnings: [
      "Rows are customer-declared, not independently observed device telemetry.",
      "CVE matches are possible associations only; they do not prove exploitation or exposure.",
      "An empty or incomplete advisory feed does not establish that products are safe.",
      "Duplicate asset/product pairs are excluded and disclosed by count.",
      "Owner references are pseudonymized, not anonymized.",
      "No network scan, endpoint agent or third-party request is performed.",
    ],
  };
}
