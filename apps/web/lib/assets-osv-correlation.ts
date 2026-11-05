import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";
import { normalizeInventoryProduct, classifyInventoryVersion } from "./assets-csv-inventory";

export type OsvPackage = {
  ecosystem: string; name: string; purl: string | null;
};
export type OsvAffected = {
  package: OsvPackage;
  versions: string[];
  rangesPresent: boolean;
};
export type OsvRecord = {
  id: string;
  modified: string;
  published: string | null;
  withdrawn: string | null;
  aliases: string[];
  affected: OsvAffected[];
};
export type OsvFeed = {
  schema: "cyberpilot.assets.osv.snapshot.v1";
  source: "USER_SUPPLIED_OSV_EXPORT";
  sourceLabel: string;
  sourceVersion: string;
  retrievedAt: string;
  recordCount: number;
  withdrawnCount: number;
  affectedPackages: number;
  rangeOnlyCount: number;
  digest: string;
  records: OsvRecord[];
  warnings: string[];
};
export type PackageBinding = {
  inventoryProduct: string;
  ecosystem: string;
  packageName: string;
  expectedPurl: string | null;
};
export type OsvCandidateInput = {
  externalId: string;
  softwareName: string;
  softwareVersion: string | null;
  versionStatus: string;
  normalizedProductKey: string;
  observedAt: Date;
  sourceRow: number;
};
export type CandidateClassification =
  "EXACT_AFFECTED_VERSION" | "NO_EXACT_VERSION_MATCH" |
  "UNKNOWN_VERSION" | "UNMAPPED_PRODUCT" |
  "RANGES_UNEVALUATED" | "WITHDRAWN_RECORD";
export type OsvCandidate = {
  externalId: string;
  softwareName: string;
  version: string | null;
  ecosystem: string | null;
  packageName: string | null;
  sourceRow: number;
  category: CandidateClassification;
  possibleAdvisoryIds: string[];
  withdrawnIds: string[];
  unresolvedRangeIds: string[];
  feedDigest: string;
  certainty: "DECLARED_EXACT_ASSOCIATION" | "UNKNOWN";
  reason: string;
  fingerprint: string;
};
export type CandidateSummary = {
  totalRows: number;
  mappedRows: number;
  unmappedRows: number;
  unknownVersions: number;
  possibleAssociations: number;
  unresolvedRanges: number;
  withdrawnRecords: number;
  noExactMatches: number;
  byClassification: Record<CandidateClassification, number>;
};
const ID = /^[A-Z0-9][A-Z0-9._:+-]{1,119}$/;
const CVE = /^CVE-[0-9]{4}-[0-9]{4,19}$/;
const VALID_PURL = /^pkg:[a-z0-9.+-]+\/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]{1,250}$/;
const INVALID_TEXT = /[\u0000-\u001f\u007f]/;
const MAX_RECORDS = 500;
const MAX_AFFECTED = 25;
const MAX_VERSIONS = 400;
const MAX_BINDINGS = 500;
const classification: CandidateClassification[] = [
  "EXACT_AFFECTED_VERSION", "NO_EXACT_VERSION_MATCH",
  "UNKNOWN_VERSION", "UNMAPPED_PRODUCT",
  "RANGES_UNEVALUATED", "WITHDRAWN_RECORD",
];
function fail(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function obj(value: unknown, where: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("Invalid OSV object at " + where + ".");
  return value as Record<string, unknown>;
}
function array(value: unknown, where: string, limit: number): unknown[] {
  if (!Array.isArray(value) || value.length > limit)
    fail("Invalid OSV array at " + where + ".");
  return value;
}
function str(value: unknown, where: string, max = 160): string {
  if (typeof value !== "string" || !value.trim() ||
      value.length > max || INVALID_TEXT.test(value))
    fail("Invalid OSV string at " + where + ".");
  return value.trim();
}
function maybe(value: unknown, where: string, max = 160): string | null {
  if (value === undefined || value === null) return null;
  return str(value, where, max);
}
function iso(value: unknown, where: string): string {
  const text = str(value, where, 40);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(text))
    fail("OSV date must be a UTC timestamp: " + where + ".");
  const time = Date.parse(text);
  if (!Number.isFinite(time) || new Date(time).toISOString()
    .slice(0, 19) !== text.slice(0, 19))
    fail("Invalid OSV timestamp at " + where + ".");
  return new Date(time).toISOString();
}
function optionalIso(value: unknown, where: string): string | null {
  return value === undefined || value === null ? null : iso(value, where);
}
function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function osvPackageKey(ecosystem: string, name: string): string {
  return ecosystem.trim().toLowerCase() + "\u0000" +
    normalizeInventoryProduct(name);
}
export function parseOsvAffected(raw: unknown, path: string): OsvAffected {
  const value = obj(raw, path);
  const pkg = obj(value.package, path + ".package");
  const ecosystem = str(pkg.ecosystem, path + ".ecosystem", 70);
  const name = str(pkg.name, path + ".name", 160);
  if (!/^[a-zA-Z][a-zA-Z0-9._:+ -]{0,69}$/.test(ecosystem))
    fail("OSV ecosystem has unsupported characters.");
  const purl = maybe(pkg.purl, path + ".purl", 255);
  if (purl && !VALID_PURL.test(purl))
    fail("OSV package URL is invalid.");
  const rawVersions = value.versions === undefined ? [] :
    array(value.versions, path + ".versions", MAX_VERSIONS);
  const versions = rawVersions.map((v, i) => {
    const result = str(v, path + ".versions." + i, 120);
    if (classifyInventoryVersion(result) !== "EXACT")
      fail("OSV enumerated version is not usable for exact comparisons.");
    return result;
  });
  if (new Set(versions).size !== versions.length)
    fail("OSV affected versions include duplicates.");
  const ranges = value.ranges === undefined ? [] :
    array(value.ranges, path + ".ranges", 100);
  for (const [index, entry] of ranges.entries()) {
    const range = obj(entry, path + ".ranges." + index);
    const rangeType = str(range.type, path + ".ranges.type", 30);
    if (!["SEMVER", "ECOSYSTEM", "GIT"].includes(rangeType))
      fail("Unsupported OSV range type.");
    const events = array(range.events, path + ".ranges.events", 200);
    if (!events.length) fail("Empty OSV range events.");
    for (const event of events) {
      const e = obj(event, path + ".ranges.event");
      if (Object.keys(e).filter(key =>
        ["introduced", "fixed", "last_affected", "limit"].includes(key))
        .length !== 1)
        fail("OSV range events require one boundary field.");
    }
  }
  if (!versions.length && !ranges.length)
    fail("OSV affected entry has no version or range evidence.");
  return {
    package: { ecosystem, name, purl },
    versions, rangesPresent: ranges.length > 0,
  };
}
export function parseOsvRecord(raw: unknown, position: number): OsvRecord {
  const input = obj(raw, "records." + position);
  const id = str(input.id, "id", 120);
  if (!ID.test(id))
    fail("OSV identifier contains unsupported characters.");
  const modified = iso(input.modified, "modified");
  const published = optionalIso(input.published, "published");
  const withdrawn = optionalIso(input.withdrawn, "withdrawn");
  const aliasesRaw = input.aliases === undefined ? [] :
    array(input.aliases, "aliases", 40);
  const aliases = aliasesRaw.map((x, i) =>
    str(x, "aliases." + i, 120));
  if (new Set(aliases).size !== aliases.length)
    fail("OSV record contains duplicate aliases.");
  const affectedRaw = input.affected === undefined ? [] :
    array(input.affected, "affected", MAX_AFFECTED);
  if (!affectedRaw.length)
    fail("OSV record must identify at least one affected package.");
  const affected = affectedRaw.map((x, i) =>
    parseOsvAffected(x, "affected." + i));
  return { id, modified, published, withdrawn, aliases, affected };
}
export function parseOsvFeed(input: unknown): OsvFeed {
  const objFeed = obj(input, "feed");
  if (Object.keys(objFeed).some(key => ![
    "sourceLabel", "sourceVersion", "retrievedAt", "records",
  ].includes(key)))
    fail("Unknown OSV feed metadata.");
  const sourceLabel = str(objFeed.sourceLabel, "sourceLabel", 120);
  const sourceVersion = str(objFeed.sourceVersion, "sourceVersion", 100);
  const retrievedAt = iso(objFeed.retrievedAt, "retrievedAt");
  const rawRecords = array(objFeed.records, "records", MAX_RECORDS);
  if (!rawRecords.length)
    fail("OSV snapshot cannot be empty; empty feeds never prove security.");
  const records = rawRecords.map((value, index) =>
    parseOsvRecord(value, index));
  const seen = new Set<string>();
  for (const entry of records) {
    if (seen.has(entry.id))
      fail("Duplicate OSV identifier in feed.");
    seen.add(entry.id);
  }
  const stable = [...records].sort((a, b) => a.id.localeCompare(b.id));
  const canonical = {
    schema: "cyberpilot.assets.osv.snapshot.v1" as const,
    source: "USER_SUPPLIED_OSV_EXPORT" as const,
    sourceLabel, sourceVersion, retrievedAt,
    recordCount: records.length,
    withdrawnCount: records.filter(x => Boolean(x.withdrawn)).length,
    affectedPackages: records.reduce((count, x) =>
      count + x.affected.length, 0),
    rangeOnlyCount: records.filter(x => x.affected.some(a =>
      a.rangesPresent && a.versions.length === 0)).length,
    records: stable,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      "OSV-shaped records are user-provided; ingestion does not authenticate the upstream source.",
      "Withdrawn advisories are excluded from positive matches and reported separately.",
      "Only enumerated affected versions are evaluated; ranges are not interpreted.",
      "A match identifies a possible package/advisory association, not confirmed endpoint exposure.",
      "Absence of a match does not establish an absence of vulnerabilities.",
      "No external request or network scan is made.",
    ],
  };
}
export function parsePackageBindings(input: unknown): PackageBinding[] {
  const list = array(input, "packageBindings", MAX_BINDINGS);
  const seen = new Set<string>();
  return list.map((item, index) => {
    const binding = obj(item, "packageBindings." + index);
    if (Object.keys(binding).some(key => ![
      "inventoryProduct", "ecosystem", "packageName", "expectedPurl",
    ].includes(key)))
      fail("Unknown package binding field.");
    const inventoryProduct = str(binding.inventoryProduct,
      "inventoryProduct", 160);
    const ecosystem = str(binding.ecosystem, "ecosystem", 70);
    const packageName = str(binding.packageName, "packageName", 160);
    const expectedPurl = maybe(binding.expectedPurl, "expectedPurl", 255);
    if (expectedPurl && !VALID_PURL.test(expectedPurl))
      fail("Invalid binding purl.");
    const key = normalizeInventoryProduct(inventoryProduct);
    if (seen.has(key))
      fail("Ambiguous package bindings for one inventory product.");
    seen.add(key);
    return { inventoryProduct, ecosystem, packageName, expectedPurl };
  });
}
function orderedAdvisories(items: string[]): string[] {
  return [...new Set(items)].sort();
}
function entryMatchesBinding(
  affected: OsvAffected, binding: PackageBinding,
): boolean {
  if (osvPackageKey(affected.package.ecosystem, affected.package.name) !==
      osvPackageKey(binding.ecosystem, binding.packageName))
    return false;
  if (binding.expectedPurl &&
      affected.package.purl !== binding.expectedPurl)
    return false;
  return true;
}
export function correlateOsvRow(
  row: OsvCandidateInput, feed: OsvFeed,
  bindings: PackageBinding[],
): OsvCandidate {
  const binding = bindings.find(item =>
    normalizeInventoryProduct(item.inventoryProduct) ===
      row.normalizedProductKey);
  const matched: string[] = [];
  const withdrawn: string[] = [];
  const unresolved: string[] = [];
  if (binding) {
    for (const record of feed.records) {
      for (const affected of record.affected) {
        if (!entryMatchesBinding(affected, binding)) continue;
        if (record.withdrawn) {
          withdrawn.push(record.id);
          continue;
        }
        if (affected.rangesPresent) unresolved.push(record.id);
        if (row.versionStatus === "EXACT" && row.softwareVersion &&
            affected.versions.includes(row.softwareVersion))
          matched.push(record.id);
      }
    }
  }
  const possibleAdvisoryIds = orderedAdvisories(matched);
  const withdrawnIds = orderedAdvisories(withdrawn);
  const unresolvedRangeIds = orderedAdvisories(unresolved);
  let category: CandidateClassification;
  let reason: string;
  if (!binding) {
    category = "UNMAPPED_PRODUCT";
    reason = "No explicit ecosystem/package binding was provided for this inventory product.";
  } else if (row.versionStatus !== "EXACT" || !row.softwareVersion) {
    category = "UNKNOWN_VERSION";
    reason = "The declared package version is absent or ambiguous.";
  } else if (possibleAdvisoryIds.length) {
    category = "EXACT_AFFECTED_VERSION";
    reason = "An explicitly mapped package has this version in an OSV affected.versions enumeration.";
  } else if (unresolvedRangeIds.length) {
    category = "RANGES_UNEVALUATED";
    reason = "Affected version ranges exist but are not evaluated by this conservative engine.";
  } else if (withdrawnIds.length) {
    category = "WITHDRAWN_RECORD";
    reason = "Matching advisory identities were withdrawn and cannot establish an active association.";
  } else {
    category = "NO_EXACT_VERSION_MATCH";
    reason = "No exact enumerated version match within the supplied snapshot; not a safety guarantee.";
  }
  const canonical = {
    externalId: row.externalId,
    softwareName: row.softwareName,
    version: row.softwareVersion,
    ecosystem: binding?.ecosystem ?? null,
    packageName: binding?.packageName ?? null,
    sourceRow: row.sourceRow, category,
    possibleAdvisoryIds, withdrawnIds, unresolvedRangeIds,
    feedDigest: feed.digest,
    certainty: category === "EXACT_AFFECTED_VERSION" ?
      "DECLARED_EXACT_ASSOCIATION" as const : "UNKNOWN" as const,
    reason,
  };
  return { ...canonical, fingerprint: hash(canonical) };
}
export function summarizeOsvCandidates(
  rows: OsvCandidate[],
): CandidateSummary {
  const counts = Object.fromEntries(classification.map(code => [code, 0])) as
    Record<CandidateClassification, number>;
  for (const row of rows) counts[row.category]++;
  return {
    totalRows: rows.length,
    mappedRows: rows.filter(x => x.ecosystem !== null).length,
    unmappedRows: counts.UNMAPPED_PRODUCT,
    unknownVersions: counts.UNKNOWN_VERSION,
    possibleAssociations: counts.EXACT_AFFECTED_VERSION,
    unresolvedRanges: rows.filter(x => x.unresolvedRangeIds.length > 0).length,
    withdrawnRecords: rows.filter(x => x.withdrawnIds.length > 0).length,
    noExactMatches: counts.NO_EXACT_VERSION_MATCH,
    byClassification: counts,
  };
}
export type OsvCandidateReport = {
  schema: "cyberpilot.assets.osv.candidates.v1";
  organizationId: string;
  importId: string;
  generatedAt: string;
  source: "USER_SUPPLIED_OSV_EXPORT";
  feed: Pick<OsvFeed,
    "sourceLabel" | "sourceVersion" | "retrievedAt" |
    "recordCount" | "withdrawnCount" | "digest">;
  bindingCount: number;
  totalRows: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  complete: boolean;
  summary: CandidateSummary;
  candidates: OsvCandidate[];
  digest: string;
  warnings: string[];
};
export function buildOsvCandidateReport(
  organizationId: string, importId: string,
  observations: OsvCandidateInput[], feed: OsvFeed,
  bindings: PackageBinding[], offset: number,
  limit: number, now: Date,
): OsvCandidateReport {
  const candidates = observations.map(row =>
    correlateOsvRow(row, feed, bindings))
    .sort((a, b) => a.externalId.localeCompare(b.externalId) ||
      a.softwareName.localeCompare(b.softwareName) ||
      a.sourceRow - b.sourceRow);
  const summary = summarizeOsvCandidates(candidates);
  const visible = candidates.slice(offset, offset + limit);
  const canonical = {
    schema: "cyberpilot.assets.osv.candidates.v1" as const,
    organizationId, importId, generatedAt: now.toISOString(),
    source: "USER_SUPPLIED_OSV_EXPORT" as const,
    feed: {
      sourceLabel: feed.sourceLabel, sourceVersion: feed.sourceVersion,
      retrievedAt: feed.retrievedAt, recordCount: feed.recordCount,
      withdrawnCount: feed.withdrawnCount, digest: feed.digest,
    },
    bindingCount: bindings.length, totalRows: candidates.length,
    offset, limit, hasMore: offset + visible.length < candidates.length,
    complete: offset === 0 && visible.length === candidates.length,
    summary, candidates: visible,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      ...feed.warnings,
      "Inventory values and package bindings are customer declarations.",
      "Only exact enumerated versions of explicitly bound packages are matched.",
      "The report does not persist findings, modify evidence or change CyberScore.",
      "The summary spans all examined import rows; candidate records are paginated.",
    ],
  };
}
