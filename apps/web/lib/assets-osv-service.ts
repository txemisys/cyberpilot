import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import {
  parseOsvFeed, parsePackageBindings, buildOsvCandidateReport,
} from "./assets-osv-correlation";
import type {
  OsvCandidateInput, OsvCandidateReport,
} from "./assets-osv-correlation";
import type { AssetScope } from "./assets-inventory-service";

export type OsvRequest = {
  importId: string;
  feed: unknown;
  packageBindings: unknown;
  offset: number;
  limit: number;
};
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected OSV correlation request.");
  return value as Record<string, unknown>;
}
function bounded(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid OSV " + label + ".");
  return value;
}
export function parseOsvRequest(input: unknown): OsvRequest {
  const raw = record(input);
  if (Object.keys(raw).some(key => ![
    "importId", "feed", "packageBindings", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown OSV correlation field.");
  if (!raw.feed || typeof raw.feed !== "object")
    throw new WorkInputError("INVALID", "An OSV export is required.");
  if (!Array.isArray(raw.packageBindings))
    throw new WorkInputError("INVALID", "Explicit package bindings are required.");
  return {
    importId: parseWorkId(raw.importId, "inventory import ID"),
    feed: raw.feed,
    packageBindings: raw.packageBindings,
    offset: bounded(raw.offset ?? 0, "offset", 0, 1000000),
    limit: bounded(raw.limit ?? 50, "limit", 1, 100),
  };
}
export type OsvReportMetadata = {
  importId: string;
  importState: string;
  importCreatedAt: string;
  inventoryObservations: number;
  importSource: string;
  feedProvenance: "DECLARED_NOT_AUTHENTICATED";
  report: OsvCandidateReport;
};
/**
 * Read-only; no remote fetch, API keys or database writes.
 * The client supplies the OSV-shaped records and explicit package bindings.
 * We validate the complete payload before reading the selected tenant's data.
 */
export async function inspectOsvInventoryCandidates(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvReportMetadata> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV candidate inspection requires inventory access.");
  const request = parseOsvRequest(input);
  const feed = parseOsvFeed(request.feed);
  const bindings = parsePackageBindings(request.packageBindings);
  if (!Number.isFinite(now.getTime()))
    throw new WorkInputError("INVALID", "Invalid evaluation timestamp.");
  const current = await db.assetInventoryImport.findFirst({
    where: {
      id: request.importId,
      organizationId: scope.organizationId,
    },
    select: {
      id: true, state: true, sourceLabel: true,
      importedCount: true, createdAt: true,
    },
  });
  if (!current)
    throw new WorkInputError("MISSING", "Inventory snapshot not found.");
  if (current.importedCount > 10000)
    throw new WorkInputError("CONFLICT", "Inventory exceeds bounded OSV inspection.");
  const devices = await db.assetInventoryDevice.findMany({
    where: {
      organizationId: scope.organizationId,
      importId: current.id,
    },
    select: {
      externalId: true, softwareName: true, softwareVersion: true,
      versionStatus: true, normalizedProductKey: true,
      observedAt: true, sourceRow: true,
    },
    take: 10001,
    orderBy: [{ externalId: "asc" }, { sourceRow: "asc" }],
  });
  if (devices.length > 10000 ||
      devices.length !== current.importedCount)
    throw new WorkInputError("CONFLICT",
      "Persisted inventory row coverage is incomplete.");
  const observations: OsvCandidateInput[] = devices;
  const report = buildOsvCandidateReport(
    scope.organizationId, current.id, observations,
    feed, bindings, request.offset, request.limit, now,
  );
  return {
    importId: current.id,
    importState: current.state,
    importCreatedAt: current.createdAt.toISOString(),
    inventoryObservations: devices.length,
    importSource: current.sourceLabel,
    feedProvenance: "DECLARED_NOT_AUTHENTICATED",
    report,
  };
}

/**
 * Compare OSV outcomes without assuming that an omitted record is fixed,
 * removed or no longer exploitable. This is useful for analyst review.
 */
export type OsvComparisonCategory =
  "NEW_ASSOCIATION" | "NO_LONGER_LISTED" | "UNCHANGED_ASSOCIATION" |
  "CHANGED_INTERPRETATION" | "UNKNOWN";
export type OsvOutcomeDiff = {
  key: string;
  externalId: string;
  softwareName: string;
  previousCategory: string | null;
  currentCategory: string | null;
  previousAdvisoryIds: string[];
  currentAdvisoryIds: string[];
  category: OsvComparisonCategory;
  explanation: string;
};
function comparisonKey(row: OsvCandidateReport["candidates"][number]): string {
  return row.externalId + "\u0000" + row.softwareName;
}
function equalIds(a: string[], b: string[]) {
  return a.length === b.length &&
    [...a].sort().every((value, i) => value === [...b].sort()[i]);
}
export function compareOsvCandidateReports(
  previous: OsvCandidateReport, current: OsvCandidateReport,
): OsvOutcomeDiff[] {
  if (previous.organizationId !== current.organizationId ||
      previous.importId !== current.importId)
    throw new WorkInputError("INVALID",
      "Different tenant or inventory snapshots cannot be compared.");
  if (!previous.complete || !current.complete)
    throw new WorkInputError("INVALID",
      "Both OSV report snapshots must be complete before comparing.");
  const a = new Map(previous.candidates.map(row => [comparisonKey(row), row]));
  const b = new Map(current.candidates.map(row => [comparisonKey(row), row]));
  const keys = [...new Set([...a.keys(), ...b.keys()])].sort();
  return keys.map(key => {
    const old = a.get(key), newer = b.get(key);
    const prior = old?.possibleAdvisoryIds ?? [];
    const next = newer?.possibleAdvisoryIds ?? [];
    let category: OsvComparisonCategory = "UNKNOWN";
    let explanation = "An incomplete or unrecognized mapping prevents classification.";
    if (old && newer) {
      if (old.category !== newer.category)
        category = "CHANGED_INTERPRETATION";
      else if (equalIds(prior, next))
        category = "UNCHANGED_ASSOCIATION";
      else if (next.some(id => !prior.includes(id)))
        category = "NEW_ASSOCIATION";
      else
        category = "NO_LONGER_LISTED";
    }
    if (category === "NEW_ASSOCIATION")
      explanation = "New possible association in the supplied OSV export; not proof of exploitation.";
    else if (category === "NO_LONGER_LISTED")
      explanation = "Previously associated IDs are not listed now; not proof of remediation.";
    else if (category === "UNCHANGED_ASSOCIATION")
      explanation = "The same possible IDs are declared; device and advisory coverage remain unverified.";
    else if (category === "CHANGED_INTERPRETATION")
      explanation = "Evidence interpretation changed; inspect upstream records, version and mappings.";
    return {
      key, externalId: (newer ?? old)!.externalId,
      softwareName: (newer ?? old)!.softwareName,
      previousCategory: old?.category ?? null,
      currentCategory: newer?.category ?? null,
      previousAdvisoryIds: prior, currentAdvisoryIds: next,
      category, explanation,
    };
  });
}
