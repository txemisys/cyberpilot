import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";
import { normalizeInventoryProduct } from "./assets-csv-inventory";
import { parsePackageBindings } from "./assets-osv-correlation";
import type { PackageBinding } from "./assets-osv-correlation";

/**
 * A customer-declared software row is NOT itself a finding. Only a
 * previously persisted, explicitly mapped provider inspection can produce
 * a candidate for human action. A missing row is never a positive safety
 * statement. No direct mutations of SecurityFinding or CyberScore.
 */
export type AssetAdviceStatus =
  "REVIEW_POSSIBLE_ADVISORY" | "REVIEW_PROVIDER_UNCERTAINTY" |
  "REVIEW_SOURCE_INTEGRITY" | "REVIEW_MISSING_MAPPING" |
  "REVIEW_UNKNOWN_VERSION" | "REVIEW_STALE_OBSERVATION" |
  "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION";
export type AssetAdvicePriority = "URGENT_REVIEW" | "NORMAL_REVIEW" | "INFORMATION";
export type AssetAdviceRow = {
  id: string;
  assetId: string;
  product: string;
  version: string | null;
  sourceRow: number;
  observedAt: string;
  normalizedProductKey: string;
  ecosystem: string | null;
  packageName: string | null;
  inspectionId: string;
  inspectionDigest: string;
  inventoryDigest: string;
  inspectionStatus: string;
  providerStatus: string | null;
  status: AssetAdviceStatus;
  priority: AssetAdvicePriority;
  possibleIds: string[];
  providerOnlyIds: string[];
  unresolvedIds: string[];
  withdrawnIds: string[];
  reasons: string[];
  actions: Array<{ code: string; title: string; instruction: string; requiresHumanReview: true }>;
  evidenceFingerprint: string;
  confidence: "DECLARED_POSSIBLE" | "UNKNOWN" | "NO_POSITIVE_MATCH_IN_SCOPE";
  notRemediationProof: true;
};
export type AssetAdviceSummary = {
  examined: number;
  possible: number;
  providerUncertain: number;
  sourceIntegrity: number;
  missingMappings: number;
  unknownVersions: number;
  staleObservations: number;
  scopedNoPositiveMatch: number;
  urgentReviews: number;
  normalReviews: number;
  informative: number;
  complete: boolean;
  byStatus: Record<AssetAdviceStatus, number>;
};
export type AssetAdviceInput = {
  importId: string;
  inspectionId: string;
  bindings: PackageBinding[];
  offset: number;
  limit: number;
  onlyReviewable: boolean;
  status: AssetAdviceStatus | null;
  maxObservationAgeDays: number;
};
export type AssetAdviceReport = {
  schema: "cyberpilot.assets.advice.preview.v1";
  organizationId: string;
  importId: string;
  inspectionId: string;
  evaluatedAt: string;
  inspectionDigest: string;
  inventoryDigest: string;
  totalRows: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  rows: AssetAdviceRow[];
  summary: AssetAdviceSummary;
  reportDigest: string;
  isReadOnly: true;
  changesCommitted: false;
  providerQueried: false;
  implications: string[];
};
export type AdviceDevice = {
  externalId: string; softwareName: string;
  softwareVersion: string | null;
  normalizedProductKey: string;
  versionStatus: string;
  freshnessStatus: string;
  observedAt: Date;
  sourceRow: number;
};
export type AdviceQuery = {
  ecosystem: string;
  packageName: string;
  version: string;
  providerStatus: string;
  possibleIds: unknown;
  providerOnlyIds: unknown;
  unresolvedIds: unknown;
  withdrawnIds: unknown;
};
export type AdviceSnapshot = {
  inspectionId: string;
  importId: string;
  inspectionDigest: string;
  inventoryDigest: string;
  inspectionStatus: string;
  inspectionCompletedAt: Date;
  importedCount: number;
  devices: AdviceDevice[];
  queries: AdviceQuery[];
};
export const ADVICE_STATUSES: AssetAdviceStatus[] = [
  "REVIEW_POSSIBLE_ADVISORY",
  "REVIEW_PROVIDER_UNCERTAINTY",
  "REVIEW_SOURCE_INTEGRITY",
  "REVIEW_MISSING_MAPPING",
  "REVIEW_UNKNOWN_VERSION",
  "REVIEW_STALE_OBSERVATION",
  "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION",
];
const sha = (input: unknown) =>
  createHash("sha256").update(JSON.stringify(input)).digest("hex");
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input))
    invalid("Asset advice input must be a JSON object.");
  return input as Record<string, unknown>;
}
function number(input: unknown, key: string, lo: number, hi: number) {
  if (typeof input !== "number" || !Number.isSafeInteger(input) ||
      input < lo || input > hi) invalid("Invalid asset advice " + key + ".");
  return input;
}
function id(input: unknown, label: string) {
  if (typeof input !== "string" ||
      !/^[a-zA-Z0-9_-]{5,150}$/.test(input))
    invalid("Invalid " + label + ".");
  return input;
}
export function parseAssetAdviceInput(input: unknown): AssetAdviceInput {
  const value = object(input);
  if (Object.keys(value).some(key => ![
    "importId", "inspectionId", "bindings", "offset", "limit",
    "onlyReviewable", "status", "maxObservationAgeDays",
  ].includes(key))) invalid("Unknown asset advice request field.");
  if (value.onlyReviewable !== undefined &&
      typeof value.onlyReviewable !== "boolean")
    invalid("onlyReviewable must be boolean.");
  const status = value.status ?? null;
  if (status !== null && !ADVICE_STATUSES.includes(
    status as AssetAdviceStatus)) invalid("Unknown asset advice category.");
  return {
    importId: id(value.importId, "import ID"),
    inspectionId: id(value.inspectionId, "inspection ID"),
    bindings: parsePackageBindings(value.bindings),
    offset: number(value.offset ?? 0, "offset", 0, 100000),
    limit: number(value.limit ?? 50, "limit", 1, 100),
    onlyReviewable: value.onlyReviewable === true,
    status: status as AssetAdviceStatus | null,
    maxObservationAgeDays: number(value.maxObservationAgeDays ?? 30,
      "observation age", 1, 365),
  };
}
function normalize(value: string) {
  return normalizeInventoryProduct(value);
}
function ids(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length > 100)
    throw new WorkInputError("CONFLICT",
      "Persisted " + label + " has invalid bounds.");
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._:+-]{1,119}$/.test(item))
      throw new WorkInputError("CONFLICT",
        "Persisted " + label + " has malformed advisory IDs.");
    if (!result.includes(item)) result.push(item);
  }
  return result.sort();
}
function action(code: string, title: string, instruction: string) {
  return { code, title, instruction, requiresHumanReview: true as const };
}
export function actionsForAssetAdvice(status: AssetAdviceStatus) {
  switch (status) {
    case "REVIEW_POSSIBLE_ADVISORY": return [
      action("VERIFY_INVENTORY", "Confirm software and version",
        "Check installed package and actual version on the affected endpoint using an authorized source."),
      action("REVIEW_UPSTREAM", "Review advisory and affected range",
        "Open the original advisory and evaluate applicability, ranges, fixed versions and withdrawal status."),
      action("PLAN_CHANGE", "Plan a validated change",
        "If applicability is confirmed, plan an approved update or mitigation; collect post-change evidence."),
      action("VERIFY_OUTCOME", "Re-evaluate independently",
        "Verify the change using new trustworthy evidence. Closing work does not prove remediation."),
    ];
    case "REVIEW_PROVIDER_UNCERTAINTY": return [
      action("CHECK_PROVIDER", "Investigate incomplete inspection",
        "Review persisted provider errors and partial pages; never conclude no vulnerability from missing results."),
      action("RECHECK_WITH_CONSENT", "Request an authorized reinspection",
        "Obtain explicit permission and ensure quotas and source freshness before a separate provider request."),
    ];
    case "REVIEW_SOURCE_INTEGRITY": return [
      action("CHECK_SOURCE", "Verify source integrity",
        "Confirm the inspection belongs to this inventory and its stored query records are internally consistent."),
      action("REBUILD_EVIDENCE", "Rebuild trusted evidence",
        "Reimport or reinspect with documented provenance; do not infer control effectiveness."),
    ];
    case "REVIEW_MISSING_MAPPING": return [
      action("MAP_PRODUCT", "Map declared product",
        "Confirm the software's ecosystem, canonical package name and optional PURL against its publisher."),
      action("REINSPECT", "Prepare package inspection",
        "Only after mapping is verified, plan an authorized provider request."),
    ];
    case "REVIEW_UNKNOWN_VERSION": return [
      action("CONFIRM_VERSION", "Obtain an exact installed version",
        "Collect version evidence for the declared endpoint; avoid inferring a version from the OS or hostname."),
    ];
    case "REVIEW_STALE_OBSERVATION": return [
      action("REFRESH_INVENTORY", "Refresh the dated observation",
        "Obtain a recent authorized inventory snapshot; a stale row cannot establish current exposure."),
    ];
    case "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION": return [
      action("RETAIN_SCOPE", "Record limited scope of no-match",
        "Preserve provider, query, package mapping, version and date; this is not evidence that the device is safe."),
    ];
  }
}
function decide(status: AssetAdviceStatus): {
  priority: AssetAdvicePriority;
  confidence: AssetAdviceRow["confidence"];
} {
  if (status === "REVIEW_POSSIBLE_ADVISORY")
    return { priority: "URGENT_REVIEW", confidence: "DECLARED_POSSIBLE" };
  if (status === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION")
    return { priority: "INFORMATION", confidence: "NO_POSITIVE_MATCH_IN_SCOPE" };
  return { priority: "NORMAL_REVIEW", confidence: "UNKNOWN" };
}
function matchKey(ecosystem: string, pkg: string, version: string) {
  return JSON.stringify([ecosystem.toLowerCase(), pkg.toLowerCase(),
    version]);
}
export function buildAssetAdviceRows(
  snapshot: AdviceSnapshot, bindings: PackageBinding[],
  ageDays: number, now: Date,
): AssetAdviceRow[] {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid asset advice evaluation time.");
  if (snapshot.importedCount !== snapshot.devices.length)
    throw new WorkInputError("CONFLICT",
      "Inventory count differs from the persisted snapshot; refuse partial analysis.");
  if (snapshot.devices.length > 10000 ||
      snapshot.queries.length > 10000)
    throw new WorkInputError("CONFLICT",
      "Persisted evidence exceeds bounded analysis capacity.");
  const mappings = new Map<string, PackageBinding>();
  for (const item of bindings) {
    const key = normalize(item.inventoryProduct);
    if (mappings.has(key))
      invalid("Duplicate normalized package binding.");
    mappings.set(key, item);
  }
  const queries = new Map<string, AdviceQuery>();
  for (const query of snapshot.queries) {
    const key = matchKey(query.ecosystem, query.packageName,
      query.version);
    if (queries.has(key))
      throw new WorkInputError("CONFLICT",
        "Duplicate package-version evidence in persisted inspection.");
    queries.set(key, query);
  }
  const seen = new Set<string>();
  const rows: AssetAdviceRow[] = [];
  for (const device of snapshot.devices) {
    const key = device.externalId + "\u0000" + device.normalizedProductKey;
    if (seen.has(key))
      throw new WorkInputError("CONFLICT",
        "Duplicate persisted device and software identity.");
    seen.add(key);
    const mapping = mappings.get(device.normalizedProductKey);
    const matching = mapping && device.softwareVersion ?
      queries.get(matchKey(mapping.ecosystem, mapping.packageName,
        device.softwareVersion)) : undefined;
    const possibleIds = matching ? ids(matching.possibleIds, "possibleIds") : [];
    const providerOnlyIds = matching ?
      ids(matching.providerOnlyIds, "providerOnlyIds") : [];
    const unresolvedIds = matching ?
      ids(matching.unresolvedIds, "unresolvedIds") : [];
    const withdrawnIds = matching ?
      ids(matching.withdrawnIds, "withdrawnIds") : [];
    const age = now.getTime() - device.observedAt.getTime();
    let status: AssetAdviceStatus;
    const reasons: string[] = [];
    if (snapshot.inspectionStatus !== "COMPLETE" ||
        snapshot.inspectionCompletedAt.getTime() > now.getTime()) {
      status = "REVIEW_SOURCE_INTEGRITY";
      reasons.push("The selected stored inspection is not a complete, time-valid source.");
    } else if (device.versionStatus !== "EXACT" ||
        !device.softwareVersion) {
      status = "REVIEW_UNKNOWN_VERSION";
      reasons.push("The customer has not provided a uniquely interpretable software version.");
    } else if (!mapping) {
      status = "REVIEW_MISSING_MAPPING";
      reasons.push("No explicit ecosystem/package mapping was supplied for this product.");
    } else if (!matching) {
      status = "REVIEW_PROVIDER_UNCERTAINTY";
      reasons.push("The historical inspection contains no matching package-version query.");
    } else if (matching.providerStatus !== "COMPLETE") {
      status = "REVIEW_PROVIDER_UNCERTAINTY";
      reasons.push("The historical provider package query was not fully completed.");
    } else if (possibleIds.length > 0) {
      status = "REVIEW_POSSIBLE_ADVISORY";
      reasons.push("The stored provider result includes advisory IDs associated with this declared package version.");
    } else if (unresolvedIds.length > 0 || providerOnlyIds.length > 0) {
      status = "REVIEW_PROVIDER_UNCERTAINTY";
      reasons.push("Provider-only or unresolved advisories require human interpretation.");
    } else if (age < 0 || age > ageDays * 86400000) {
      status = "REVIEW_STALE_OBSERVATION";
      reasons.push("The inventory observation is future-dated or exceeds the selected freshness threshold.");
    } else {
      status = "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION";
      reasons.push("No positive advisory ID was reported in this one bounded historical inspection.");
    }
    if (withdrawnIds.length)
      reasons.push("Withdrawn advisories were separately recorded; confirm current publisher status.");
    if (age < 0 || age > ageDays * 86400000)
      reasons.push("Inventory age limits confidence in current endpoint state.");
    reasons.push("All asset and software attributes originate from customer-supplied CSV.");
    const severity = decide(status);
    const canonical = {
      assetId: device.externalId, product: device.softwareName,
      normalizedProductKey: device.normalizedProductKey,
      version: device.softwareVersion, sourceRow: device.sourceRow,
      inspectionId: snapshot.inspectionId,
      inspectionDigest: snapshot.inspectionDigest,
      inventoryDigest: snapshot.inventoryDigest,
      mapping: mapping ? [mapping.ecosystem,
        mapping.packageName, mapping.expectedPurl] : null,
      query: matching ? [
        matching.providerStatus, possibleIds, providerOnlyIds,
        unresolvedIds, withdrawnIds,
      ] : null, observedAt: device.observedAt.toISOString(),
      status,
    };
    rows.push({
      id: sha(canonical).slice(0, 32),
      assetId: device.externalId, product: device.softwareName,
      version: device.softwareVersion, sourceRow: device.sourceRow,
      observedAt: device.observedAt.toISOString(),
      normalizedProductKey: device.normalizedProductKey,
      ecosystem: mapping?.ecosystem ?? null,
      packageName: mapping?.packageName ?? null,
      inspectionId: snapshot.inspectionId,
      inspectionDigest: snapshot.inspectionDigest,
      inventoryDigest: snapshot.inventoryDigest,
      inspectionStatus: snapshot.inspectionStatus,
      providerStatus: matching?.providerStatus ?? null,
      status, priority: severity.priority,
      possibleIds, providerOnlyIds, unresolvedIds, withdrawnIds,
      reasons, actions: actionsForAssetAdvice(status),
      evidenceFingerprint: sha(canonical),
      confidence: severity.confidence, notRemediationProof: true,
    });
  }
  return rows.sort((a, b) => {
    const rank = (x: AssetAdvicePriority) => x === "URGENT_REVIEW" ?
      0 : x === "NORMAL_REVIEW" ? 1 : 2;
    return rank(a.priority) - rank(b.priority) ||
      a.assetId.localeCompare(b.assetId) ||
      a.normalizedProductKey.localeCompare(b.normalizedProductKey);
  });
}
export function summarizeAssetAdvice(
  rows: AssetAdviceRow[], complete: boolean,
): AssetAdviceSummary {
  const byStatus = Object.fromEntries(ADVICE_STATUSES.map(status =>
    [status, rows.filter(row => row.status === status).length])
  ) as Record<AssetAdviceStatus, number>;
  return {
    examined: rows.length,
    possible: byStatus.REVIEW_POSSIBLE_ADVISORY,
    providerUncertain: byStatus.REVIEW_PROVIDER_UNCERTAINTY,
    sourceIntegrity: byStatus.REVIEW_SOURCE_INTEGRITY,
    missingMappings: byStatus.REVIEW_MISSING_MAPPING,
    unknownVersions: byStatus.REVIEW_UNKNOWN_VERSION,
    staleObservations: byStatus.REVIEW_STALE_OBSERVATION,
    scopedNoPositiveMatch:
      byStatus.NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION,
    urgentReviews: rows.filter(x => x.priority === "URGENT_REVIEW").length,
    normalReviews: rows.filter(x => x.priority === "NORMAL_REVIEW").length,
    informative: rows.filter(x => x.priority === "INFORMATION").length,
    complete, byStatus,
  };
}
export function buildAssetAdviceReport(
  organizationId: string, input: AssetAdviceInput,
  snapshot: AdviceSnapshot, now: Date,
): AssetAdviceReport {
  if (snapshot.importId !== input.importId ||
      snapshot.inspectionId !== input.inspectionId)
    throw new WorkInputError("CONFLICT",
      "Inspection and requested inventory are not associated.");
  const rows = buildAssetAdviceRows(snapshot, input.bindings,
    input.maxObservationAgeDays, now);
  const filtered = rows.filter(row =>
    (input.onlyReviewable ? row.priority !== "INFORMATION" : true) &&
    (input.status ? row.status === input.status : true));
  const visible = filtered.slice(input.offset,
    input.offset + input.limit);
  const canonical = {
    schema: "cyberpilot.assets.advice.preview.v1" as const,
    organizationId, importId: input.importId,
    inspectionId: input.inspectionId,
    evaluatedAt: now.toISOString(),
    inspectionDigest: snapshot.inspectionDigest,
    inventoryDigest: snapshot.inventoryDigest,
    totalRows: filtered.length, offset: input.offset,
    limit: input.limit,
    hasMore: input.offset + visible.length < filtered.length,
    rows: visible,
    summary: summarizeAssetAdvice(rows, true),
    isReadOnly: true as const, changesCommitted: false as const,
    providerQueried: false as const,
  };
  return { ...canonical, reportDigest: sha(canonical),
    implications: [
      "No endpoint vulnerability, exploitation, remediation, patch state or security assurance is inferred.",
      "Provider queries and customer declarations remain separate, bounded sources.",
      "An action checklist is a human review proposal, not a verified security finding.",
      "No security finding, CyberScore, remediation or work item has been changed.",
      "The overall summary covers all inventory rows; the displayed list can be filtered or paginated.",
    ],
  };
}
