/** Classifies already-collected _dmarc TXT answers; this never performs DNS lookups. */
export type DmarcRecordInventory = {
  status: "MISSING" | "PRESENT" | "MULTIPLE";
  records: string[];
};

export function inventoryDmarcTxtRecords(txtRecords: readonly string[]): DmarcRecordInventory {
  const records = txtRecords.filter((record) => /^v=dmarc1(?:\s*;|\s*$)/i.test(record.trim()));
  return {
    status: records.length === 0 ? "MISSING" : records.length === 1 ? "PRESENT" : "MULTIPLE",
    records,
  };
}

/** Extract only an unambiguous DMARC p= tag; this is not full policy validation. */
export function extractDmarcPolicy(txtRecords: readonly string[]): "none" | "quarantine" | "reject" | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((tag) => tag.trim());
  const policies = tags.filter((tag) => /^p\s*=/i.test(tag));
  if (policies.length !== 1) return null;
  const match = /^p\s*=\s*(none|quarantine|reject)\s*$/i.exec(policies[0]!);
  return match ? match[1]!.toLowerCase() as "none" | "quarantine" | "reject" : null;
}

/** Extract an explicit sp= policy; null means absent or ambiguous, not inherited. */
export function extractDmarcSubdomainPolicy(txtRecords: readonly string[]): "none" | "quarantine" | "reject" | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((tag) => tag.trim());
  const policies = tags.filter((tag) => /^sp\s*=/i.test(tag));
  if (policies.length !== 1) return null;
  const match = /^sp\s*=\s*(none|quarantine|reject)\s*$/i.exec(policies[0]!);
  return match ? match[1]!.toLowerCase() as "none" | "quarantine" | "reject" : null;
}

/** Returns an explicitly configured DMARC pct integer; null means absent or invalid. */
export function extractDmarcPercentage(txtRecords: readonly string[]): number | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((tag) => tag.trim());
  const values = tags.filter((tag) => /^pct\s*=/i.test(tag));
  if (values.length !== 1) return null;
  const match = /^pct\s*=\s*(\d{1,3})\s*$/i.exec(values[0]!);
  if (!match) return null;
  const value = Number(match[1]);
  return value <= 100 ? value : null;
}

/** Extract explicit DMARC alignment mode (strict or relaxed) from collected TXT. */
export function extractDmarcAlignment(
  txtRecords: readonly string[],
  tag: "adkim" | "aspf",
): "strict" | "relaxed" | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((part) => part.trim());
  const matches = tags.filter((part) => part.split("=")[0]?.trim().toLowerCase() === tag);
  if (matches.length !== 1) return null;
  const value = matches[0]!.split("=");
  if (value.length !== 2) return null;
  const mode = value[1]!.trim().toLowerCase();
  return mode === "s" ? "strict" : mode === "r" ? "relaxed" : null;
}

/** Extract raw aggregate-report destinations from an unambiguous rua tag.
 * Addresses are informational only; no messages or requests are sent.
 */
function extractDmarcMailtoUris(txtRecords: readonly string[], tag: "rua" | "ruf"): string[] | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((part) => part.trim());
  const values = tags.filter((part) => part.split("=")[0]?.trim().toLowerCase() === tag);
  if (values.length !== 1) return null;
  const pieces = values[0]!.split("=");
  if (pieces.length !== 2) return null;
  const uris = pieces[1]!.split(",").map((uri) => uri.trim());
  if (uris.length === 0 || uris.some((uri) => !/^mailto:[^\s@,]+@[^\s@,]+$/i.test(uri))) return null;
  return uris;
}

export function extractDmarcAggregateReportUris(txtRecords: readonly string[]): string[] | null {
  return extractDmarcMailtoUris(txtRecords, "rua");
}

/** Read explicit forensic report addresses, without contacting them. */
export function extractDmarcFailureReportUris(txtRecords: readonly string[]): string[] | null {
  return extractDmarcMailtoUris(txtRecords, "ruf");
}

/** Explicit DMARC failure-reporting options; null denotes missing or ambiguous input. */
export function extractDmarcFailureOptions(txtRecords: readonly string[]): string[] | null {
  const inventory = inventoryDmarcTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tags = inventory.records[0]!.split(";").slice(1).map((part) => part.trim());
  const values = tags.filter((part) => part.split("=")[0]?.trim().toLowerCase() === "fo");
  if (values.length !== 1) return null;
  const pieces = values[0]!.split("=");
  if (pieces.length !== 2) return null;
  const options = pieces[1]!.trim().split(":");
  if (options.some((option) => !["0", "1", "d", "s"].includes(option)) || new Set(options).size !== options.length) return null;
  return options;
}
