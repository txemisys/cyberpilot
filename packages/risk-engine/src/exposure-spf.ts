/** Passive SPF inventory from already-collected DNS TXT strings; no network requests. */
export type SpfRecordInventory = {
  status: "MISSING" | "PRESENT" | "MULTIPLE";
  records: string[];
};

export function inventorySpfTxtRecords(txtRecords: readonly string[]): SpfRecordInventory {
  const records = txtRecords.filter((record) => /^v=spf1(?:\s|$)/i.test(record.trim()));
  return {
    status: records.length === 0 ? "MISSING" : records.length === 1 ? "PRESENT" : "MULTIPLE",
    records,
  };
}

/** Extract the explicit SPF all mechanism only for a single SPF record.
 * null means absent or ambiguous; it does not represent SPF pass/fail.
 */
export function extractSpfAllQualifier(txtRecords: readonly string[]): "pass" | "fail" | "softfail" | "neutral" | null {
  const inventory = inventorySpfTxtRecords(txtRecords);
  if (inventory.status !== "PRESENT") return null;
  const tokens = inventory.records[0]!.trim().split(/\s+/).slice(1);
  const all = tokens.filter((token) => /^[+~?-]?all$/i.test(token));
  if (all.length !== 1) return null;
  const token = all[0]!.toLowerCase();
  if (token === "-all") return "fail";
  if (token === "~all") return "softfail";
  if (token === "?all") return "neutral";
  return "pass";
}
