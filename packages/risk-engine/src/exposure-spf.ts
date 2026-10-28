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
