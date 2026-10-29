/** Passive DKIM TXT inventory at a caller-supplied selector hostname; no DNS lookups. */
export type DkimTxtInventory = {
  status: "MISSING" | "PRESENT" | "MULTIPLE";
  records: string[];
};

export function inventoryDkimTxtRecords(txtRecords: readonly string[]): DkimTxtInventory {
  const records = txtRecords.filter((record) => /^v=dkim1(?:\s*;|\s*$)/i.test(record.trim()));
  return {
    status: records.length === 0 ? "MISSING" : records.length === 1 ? "PRESENT" : "MULTIPLE",
    records,
  };
}
