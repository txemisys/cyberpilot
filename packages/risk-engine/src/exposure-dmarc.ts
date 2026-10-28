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
