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
