/** Read-only MX inventory using DNS answers supplied by a trusted caller. No DNS lookups. */
export type MxRecord = { priority: number; exchange: string };
export type MxInventory = {
  status: "MISSING" | "PRESENT" | "NULL_MX" | "INVALID";
  records: MxRecord[];
};

/** Fail closed if any record is malformed instead of presenting partial data as valid. */
export function inventoryMxRecords(records: readonly MxRecord[]): MxInventory {
  if (records.some((record) =>
    !Number.isInteger(record.priority) ||
    record.priority < 0 ||
    record.priority > 65535 ||
    typeof record.exchange !== "string" ||
    (record.exchange !== "." && !/^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(record.exchange))
  )) return { status: "INVALID", records: [] };
  // Collapse identical answers while preserving the first representative.
  const seen = new Set<string>();
  const unique = records.filter((record) => {
    const key = JSON.stringify([record.priority, record.exchange.toLowerCase().replace(/\.$/, "")]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  // RFC 7505: a null MX is valid only as the sole MX with preference zero.
  if (records.some((record) => record.exchange === ".") &&
      (records.length !== 1 || records[0]!.priority !== 0)) {
    return { status: "INVALID", records: [] };
  }
  return { status: records.length === 0 ? "MISSING" : records[0]?.exchange === "." ? "NULL_MX" : "PRESENT", records: unique };
}

/** Descriptive summary only: DNS MX presence cannot prove that inbound mail works. */
export function summarizeMxRouting(records: readonly MxRecord[]): {
  status: MxInventory["status"];
  primaryExchanges: string[];
  backupExchanges: string[];
  distinctExchangeCount: number;
  lowestPreference: number | null;
} {
  const inventory = inventoryMxRecords(records);
  if (inventory.status !== "PRESENT") {
    return { status: inventory.status, primaryExchanges: [], backupExchanges: [], distinctExchangeCount: 0, lowestPreference: null };
  }
  const minimum = Math.min(...inventory.records.map((record) => record.priority));
  return {
    status: inventory.status,
    lowestPreference: minimum,
    primaryExchanges: inventory.records.filter((record) => record.priority === minimum).map((record) => record.exchange),
    backupExchanges: inventory.records.filter((record) => record.priority > minimum).map((record) => record.exchange),
    distinctExchangeCount: new Set(inventory.records.map((record) => record.exchange.toLowerCase().replace(/\.$/, ""))).size,
  };
}
