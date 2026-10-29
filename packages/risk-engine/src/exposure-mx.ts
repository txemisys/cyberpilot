/** Read-only MX inventory using DNS answers supplied by a trusted caller. No DNS lookups. */
export type MxRecord = { priority: number; exchange: string };
export type MxInventory = {
  status: "MISSING" | "PRESENT" | "INVALID";
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
  // RFC 7505: a null MX is valid only as the sole MX with preference zero.
  if (records.some((record) => record.exchange === ".") &&
      (records.length !== 1 || records[0]!.priority !== 0)) {
    return { status: "INVALID", records: [] };
  }
  return { status: records.length === 0 ? "MISSING" : "PRESENT", records: [...records] };
}
