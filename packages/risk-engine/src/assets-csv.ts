/** Offline CSV asset inventory. This module does not probe endpoints or identify verified vulnerabilities. */
export type AssetKind = "SERVER" | "WORKSTATION" | "LAPTOP" | "MOBILE" | "NETWORK" | "IOT" | "CLOUD" | "OTHER";
export type AssetRecord = {
  assetId: string; kind: AssetKind; hostname: string; owner: string; os: string;
  osVersion: string; ip: string; criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  location: string; lifecycle: "ACTIVE" | "RETIRED" | "UNKNOWN";
};
export const ASSET_COLUMNS = ["assetId", "kind", "hostname", "owner", "os", "osVersion", "ip", "criticality", "location", "lifecycle"] as const;
export type AssetImportIssue = { row: number; code: string; field?: string };
export type AssetImportResult = { records: AssetRecord[]; issues: AssetImportIssue[]; rejectedRows: number; duplicateIds: string[] };
function csvRows(input: string): string[][] | null {
  const rows: string[][] = []; let row: string[] = []; let field = ""; let quoted = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i]!;
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') { field += '"'; i++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field === "") quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (char === "\r") { if (input[i + 1] !== "\n") { row.push(field); rows.push(row); row = []; field = ""; } }
    else if (char === '"') return null;
    else field += char;
  }
  if (quoted) return null;
  if (row.length || field.length) { row.push(field); rows.push(row); }
  return rows;
}
const kinds = new Set<AssetKind>(["SERVER","WORKSTATION","LAPTOP","MOBILE","NETWORK","IOT","CLOUD","OTHER"]);
const criticalities = new Set<AssetRecord["criticality"]>(["LOW","MEDIUM","HIGH","CRITICAL"]);
const lifecycles = new Set<AssetRecord["lifecycle"]>(["ACTIVE","RETIRED","UNKNOWN"]);
export function parseAssetCsv(csv: string, maxRows = 10000): AssetImportResult {
  const empty = (): AssetImportResult => ({ records: [], issues: [], rejectedRows: 0, duplicateIds: [] });
  const result = empty();
  if (csv.length > 5_000_000) { result.issues.push({row: 0,code:"FILE_TOO_LARGE"}); return result; }
  const rows = csvRows(csv);
  if (!rows || rows.length === 0) { result.issues.push({row: 0,code:"INVALID_CSV"}); return result; }
  if (rows[0]!.join(",") !== ASSET_COLUMNS.join(",")) { result.issues.push({row: 1,code:"INVALID_HEADER"}); return result; }
  if (rows.length - 1 > maxRows) { result.issues.push({row: 0,code:"TOO_MANY_ROWS"}); return result; }
  const seen = new Set<string>();
  for (let i = 1; i < rows.length; i++) {
    const fields = rows[i]!;
    if (fields.length === 1 && fields[0] === "") continue;
    if (fields.length !== ASSET_COLUMNS.length) { result.issues.push({row:i+1,code:"COLUMN_COUNT"}); result.rejectedRows++; continue; }
    const values = Object.fromEntries(ASSET_COLUMNS.map((column,j) => [column,fields[j]!.trim()])) as Record<typeof ASSET_COLUMNS[number],string>;
    if (!values.assetId || values.assetId.length > 128 || !/^[a-z0-9._:-]+$/i.test(values.assetId)) { result.issues.push({row:i+1,code:"INVALID_ID",field:"assetId"}); result.rejectedRows++; continue; }
    if (seen.has(values.assetId.toLowerCase())) { result.issues.push({row:i+1,code:"DUPLICATE_ID",field:"assetId"}); result.duplicateIds.push(values.assetId); result.rejectedRows++; continue; }
    if (!kinds.has(values.kind as AssetKind) || !criticalities.has(values.criticality as AssetRecord["criticality"]) || !lifecycles.has(values.lifecycle as AssetRecord["lifecycle"])) {
      result.issues.push({row:i+1,code:"INVALID_ENUM"}); result.rejectedRows++; continue;
    }
    if ([values.hostname,values.owner,values.os,values.osVersion,values.ip,values.location].some((value) => value.length > 512)) {
      result.issues.push({row:i+1,code:"FIELD_TOO_LONG"}); result.rejectedRows++; continue;
    }
    seen.add(values.assetId.toLowerCase());
    result.records.push(values as AssetRecord);
  }
  return result;
}
