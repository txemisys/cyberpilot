/** Offline inventory hygiene checks; observations are DECLARED, not verified scans. */
import type { AssetRecord } from "./assets-csv";
export type AssetFinding = { assetId: string; code: string; severity: "INFO" | "LOW" | "MEDIUM" | "HIGH"; source: "DECLARED"; detail: string };
export const ASSET_HYGIENE_RULES = [
  ["MISSING_HOSTNAME","hostname","MEDIUM"],
  ["MISSING_OWNER","owner","MEDIUM"],
  ["MISSING_OS","os","LOW"],
  ["MISSING_OS_VERSION","osVersion","LOW"],
  ["MISSING_IP","ip","INFO"],
  ["MISSING_LOCATION","location","INFO"],
] as const;
/** Produces actionable data-quality warnings, never unsupported CVE claims. */
export function assessAssetInventory(records: readonly AssetRecord[]): AssetFinding[] {
  const findings: AssetFinding[] = [];
  for (const asset of records) {
    if (asset.lifecycle === "RETIRED") continue;
    for (const [code, field, severity] of ASSET_HYGIENE_RULES) {
      if (!asset[field].trim()) findings.push({assetId:asset.assetId,code,severity,source:"DECLARED",detail:field});
    }
    if (asset.lifecycle === "UNKNOWN") findings.push({assetId:asset.assetId,code:"UNKNOWN_LIFECYCLE",severity:"MEDIUM",source:"DECLARED",detail:"lifecycle"});
    if (asset.criticality === "CRITICAL" && !asset.owner.trim()) findings.push({assetId:asset.assetId,code:"CRITICAL_ASSET_WITHOUT_OWNER",severity:"HIGH",source:"DECLARED",detail:"owner"});
  }
  return findings;
}
export type AssetInventorySummary = { total: number; active: number; retired: number; unknownLifecycle: number; withoutOwner: number; critical: number; byKind: Record<string,number> };
export function summarizeAssetInventory(records: readonly AssetRecord[]): AssetInventorySummary {
  const byKind: Record<string,number> = {};
  for (const asset of records) byKind[asset.kind] = (byKind[asset.kind] ?? 0) + 1;
  return {
    total:records.length,
    active:records.filter(x=>x.lifecycle==="ACTIVE").length,
    retired:records.filter(x=>x.lifecycle==="RETIRED").length,
    unknownLifecycle:records.filter(x=>x.lifecycle==="UNKNOWN").length,
    withoutOwner:records.filter(x=>!x.owner.trim()).length,
    critical:records.filter(x=>x.criticality==="CRITICAL").length,
    byKind,
  };
}
