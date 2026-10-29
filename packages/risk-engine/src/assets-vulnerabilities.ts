/** Offline matching of externally supplied vulnerability advisories to declared asset software.
 * A match is only a CANDIDATE, never verified exploitability or a confirmed CVE.
 */
import type { AssetRecord } from "./assets-csv";
export type VulnerabilityAdvisory = {
  advisoryId: string; product: string; version: string; severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; reference?: string;
};
export type VulnerabilityCandidate = { assetId: string; advisoryId: string; severity: VulnerabilityAdvisory["severity"]; state: "CANDIDATE"; source: "DECLARED"; reference: string | null };
export function matchDeclaredVulnerabilities(
  assets: readonly AssetRecord[], advisories: readonly VulnerabilityAdvisory[],
): VulnerabilityCandidate[] {
  const candidates: VulnerabilityCandidate[] = [];
  const seen = new Set<string>();
  for (const asset of assets) {
    if (asset.lifecycle === "RETIRED" || !asset.os.trim() || !asset.osVersion.trim()) continue;
    for (const advisory of advisories) {
      if (!advisory.advisoryId.trim() || !advisory.product.trim() || !advisory.version.trim()) continue;
      if (asset.os.trim().toLowerCase() !== advisory.product.trim().toLowerCase() ||
          asset.osVersion.trim().toLowerCase() !== advisory.version.trim().toLowerCase()) continue;
      const key = asset.assetId.toLowerCase() + "\u0000" + advisory.advisoryId.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ assetId:asset.assetId,advisoryId:advisory.advisoryId,severity:advisory.severity,state:"CANDIDATE",source:"DECLARED",reference:advisory.reference ?? null });
    }
  }
  return candidates;
}
