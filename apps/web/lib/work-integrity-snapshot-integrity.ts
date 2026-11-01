import { createHash } from "node:crypto";
import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";

export type SnapshotManifestEntry = {
  source: string;
  capturedAt: string;
  sha256: string;
  caseCount: number;
  complete: boolean;
};
export type SnapshotManifest = {
  version: 1;
  organizationId: string;
  generatedAt: string;
  entries: SnapshotManifestEntry[];
  rootSha256: string;
  limitations: string[];
};
export type ManifestVerification = {
  organizationId: string;
  verified: boolean;
  missing: string[];
  unexpected: string[];
  modified: string[];
  warnings: string[];
};
function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const object = value as Record<string, unknown>;
  return "{" + Object.keys(object).sort().map(key =>
    JSON.stringify(key) + ":" + canonical(object[key])).join(",") + "}";
}
function identity(entry: { source: string; capturedAt: string }): string {
  return JSON.stringify([entry.source, Date.parse(entry.capturedAt)]);
}
function normalized(capture: CaseSnapshot): CaseSnapshot {
  return { ...capture, capturedAt: new Date(capture.capturedAt).toISOString(),
    cases: [...capture.cases].sort((a, b) => a.key.localeCompare(b.key)) };
}
export function buildSnapshotManifest(
  input: readonly unknown[], organizationId: string, generatedAt: string,
): SnapshotManifest {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (!Number.isFinite(Date.parse(generatedAt)))
    throw new Error("Invalid manifest generation time.");
  if (input.length > 10000) throw new Error("Manifest exceeds capture limit.");
  const seen = new Set<string>();
  const entries = input.map(value => {
    const capture = parseCaseSnapshot(value);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization manifest is forbidden.");
    const key = identity(capture);
    if (seen.has(key)) throw new Error("Duplicate manifest capture identity.");
    seen.add(key);
    return {
      source: capture.source,
      capturedAt: new Date(capture.capturedAt).toISOString(),
      sha256: sha256(canonical(normalized(capture))),
      caseCount: capture.cases.length,
      complete: capture.complete,
    };
  }).sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
  return {
    version: 1, organizationId, generatedAt: new Date(generatedAt).toISOString(),
    entries, rootSha256: sha256(canonical({ organizationId, entries })),
    limitations: [
      "Hashes detect differences relative to a trusted stored manifest, but cannot authenticate an untrusted original.",
      "This manifest is not digitally signed and does not independently establish who created the snapshots.",
      "Content integrity does not prove security effectiveness or complete organizational coverage.",
    ],
  };
}
export function verifySnapshotManifest(
  manifest: SnapshotManifest, input: readonly unknown[],
): ManifestVerification {
  if (manifest.version !== 1 || !manifest.organizationId)
    throw new Error("Unsupported snapshot manifest.");
  const actual = buildSnapshotManifest(input, manifest.organizationId, manifest.generatedAt);
  const expected = new Map<string, SnapshotManifestEntry>();
  for (const entry of manifest.entries) {
    const key = identity(entry);
    if (expected.has(key)) throw new Error("Duplicate expected manifest identity.");
    expected.set(key, entry);
  }
  const actualEntries = new Map(actual.entries.map(entry => [identity(entry), entry]));
  const missing: string[] = [];
  const unexpected: string[] = [];
  const modified: string[] = [];
  for (const [key, entry] of expected) {
    const found = actualEntries.get(key);
    if (!found) missing.push(key);
    else if (entry.sha256 !== found.sha256 ||
      entry.caseCount !== found.caseCount || entry.complete !== found.complete)
      modified.push(key);
  }
  for (const key of actualEntries.keys()) if (!expected.has(key)) unexpected.push(key);
  const expectedRoot = sha256(canonical({
    organizationId: manifest.organizationId, entries: [...manifest.entries].sort(
      (a, b) => a.source.localeCompare(b.source) || a.capturedAt.localeCompare(b.capturedAt)),
  }));
  const rootMatches = expectedRoot === manifest.rootSha256;
  return {
    organizationId: manifest.organizationId,
    verified: rootMatches && missing.length === 0 && unexpected.length === 0 && modified.length === 0,
    missing, unexpected, modified,
    warnings: [
      ...(!rootMatches ? ["Manifest root digest does not match its entries."] : []),
      "Successful verification only proves consistency against the supplied manifest, not authenticity.",
    ],
  };
}
