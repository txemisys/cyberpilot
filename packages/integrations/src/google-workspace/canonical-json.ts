import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Canonical JSON payload used by offline Google contracts and persisted
 * JSONB snapshots. PostgreSQL JSONB is free to reorder object keys: raw
 * JSON.stringify is not a stable evidence fingerprint across storage.
 */
export class CanonicalGoogleJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalGoogleJsonError";
  }
}
export function canonicalGoogleJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new CanonicalGoogleJsonError("Nonfinite JSON value.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > 50000)
      throw new CanonicalGoogleJsonError("Canonical array bound exceeded.");
    return "[" + value.map(v => canonicalGoogleJson(v)).join(",") + "]";
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length > 20000)
      throw new CanonicalGoogleJsonError("Canonical object bound exceeded.");
    const keys = entries.map(([key]) => key).sort();
    return "{" + keys.map(key => {
      const field = (value as Record<string, unknown>)[key];
      if (field === undefined)
        throw new CanonicalGoogleJsonError("Undefined JSON property.");
      return JSON.stringify(key) + ":" + canonicalGoogleJson(field);
    }).join(",") + "}";
  }
  throw new CanonicalGoogleJsonError(
    "Unsupported JSON field type in evidence digest.");
}
export function canonicalGoogleHash(value: unknown): string {
  return createHash("sha256")
    .update(canonicalGoogleJson(value))
    .digest("hex");
}
export function canonicalGoogleEqual(a: unknown, b: unknown): boolean {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
