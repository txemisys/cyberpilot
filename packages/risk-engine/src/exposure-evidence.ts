/** Tenant-scoped intake envelope for passive Exposure observations.
 * Caller declares provenance; this function never promotes declarations to observations.
 */
export type ExposureEvidenceSource = "DECLARED" | "OBSERVED";
export type ExposureEvidenceEnvelope<T> = {
  tenantId: string;
  source: ExposureEvidenceSource;
  collectedAt: string | null;
  payload: T | null;
};
export type ExposureEvidenceResult<T> = {
  state: "PRESENT" | "UNKNOWN" | "INVALID" | "FOREIGN_TENANT";
  source: ExposureEvidenceSource;
  collectedAt: string | null;
  payload: T | null;
};
export function validateExposureEvidence<T>(tenantId: string, evidence: ExposureEvidenceEnvelope<T>): ExposureEvidenceResult<T> {
  const source = evidence.source;
  const unknown = (state: ExposureEvidenceResult<T>["state"]): ExposureEvidenceResult<T> => ({
    state, source, collectedAt: null, payload: null,
  });
  if (!tenantId || !evidence.tenantId || tenantId !== evidence.tenantId) return unknown("FOREIGN_TENANT");
  if (evidence.payload == null) return unknown("UNKNOWN");
  if (source === "OBSERVED" && (!evidence.collectedAt || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(evidence.collectedAt) || !Number.isFinite(Date.parse(evidence.collectedAt)))) return unknown("INVALID");
  if (source === "DECLARED" && evidence.collectedAt && !Number.isFinite(Date.parse(evidence.collectedAt))) return unknown("INVALID");
  return { state: "PRESENT", source, collectedAt: evidence.collectedAt, payload: evidence.payload };
}
export function selectTenantExposureEvidence<T>(tenantId: string, entries: readonly ExposureEvidenceEnvelope<T>[]): ExposureEvidenceResult<T>[] {
  return entries.filter((item) => item.tenantId === tenantId).map((item) => validateExposureEvidence(tenantId, item));
}
