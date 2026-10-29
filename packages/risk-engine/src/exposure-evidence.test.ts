import { describe, expect, it } from "vitest";
import { validateExposureEvidence, selectTenantExposureEvidence } from "./exposure-evidence";
describe("tenant-bound passive Exposure evidence", () => {
  const data = { tenantId: "tenant-a", source: "OBSERVED" as const, collectedAt: "2026-10-29T00:00:00Z", payload: { status: 200 } };
  it("preserves the source and timestamp of observations", () => {
    expect(validateExposureEvidence("tenant-a", data)).toEqual({
      state: "PRESENT", source: "OBSERVED", collectedAt: "2026-10-29T00:00:00Z", payload: { status: 200 },
    });
  });
  it("rejects cross-tenant payload before exposing its contents", () => {
    expect(validateExposureEvidence("tenant-b", data)).toEqual({
      state: "FOREIGN_TENANT", source: "OBSERVED", collectedAt: null, payload: null,
    });
  });
  it("never upgrades declared evidence to observed", () => {
    expect(validateExposureEvidence("tenant-a", { ...data, source: "DECLARED", collectedAt: null }).source).toBe("DECLARED");
  });
  it("requires valid observation timestamps", () => {
    expect(validateExposureEvidence("tenant-a", { ...data, collectedAt: null }).state).toBe("INVALID");
    expect(validateExposureEvidence("tenant-a", { ...data, collectedAt: "invalid" }).state).toBe("INVALID");
  });
  it("keeps missing payloads unknown", () => {
    expect(validateExposureEvidence("tenant-a", { ...data, payload: null }).state).toBe("UNKNOWN");
  });
  it("selects only the requested tenant without revealing foreign entries", () => {
    const result = selectTenantExposureEvidence("tenant-a", [
      data, { ...data, tenantId: "tenant-b", payload: { status: 401 } },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0]?.payload).toEqual({ status: 200 });
  });
});
