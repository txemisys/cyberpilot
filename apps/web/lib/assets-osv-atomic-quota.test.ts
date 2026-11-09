import { describe, expect, it } from "vitest";
import {
  OSV_DEFAULT_DAILY_INSPECTION_LIMIT,
  OSV_DEFAULT_DAILY_REQUEST_LIMIT,
  parseOsvQuotaPolicy, parseOsvQuotaCommand,
  utcQuotaDay, quotaReservationDigest,
  evaluateQuotaCapacity, computeReservedRequestPages,
  classifyQuotaSettlement, createOsvQuotaCommand,
} from "./assets-osv-atomic-quota";

const now = new Date("2026-11-09T12:59:59.000Z");
const request = {
  requestKey: "osv-quota-request-12345",
  requestDigest: "a".repeat(64),
  inventoryImportId: "import-12345",
  reservedRequests: 6,
};
describe("OSV atomic quota policy validation", () => {
  it("defines finite and conservative defaults", () => {
    expect(OSV_DEFAULT_DAILY_INSPECTION_LIMIT).toBe(20);
    expect(OSV_DEFAULT_DAILY_REQUEST_LIMIT).toBe(200);
    expect(parseOsvQuotaPolicy()).toEqual({
      dailyInspectionLimit: 20,
      dailyRequestLimit: 200,
      maxReservedRequestsPerInspection: 60,
    });
  });
  it.each([
    { dailyInspectionLimit: 0 },
    { dailyInspectionLimit: 101 },
    { dailyRequestLimit: -1 },
    { dailyRequestLimit: 2001 },
    { maxReservedRequestsPerInspection: 0 },
    { maxReservedRequestsPerInspection: 101 },
    { dailyRequestLimit: 5, maxReservedRequestsPerInspection: 10 },
    { unrecognized: "untrusted" },
  ])("rejects invalid quotas %j", overrides => {
    expect(() => parseOsvQuotaPolicy(overrides)).toThrow();
  });
  it("computes UTC day boundaries and does not depend on local time", () => {
    expect(utcQuotaDay(now).toISOString()).toBe("2026-11-09T00:00:00.000Z");
    expect(utcQuotaDay(new Date("2026-11-10T00:00:00.000Z"))
      .toISOString()).toBe("2026-11-10T00:00:00.000Z");
    expect(() => utcQuotaDay(new Date(NaN))).toThrow();
  });
  it("demands a stable idempotency key and digest", () => {
    expect(parseOsvQuotaCommand(request)).toEqual(request);
    expect(() => parseOsvQuotaCommand({
      ...request, requestKey: "short",
    })).toThrow();
    expect(() => parseOsvQuotaCommand({
      ...request, requestKey: "bad\nkey-is-forbidden",
    })).toThrow();
    expect(() => parseOsvQuotaCommand({
      ...request, requestDigest: "wrong-digest",
    })).toThrow();
  });
  it.each([
    { reservedRequests: 0 },
    { reservedRequests: 61 },
    { reservedRequests: 1.5 },
    { reservedRequests: NaN },
    { inventoryImportId: "../path" },
    { inventoryImportId: "" },
    { unexpected: "value" },
  ])("rejects malformed reservations %j", value => {
    expect(() => parseOsvQuotaCommand({
      ...request, ...value,
    })).toThrow();
  });
  it("hashes reservations deterministically and in tenant scope", () => {
    const a = quotaReservationDigest("org-one", request);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    expect(a).toBe(quotaReservationDigest("org-one", request));
    expect(a).not.toBe(quotaReservationDigest("org-other", request));
  });
  it("charges upper-bound HTTP pages rather than successful matches", () => {
    expect(computeReservedRequestPages(5, 3)).toBe(15);
    expect(computeReservedRequestPages(20, 3)).toBe(60);
    expect(computeReservedRequestPages(0, 3)).toBe(0);
    expect(() => computeReservedRequestPages(21, 3)).toThrow();
    expect(() => computeReservedRequestPages(20, 4)).toThrow();
  });
  it("computes remaining daily capacity without going negative", () => {
    const available = evaluateQuotaCapacity({
      inspectionsReserved: 5, requestsReserved: 40,
      inspectionLimit: 20, requestLimit: 200,
    }, 30);
    expect(available).toMatchObject({
      allowed: true, remainingInspections: 15,
      remainingRequests: 160, reason: "AVAILABLE",
    });
  });
  it("enforces exactly the remaining quota and rejects one page too many", () => {
    const values = {
      inspectionsReserved: 19, requestsReserved: 198,
      inspectionLimit: 20, requestLimit: 200,
    };
    expect(evaluateQuotaCapacity(values, 2).allowed).toBe(true);
    expect(evaluateQuotaCapacity(values, 3)).toMatchObject({
      allowed: false, reason: "REQUESTS_EXHAUSTED",
    });
  });
  it("blocks even small queries after inspection quota exhaustion", () => {
    const capacity = evaluateQuotaCapacity({
      inspectionsReserved: 20, requestsReserved: 1,
      inspectionLimit: 20, requestLimit: 200,
    }, 1);
    expect(capacity.reason).toBe("INSPECTIONS_EXHAUSTED");
    expect(capacity.allowed).toBe(false);
  });
  it("settles only within the original reservation", () => {
    expect(classifyQuotaSettlement("RESERVED", "FINISHED", 2, 6))
      .toMatchObject({ allowed: true, next: "FINISHED", actualRequests: 2 });
    expect(classifyQuotaSettlement("RESERVED", "FAILED", 0, 6))
      .toMatchObject({ allowed: true, next: "FAILED" });
    expect(() => classifyQuotaSettlement("RESERVED",
      "FINISHED", 7, 6)).toThrow();
    expect(() => classifyQuotaSettlement("RESERVED",
      "FINISHED", -1, 6)).toThrow();
  });
  it("refuses to change settled terminal states", () => {
    expect(classifyQuotaSettlement("FINISHED", "FINISHED", 2, 6))
      .toMatchObject({ allowed: false, next: "FINISHED" });
    expect(classifyQuotaSettlement("FAILED", "FINISHED", 2, 6))
      .toMatchObject({ allowed: false, next: "FAILED" });
  });
  it("generates scoped reservation tokens and page allowances", () => {
    const a = createOsvQuotaCommand("org-one", "import-12345",
      3, 2, "some-request-key-12345");
    expect(a).toMatchObject({
      inventoryImportId: "import-12345",
      reservedRequests: 6, requestKey: "some-request-key-12345",
    });
    expect(a.requestDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(a.requestDigest).not.toBe(createOsvQuotaCommand(
      "org-other", "import-12345", 3, 2,
      "some-request-key-12345").requestDigest);
  });
});
