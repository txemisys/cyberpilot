import { describe, expect, it } from "vitest";
import {
  parseDispatchOperationalPolicy, correlateSignedDispatch,
  summarizeSignedDispatchAlerts,
} from "./assets-osv-dispatch-observability";

const now = new Date("2026-11-10T12:00:00.000Z");
const policy = parseDispatchOperationalPolicy({});
const nonce = (acceptedAt = "2026-11-10T11:00:00.000Z",
  scheduleId = "osv-schedule-12345") => ({
  requestDigest: "a".repeat(64),
  nonceDigest: "b".repeat(64),
  keyId: "osv-key-12345",
  scheduleId,
  acceptedAt: new Date(acceptedAt),
  expiresAt: new Date("2026-11-10T11:01:00.000Z"),
});
const run = (claimedAt = "2026-11-10T11:00:10.000Z",
  state = "COMPLETE") => ({
  id: "osv-run-12345",
  scheduleId: "osv-schedule-12345",
  claimedAt: new Date(claimedAt),
  slotAt: new Date("2026-11-10T11:00:00.000Z"),
  state, commandDigest: "c".repeat(64),
});
describe("OSV signed dispatcher operational policy", () => {
  it("uses bounded diagnostic defaults", () => {
    expect(policy).toEqual({
      lookbackHours: 24, maximumRecent: 50,
      alertAfterMinutes: 45, alertFailureThreshold: 3,
      alertUnsettledThreshold: 1,
    });
  });
  it.each([
    { lookbackHours: 0 }, { lookbackHours: 721 },
    { maximumRecent: 0 }, { maximumRecent: 101 },
    { alertAfterMinutes: 0 }, { alertAfterMinutes: 1441 },
    { alertFailureThreshold: 0 }, { alertFailureThreshold: 51 },
    { alertUnsettledThreshold: 0 }, { alertUnsettledThreshold: 51 },
    { unexpected: "untrusted" },
  ])("rejects malformed operational controls %j", patch => {
    expect(() => parseDispatchOperationalPolicy(patch)).toThrow();
  });
  it("links a single close run by time, without claiming proof of causality", () => {
    const report = correlateSignedDispatch([nonce()], [run()],
      now, policy);
    expect(report.unmatched).toBe(0);
    expect(report.rows[0]).toMatchObject({
      runId: "osv-run-12345",
      runState: "COMPLETE", hasRunClaim: true,
      warningCode: null,
    });
  });
  it("never associates runs from a different organization schedule", () => {
    const report = correlateSignedDispatch([
      nonce("2026-11-10T11:00:00.000Z", "foreign-schedule-12345"),
    ], [run()], now, policy);
    expect(report.unmatched).toBe(1);
    expect(report.rows[0]?.runId).toBeNull();
    expect(report.rows[0]?.warningCode)
      .toBe("ACCEPTED_WITHOUT_OBSERVED_CLAIM");
  });
  it("reports ambiguous concurrent runs instead of inventing a unique match", () => {
    const report = correlateSignedDispatch([nonce()], [
      run(), { ...run("2026-11-10T11:00:20.000Z"),
        id: "osv-run-second-12345" },
    ], now, policy);
    expect(report.rows[0]?.runId).toBeNull();
    expect(report.rows[0]?.warningCode)
      .toBe("AMBIGUOUS_RUN_ASSOCIATION");
  });
  it("recognizes a failed provider run without equating it to no network traffic", () => {
    const report = correlateSignedDispatch([nonce()],
      [run("2026-11-10T11:00:10.000Z", "FAILED")], now, policy);
    expect(report.rows[0]?.runState).toBe("FAILED");
    expect(report.rows[0]?.warningCode).toBe("DISPATCH_FAILED");
  });
  it("labels unverified provider outcomes as unknown", () => {
    const report = correlateSignedDispatch([nonce()],
      [run("2026-11-10T11:00:10.000Z", "UNKNOWN")], now, policy);
    expect(report.rows[0]?.warningCode).toBe("UNKNOWN_PROVIDER_RESULT");
  });
  it("flags very old unfinished claims as still unsettled", () => {
    const report = correlateSignedDispatch([nonce()],
      [run("2026-11-10T11:00:10.000Z", "CLAIMED")], now, policy);
    expect(report.rows[0]?.warningCode)
      .toBe("INCOMPLETE_SCHEDULE_CLAIM");
  });
  it("does not alert on a recently received signed request", () => {
    const recently = nonce("2026-11-10T11:59:30.000Z");
    const report = correlateSignedDispatch([recently], [],
      now, policy);
    expect(report.rows[0]?.warningCode).toBeNull();
  });
  it("detects invalid evaluation timestamps rather than silently accepting them", () => {
    expect(() => correlateSignedDispatch([nonce()], [],
      new Date(NaN), policy)).toThrow();
  });
  it("proposes manual remediation actions, not automatic retries", () => {
    const alerts = summarizeSignedDispatchAlerts({
      unmatched: 2, failureCount: 4, unknownCount: 1,
      unsettledCount: 2, oldestUnsettledMinutes: 120,
      credentialReady: false,
    }, policy);
    expect(alerts.length).toBeGreaterThanOrEqual(5);
    expect(alerts.map(x => x.code))
      .toContain("SERVICE_CREDENTIAL_NOT_READY");
    expect(alerts.map(x => x.code))
      .toContain("DISPATCH_FAILURE_THRESHOLD");
    expect(alerts.map(x => x.code))
      .toContain("STALE_SCHEDULE_CLAIM");
    expect(alerts.every(x => x.action.length > 10)).toBe(true);
    expect(JSON.stringify(alerts)).not.toMatch(/automatically retry the provider/i);
  });
  it("allows an empty diagnostic result with no fabricated incident", () => {
    const result = correlateSignedDispatch([], [], now, policy);
    expect(result).toEqual({ rows: [], unmatched: 0 });
    expect(summarizeSignedDispatchAlerts({
      unmatched: 0, failureCount: 0, unknownCount: 0,
      unsettledCount: 0, oldestUnsettledMinutes: null,
      credentialReady: true,
    }, policy)).toEqual([]);
  });
});
