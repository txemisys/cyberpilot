import { describe, expect, it } from "vitest";
import {
  parsePreflightPolicy, parsePreflightInput,
  evaluatePreflightSchedule, simulateSignedDispatchChallenge,
} from "./assets-osv-dispatch-preflight";
import type {
  PreflightScheduleSnapshot, PreflightEnvironmentSnapshot,
} from "./assets-osv-dispatch-preflight";
import {
  parseOsvScheduleConfig, scheduleConsentDigest,
} from "./assets-osv-renewal-schedules";

const now = new Date("2026-11-10T12:00:00.000Z");
const org = "preflight-organization-12345";
const scheduleId = "preflight-schedule-12345";
const importId = "preflight-inventory-12345";
const inspectionId = "preflight-inspection-12345";
const secret = "a2".repeat(32);
const config = () => ({
  name: "Synthetic preflight",
  inventoryImportId: importId,
  sourceInspectionId: inspectionId, cadenceMinutes: 60,
  inspection: {
    importId, dryRun: true, packageBindings: [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }], limitPackages: 5,
    maxPagesPerPackage: 2, maxRecordsPerPackage: 50,
    maxAgeMinutes: 60,
  },
  policy: {
    freshnessMinutes: 60, minimumRetryMinutes: 60,
    maximumPackagesPerRun: 5,
    maximumQueriesPerDay: 200,
    maximumInspectionsPerDay: 20,
    historyWindowDays: 90, includeIncomplete: true,
  },
  allowNewPackages: false, allowIncompleteInventory: false,
});
const schedule = (): PreflightScheduleSnapshot => ({
  id: scheduleId, name: config().name,
  revision: 2, enabled: true,
  outboundConsent: true,
  consentedAt: new Date("2026-11-10T10:00:00.000Z"),
  consentDigest: scheduleConsentDigest(org,
    parseOsvScheduleConfig(config())),
  inventoryImportId: importId, sourceInspectionId: inspectionId,
  nextDueAt: new Date("2026-11-10T11:00:00.000Z"),
  cadenceMinutes: 60,
  inspection: config().inspection, policy: config().policy,
  allowNewPackages: false, allowIncompleteInventory: false,
});
const env = (): PreflightEnvironmentSnapshot => ({
  activeInventoryIds: new Set([importId]),
  sourceInspectionIds: new Set([inspectionId]),
  openClaims: 0, openQuotaReservations: 0,
  openCriticalIncidents: 0,
  remainingRequests: 100, remainingInspections: 10,
  keyConfig: { enabled: true, keys: [{
    id: "preflight-key-12345",
    organizationId: org, secretHex: secret,
  }] },
});
describe("signed dispatcher preflight policy", () => {
  it("uses security-first defaults", () => {
    expect(parsePreflightPolicy()).toMatchObject({
      maxSchedules: 25, maximumObservations: 1000,
      requireNoOpenCriticalIncidents: true,
      requireNoUnsettledClaims: true,
      requireNoUnsettledQuotas: true,
      requireFreshInventory: true,
      inspectSignatureAuthentication: true,
      minimumRemainingRequests: 1,
    });
  });
  it.each([
    { maxSchedules: 0 }, { maxSchedules: 51 },
    { maximumObservations: 9 },
    { requireNoOpenCriticalIncidents: "false" },
    { requireNoUnsettledClaims: 1 },
    { requireNoUnsettledQuotas: "true" },
    { minimumRemainingInspections: -1 },
    { minimumRemainingRequests: 201 },
    { unknown: 1 },
  ])("rejects unbounded and malformed policy %j", patch => {
    expect(() => parsePreflightPolicy(patch)).toThrow();
  });
  it("rejects unknown request fields and malformed identifiers", () => {
    expect(parsePreflightInput({ scheduleId })).toMatchObject({
      scheduleId,
    });
    expect(() => parsePreflightInput({
      scheduleId: "bad/path",
    })).toThrow();
    expect(() => parsePreflightInput({
      scheduleId, organizationId: "spoofed",
    })).toThrow();
  });
  it("accepts a fully consented, due, healthy tenant for manual review", () => {
    const result = evaluatePreflightSchedule(org, schedule(),
      env(), parsePreflightPolicy(), now);
    expect(result.blocked).toBe(0);
    expect(result.canConsiderManualDispatch).toBe(true);
    expect(result.passed).toBeGreaterThan(10);
    expect(result.authorizingKeyIds).toEqual(["preflight-key-12345"]);
  });
  it("blocks forged canonical schedule consent", () => {
    const result = evaluatePreflightSchedule(org, {
      ...schedule(), consentDigest: "e".repeat(64),
    }, env(), parsePreflightPolicy(), now);
    expect(result.canConsiderManualDispatch).toBe(false);
    expect(result.checks.find(x => x.id === "CONSENT_DIGEST")?.level)
      .toBe("BLOCK");
  });
  it("blocks an unconsented schedule even when its digest is correct", () => {
    const result = evaluatePreflightSchedule(org, {
      ...schedule(), outboundConsent: false, consentedAt: null,
    }, env(), parsePreflightPolicy(), now);
    expect(result.checks.find(x => x.id === "OUTBOUND_CONSENT")?.level)
      .toBe("BLOCK");
  });
  it("blocks future, retired and excessively delayed slots", () => {
    const active = parsePreflightPolicy();
    for (const due of ["2026-11-11T12:00:00.000Z",
      "2026-09-01T12:00:00.000Z"]) {
      const result = evaluatePreflightSchedule(org, {
        ...schedule(), nextDueAt: new Date(due),
      }, env(), active, now);
      expect(result.canConsiderManualDispatch).toBe(false);
    }
  });
  it("blocks missing inventory and expired source evidence", () => {
    const environment = env();
    environment.activeInventoryIds.clear();
    environment.sourceInspectionIds.clear();
    const result = evaluatePreflightSchedule(org, schedule(),
      environment, parsePreflightPolicy(), now);
    expect(result.blocked).toBeGreaterThanOrEqual(2);
  });
  it("blocks unsettled claims, quotas and critical incidents", () => {
    const environment = env();
    environment.openClaims = 1;
    environment.openQuotaReservations = 3;
    environment.openCriticalIncidents = 2;
    const result = evaluatePreflightSchedule(org, schedule(),
      environment, parsePreflightPolicy(), now);
    expect(result.canConsiderManualDispatch).toBe(false);
    expect(result.checks.filter(x =>
      x.level === "BLOCK" && ["CLAIMS", "INCIDENTS", "QUOTA"].includes(
        x.category)).length).toBeGreaterThanOrEqual(3);
  });
  it("makes relaxed incident gates advisory but never waives consent", () => {
    const environment = env();
    environment.openClaims = 1;
    environment.openQuotaReservations = 1;
    const result = evaluatePreflightSchedule(org, {
      ...schedule(), outboundConsent: false,
    }, environment, parsePreflightPolicy({
      requireNoUnsettledClaims: false,
      requireNoUnsettledQuotas: false,
    }), now);
    expect(result.warnings).toBe(2);
    expect(result.blocked).toBeGreaterThanOrEqual(1);
  });
  it("blocks absent keys and globally disabled service dispatch", () => {
    const environment = env();
    environment.keyConfig.enabled = false;
    const result = evaluatePreflightSchedule(org, schedule(),
      environment, parsePreflightPolicy(), now);
    expect(result.canConsiderManualDispatch).toBe(false);
    expect(result.checks.find(x => x.id === "SCOPED_KEY")?.level)
      .toBe("BLOCK");
  });
  it("blocks insufficient daily HTTP and inspection budgets", () => {
    const environment = env();
    environment.remainingRequests = 0;
    environment.remainingInspections = 0;
    const result = evaluatePreflightSchedule(org, schedule(),
      environment, parsePreflightPolicy(), now);
    expect(result.canConsiderManualDispatch).toBe(false);
  });
});
describe("in-process signed dispatch challenge", () => {
  it("runs signature, mutation, tenant and expiry checks without network", () => {
    const result = simulateSignedDispatchChallenge(org,
      scheduleId, 2, env().keyConfig, now);
    expect(result).toMatchObject({
      protocolMatched: true,
      crossTenantRejected: true,
      signatureMutationRejected: true,
      expiredRejected: true, authenticationAccepted: true,
      signedRequestSent: false, noncePersisted: false,
      providerContacted: false, scheduleChanged: false,
    });
    expect(JSON.stringify(result)).not.toContain(secret);
  });
  it("never claims that a disabled signer has authenticated", () => {
    const keys = env().keyConfig;
    keys.enabled = false;
    const result = simulateSignedDispatchChallenge(org,
      scheduleId, 2, keys, now);
    expect(result.authenticationAccepted).toBe(false);
  });
  it("does not accept a cryptographic identity belonging to another tenant", () => {
    const result = simulateSignedDispatchChallenge(
      "another-organization-12345", scheduleId,
      2, env().keyConfig, now);
    expect(result.authenticationAccepted).toBe(false);
  });
});
