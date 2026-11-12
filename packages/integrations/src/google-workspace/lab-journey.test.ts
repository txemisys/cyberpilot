import { describe, expect, it } from "vitest";
import {
  makeGoogleLabScenario, verifyGoogleLabScenario,
  scenarioFaults, buildGoogleLabSimulation,
  GOOGLE_LAB_SCENARIOS,
} from "./lab-scenarios";
import {
  parseGoogleLabJourneyInput, runGoogleLabJourney,
  inspectGoogleLabJourney, googleLabJourneySummary,
  googleLabJourneyOperatorActions,
} from "./lab-journey";
const organizationId = "google-fixture-org-12345";
const checkedAt = "2026-11-12T10:00:00.000Z";
function run(scenario: typeof GOOGLE_LAB_SCENARIOS[number]["id"],
  options: Record<string, unknown> = {}) {
  return runGoogleLabJourney({
    organizationId, checkedAt, scenario, ...options,
  });
}
describe("Google Workspace simulated Directory and Reports journey", () => {
  it("runs a complete fixture with reporting and no provider access", async () => {
    const result = await run("HEALTHY_REFERENCE");
    expect(result.collection.providerContacted).toBe(false);
    expect(result.diagnostics.externalApiRequests).toBe(0);
    expect(result.collection.observation.users.length).toBe(3);
    expect(result.collection.observation.reports.length).toBe(3);
    expect(result.report.sections).toHaveLength(11);
    expect(result.assessment.score.score).toBe(null);
    expect(result.acceptedForCustomerOperations).toBe(false);
    expect(result.acceptedForOfflineDevelopment).toBe(true);
    expect(inspectGoogleLabJourney(result).valid).toBe(true);
  });
  it("collects multiple deterministic pages without live requests", async () => {
    const result = await run("PAGINATED_DIRECTORY", {
      userCount: 11, pageSize: 2,
    });
    expect(result.collection.observation.users).toHaveLength(11);
    expect(result.fixtureTrace.filter(t =>
      t.resource === "USERS").length).toBe(6);
    expect(result.collection.observation.truncation.DIRECTORY_USERS)
      .toBe(false);
    expect(result.diagnostics.requests).toBeGreaterThan(6);
  });
  it("propagates permission denial conservatively", async () => {
    const result = await run("PERMISSION_DENIED");
    expect(result.collection.observation.coverage.DIRECTORY_USERS)
      .toBe("REQUIRES_PERMISSION");
    expect(result.collection.evidenceIncomplete).toBe(true);
    expect(result.assessment.score.score).toBe(null);
    expect(result.diagnostics.permissionFailures).toBeGreaterThan(0);
  });
  it("recovers from an injected 429 using bounded retries", async () => {
    const result = await run("QUOTA_THEN_RECOVER");
    expect(result.fixtureTrace.some(t => t.status === 429)).toBe(true);
    expect(result.diagnostics.retriesObserved).toBeGreaterThan(0);
    expect(result.collection.observation.users.length).toBe(3);
  });
  it("keeps exhausted quotas and truncated pages as unknown", async () => {
    const result = await run("QUOTA_EXHAUSTED");
    expect(result.collection.evidenceIncomplete).toBe(true);
    expect(result.collection.observation.unknownCapabilities)
      .toContain("DIRECTORY_USERS");
    expect(result.diagnostics.externalApiRequests).toBe(0);
  });
  it("does not classify partial user pages as complete inventory", async () => {
    const result = await run("PARTIAL_DIRECTORY", {
      pageSize: 2,
    });
    expect(result.collection.observation.truncation.DIRECTORY_USERS)
      .toBe(true);
    expect(result.assessment.score.healthyLabelAllowed).toBe(false);
  });
  it("separates Reports permission from Directory permission", async () => {
    const result = await run("REPORTS_UNAVAILABLE");
    expect(result.collection.observation.coverage.REPORTS_LOGIN)
      .toBe("REQUIRES_PERMISSION");
    expect(result.collection.observation.coverage.REPORTS_ADMIN)
      .toBe("REQUIRES_PERMISSION");
    expect(result.collection.observation.coverage.DIRECTORY_USERS)
      .toBe("AVAILABLE");
  });
  it("does not turn missing 2SV attributes into good posture", async () => {
    const result = await run("UNKNOWN_MFA");
    expect(result.assessment.counts.usersWithUnknownMfa)
      .toBeGreaterThan(0);
    expect(result.neutral.coverage.externalProviderVerified).toBe(false);
  });
  it("reports superadmin MFA gaps without changing any accounts", async () => {
    const result = await run("ADMIN_RISK");
    expect(result.assessment.findings.some(x =>
      x.ruleId === "SUPERADMIN_2SV_NOT_ENROLLED")).toBe(true);
    expect(result.assessment.accountWrites).toBe(0);
    expect(googleLabJourneyOperatorActions(result)
      .every(x => x.executed === false)).toBe(true);
  });
  it("rejects modified signed-in-the-local-sense fixture bytes", () => {
    const fixture = makeGoogleLabScenario({
      organizationId, checkedAt, scenario: "HEALTHY_REFERENCE",
    });
    fixture.users[0]!.isAdmin = false;
    expect(verifyGoogleLabScenario(fixture).valid).toBe(false);
    expect(() => buildGoogleLabSimulation(fixture)).toThrow();
  });
  it("does not leak literal fixture token in mock traces", async () => {
    const result = await run("HEALTHY_REFERENCE");
    expect(JSON.stringify(result.fixtureTrace))
      .not.toContain("offline-fixture-only-no-provider-credential");
    expect(result.fixtureTrace.every(t =>
      !t.bearerTokenLogged && !t.rawAuthorizationHeadersLogged)).toBe(true);
    expect(googleLabJourneySummary(result).customerApproval).toBe(false);
  });
  it("rejects cross-scenario identity spoofing and invalid bounds", () => {
    expect(() => parseGoogleLabJourneyInput({
      organizationId: "../unsafe", checkedAt,
      scenario: "HEALTHY_REFERENCE",
    })).toThrow();
    expect(() => parseGoogleLabJourneyInput({
      organizationId, checkedAt,
      scenario: "HEALTHY_REFERENCE", pageSize: 10000,
    })).toThrow();
    expect(() => parseGoogleLabJourneyInput({
      organizationId, checkedAt,
      scenario: "REAL_GOOGLE",
    })).toThrow();
  });
  it("catalogs all scenarios as pure offline operations", () => {
    expect(GOOGLE_LAB_SCENARIOS.length).toBeGreaterThan(15);
    for (const scenario of GOOGLE_LAB_SCENARIOS) {
      expect(scenario.producesGoogleTraffic).toBe(false);
      expect(scenario.containsRealUserData).toBe(false);
      expect(scenario.customerTenantAuthenticated).toBe(false);
    }
    expect(scenarioFaults(makeGoogleLabScenario({
      organizationId, checkedAt,
      scenario: "PERMISSION_DENIED",
    })).some(f => f.status === 403)).toBe(true);
  });
});
