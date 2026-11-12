import { describe, expect, it } from "vitest";
import { runGoogleLabJourney } from
  "@cyberpilot/integrations/google-workspace";
import {
  parseScenarioRunCommand, sanitizeGoogleScenarioJourney,
  inspectSanitizedGoogleRun, googleScenarioCatalog,
} from "./google-lab-scenario-service";
const organizationId = "google-scenario-org-12345";
const checkedAt = "2026-11-12T10:00:00.000Z";
const validInput = {
  connectionId: "google-conn-12345",
  expectedConnectionRevision: 2,
  scenario: "HEALTHY_REFERENCE",
  checkedAt, retentionDays: 30,
  persist: false, includeAuditTrace: true,
};
function source(scenario:
  "HEALTHY_REFERENCE" | "PERMISSION_DENIED" | "MFA_GAPS") {
  return runGoogleLabJourney({
    organizationId, checkedAt, scenario,
  });
}
describe("Google Workspace LAB scenario web response boundary", () => {
  it("redacts the full Directory fixture from a public API response", async () => {
    const journey = await source("HEALTHY_REFERENCE");
    const result = sanitizeGoogleScenarioJourney(journey,
      parseScenarioRunCommand(validInput), null);
    const json = JSON.stringify(result);
    expect(json).not.toContain(".example.invalid");
    expect(json).not.toContain("offline-fixture-only-no-provider-credential");
    expect(result.googleApiRequests).toBe(0);
    expect(result.googleAccountWrites).toBe(0);
    expect(result.realAdministratorConsentVerified).toBe(false);
    expect(result.canonicalCyberScoreModified).toBe(false);
    expect(inspectSanitizedGoogleRun(result).valid).toBe(true);
    expect(result.report.sections).toHaveLength(11);
  });
  it("preserves 403 permission gaps and the resulting unknown coverage", async () => {
    const journey = await source("PERMISSION_DENIED");
    const result = sanitizeGoogleScenarioJourney(journey,
      parseScenarioRunCommand({
        ...validInput, scenario: "PERMISSION_DENIED",
      }), null);
    expect(result.failures.some(f => f.category === "PERMISSION"))
      .toBe(true);
    expect(result.report.summary.customerSecurityStatus)
      .toBe("NOT_DETERMINED");
    expect(result.coverage.some(c =>
      c.status === "DENIED")).toBe(true);
  });
  it("exposes risks as proposals and no live remediation", async () => {
    const journey = await source("MFA_GAPS");
    const result = sanitizeGoogleScenarioJourney(journey,
      parseScenarioRunCommand({
        ...validInput, scenario: "MFA_GAPS",
      }), null);
    expect(result.findings.some(f => f.ruleId ===
      "SUPERADMIN_2SV_NOT_ENROLLED")).toBe(true);
    expect(result.findings.every(f => !f.autoRemediated)).toBe(true);
    expect(result.operatorActions.every(f =>
      !f.executed)).toBe(true);
  });
  it("rejects unrecognized HTTP parameters and impossible budgets", () => {
    for (const value of [
      { ...validInput, scenario: "CUSTOM_REAL_TENANT" },
      { ...validInput, unexpected: "token" },
      { ...validInput, expectedConnectionRevision: -1 },
      { ...validInput, maxRetries: 99 },
      { ...validInput, pageSize: 0 },
      { ...validInput, retentionDays: 0 },
      { ...validInput, includeAuditTrace: "true" },
    ]) expect(() => parseScenarioRunCommand(value)).toThrow();
  });
  it("enforces safe catalog-only fixture execution", () => {
    const scenarios = googleScenarioCatalog();
    expect(scenarios.length).toBe(17);
    expect(scenarios.every(x => !x.needsRealGoogleTenant &&
      !x.producesProviderRequests &&
      !x.containsCustomerData &&
      !x.externalGoogleConsentSatisfied &&
      !x.canModifyGoogleAccounts)).toBe(true);
  });
  it("catches invented snapshot persistence and customer authorization", async () => {
    const journey = await source("HEALTHY_REFERENCE");
    const result = sanitizeGoogleScenarioJourney(journey,
      parseScenarioRunCommand(validInput), null);
    const changed = JSON.parse(JSON.stringify(result)) as typeof result;
    changed.workflow.saved = true;
    expect(inspectSanitizedGoogleRun(changed).valid).toBe(false);
    changed.workflow.saved = false;
    changed.workflow.customerDeploymentAccepted = true as false;
    expect(inspectSanitizedGoogleRun(changed).valid).toBe(false);
  });
});
