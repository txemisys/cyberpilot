import { describe, expect, it } from "vitest";
import {
  normalizeBatch, subjectHash, verifyObservation,
} from "./directory-contract";
import {
  parseGoogleAssessmentPolicy, classifyGoogleCoverage,
  assessGoogleWorkspace, verifyGoogleRiskAssessment,
  googleRemediationPlan, googleAssessmentManifest,
} from "./risk-assessment";
import {
  buildGoogleExecutiveReport, verifyGoogleExecutiveReport,
  exportGoogleReportJson, exportGoogleReportMarkdown,
  diffGoogleReports, verifyGoogleReportDiff,
  buildGoogleHistory, verifyGoogleHistory,
  inspectGoogleOfflineFixture,
} from "./assessment-report";

const organizationId = "test-google-org-12345";
const at = new Date("2026-11-12T10:00:00.000Z");
function source(overrides: Record<string, unknown> = {}) {
  return normalizeBatch({
    organizationId, checkedAt: at.toISOString(),
    source: "SYNTHETIC_FIXTURE",
    users: [{
      id: "user-one",
      primaryEmail: "admin@example.test",
      suspended: false, isAdmin: true,
      isEnrolledIn2Sv: false, isEnforcedIn2Sv: false,
      lastLoginTime: "2026-01-01T10:00:00.000Z",
    }],
    domains: [{ domainName: "example.test", verified: false }],
    coverage: {
      DIRECTORY_USERS: "AVAILABLE",
      USER_MFA_ATTRIBUTES: "AVAILABLE",
      DIRECTORY_DOMAINS: "AVAILABLE",
      DIRECTORY_ORGANIZATION_UNITS: "UNKNOWN",
      REPORTS_LOGIN: "UNKNOWN", REPORTS_ADMIN: "UNKNOWN",
    },
    ...overrides,
  });
}
describe("Google Workspace Phase 5 offline risk engine", () => {
  it("emits cautious superadmin MFA and observed domain findings", () => {
    const result = assessGoogleWorkspace(source(), {
      staleAfterDays: 90,
    }, at);
    expect(result.findings.map(f => f.ruleId))
      .toContain("SUPERADMIN_2SV_NOT_ENROLLED");
    expect(result.findings.map(f => f.ruleId))
      .toContain("SUPERADMIN_2SV_NOT_ENFORCED");
    expect(result.findings.map(f => f.ruleId))
      .toContain("DOMAIN_UNVERIFIED");
    expect(result.findings.map(f => f.ruleId))
      .toContain("STALE_ACTIVE_IDENTITY");
    expect(result.score.score).toBe(null);
    expect(result.score.cyberScoreUpdated).toBe(false);
    expect(result.counts.superadminsObserved).toBe(1);
    expect(verifyGoogleRiskAssessment(result).valid).toBe(true);
  });
  it("links finding evidence only to tenant-salted pseudonymous subjects", () => {
    const result = assessGoogleWorkspace(source(), {}, at);
    const user = result.evidence.find(e =>
      e.controlId === "GOOGLE_USER_2SV");
    expect(user?.subjectHash).toBe(
      subjectHash(organizationId, "user-one"));
    const finding = result.findings.find(f =>
      f.ruleId === "SUPERADMIN_2SV_NOT_ENROLLED");
    expect(finding?.evidenceIds.length).toBeGreaterThan(0);
    expect(JSON.stringify(finding)).not.toContain("admin@example.test");
  });
  it("preserves missing license and privileged-status UNKNOWN", () => {
    const observation = source({
      users: [{
        id: "user-two", primaryEmail: "user@example.test",
        suspended: null, isAdmin: null,
        isEnrolledIn2Sv: null, isEnforcedIn2Sv: null,
      }],
      coverage: { DIRECTORY_USERS: "AVAILABLE",
        USER_MFA_ATTRIBUTES: "NOT_AVAILABLE" },
    });
    const result = assessGoogleWorkspace(observation, {}, at);
    expect(result.findings.map(f => f.ruleId))
      .toContain("UNKNOWN_ADMIN_STATUS");
    expect(result.findings.map(f => f.ruleId))
      .toContain("UNKNOWN_MFA_SIGNAL");
    expect(result.findings.map(f => f.ruleId))
      .toContain("SUSPENSION_STATUS_UNKNOWN");
    expect(classifyGoogleCoverage(observation, result.evidence).find(c =>
      c.capability === "USER_MFA_ATTRIBUTES")?.status)
      .toBe("NOT_LICENSED");
    expect(result.score.healthyLabelAllowed).toBe(false);
  });
  it("does not classify suspended identity as urgent active account", () => {
    const result = assessGoogleWorkspace(source({
      users: [{
        id: "user-two", primaryEmail: "admin@example.test",
        suspended: true, isAdmin: true,
        isEnrolledIn2Sv: false, isEnforcedIn2Sv: false,
      }],
    }), {}, at);
    expect(result.findings.map(f => f.ruleId))
      .toContain("SUPERADMIN_SUSPENDED_CONFLICT");
    expect(result.findings.map(f => f.ruleId))
      .not.toContain("SUPERADMIN_2SV_NOT_ENROLLED");
  });
  it("bounds assessment thresholds and rejects date manipulation", () => {
    for (const bad of [
      { staleAfterDays: 0 }, { staleAfterDays: 3651 },
      { maximumFindings: 0 }, { maximumFindings: 10001 },
      { includeNonAdmin2Sv: "yes" }, { unknown: true },
    ]) expect(() => parseGoogleAssessmentPolicy(bad, at)).toThrow();
    expect(() => assessGoogleWorkspace(source(), {
      referenceDate: "2026-01-01T00:00:00Z",
    }, at)).toThrow();
  });
  it("rejects altered observation rather than trusting stale SHA", () => {
    const observation = source();
    observation.users[0]!.isAdmin = false;
    expect(verifyObservation(observation).valid).toBe(false);
    expect(() => assessGoogleWorkspace(observation, {}, at))
      .toThrow();
  });
  it("does not auto-remediate or grant tenant permission", () => {
    const result = assessGoogleWorkspace(source(), {}, at);
    const actions = googleRemediationPlan(result);
    expect(actions.every(a => !a.executedByConnector &&
      !a.approvedByCustomer &&
      a.requiresAdministratorApproval)).toBe(true);
    expect(result.accountWrites).toBe(0);
    expect(result.liveProviderVerified).toBe(false);
    expect(result.customerLegalApproval).toBe(false);
  });
  it("prevents fake external verification even with changed report digest", () => {
    const result = assessGoogleWorkspace(source(), {}, at);
    result.score.cyberScoreUpdated = true;
    expect(verifyGoogleRiskAssessment(result).valid).toBe(false);
    expect(() => googleAssessmentManifest(result)).toThrow();
  });
});
describe("Google Workspace Phase 5 executive evidence report", () => {
  it("creates eleven sections with full caveats and explicit UNKNOWN", () => {
    const assessment = assessGoogleWorkspace(source(), {}, at);
    const report = buildGoogleExecutiveReport(assessment);
    expect(report.sections).toHaveLength(11);
    expect(report.coverage).toHaveLength(6);
    expect(report.summary.customerSecurityStatus)
      .toBe("NOT_DETERMINED");
    expect(report.summary.previewScore).toBe(null);
    expect(report.realTenantConsentProven).toBe(false);
    expect(verifyGoogleExecutiveReport(report).valid).toBe(true);
  });
  it("exports report without emails, credentials or unsafe claims", () => {
    const report = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    const exported = exportGoogleReportJson(report);
    const markdown = exportGoogleReportMarkdown(report);
    expect(exported).not.toContain("admin@example.test");
    expect(markdown).toContain("offline evidence report");
    expect(markdown).not.toContain("admin@example.test");
    expect(JSON.parse(exported).sourceEmailsExported).toBe(false);
  });
  it("reports identity observations and coverage without certification", () => {
    const output = inspectGoogleOfflineFixture(source(), at);
    expect(output.report.summary.usersObserved).toBe(1);
    expect(output.report.customerCertified).toBe(false);
    expect(output.customerLiveValidated).toBe(false);
    expect(output.accountWrites).toBe(0);
    expect(output.actionPlan.some(a =>
      a.state === "PROPOSED_ONLY")).toBe(true);
  });
  it("detects any tampering with report and refuses exports", () => {
    const report = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    report.summary.tenantCertifiedSecure = true;
    expect(verifyGoogleExecutiveReport(report).valid).toBe(false);
    expect(() => exportGoogleReportMarkdown(report)).toThrow();
  });
  it("compares snapshots as observations, not proof of remediation", () => {
    const baseline = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    const later = new Date("2026-11-13T10:00:00.000Z");
    const current = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source({
        users: [{
          id: "user-one", primaryEmail: "admin@example.test",
          suspended: false, isAdmin: true,
          isEnrolledIn2Sv: true, isEnforcedIn2Sv: true,
          lastLoginTime: "2026-11-12T10:00:00.000Z",
        }],
        checkedAt: later.toISOString(),
        domains: [{ domainName: "example.test", verified: true }],
      }), {}, later));
    const diff = diffGoogleReports(baseline, current);
    expect(diff.findingsRemovedFromSnapshot.length)
      .toBeGreaterThan(0);
    expect(diff.resolvedRiskClaimed).toBe(false);
    expect(diff.cyberScoreDeltaClaimed).toBe(false);
    expect(verifyGoogleReportDiff(diff).valid).toBe(true);
    const history = buildGoogleHistory([baseline, current]);
    expect(history.reportCount).toBe(2);
    expect(history.trendIsFullTenantSecurity).toBe(false);
    expect(verifyGoogleHistory(history).valid).toBe(true);
  });
  it("rejects cross-organization comparisons", () => {
    const first = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    const second = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source({
        organizationId: "foreign-org-12345",
      }), {}, at));
    expect(() => diffGoogleReports(first, second)).toThrow();
    expect(() => buildGoogleHistory([first, second])).toThrow();
  });
  it("fails on duplicate history and invalid gap thresholds", () => {
    const report = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    expect(() => buildGoogleHistory([report, report])).toThrow();
    expect(() => buildGoogleHistory([report], 0)).toThrow();
  });
  it("never turns sample evidence into a Google LIVE claim", () => {
    const report = buildGoogleExecutiveReport(
      assessGoogleWorkspace(source(), {}, at));
    const text = JSON.stringify(report);
    expect(text).toContain("SYNTHETIC");
    expect(report.summary.providerLiveValidated).toBe(false);
    expect(report.externalProviderValidated).toBe(false);
    expect(report.customerCertified).toBe(false);
    expect(report.sourceTokensExported).toBe(false);
  });
});
