import { describe, expect, it } from "vitest";
import {
  buildBaselineFollowUpExecutive,
  exportBaselineFollowUpExecutive,
  verifyBaselineFollowUpExecutive,
} from "./baseline-followup-report";
import type { BaselineFollowUpView } from "./baseline-followup-service";

const org = "followup-report-tenant-12345";
const at = "2026-11-13T15:00:00.000Z";
function item(overrides: Partial<BaselineFollowUpView> = {}):
BaselineFollowUpView {
  return {
    id: "report-action-12345",
    organizationId: org, questionnaireVersion: 1,
    questionId: "backups", sourceDraftRevision: 3,
    revision: 2, severity: "CRITICAL",
    status: "OPEN", title: "Verify backup coverage",
    nextAction: "Collect restore-test evidence.",
    evidenceNeeded: "Dated restore report",
    evidenceReference: "doc-backups-12345",
    ownerUserId: "owner-12345",
    dueAt: "2026-11-12T15:00:00.000Z",
    completedAt: null,
    createdAt: "2026-11-01T15:00:00.000Z",
    updatedAt: "2026-11-12T15:00:00.000Z",
    independentlyVerified: false,
    securityCertified: false, historicalCyberScoreModified: false,
    ...overrides,
  };
}
describe("Management follow-up reporting with no false technical scoring", () => {
  it("summarizes overdue, unowned and incomplete work", () => {
    const result = buildBaselineFollowUpExecutive(org, [
      item(),
      item({
        id: "other-action-12345", questionId: "mfa",
        severity: "HIGH", status: "IN_PROGRESS",
        ownerUserId: null, dueAt: "2026-11-14T15:00:00.000Z",
      }),
    ], at);
    expect(result.summary.total).toBe(2);
    expect(result.summary.overdue).toBe(1);
    expect(result.summary.withoutOwner).toBe(1);
    expect(result.summary.highPriority).toBe(2);
    expect(result.summary.completedTechnicallyVerified).toBe(0);
    expect(result.summary.certifiedCompliant).toBe(false);
    expect(verifyBaselineFollowUpExecutive(result).valid).toBe(true);
  });
  it("counts a reported completion without technical proof", () => {
    const report = buildBaselineFollowUpExecutive(org, [
      item({
        status: "COMPLETED_REPORTED",
        completedAt: "2026-11-12T15:00:00.000Z",
      }),
    ], at);
    expect(report.summary.reportedComplete).toBe(1);
    expect(report.summary.overdue).toBe(0);
    expect(report.priorities[0]?.remediationVerified).toBe(false);
  });
  it("rejects data from another organization", () => {
    expect(() => buildBaselineFollowUpExecutive(org, [
      item({ organizationId: "other-tenant-12345" }),
    ], at)).toThrow();
  });
  it("rejects duplicate actions and exaggerated certification flags", () => {
    expect(() => buildBaselineFollowUpExecutive(org, [
      item(), item(),
    ], at)).toThrow();
    const forged = item();
    (forged as unknown as Record<string, unknown>).independentlyVerified =
      true;
    expect(() => buildBaselineFollowUpExecutive(org, [
      forged,
    ], at)).toThrow();
  });
  it("detects digest tampering and refuses exports", () => {
    const report = buildBaselineFollowUpExecutive(org, [item()], at);
    report.summary.overdue = 0;
    expect(verifyBaselineFollowUpExecutive(report).valid).toBe(false);
    expect(() => exportBaselineFollowUpExecutive(
      report, "JSON")).toThrow();
  });
  it("exports JSON, CSV and Markdown without security certification", () => {
    const report = buildBaselineFollowUpExecutive(org, [item()], at);
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const data = exportBaselineFollowUpExecutive(report, format);
      expect(data.payload.length).toBeGreaterThan(100);
      expect(data.containsRawSensitiveNotes).toBe(false);
      expect(data.customerSecurityCertified).toBe(false);
      expect(data.payloadDigest).toMatch(/^[a-f0-9]{64}$/);
    }
  });
  it("reproduces report from original source snapshots", () => {
    const rows = [item(), item({
      id: "second-action-12345", questionId: "mfa",
    })];
    const report = buildBaselineFollowUpExecutive(org, rows, at);
    expect(verifyBaselineFollowUpExecutive(report, rows).valid).toBe(true);
    const other = [item()];
    expect(verifyBaselineFollowUpExecutive(report, other).valid).toBe(false);
  });
});
