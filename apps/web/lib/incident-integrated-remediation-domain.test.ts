import { describe, expect, it } from "vitest";
import { createIncident } from "./incident-case-domain";
import { assessIncidentRemediationReadiness }
  from "./incident-integrated-remediation-domain";
import { planRemediationHandoffs, summarizeRemediationReadiness,
  buildIncidentRemediationDecisions, exportRemediationIntegration }
  from "./incident-integrated-remediation-operations";
const at = "2026-11-23T09:00:00.000Z";
const incident = () => createIncident({ id: "incident-1234",
  organizationId: "tenant-1234", type: "COMPROMISED_ACCOUNT",
  title: "Identity containment", subjectReference: "principal-1234",
  actorUserId: "admin-1234", ownerUserId: null, at });
const finding = { id: "finding-1234", organizationId: "tenant-1234",
  severity: "CRITICAL", status: "OPEN", title: "Excess privilege",
  ruleId: "IAM-100", lastSeenAt: at };
const remediation = { id: "remediation-1234", organizationId: "tenant-1234",
  findingId: finding.id, playbookId: "revoke-sessions",
  mode: "GUIDED" as const, status: "PROPOSED", title: "Revoke sessions",
  summary: "Approved session containment",
  approvedByUserId: null, approvedAt: null, startedAt: null,
  completedAt: null, verifiedAt: null, failureCode: null,
  createdAt: at, updatedAt: at };
const work = { id: "work-1234", organizationId: "tenant-1234",
  remediationId: remediation.id, findingId: finding.id,
  title: "Review sessions", status: "TODO", priority: "HIGH",
  assigneeUserId: null, dueAt: null, revision: 1,
  completedAt: null };
function review(overrides: Record<string, unknown> = {}) {
  return assessIncidentRemediationReadiness({
    incident: incident(), selection: { remediationIds: [remediation.id],
      findingIds: [finding.id], workItemIds: [work.id],
      expectedIncidentRevision: 1 },
    remediations: [remediation], findings: [finding],
    works: [work], at, approvalMaxAgeHours: 24,
    truncated: false, ...overrides,
  });
}
describe("incident remediation supervisory integration", () => {
  it("connects only selected persisted remediations with human-only handoffs", () => {
    const result = review();
    expect(result.targetReviews).toHaveLength(1);
    expect(result.targetReviews[0]?.selectedVia).toBe("EXPLICIT_ID");
    expect(result.actualProviderWrites).toBe(0);
    expect(result.consentEstablishedForAutomatedExecution).toBe(false);
    expect(planRemediationHandoffs(result).automaticExecutionEnabled).toBe(false);
  });
  it("blocks automated modes without external consents, even if historically verified", () => {
    const result = review({ remediations: [{
      ...remediation, mode: "AUTOMATED", status: "VERIFIED",
    }] });
    expect(result.gate).toBe("BLOCKED");
    expect(result.unsafeAutomations).toBe(1);
    expect(result.targetReviews[0]?.barriers)
      .toContain("AUTOMATED_MODE_NOT_AUTHORIZED");
    expect(result.actualContainmentVerified).toBe(false);
  });
  it("rejects self approval, stale case revisions and cross-tenant rows", () => {
    const s = incident();
    const approved = { ...remediation,
      approvedByUserId: s.updatedById, approvedAt: at };
    const a = review({ incident: s, remediations: [approved] });
    expect(a.targetReviews[0]?.barriers)
      .toContain("APPROVER_IS_INCIDENT_OWNER");
    const stale = review({ selection: { remediationIds: [remediation.id],
      findingIds: [], workItemIds: [], expectedIncidentRevision: 0 } });
    expect(stale.blockers).toContain("INCIDENT_REVISION_DRIFT");
    const foreign = review({ findings: [{
      ...finding, organizationId: "foreign-tenant",
    }] });
    expect(foreign.foreignTenantIds).toContain(finding.id);
    expect(foreign.gate).toBe("BLOCKED");
  });
  it("retains unknown state when work is unfinished or finding is resolved", () => {
    const missing = review({ findings: [{ ...finding, status: "RESOLVED" }] });
    expect(missing.targetReviews[0]?.barriers).toContain("FINDING_NOT_OPEN");
    expect(review().unfinishedWorkItems).toBe(1);
    expect(review().missingIndependentProof).toBeGreaterThan(0);
  });
  it("exposes safe manual decisions and export without executor operations", () => {
    const result = review();
    expect(summarizeRemediationReadiness(result).effectiveSecurityRemediationProven)
      .toBe(false);
    expect(buildIncidentRemediationDecisions(result)[0]?.autoExecution).toBe(false);
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const artifact = exportRemediationIntegration(result, format);
      expect(artifact.content.length).toBeGreaterThan(0);
      expect(artifact.digest).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});
