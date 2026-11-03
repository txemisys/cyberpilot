import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationSlaPolicy,
  addIntegritySlaHours,
  countIntegritySlaMinutes,
  evaluateIntegrityRemediationSla,
  parseIntegrityRemediationSlaQuery,
  queryIntegrityRemediationSla,
  compareIntegrityRemediationSla,
} from "./work-integrity-remediation-sla";
import {
  parseIntegrityEscalationPolicy,
  parseIntegrityEscalationAcknowledgements,
  evaluateIntegrityEscalations,
  parseIntegrityEscalationQuery,
  queryIntegrityEscalations,
  buildIntegrityEscalationDeliveryManifest,
  compareIntegrityEscalationReports,
} from "./work-integrity-remediation-escalation";
const start = "2026-11-02T09:00:00.000Z";
const later = "2026-11-05T09:00:00.000Z";
const input = {
  captureId: "capture-one",
  policies: [parseIntegrityEvidenceCoveragePolicy({
    captureId: "capture-one",
    rules: [{
      id: "rule-one", caseKey: "case-one",
      minimumActiveWorkItems: 1, requiredWorkItemIds: ["work-one"],
    }],
  })],
};
const rules = (hours = 1) => ["P0", "P1", "P2", "P3"].map(priority => ({
  priority, responseHours: hours,
  resolutionHours: hours * 2, escalationHours: hours * 3,
}));
const slaPolicy = parseIntegrityRemediationSlaPolicy({
  clock: "CALENDAR", rules: rules(),
});
const escalationPolicy = parseIntegrityEscalationPolicy({
  rules: [{
    id: "breach", level: "CRITICAL",
    statuses: ["ESCALATION_OVERDUE", "RESOLUTION_OVERDUE"],
    minimumOverdueMinutes: 1, minimumRiskPoints: 0,
    channels: ["IN_APP", "EMAIL"], recipients: ["owner"],
  }],
});
describe("integrity remediation SLA", () => {
  it("computes calendar-hour deadlines", () => {
    expect(addIntegritySlaHours(start, 2, slaPolicy))
      .toBe("2026-11-02T11:00:00.000Z");
  });
  it("computes business-hour deadlines over a weekend", () => {
    const business = parseIntegrityRemediationSlaPolicy({
      clock: "BUSINESS", rules: rules(),
    });
    expect(addIntegritySlaHours("2026-11-06T16:00:00.000Z", 2, business))
      .toBe("2026-11-09T10:00:00.000Z");
  });
  it("counts only business minutes", () => {
    const business = parseIntegrityRemediationSlaPolicy({
      clock: "BUSINESS", rules: rules(),
    });
    expect(countIntegritySlaMinutes(
      "2026-11-06T16:00:00.000Z",
      "2026-11-09T10:00:00.000Z", business)).toBe(120);
  });
  it("rejects duplicate priority rules", () => {
    expect(() => parseIntegrityRemediationSlaPolicy({
      rules: [rules()[0], rules()[0], rules()[2], rules()[3]],
    })).toThrow();
  });
  it("reports overdue candidate deadlines", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const report = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    expect(report.totals.candidates).toBeGreaterThan(0);
    expect(report.totals.escalationOverdue).toBeGreaterThan(0);
  });
  it("paginates overdue candidates", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const report = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const query = parseIntegrityRemediationSlaQuery({
      overdueOnly: true, limit: 1,
    });
    expect(queryIntegrityRemediationSla(report, query).entries).toHaveLength(1);
  });
  it("detects worsening compliance", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const before = evaluateIntegrityRemediationSla(
      plan, [], start, start, slaPolicy);
    const after = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    expect(compareIntegrityRemediationSla(before, after)
      .deteriorated.length).toBeGreaterThan(0);
  });
});
describe("integrity remediation escalation", () => {
  it("creates critical alerts for overdue work", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const sla = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const report = evaluateIntegrityEscalations(sla, escalationPolicy);
    expect(report.totals.critical).toBeGreaterThan(0);
  });
  it("generates recipient delivery manifests", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const sla = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const report = evaluateIntegrityEscalations(sla, escalationPolicy);
    const manifest = buildIntegrityEscalationDeliveryManifest(report);
    expect(manifest.some(x => x.channel === "EMAIL" &&
      x.recipient === "owner")).toBe(true);
  });
  it("filters escalation alerts by severity", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const sla = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const report = evaluateIntegrityEscalations(sla, escalationPolicy);
    const page = queryIntegrityEscalations(report,
      parseIntegrityEscalationQuery({ levels: ["CRITICAL"], limit: 1 }));
    expect(page.alerts).toHaveLength(1);
  });
  it("rejects duplicate alert acknowledgements", () => {
    const record = {
      alertId: "alert-one", acknowledgedBy: "actor-one",
      acknowledgedAt: later, note: "Reviewed",
    };
    expect(() => parseIntegrityEscalationAcknowledgements([
      record, record,
    ])).toThrow();
  });
  it("suppresses alerts during the cooldown window", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const sla = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const before = evaluateIntegrityEscalations(sla, escalationPolicy);
    const after = evaluateIntegrityEscalations(
      sla, escalationPolicy, [], [], before);
    expect(after.totals.alerts).toBe(0);
    expect(after.totals.suppressed).toBeGreaterThan(0);
  });
  it("compares alert introduction and resolution", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const before = evaluateIntegrityEscalations(
      evaluateIntegrityRemediationSla(
        plan, [], start, start, slaPolicy), escalationPolicy);
    const after = evaluateIntegrityEscalations(
      evaluateIntegrityRemediationSla(
        plan, [], start, later, slaPolicy), escalationPolicy);
    expect(compareIntegrityEscalationReports(before, after)
      .introduced.length).toBeGreaterThan(0);
  });
  it("does not mistake accepting a proposal for verified completion", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const candidate = plan.candidates[0]!;
    const decisions = [{
      candidateId: candidate.id, decision: "ACCEPT" as const,
      reason: "Approved for work", reviewerId: "reviewer",
      reviewedAt: start,
    }];
    const sla = evaluateIntegrityRemediationSla(
      plan, decisions, start, later, slaPolicy);
    const row = sla.entries.find(x => x.candidateId === candidate.id);
    expect(row?.status).not.toBe("RESOLVED");
    expect(row?.resolutionAt).toBeNull();
  });
  it("rejects unissued alert acknowledgements as proof of acknowledgement", () => {
    const plan = buildIntegrityRemediationWorkspace(input, []).plan;
    const sla = evaluateIntegrityRemediationSla(
      plan, [], start, later, slaPolicy);
    const first = evaluateIntegrityEscalations(sla, escalationPolicy);
    const acknowledgements = parseIntegrityEscalationAcknowledgements(
      first.alerts.map(x => ({
        alertId: x.id, acknowledgedBy: "reviewer",
        acknowledgedAt: later, note: "Acknowledged",
      })));
    const unissued = evaluateIntegrityEscalations(
      sla, escalationPolicy, [], acknowledgements);
    expect(unissued.totals.acknowledged).toBe(0);
  });
});
