import { describe, expect, it } from "vitest";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import {
  buildIntegrityRemediationWorkspace,
  parseIntegrityRemediationDecisions,
  summarizeIntegrityRemediationDecisions,
  auditIntegrityRemediationDecisions,
  evaluateIntegrityRemediationReadiness,
  parseIntegrityRemediationDecisionPolicy,
} from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationGatePolicy,
  evaluateIntegrityRemediationGate,
  compareIntegrityRemediationGates,
} from "./work-integrity-remediation-gates";
import {
  parseIntegrityRemediationExportRequest,
  exportIntegrityRemediation,
} from "./work-integrity-remediation-export";
const captureId = "capture-one";
const input = {
  captureId,
  policies: [parseIntegrityEvidenceCoveragePolicy({
    captureId,
    rules: [{
      id: "rule-one", caseKey: "case-one",
      minimumActiveWorkItems: 1,
      requiredWorkItemIds: ["work-one"],
    }],
  })],
};
const event: IntegrityLinkHistoryEvent = {
  auditId: "audit-one", originalAuditId: null,
  action: "LINK", captureId, caseKey: "case-one",
  workItemId: "work-one", actorUserId: "actor-one",
  occurredAt: "2026-11-02T00:00:00.000Z",
};
describe("integrity remediation workspace", () => {
  it("generates a plan and workload from evidence", () => {
    const result = buildIntegrityRemediationWorkspace(input, []);
    expect(result.plan.candidates.length).toBeGreaterThan(0);
    expect(result.workload.totals.candidates).toBe(result.plan.candidates.length);
  });
  it("requires urgent candidate review before readiness", () => {
    const result = buildIntegrityRemediationWorkspace(input, []);
    expect(result.readiness.ready).toBe(false);
    expect(result.readiness.outstandingUrgent.length).toBeGreaterThan(0);
  });
  it("rejects duplicate candidate decisions", () => {
    const record = {
      candidateId: "candidate-one", decision: "DEFER",
      reason: "Awaiting review", reviewerId: "reviewer-one",
      reviewedAt: "2026-11-03T00:00:00.000Z",
    };
    expect(() => parseIntegrityRemediationDecisions([record, record])).toThrow();
  });
  it("rejects invalid reviewer timestamps", () => {
    expect(() => parseIntegrityRemediationDecisions([{
      candidateId: "candidate-one", decision: "ACCEPT",
      reason: "", reviewerId: "reviewer-one", reviewedAt: "invalid",
    }])).toThrow();
  });
  it("detects stale decisions and missing rejection reasons", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const decisions = parseIntegrityRemediationDecisions([{
      candidateId: "unknown-candidate", decision: "REJECT",
      reason: "", reviewerId: "reviewer-one",
      reviewedAt: "2026-11-03T00:00:00.000Z",
    }]);
    const audit = auditIntegrityRemediationDecisions(
      workspace.plan, decisions, parseIntegrityRemediationDecisionPolicy({}));
    expect(audit.valid).toBe(false);
    expect(audit.errors.length).toBeGreaterThanOrEqual(2);
  });
  it("counts pending decisions against the current plan", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const summary = summarizeIntegrityRemediationDecisions(workspace.plan, []);
    expect(summary.pending).toBe(workspace.plan.candidates.length);
    expect(summary.reviewCoverage).toBe(0);
  });
  it("rejects mismatched gate captures in readiness", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const report = evaluateIntegrityRemediationGate(workspace.plan,
      parseIntegrityRemediationGatePolicy({
        rules: [{ id: "gate-one", kind: "MAX_OPEN", threshold: 0 }],
      }));
    expect(() => evaluateIntegrityRemediationReadiness(
      workspace.plan, workspace.decisions, {
        ...report, captureId: "another-capture",
      })).toThrow();
  });
  it("fails a strict gate when remediation is outstanding", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const policy = parseIntegrityRemediationGatePolicy({
      rules: [{ id: "gate-one", kind: "MAX_OPEN", threshold: 0 }],
    });
    const report = evaluateIntegrityRemediationGate(workspace.plan, policy);
    expect(report.passed).toBe(false);
    expect(report.failingRules).toBe(1);
  });
  it("detects gate resolution when evidence is linked", () => {
    const policy = parseIntegrityRemediationGatePolicy({
      rules: [{
        id: "missing-work", kind: "REQUIRE_ACTION_LIMIT",
        action: "LINK_REQUIRED_WORK", threshold: 0,
      }],
    });
    const before = buildIntegrityRemediationWorkspace(input, []);
    const after = buildIntegrityRemediationWorkspace(input, [event]);
    const delta = compareIntegrityRemediationGates(
      evaluateIntegrityRemediationGate(before.plan, policy),
      evaluateIntegrityRemediationGate(after.plan, policy));
    expect(delta.resolved.map(x => x.ruleId)).toContain("missing-work");
  });
  it("rejects unknown gate action names", () => {
    expect(() => parseIntegrityRemediationGatePolicy({
      rules: [{
        id: "bad-action", kind: "REQUIRE_ACTION_LIMIT",
        action: "NOT_AN_ACTION", threshold: 0,
      }],
    })).toThrow();
  });
  it("exports candidate records as JSON", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const request = parseIntegrityRemediationExportRequest({
      format: "json", datasets: ["candidates"],
    });
    const result = exportIntegrityRemediation(workspace.plan, request);
    const rows = JSON.parse(result.files[0]!.body);
    expect(rows.length).toBe(workspace.plan.candidates.length);
  });
  it("exports candidate records with CSV headers", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const request = parseIntegrityRemediationExportRequest({
      format: "csv", datasets: ["candidates"],
    });
    const result = exportIntegrityRemediation(workspace.plan, request);
    expect(result.files[0]?.body).toContain('"candidateId"'.replace(
      "candidateId", "id"));
  });
  it("rejects exports requiring unavailable history", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, []);
    const request = parseIntegrityRemediationExportRequest({
      format: "jsonl", datasets: ["trends"],
    });
    expect(() => exportIntegrityRemediation(workspace.plan, request)).toThrow();
  });
  it("returns historical exports with workspace checkpoints", () => {
    const workspace = buildIntegrityRemediationWorkspace(input, [event], {
      checkpoints: [
        "2026-11-01T00:00:00.000Z",
        "2026-11-03T00:00:00.000Z",
      ],
      exportRequest: {
        format: "json", datasets: ["transitions"],
      },
    });
    expect(workspace.history?.transitions).toHaveLength(1);
    expect(workspace.exports?.files[0]?.rows).toBe(1);
  });
});
