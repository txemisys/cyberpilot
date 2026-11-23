import { describe, expect, it } from "vitest";
import { INCIDENT_TYPES, getIncidentPlaybook,
  validateIncidentPlaybooks, evaluatePlaybookCapability } from "./incident-playbook-catalog";
import { createIncident, incidentCreationEvent, applyIncidentCommand,
  incidentApprovalScope, incidentDigest, auditIncident, type IncidentMutation,
  type IncidentEvidence, type IncidentSnapshot } from "./incident-case-domain";
import { buildIncidentPortfolio, evaluateIncidentReadiness, exportIncidentDossier,
  summarizeIncidentEvidence, identifyIncidentEvidenceConflicts } from "./incident-operations-domain";
const at = "2026-11-23T12:00:00.000Z";
const after = "2026-11-23T12:01:00.000Z";
const id = "incident-1234", org = "tenant-1234", actor = "admin-1234";
function sample(type: typeof INCIDENT_TYPES[number] = "PHISHING_CAMPAIGN") {
  return createIncident({ id, organizationId: org, type, title: "Observed suspicious activity",
    subjectReference: "provider-object-1234", actorUserId: actor,
    at, ownerUserId: null });
}
function cmd(s: IncidentSnapshot, kind: IncidentMutation["kind"],
  extra: Partial<IncidentMutation> = {}) {
  return applyIncidentCommand(s, { incidentId: s.id, organizationId: s.organizationId,
    actorUserId: actor, role: "ADMIN", expectedRevision: s.revision,
    at: after, kind, ...extra });
}
function observed(stepId: string, source: string): IncidentEvidence {
  return { id: "evidence-1234", stepId, source, sourceReference: "source-1234",
    verdict: "OBSERVED", summary: "Verified by independent provider record",
    observedAt: at, recordedAt: at, independent: true, providerOperation: false };
}
describe("guided incident playbook registry", () => {
  it("defines five stable distinct fully guided playbooks", () => {
    expect(INCIDENT_TYPES).toHaveLength(5);
    expect(validateIncidentPlaybooks()).toEqual([]);
    const stepIds = new Set<string>();
    for (const type of INCIDENT_TYPES) {
      const book = getIncidentPlaybook(type);
      expect(book.steps.length).toBeGreaterThanOrEqual(6);
      expect(book.providerWrites).toBe(0);
      expect(book.scopeLimitations.length).toBeGreaterThanOrEqual(2);
      for (const step of book.steps) {
        expect(step.automationAllowed).toBe(false);
        expect(step.fallback.length).toBeGreaterThan(10);
        expect(step.proofRequired.length).toBeGreaterThan(0);
        stepIds.add(type + "/" + step.id);
      }
    }
    expect(stepIds.size).toBe(INCIDENT_TYPES.reduce(
      (n, type) => n + getIncidentPlaybook(type).steps.length, 0));
  });
  it("rejects unsupported types, keeps missing provider capabilities unavailable", () => {
    expect(() => getIncidentPlaybook("NOT_A_PLAYBOOK" as typeof INCIDENT_TYPES[number]))
      .toThrow("INCIDENT_TYPE_UNSUPPORTED");
    for (const type of INCIDENT_TYPES) {
      const capabilities = evaluatePlaybookCapability(type, new Set());
      expect(capabilities.every(c => c.availability === "UNAVAILABLE")).toBe(true);
      expect(capabilities.every(c => c.operationExecuted === false)).toBe(true);
    }
  });
});
describe("immutable incident case transitions", () => {
  it("initializes each book and commits valid append-only creation event", () => {
    for (const type of INCIDENT_TYPES) {
      const s = sample(type), e = incidentCreationEvent(s);
      expect(e.snapshotDigest).toBe(incidentDigest(s));
      expect(auditIncident(s, [e]).valid).toBe(true);
      expect(s.providerOperations).toBe(0);
      expect(s.containmentVerified).toBe(false);
    }
  });
  it("preserves snapshot digest across PostgreSQL JSONB key ordering", () => {
    const source = sample("COMPROMISED_ACCOUNT");
    const reorder = (item: unknown): unknown => {
      if (Array.isArray(item)) return item.map(reorder);
      if (item && typeof item === "object") {
        return Object.fromEntries(Object.entries(item).reverse().map(
          ([key, value]) => [key, reorder(value)]));
      }
      return item;
    };
    const reordered = reorder(source) as IncidentSnapshot;
    expect(incidentDigest(reordered)).toBe(incidentDigest(source));
    expect(auditIncident(reordered, [incidentCreationEvent(source)]).valid).toBe(true);
  });
  it("rejects stale revisions and cross-tenant mutations without event", () => {
    const s = sample();
    expect(cmd(s, "START_TRIAGE", { expectedRevision: 0 }).code)
      .toBe("INCIDENT_REVISION_CONFLICT");
    expect(cmd(s, "START_TRIAGE", { organizationId: "another-tenant" }).code)
      .toBe("INCIDENT_SCOPE_OR_ACTOR_INVALID");
    expect(cmd(s, "START_CONTAINMENT").code)
      .toBe("INCIDENT_STATE_TRANSITION_INVALID");
    expect(cmd(s, "STEP_VERIFY", { stepId: s.steps[0]!.stepId }).accepted).toBe(false);
  });
  it("advances triage only in permitted order", () => {
    const s = sample();
    const triage = cmd(s, "START_TRIAGE");
    expect(triage.accepted).toBe(true);
    expect(triage.snapshot.status).toBe("TRIAGE");
    expect(triage.snapshot.revision).toBe(2);
    expect(cmd(triage.snapshot, "START_RECOVERY").accepted).toBe(false);
    expect(cmd(triage.snapshot, "START_CONTAINMENT").accepted).toBe(true);
  });
  it("requires observed independent evidence, not a declaration, for verification", () => {
    const s = sample();
    const stepId = s.steps[0]!.stepId;
    const started = cmd(s, "STEP_START", { stepId }).snapshot;
    const added = cmd(started, "ATTACH_EVIDENCE", { stepId,
      evidence: { ...observed(stepId, "message-headers"), verdict: "DECLARED" } }).snapshot;
    const reported = cmd(added, "STEP_REPORT", { stepId }).snapshot;
    expect(cmd(reported, "STEP_VERIFY", { stepId }).code)
      .toBe("INCIDENT_INDEPENDENT_EVIDENCE_REQUIRED");
    const independent = cmd(reported, "ATTACH_EVIDENCE", { stepId,
      evidence: { ...observed(stepId, "message-headers"), id: "evidence-5678" } }).snapshot;
    const checked = cmd(independent, "STEP_VERIFY", { stepId });
    expect(checked.accepted).toBe(true);
    expect(checked.snapshot.steps[0]!.verifiedById).toBe(actor);
    expect(checked.snapshot.containmentVerified).toBe(false);
  });
  it("does not allow expired or mismatched approval scope", () => {
    const s = sample("LOST_DEVICE");
    const stepId = "wipe";
    const bad = cmd(s, "RECORD_APPROVAL", { stepId, approval: {
      stepId, approvedById: actor, approvedAt: at,
      expiresAt: "2026-11-23T13:00:00.000Z",
      reason: "Approved by assigned administrator",
      scopeDigest: "0".repeat(64), forExecution: false,
    } });
    expect(bad.code).toBe("INCIDENT_APPROVAL_SCOPE_INVALID");
    const good = cmd(s, "RECORD_APPROVAL", { stepId, approval: {
      ...bad.snapshot.approvals[0], stepId, approvedById: actor,
      approvedAt: at, expiresAt: "2026-11-23T13:00:00.000Z",
      reason: "Authorized select corporate content wipe after confirmation",
      scopeDigest: incidentApprovalScope(s, stepId), forExecution: false,
    } });
    expect(good.accepted).toBe(true);
    expect(good.snapshot.providerOperations).toBe(0);
  });
  it("rejects false technical claims and tampered digest", () => {
    const s = sample();
    const forged = { ...s, containmentVerified: true as false };
    expect(() => incidentCreationEvent(forged)).toThrow();
    const corrupt = { ...incidentCreationEvent(s), snapshotDigest: "f".repeat(64) };
    expect(auditIncident(s, [corrupt]).valid).toBe(false);
  });
  it("does not close workflows with unresolved steps", () => {
    const s = sample();
    const triage = cmd(s, "START_TRIAGE").snapshot;
    const review = cmd(triage, "REQUEST_REVIEW", {
      reason: "Need a follow-up review for incomplete evidence",
    }).snapshot;
    expect(cmd(review, "CLOSE", {
      reason: "Attempt to close despite incomplete evidence",
    }).code).toBe("INCIDENT_OPEN_STEPS");
  });
});
describe("incident portfolio, exports and evidence coverage", () => {
  it("refuses cross-org portfolio and dossier", () => {
    const s = sample();
    expect(() => buildIncidentPortfolio("other-tenant", [s], false, at)).toThrow();
    expect(() => exportIncidentDossier(s, [{ ...incidentCreationEvent(s),
      organizationId: "other-tenant" }], "CSV")).toThrow();
  });
  it("conservatively counts unknown evidence and outstanding actions", () => {
    const s = sample("RANSOMWARE");
    const p = buildIncidentPortfolio(org, [s], false, after);
    expect(p.urgent).toBe(1);
    expect(p.unassigned).toBe(1);
    expect(p.riskReductionProven).toBe(false);
    const readiness = evaluateIncidentReadiness(s, after);
    expect(readiness.gate).toBe("REQUIRES_REVIEW");
    expect(readiness.technicalContainmentEstablished).toBe(false);
  });
  it("exports CSV without formula injection and carries caution in JSON and Markdown", () => {
    const s = sample();
    const e = incidentCreationEvent(s);
    s.evidence.push({ ...observed(s.steps[0]!.stepId, "=HYPERLINK(123)"),
      id: "export-1234" });
    const csv = exportIncidentDossier(s, [e], "CSV");
    expect(csv.content).toContain("'=HYPERLINK");
    expect(exportIncidentDossier(s, [e], "JSON").content).toContain("actualContainmentVerified");
    expect(exportIncidentDossier(s, [e], "MARKDOWN").content).toContain("Provider writes performed: 0");
  });
  it("reports contradictory telemetry instead of hiding it", () => {
    const one = observed("sample", "message-headers");
    expect(identifyIncidentEvidenceConflicts([one, { ...one,
      id: "other-1234", verdict: "ERROR" }])).toHaveLength(1);
    const s = sample();
    s.evidence.push({ ...one, stepId: s.steps[0]!.stepId });
    expect(summarizeIncidentEvidence(s, after).coverage[0]?.independent).toBe(1);
  });
});
