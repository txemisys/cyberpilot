import { describe, it, expect } from "vitest";
import { normalizeTimelineEvent } from "./incident-operational-timeline-domain";
import { inspectIncidentForensics } from "./incident-timeline-forensics-domain";
import {
  buildInvestigationCasebook, verifyInvestigationCasebook,
  compareInvestigationCasebooks, investigationTaskQueue,
  exportInvestigationCasebookJSON, exportInvestigationTaskCSV,
  validateInvestigationPolicy,
} from "./incident-timeline-investigation-domain";
const org = "org-casebook-test";
const incident = "incident-casebook-test";
const at = "2026-11-24T14:00:00.000Z";
const a = "a".repeat(64);
function make(overrides: Record<string, unknown> = {}) {
  return normalizeTimelineEvent({
    organizationId: org, incidentId: incident, source: "INCIDENT",
    sourceId: incident, sourceRevision: 1, eventId: "event-casebook",
    actorUserId: "operator-user", operation: "CREATE",
    occurredAt: "2026-11-24T13:30:00.000Z",
    priorState: null, nextState: "OPEN", priorDigest: null,
    nextDigest: a, sourceEventDigest: null,
    sourceIntegrity: "INCOMPLETE", ...overrides,
  });
}
function casebook(options: { missing?: boolean; other?: boolean } = {}) {
  const event = make(options.other ? { sourceId: "incident-different" } : {});
  const report = inspectIncidentForensics({
    organizationId: org, incidentId: incident, analyzedAt: at,
    inventoryComplete: !options.missing, events: [event],
    requiredSources: options.missing ? ["TABLETOP_SESSION"] : [],
  });
  return buildInvestigationCasebook({
    organizationId: org, incidentId: incident,
    generatedAt: at, events: [event], report,
  });
}
describe("forensic investigation casebook", () => {
  it("offers evidence requests without assigning owners or executing actions", () => {
    const value = casebook();
    expect(verifyInvestigationCasebook(value)).toEqual([]);
    expect(value.signals.length).toBeGreaterThan(0);
    expect(value.tasks[0]?.manualOnly).toBe(true);
    expect(value.tasks[0]?.ownerUserId).toBeNull();
    expect(value.requests[0]?.collected).toBe(false);
    expect(value.externalWrites).toBe(0);
    expect(value.providerOutcomesVerified).toBe(false);
  });
  it("classifies missing sources and preserves unknown coverage", () => {
    const value = casebook({ missing: true });
    expect(value.signals.some(s => s.workstream === "COVERAGE")).toBe(true);
    expect(value.tasks.some(t => t.status === "BLOCKED")).toBe(true);
    expect(value.inventoryComplete).toBe(false);
  });
  it("validates safe policy, bounded output and forbidden external claims", () => {
    expect(() => validateInvestigationPolicy({
      requireSeparateApproval: false,
    })).toThrow("INVESTIGATION_POLICY_UNSAFE");
    expect(() => validateInvestigationPolicy({
      maximumSignals: 0,
    })).toThrow("INVESTIGATION_POLICY_LIMIT_INVALID");
    const value = casebook();
    expect(verifyInvestigationCasebook({
      ...value, providerOutcomesVerified: true as never,
    })).toContain("CASEBOOK_PROVIDER_CLAIM_INVALID");
    expect(() => buildInvestigationCasebook({
      organizationId: "org-other", incidentId: incident,
      generatedAt: at, events: [make()], report:
        inspectIncidentForensics({
          organizationId: org, incidentId: incident,
          analyzedAt: at, inventoryComplete: true, events: [make()],
        }),
    })).toThrow("INVESTIGATION_SCOPE_MISMATCH");
  });
  it("enforces source-digest integrity in exports", () => {
    const value = casebook();
    expect(JSON.parse(exportInvestigationCasebookJSON(value)).digest)
      .toBe(value.digest);
    expect(exportInvestigationTaskCSV(value)).toContain("externalActions");
    expect(() => exportInvestigationTaskCSV({
      ...value, digest: "a".repeat(64),
    })).toThrow("CASEBOOK_EXPORT_INVALID");
  });
  it("reports disappearance as inventory change, never remediation proof", () => {
    const before = casebook({ missing: true });
    const after = casebook();
    const diff = compareInvestigationCasebooks(before, after);
    expect(diff.noLongerPresent.length).toBeGreaterThan(0);
    expect(diff.independentProviderVerification).toBe(false);
    const invalid = { ...after, organizationId: "org-other" };
    expect(() => compareInvestigationCasebooks(before, invalid))
      .toThrow("CASEBOOK_COMPARE_INVALID");
  });
  it("filters internal role queues without altering evidence", () => {
    const value = casebook({ missing: true });
    const auditor = investigationTaskQueue(value, "AUDITOR");
    expect(auditor.every(t => t.assignedRole === "AUDITOR")).toBe(true);
    expect(investigationTaskQueue(value).length).toBe(value.tasks.length);
  });
});
