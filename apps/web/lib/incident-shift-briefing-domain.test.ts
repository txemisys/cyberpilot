import { describe, it, expect } from "vitest";
import { normalizeTimelineEvent, type TimelineEvent } from
  "./incident-operational-timeline-domain";
import { inspectIncidentForensics } from
  "./incident-timeline-forensics-domain";
import { buildInvestigationCasebook } from
  "./incident-timeline-investigation-domain";
import {
  buildIncidentShiftBriefing, defaultShiftPolicy, validateShiftPolicy,
  validateShiftWindow, verifyIncidentShiftBriefing,
  previewShiftAcceptance, compareShiftBriefings, shiftRoleWorkload,
  shiftProofMatrix, shiftPrioritizedQueue, exportShiftJSON,
  exportShiftWorkCSV, exportShiftMarkdown,
  type ShiftWindow,
} from "./incident-shift-briefing-domain";
const org = "org-shift-test";
const incident = "incident-shift-test";
const at = "2026-11-24T14:00:00.000Z";
const digest = "a".repeat(64);
function event(revision = 1): TimelineEvent {
  return normalizeTimelineEvent({
    organizationId: org, incidentId: incident, source: "INCIDENT",
    sourceId: incident, sourceRevision: revision,
    eventId: "event-" + revision,
    actorUserId: "owner-shift-test",
    operation: revision === 1 ? "CREATE" : "REVIEW",
    occurredAt: new Date(Date.parse(at) - 1800000 +
      revision * 60000).toISOString(),
    priorState: revision === 1 ? null : "OPEN",
    nextState: "OPEN",
    priorDigest: revision === 1 ? null : digest,
    nextDigest: digest, sourceEventDigest: null,
    sourceIntegrity: "INCOMPLETE",
  });
}
function window(overrides: Partial<ShiftWindow> = {}): ShiftWindow {
  return {
    shiftId: "shift-test-0001",
    startsAt: "2026-11-24T13:00:00.000Z",
    endsAt: "2026-11-24T15:00:00.000Z",
    evaluatedAt: at,
    outgoingRole: "OWNER", incomingRole: "ADMIN",
    outgoingUserId: "owner-shift-test", incomingUserId: null,
    acknowledgedBy: null, acceptedAt: null,
    ...overrides,
  };
}
function brief(events = [event(1)], w = window()) {
  const forensics = inspectIncidentForensics({
    organizationId: org, incidentId: incident,
    analyzedAt: at, events, inventoryComplete: true,
  });
  const investigation = buildInvestigationCasebook({
    organizationId: org, incidentId: incident,
    generatedAt: at, events, report: forensics,
  });
  return buildIncidentShiftBriefing({
    organizationId: org, incidentId: incident, incidentRevision: 1,
    window: w, events, forensics, investigation,
  });
}
describe("internal incident shift briefing", () => {
  it("proposes an auditable handoff without persisted receipt or external writes", () => {
    const result = brief();
    expect(verifyIncidentShiftBriefing(result)).toEqual([]);
    expect(result.receiptIssued).toBe(false);
    expect(result.handoffAcknowledged).toBe(false);
    expect(result.externalActions).toBe(0);
    expect(result.providerOutcomesIndependentlyVerified).toBe(false);
    expect(result.activity[0]?.providerReceiptAvailable).toBe(false);
    expect(result.workItems.every(x =>
      x.providerWritePermitted === false &&
      x.assignedUserId === null)).toBe(true);
  });
  it("rejects forged acknowledgements, external actions and policy waivers", () => {
    expect(validateShiftWindow(window({
      acknowledgedBy: "owner-shift-test" as never,
    }))).toContain("SHIFT_FORGED_ACKNOWLEDGEMENT");
    expect(validateShiftPolicy({
      ...defaultShiftPolicy(),
      allowExternalActions: true as never,
    })).toContain("SHIFT_POLICY_PROVIDER_WRITE_FORBIDDEN");
    expect(verifyIncidentShiftBriefing({
      ...brief(), handoffAcknowledged: true as never,
    })).toContain("SHIFT_BRIEF_FALSE_ACCEPTANCE_OR_EXECUTION");
  });
  it("denies cross-tenant event mixing before investigation projection", () => {
    const own = event(1);
    const forensics = inspectIncidentForensics({
      organizationId: org, incidentId: incident,
      analyzedAt: at, events: [own], inventoryComplete: true,
    });
    const investigation = buildInvestigationCasebook({
      organizationId: org, incidentId: incident,
      generatedAt: at, events: [own], report: forensics,
    });
    expect(() => buildIncidentShiftBriefing({
      organizationId: org, incidentId: incident, incidentRevision: 1,
      window: window(), events: [{
        ...own, organizationId: "org-other",
      }], forensics, investigation,
    })).toThrow("SHIFT_CROSS_TENANT_OR_INCIDENT");
  });
  it("emits conservative coverage and freshness watchpoints", () => {
    const value = brief();
    expect(value.watchpoints.some(x =>
      x.category === "COVERAGE")).toBe(true);
    expect(value.sourceInventory.find(x =>
      x.source === "INCIDENT")?.eventCount).toBe(1);
    expect(shiftProofMatrix(value).every(x =>
      x.independentlyVerifiedEvents === 0 &&
      x.providerReceipts === 0)).toBe(true);
  });
  it("rejects stale confirmation preview without persisting anything", () => {
    const value = brief();
    expect(() => previewShiftAcceptance({
      briefing: value, actorId: "admin-incoming-test",
      actorRole: "ADMIN", action: "REVIEW_PREVIEW",
      checkedAt: at, expectedDigest: digest,
    })).toThrow("SHIFT_ACCEPTANCE_STALE_DIGEST");
    const reviewed = previewShiftAcceptance({
      briefing: value, actorId: "admin-incoming-test",
      actorRole: "ADMIN", action: "REQUEST_RECONCILIATION",
      checkedAt: at, expectedDigest: value.digest,
    });
    expect(reviewed.locallyRecorded).toBe(false);
    expect(reviewed.providerActionsAuthorized).toBe(false);
    expect(reviewed.canAcknowledgeAfterPersistence).toBe(false);
  });
  it("classifies role workload and bounded priority order", () => {
    const value = brief();
    const workload = shiftRoleWorkload(value);
    expect(workload).toHaveLength(3);
    expect(workload.every(w => w.isConfirmedOwner === false)).toBe(true);
    expect(shiftPrioritizedQueue(value).length).toBe(
      value.workItems.length);
    expect(shiftPrioritizedQueue(value, "AUDITOR").every(x =>
      x.assignedRole === "AUDITOR")).toBe(true);
  });
  it("exports digest-checked JSON, CSV and markdown with safety caveats", () => {
    const value = brief();
    expect(JSON.parse(exportShiftJSON(value)).digest).toBe(value.digest);
    expect(exportShiftWorkCSV(value)).toContain("providerWrites");
    expect(exportShiftMarkdown(value)).toContain(
      "No acredita contención");
    expect(() => exportShiftJSON({
      ...value, digest: "b".repeat(64),
    })).toThrow("SHIFT_EXPORT_INVALID");
  });
  it("reports delta without treating disappearance as successful mitigation", () => {
    const before = brief([event(1)]);
    const after = brief([event(1), event(2)]);
    const result = compareShiftBriefings(before, after);
    expect(result.newEvents.length).toBe(1);
    expect(result.mitigationProven).toBe(false);
    expect(result.acknowledgementProven).toBe(false);
    expect(() => compareShiftBriefings(before, {
      ...after, incidentId: "incident-foreign",
    })).toThrow("SHIFT_COMPARE_INVALID");
  });
});
