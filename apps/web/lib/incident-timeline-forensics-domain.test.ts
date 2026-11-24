import { describe, expect, it } from "vitest";
import {
  inspectIncidentForensics, compareForensicReports,
  validateForensicRequest,
} from "./incident-timeline-forensics-domain";
import { normalizeTimelineEvent, type TimelineEvent } from
  "./incident-operational-timeline-domain";
const org = "org-forensic-test";
const incident = "incident-forensic-test";
const at = "2026-11-24T14:00:00.000Z";
const a = "a".repeat(64);
const b = "b".repeat(64);
function event(rev: number, overrides: Partial<TimelineEvent> = {}) {
  return normalizeTimelineEvent({
    organizationId: org, incidentId: incident,
    source: "INCIDENT", sourceId: incident,
    sourceRevision: rev, eventId: "event-" + rev,
    actorUserId: "operator-user", operation: rev === 1 ? "CREATE" : "REVIEW",
    occurredAt: new Date(Date.parse(at) - 600000 + rev * 60000).toISOString(),
    priorState: rev === 1 ? null : "OPEN", nextState: "OPEN",
    priorDigest: rev === 1 ? null : a,
    nextDigest: rev === 1 ? a : b,
    sourceEventDigest: a, sourceIntegrity: "INCOMPLETE",
    ...overrides,
  });
}
const run = (events: TimelineEvent[], expectedRevision = events.length) =>
  inspectIncidentForensics({
    organizationId: org, incidentId: incident, analyzedAt: at,
    events, inventoryComplete: true,
    expectations: [{
      source: "INCIDENT", sourceId: incident,
      expectedRevision, expectedDigest: events.at(-1)?.nextDigest ?? b,
      inventoryComplete: true,
    }],
  });
describe("incident timeline forensic reconciliation", () => {
  it("rejects malformed foreign tenant rows before considering validity", () => {
    const row = { ...event(1), organizationId: "org-other",
      sourceRevision: 0 };
    expect(() => run([row])).toThrow("FORENSIC_CROSS_TENANT_OR_INCIDENT");
    expect(() => run([{ ...event(1), incidentId: "incident-other" }]))
      .toThrow("FORENSIC_CROSS_TENANT_OR_INCIDENT");
  });
  it("reconciles a continuous internal ledger without provider claims", () => {
    const r = run([event(1), event(2)], 2);
    expect(r.integrity).toBe("VERIFIED");
    expect(r.externalActions).toBe(0);
    expect(r.independentProviderProof).toBe(false);
    expect(r.ledgers[0]?.eventDigestCoverage).toBe(2);
  });
  it("reports missing origin, gaps and expected revision mismatch", () => {
    const r = run([event(2), event(4, { priorDigest: b })], 5);
    expect(r.findings.map(x => x.code)).toContain("FIRST_REVISION_MISSING");
    expect(r.findings.map(x => x.code)).toContain("REVISION_GAP");
    expect(r.findings.map(x => x.code)).toContain("SNAPSHOT_REVISION_MISMATCH");
    expect(r.integrity).toBe("INCOMPLETE");
  });
  it("detects duplicate revision, broken chain and timestamp regression", () => {
    const r = run([event(1), event(2), event(2, {
      eventId: "event-other", priorDigest: a,
      occurredAt: "2026-11-24T12:00:00.000Z",
    })], 2);
    expect(r.integrity).toBe("CONFLICT");
    expect(r.findings.map(x => x.code)).toContain("REVISION_DUPLICATE");
    expect(r.findings.map(x => x.code)).toContain("CHAIN_LINK_MISMATCH");
    expect(r.findings.map(x => x.code)).toContain("EVENT_TIME_REGRESSION");
  });
  it("preserves true finding totals when display is truncated", () => {
    const r = inspectIncidentForensics({
      organizationId: org, incidentId: incident, analyzedAt: at,
      inventoryComplete: false, events: [event(2, { sourceEventDigest: null })],
      maxFindings: 1, requiredSources: ["INCIDENT", "TABLETOP_SESSION"],
    });
    expect(r.findings).toHaveLength(1);
    expect(r.findingsTruncated).toBe(true);
    expect(r.integrity).not.toBe("VERIFIED");
  });
  it("compares source regression without confusing it for containment", () => {
    const before = run([event(1), event(2)], 2);
    const after = run([event(1)], 2);
    const diff = compareForensicReports(before, after);
    expect(diff.regressions).toHaveLength(1);
    expect(diff.providerOutcomesVerified).toBe(false);
    expect(() => compareForensicReports(before, {
      ...after, organizationId: "org-other",
    })).toThrow("FORENSIC_COMPARE_CROSS_TENANT_OR_INCIDENT");
  });
  it("denies invalid expectations, duplicate inventories and unbounded input", () => {
    const req = {
      organizationId: org, incidentId: incident, analyzedAt: at,
      inventoryComplete: true, events: [event(1)],
      expectations: [
        { source: "INCIDENT" as const, sourceId: incident,
          expectedRevision: 1, expectedDigest: a, inventoryComplete: true },
      ],
    };
    validateForensicRequest(req);
    expect(() => validateForensicRequest({
      ...req, expectations: [req.expectations[0]!, req.expectations[0]!],
    })).toThrow("FORENSIC_EXPECTATION_DUPLICATE");
    expect(() => validateForensicRequest({
      ...req, maxFindings: 6000,
    })).toThrow("FORENSIC_FINDING_LIMIT");
  });
});
