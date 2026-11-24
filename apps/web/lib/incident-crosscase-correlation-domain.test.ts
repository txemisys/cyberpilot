import { describe, expect, it } from "vitest";
import { normalizeTimelineEvent, type TimelineEvent } from
  "./incident-operational-timeline-domain";
import { inspectIncidentForensics } from
  "./incident-timeline-forensics-domain";
import {
  correlateSelectedIncidents, defaultCorrelationPolicy,
  validateCorrelationPolicy, validateCorrelationSelection,
  graphSelectedCorrelations, prepareCorrelationReviews,
  exportCorrelationCSV, exportCorrelationJSON,
  compareCorrelationReports, verifyCorrelationReport,
  summarizeCorrelationByKind,
  type CorrelationCaseInput,
} from "./incident-crosscase-correlation-domain";
const org = "org-correlation-test";
const at = "2026-11-24T14:00:00.000Z";
const digest = "a".repeat(64);
function row(incidentId: string, sourceId: string,
  eventId: string, actor = "shared-operator",
  occurredAt = "2026-11-24T13:00:00.000Z"): TimelineEvent {
  return normalizeTimelineEvent({
    organizationId: org, incidentId, source: "INCIDENT",
    sourceId, sourceRevision: 1, eventId,
    actorUserId: actor, operation: "CREATE",
    occurredAt, priorState: null, nextState: "OPEN",
    priorDigest: null, nextDigest: digest,
    sourceEventDigest: null, sourceIntegrity: "INCOMPLETE",
  });
}
function selected(incidentId: string, events: TimelineEvent[],
  complete = true): CorrelationCaseInput {
  return {
    incidentId, incidentRevision: 1, timelineEvents: events,
    forensic: inspectIncidentForensics({
      organizationId: org, incidentId, analyzedAt: at,
      inventoryComplete: complete, events,
    }),
    eventInventoryComplete: complete,
  };
}
function candidates(options?: { coverage?: boolean; shared?: boolean }) {
  const left = selected("incident-first", [
    row("incident-first", options?.shared ? "source-common" :
      "incident-first", "event-first"),
  ], !options?.coverage);
  const right = selected("incident-second", [
    row("incident-second", options?.shared ? "source-common" :
      "incident-second", "event-second",
      "shared-operator", "2026-11-24T13:20:00.000Z"),
  ], !options?.coverage);
  return correlateSelectedIncidents({
    organizationId: org, requestedAt: at, cases: [left, right],
  });
}
describe("explicit crosscase incident correlation", () => {
  it("requires explicit distinct cases and tenant-safe provenance", () => {
    const left = selected("incident-first", [
      row("incident-first", "incident-first", "event-first"),
    ]);
    const policy = defaultCorrelationPolicy();
    expect(() => validateCorrelationSelection({
      organizationId: org, requestedAt: at, cases: [left], policy,
    })).toThrow("CORRELATION_EXPLICIT_SELECTION_REQUIRED");
    expect(() => validateCorrelationSelection({
      organizationId: org, requestedAt: at,
      cases: [left, left], policy,
    })).toThrow("CORRELATION_CASE_SELECTION_INVALID");
    expect(() => validateCorrelationSelection({
      organizationId: "org-other", requestedAt: at,
      cases: [left, selected("incident-second", [
        row("incident-second", "incident-second", "event-second"),
      ])], policy,
    })).toThrow("CORRELATION_CROSS_TENANT_OR_INCIDENT");
  });
  it("keeps all association claims tentative and external actions zero", () => {
    const report = candidates({ shared: true });
    expect(verifyCorrelationReport(report)).toEqual([]);
    expect(report.findings.some(x => x.kind === "COMMON_SOURCE_KEY"))
      .toBe(true);
    expect(report.findings.every(x =>
      x.compromiseEstablished === false &&
      x.identityEquivalenceEstablished === false &&
      x.providerOutcomeVerified === false &&
      x.manualReviewRequired === true)).toBe(true);
    expect(report.providerContainmentConfirmed).toBe(false);
    expect(report.externalActions).toBe(0);
    expect(report.completeness).toBe("PARTIAL");
  });
  it("finds time proximity but never upgrades it into campaign proof", () => {
    const report = candidates();
    const nearby = report.findings.find(x => x.kind === "NEARBY_ACTIVITY");
    expect(nearby?.strength).toBe("WEAK");
    expect(nearby?.compromiseEstablished).toBe(false);
    expect(nearby?.evidence[0].incidentId).toBe("incident-first");
  });
  it("marks shared coverage gaps as unknown and reviewable", () => {
    const report = candidates({ coverage: true });
    expect(report.completeness).toBe("UNKNOWN");
    expect(report.findings.some(x => x.kind === "JOINT_COVERAGE_GAP"))
      .toBe(true);
    expect(prepareCorrelationReviews(report).every(x =>
      x.externalActionAuthorized === false &&
      x.identityMatchConfirmed === false)).toBe(true);
  });
  it("derives candidate graph and isolated nodes", () => {
    const report = candidates();
    const graph = graphSelectedCorrelations(report);
    expect(graph.provenSharedCompromises).toBe(0);
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges.length).toBeGreaterThan(0);
    expect(graph.components).toHaveLength(1);
  });
  it("rejects unsafe policy and external identity claims", () => {
    const unsafe = {
      ...defaultCorrelationPolicy(),
      allowExternalIdentityClaims: true as never,
    };
    expect(validateCorrelationPolicy(unsafe)).toContain(
      "CORRELATION_POLICY_UNSAFE");
    const report = candidates();
    expect(verifyCorrelationReport({
      ...report, providerIdentityConfirmed: true as never,
    })).toContain("CORRELATION_REPORT_PROVIDER_FORGERY");
  });
  it("exports escaped CSV and stable JSON without provider writes", () => {
    const report = candidates();
    expect(JSON.parse(exportCorrelationJSON(report)).digest)
      .toBe(report.digest);
    expect(exportCorrelationCSV(report)).toContain("identityProven");
    expect(() => exportCorrelationCSV({
      ...report, digest: "b".repeat(64),
    })).toThrow("CORRELATION_EXPORT_INVALID");
    expect(summarizeCorrelationByKind(report).some(x => x.links > 0))
      .toBe(true);
  });
  it("reports changes in selected source without implying mitigation", () => {
    const before = candidates();
    const after = candidates({ shared: true });
    const comparison = compareCorrelationReports(before, after);
    expect(comparison.newCandidates.length).toBeGreaterThan(0);
    expect(comparison.identityVerified).toBe(false);
    expect(comparison.reductionDoesNotProveContainment).toBe(true);
  });
  it("enforces bounded source and output policy", () => {
    const policy = defaultCorrelationPolicy();
    const a = selected("incident-first", [
      row("incident-first", "incident-first", "event-first"),
    ]);
    const b = selected("incident-second", [
      row("incident-second", "incident-second", "event-second"),
    ]);
    expect(() => correlateSelectedIncidents({
      organizationId: org, requestedAt: at, cases: [a, b],
      policy: { ...policy, maximumEventsPerCase: 0 },
    })).toThrow("CORRELATION_POLICY_BOUNDS_INVALID");
  });
});
