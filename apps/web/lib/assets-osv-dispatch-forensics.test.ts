import { describe, expect, it } from "vitest";
import {
  parseOsvForensicInput, canonicalForensicNode,
  composeOsvForensicReport,
} from "./assets-osv-dispatch-forensics";
import type {
  OsvForensicDataset,
} from "./assets-osv-dispatch-forensics";
import {
  verifyOsvForensicReport,
} from "./assets-osv-forensic-verification";

const now = new Date("2026-11-10T12:00:00.000Z");
const org = "forensic-tenant-12345";
const schedule = "forensic-schedule-12345";
const slot = new Date("2026-11-10T10:00:00.000Z");
const data = (): OsvForensicDataset => ({
  signatures: [{
    id: "signature-12345", scheduleId: schedule,
    acceptedAt: new Date("2026-11-10T10:00:00.000Z"),
    expiresAt: new Date("2026-11-10T10:01:00.000Z"),
    requestDigest: "a".repeat(64),
    nonceDigest: "b".repeat(64),
    keyId: "forensic-key-12345",
  }],
  runs: [{
    id: "run-12345", scheduleId: schedule, slotAt: slot,
    claimedAt: new Date("2026-11-10T10:00:10.000Z"),
    claimExpiresAt: new Date("2026-11-10T10:30:00.000Z"),
    completedAt: null, state: "CLAIMED",
    commandDigest: "c".repeat(64),
    inspectionId: "inspection-12345", errorCode: null,
  }],
  quotas: [{
    id: "quota-12345", requestKey: "provider-key-12345",
    startedAt: new Date("2026-11-10T10:00:12.000Z"),
    finishedAt: null, state: "RESERVED",
    reservedRequests: 2, actualRequests: 0,
    errorCode: null, requestDigest: "d".repeat(64),
  }],
  inspections: [{
    id: "inspection-12345", requestKey: "provider-key-12345",
    completedAt: new Date("2026-11-10T10:00:20.000Z"),
    status: "COMPLETE", reportDigest: "e".repeat(64),
    queryCount: 1, completedCount: 1,
  }],
  audits: [{
    id: "audit-12345", occurredAt:
      new Date("2026-11-10T10:00:11.000Z"),
    actorType: "SYSTEM",
    action: "assets.osv.schedule.run.claimed",
    resourceType: "AssetOsvRenewalRun",
    resourceId: "run-12345",
  }],
});
const opts = () => parseOsvForensicInput({});
function report() {
  return composeOsvForensicReport(
    org, opts(), data(), now);
}
describe("OSV forensic evidence graph", () => {
  it("normalizes constrained windows and source selection", () => {
    expect(opts()).toMatchObject({
      scheduleId: null, lookbackHours: 72,
      maximumRecords: 100, includeAudit: true,
      includeInspections: true, includeQuota: true,
      strictCompleteness: true,
    });
  });
  it.each([
    { lookbackHours: 0 }, { lookbackHours: 721 },
    { maximumRecords: 0 }, { maximumRecords: 501 },
    { includeAudit: "yes" }, { includeQuota: null },
    { includeInspections: 123 },
    { strictCompleteness: "false" },
    { scheduleId: "../../etc/passwd" },
    { unknown: true },
  ])("rejects unsafe forensic options %j", patch => {
    expect(() => parseOsvForensicInput(patch)).toThrow();
  });
  it("records exact and heuristic relationships separately", () => {
    const result = report();
    expect(result.summary.nodes).toBe(5);
    expect(result.summary.exactReferences).toBe(3);
    expect(result.summary.heuristicLinks).toBe(1);
    expect(result.edges.some(x => x.relation ===
      "TIME_ADJACENT_ONLY" && x.confidence === "HEURISTIC"))
      .toBe(true);
    expect(result.edges.some(x => x.relation ===
      "EXACT_INSPECTION" && x.confidence === "EXACT_REFERENCE"))
      .toBe(true);
  });
  it("does not assert provider verification from local evidence", () => {
    const result = report();
    expect(result).toMatchObject({
      complete: true,
      liveProviderVerified: false, changesCommitted: false,
      networkRequestsMade: 0, findingsModified: false,
    });
    expect(result.summary.criticalAnomalies).toBeGreaterThanOrEqual(2);
  });
  it("detects old unsettled claims and old quota reservations", () => {
    const result = report();
    const codes = result.anomalies.map(x => x.code);
    expect(codes).toContain("STALE_UNSETTLED_CLAIM");
    expect(codes).toContain("UNSETTLED_PROVIDER_RESERVATION");
  });
  it("detects impossible provider request accounting", () => {
    const fixture = data();
    fixture.quotas[0]!.actualRequests = 3;
    const result = composeOsvForensicReport(org,
      opts(), fixture, now);
    expect(result.anomalies.map(x => x.code))
      .toContain("QUOTA_EXCEEDS_RESERVATION");
  });
  it("detects impossible inspection completion counts", () => {
    const fixture = data();
    fixture.inspections[0]!.completedCount = 4;
    const result = composeOsvForensicReport(org,
      opts(), fixture, now);
    expect(result.anomalies.map(x => x.code))
      .toContain("INVALID_INSPECTION_COUNTER");
  });
  it("detects a missing local inspection in the bounded window", () => {
    const fixture = data();
    fixture.inspections = [];
    const result = composeOsvForensicReport(org,
      opts(), fixture, now);
    expect(result.anomalies.some(x => x.code ===
      "INSPECTION_NOT_IN_WINDOW")).toBe(true);
  });
  it("never assigns a signature to two ambiguous nearby claims", () => {
    const fixture = data();
    fixture.runs.push({
      ...fixture.runs[0]!, id: "run-duplicate-12345",
      claimedAt: new Date("2026-11-10T10:00:20.000Z"),
    });
    const result = composeOsvForensicReport(org,
      opts(), fixture, now);
    expect(result.anomalies.map(x => x.code))
      .toContain("AMBIGUOUS_SIGNED_CLAIM");
    expect(result.edges.filter(x =>
      x.relation === "TIME_ADJACENT_ONLY")).toHaveLength(0);
  });
  it("marks missing nearby claims as uncertain not as failed HTTP", () => {
    const fixture = data();
    fixture.runs = [];
    const result = composeOsvForensicReport(org,
      opts(), fixture, now);
    expect(result.anomalies.map(x => x.code))
      .toContain("SIGNATURE_WITHOUT_VISIBLE_CLAIM");
    expect(JSON.stringify(result.warnings)).toMatch(/not proof/i);
  });
  it("marks exceeded bounded collection sizes as incomplete", () => {
    const result = composeOsvForensicReport(org,
      opts(), data(), now, { runs: 9 });
    expect(result.complete).toBe(false);
    expect(result.truncatedCollections).toContain("runs");
  });
  it("keeps ordering and report digest stable for identical input", () => {
    expect(report().reportDigest).toBe(report().reportDigest);
    expect(report().nodes.map(x => x.eventAt))
      .toEqual([...report().nodes.map(x => x.eventAt)].sort());
  });
  it("never stores raw signing credentials in the evidence graph", () => {
    const result = report();
    expect(JSON.stringify(result)).not.toContain("secretHex");
    expect(JSON.stringify(result)).not.toContain("HMAC-SHA256-SECRET");
  });
  it("normalizes each evidence node with a tamper-evident digest", () => {
    const value = canonicalForensicNode(
      "SIGNATURE", "signature-12345", schedule, now,
      "ACCEPTED", { keyId: "forensic-key-12345" });
    expect(value.digest).toMatch(/^[a-f0-9]{64}$/);
  });
});
describe("OSV forensic report structure and consistency verification", () => {
  it("verifies an internally consistent local forensic report", () => {
    const result = verifyOsvForensicReport(report());
    expect(result.validForInternalReview).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.checkedNodes).toBe(5);
  });
  it("detects a mutated report-level fingerprint", () => {
    const target = report();
    target.reportDigest = "f".repeat(64);
    const result = verifyOsvForensicReport(target);
    expect(result.fingerprintValid).toBe(false);
    expect(result.validForInternalReview).toBe(false);
  });
  it("detects changed evidence attributes after report creation", () => {
    const target = report();
    target.nodes[0]!.state = "UNEXPECTED";
    const result = verifyOsvForensicReport(target);
    expect(result.nodeDigestsValid).toBe(false);
    expect(result.validForInternalReview).toBe(false);
  });
  it("rejects forged graph references", () => {
    const target = report();
    target.edges[0]!.to = "inspection:nonexistent";
    const result = verifyOsvForensicReport(target);
    expect(result.referencesValid).toBe(false);
  });
  it("rejects incorrect node and relationship statistics", () => {
    const target = report();
    target.summary.edges = 999;
    const result = verifyOsvForensicReport(target);
    expect(result.summaryValid).toBe(false);
  });
  it("does not validate a report that falsely claims provider verification", () => {
    const target = report();
    (target as unknown as { liveProviderVerified: boolean })
      .liveProviderVerified = true;
    const result = verifyOsvForensicReport(target);
    expect(result.noExternalActionsClaimed).toBe(false);
  });
  it("rejects incomplete datasets even when their hash is well formed", () => {
    const incomplete = composeOsvForensicReport(org,
      opts(), data(), now, { signatures: 5 });
    const result = verifyOsvForensicReport(incomplete);
    expect(result.completeWithinWindow).toBe(false);
    expect(result.validForInternalReview).toBe(false);
  });
});
