import { describe, expect, it } from "vitest";
import { DEFAULT_SIEM_POLICY, classifyAuditAction,
  normalizePortableAuditEvent, redactAuditMetadata,
  validateSiemPolicy, verifyPortableAuditBatch,
  type PortableAuditInput } from "./siem-audit-interchange-domain";
import { buildSiemPage, decodeSiemCursor, encodeSiemCursor,
  verifySiemContinuity } from "./siem-audit-cursor-and-continuity";
import { buildSiemExport, inspectSiemPageQuality,
  inspectSiemForwardingReadiness } from "./siem-audit-exports";
import { compareSiemTargetPreparations } from "./siem-target-compatibility";
const org = "tenant-1234", secret = "a-private-testing-secret-at-least-32-chars-long";
const at = "2026-11-23T09:00:00.000Z", until = "2026-11-23T09:30:00.000Z";
function input(id = "event-1234"): PortableAuditInput {
  return { id, organizationId: org, actorType: "USER", actorUserId: "admin-1234",
    action: "remediation.approved", resourceType: "Remediation",
    resourceId: "resource-1234", occurredAt: at,
    metadata: { result: "APPROVED", token: "secret-value-9999",
      accountNumber: "123456789", revision: 2, url: "https://evil.example" } };
}
const query = { organizationId: org, since: "2026-11-22T00:00:00.000Z",
  until, action: null, resourceType: null, limit: 50, cursor: null };
function page(items = [input()], hasMore = false) {
  return buildSiemPage(query, items, at, hasMore, secret);
}
describe("SIEM neutral audit normalization", () => {
  it("suppresses secrets and sensitive free-text even when in metadata", () => {
    const normalized = normalizePortableAuditEvent(input());
    expect(normalized.metadataFields).toEqual({ result: "APPROVED", revision: 2 });
    expect(normalized.redactedFields).toBe(3);
    expect(normalized.actorReference).toBeNull();
    expect(normalized.resourceReference).toBeNull();
    expect(normalized.actualRemediationProven).toBe(false);
    expect(normalized.transmissionVerified).toBe(false);
    expect(normalized.confidence).toBe("PARTIAL");
  });
  it("cannot allowlist forbidden credential names", () => {
    expect(validateSiemPolicy({ ...DEFAULT_SIEM_POLICY,
      allowlistedMetadataKeys: ["result", "token"] }).length).toBeGreaterThan(0);
  });
  it("identifies malformed metadata and invalid scope", () => {
    expect(redactAuditMetadata(["secret"] as unknown).malformed).toBe(true);
    expect(() => normalizePortableAuditEvent({ ...input(),
      organizationId: "x" })).toThrow();
    expect(verifyPortableAuditBatch(org, [
      normalizePortableAuditEvent(input()),
      normalizePortableAuditEvent({ ...input(), id: "event-2345",
        organizationId: "other-tenant" }),
    ]).valid).toBe(false);
  });
  it("prioritizes sensitive remediation but without implying execution", () => {
    expect(classifyAuditAction("remediation.approved").category).toBe("REMEDIATION");
    expect(classifyAuditAction("remediation.approved").severity).toBe("CRITICAL");
    expect(classifyAuditAction("integration.sync_failed").category).toBe("INTEGRATION");
  });
});
describe("SIEM HMAC cursors and page integrity", () => {
  it("authenticates organization-bound cursor and rejects modification", () => {
    const cursor = encodeSiemCursor({
      version: 1, organizationId: org, afterAt: at,
      afterEventId: "event-1234", upperBound: until,
      actionFilter: null, resourceFilter: null,
    }, secret);
    expect(decodeSiemCursor(cursor, secret, org).afterEventId).toBe("event-1234");
    expect(() => decodeSiemCursor(cursor, secret, "other-tenant")).toThrow();
    expect(() => decodeSiemCursor(cursor.slice(0, -2) + "aa",
      secret, org)).toThrow();
  });
  it("builds stable partial pages and finds broken continuity", () => {
    const one = page([input()], true);
    const two = page([{ ...input(), id: "event-2345", occurredAt: until }], false);
    expect(one.nextCursor).toBeTruthy();
    expect(verifySiemContinuity([one, two], org).complete).toBe(true);
    expect(verifySiemContinuity([one, one], org).complete).toBe(false);
  });
  it("refuses out-of-order or duplicate rows without pretending completeness", () => {
    expect(() => page([input("event-2345"), input("event-1234")])).toThrow();
    expect(() => page([input(), input()])).toThrow();
  });
});
describe("SIEM exports and target review", () => {
  it("offers four representations without transmitting", () => {
    const p = page();
    for (const format of ["JSONL", "ECS", "CEF", "CSV"] as const) {
      const exported = buildSiemExport(p, format);
      expect(exported.content.length).toBeGreaterThan(0);
      expect(exported.externallyDelivered).toBe(false);
      expect(exported.deliveryReceipt).toBeNull();
      expect(exported.artifactDigest).toMatch(/^[a-f0-9]{64}$/);
    }
    expect(buildSiemExport(p, "CEF").content).toContain("CEF:0|CyberPilot");
    expect(buildSiemExport(p, "ECS").content).toContain("ecs");
    expect(buildSiemExport(p, "CSV").content).toContain("eventId");
  });
  it("maps three SIEM target requirements without fake credentials", () => {
    const profiles = compareSiemTargetPreparations(page());
    expect(profiles.profiles).toHaveLength(3);
    expect(profiles.destinationsConnected).toBe(0);
    expect(profiles.profiles.every(p => !p.apiDeliveryAttempted &&
      !p.remoteAckObserved)).toBe(true);
  });
  it("surfaces redaction and incomplete-page warnings", () => {
    const p = page([input()], true);
    expect(inspectSiemPageQuality(p).partiallyRedacted).toBe(1);
    expect(inspectSiemForwardingReadiness(p).findings)
      .toContain("EXPORT_WINDOW_PARTIAL");
    expect(inspectSiemForwardingReadiness(p).verdict).toBe("NOT_CONNECTED");
  });
});
