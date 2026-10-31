import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { buildHandoffManifest, auditHandoffManifest, compareHandoffManifests,
  handoffCsv, recipientEligible, validateHandoffPolicy } from "./work-integrity-handoff";
import { validateEvidenceRequirements, applicableEvidenceRequirements,
  buildEvidencePacket, buildEvidenceReadiness, compareEvidenceReadiness,
  evidenceReviewQueue, evidencePacketJson, evidenceReadinessCsv, evidenceWorklist } from "./work-integrity-evidence-readiness";

const row = (id: string, overrides: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 2, severity: "attention",
  diagnostic: "No completion timestamp", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...overrides,
});
const a = row("a");
const b = row("b", { severity: "critical", state: "STALE",
  reviewEventId: "review-b", reviewedRevision: 1 });
const c = row("c", { severity: "info", state: "INVESTIGATING",
  reviewEventId: "review-c", reviewedRevision: 2,
  reviewRationale: "Checked", reviewReference: "ticket-123",
  reviewedAt: "2026-10-31T12:00:00.000Z" });
const d = row("d", { historicalOnly: true, state: "NO_LONGER_DETECTED" });
const e = row("e", { completeCoverage: false });
const snapshot = (cases: CaseRow[], complete = true, at = "2026-10-31T12:00:00.000Z") =>
  parseCaseSnapshot({ organizationId: "org-a", capturedAt: at,
    source: "case-queue", complete, cases });
const source = snapshot([a, b, c, d, e]);
const policy = {
  recipients: [
    { id: "analyst-a", capacity: 2, codes: [] as string[], workItemIds: [] as string[] },
    { id: "analyst-b", capacity: 2, codes: [] as string[], workItemIds: [] as string[] },
  ],
  includeReviewed: true, includeHistorical: true,
  requireCompleteCoverage: false, allowUnassigned: true,
};
const requirement = {
  id: "human-review", diagnosticCodes: [] as string[],
  mandatoryFields: ["diagnostic", "recommendation", "reviewRationale",
    "reviewReference", "reviewedAt", "reviewEventId"] as Array<
      "diagnostic" | "recommendation" | "reviewRationale" |
      "reviewReference" | "reviewedAt" | "reviewEventId">,
  requireCurrentRevision: true, requireCompleteCoverage: true,
  requireHumanReview: true,
};
describe("handoff policy validation", () => {
  it("accepts a valid policy", () => {
    expect(validateHandoffPolicy(policy).recipients).toHaveLength(2);
  });
  it("sorts recipients deterministically", () => {
    const reversed = { ...policy, recipients: [...policy.recipients].reverse() };
    expect(validateHandoffPolicy(reversed).recipients[0]?.id).toBe("analyst-a");
  });
  it("rejects missing recipients", () => {
    expect(() => validateHandoffPolicy({ ...policy, recipients: [] })).toThrow();
  });
  it("rejects duplicate recipient IDs", () => {
    expect(() => validateHandoffPolicy({
      ...policy, recipients: [policy.recipients[0]!, policy.recipients[0]!],
    })).toThrow();
  });
  it("rejects negative capacity", () => {
    expect(() => validateHandoffPolicy({
      ...policy, recipients: [{ ...policy.recipients[0]!, capacity: -1 }],
    })).toThrow();
  });
  it("rejects excessive capacity", () => {
    expect(() => validateHandoffPolicy({
      ...policy, recipients: [{ ...policy.recipients[0]!, capacity: 10001 }],
    })).toThrow();
  });
  it("rejects invalid flags", () => {
    expect(() => validateHandoffPolicy({
      ...policy, includeReviewed: "true" as never,
    })).toThrow();
  });
  it("rejects invalid code restrictions", () => {
    expect(() => validateHandoffPolicy({
      ...policy, recipients: [{ ...policy.recipients[0]!, codes: [123] as never }],
    })).toThrow();
  });
  it("matches unrestricted recipient", () => {
    expect(recipientEligible(a, policy.recipients[0]!)).toBe(true);
  });
  it("matches allowed diagnostic code", () => {
    expect(recipientEligible(a, { ...policy.recipients[0]!, codes: [a.code] })).toBe(true);
  });
  it("rejects unallowed diagnostic code", () => {
    expect(recipientEligible(a, { ...policy.recipients[0]!, codes: ["OTHER"] })).toBe(false);
  });
  it("rejects unallowed work item", () => {
    expect(recipientEligible(a, { ...policy.recipients[0]!, workItemIds: ["b"] })).toBe(false);
  });
});
describe("handoff allocation", () => {
  const manifest = buildHandoffManifest(source, policy);
  it("includes five cases", () => expect(manifest.items).toHaveLength(5));
  it("limits recipient capacity", () => {
    expect(Object.values(manifest.recipientLoads)).toEqual([2, 2]);
  });
  it("records unassigned case", () => expect(manifest.unassigned).toHaveLength(1));
  it("does not silently drop unassigned cases", () => {
    expect(manifest.items.filter(item => item.recipientId === null)).toHaveLength(1);
  });
  it("refuses unassigned when policy prohibits it", () => {
    expect(() => buildHandoffManifest(source, { ...policy, allowUnassigned: false })).toThrow();
  });
  it("excludes reviewed cases when configured", () => {
    expect(buildHandoffManifest(source, { ...policy, includeReviewed: false }).items).toHaveLength(3);
  });
  it("excludes historical cases when configured", () => {
    expect(buildHandoffManifest(source, { ...policy, includeHistorical: false }).items).toHaveLength(4);
  });
  it("excludes incomplete linked cases", () => {
    expect(buildHandoffManifest(source, {
      ...policy, requireCompleteCoverage: true,
    }).items).toHaveLength(4);
  });
  it("respects recipient diagnostic restrictions", () => {
    const restricted = buildHandoffManifest(source, {
      ...policy, recipients: [{ id: "only-other", capacity: 10,
        codes: ["OTHER"], workItemIds: [] }],
    });
    expect(restricted.unassigned).toHaveLength(5);
  });
  it("respects recipient work item restrictions", () => {
    const restricted = buildHandoffManifest(source, {
      ...policy, recipients: [{ id: "only-a", capacity: 10,
        codes: [], workItemIds: ["a"] }],
    });
    expect(restricted.items.filter(item => item.recipientId !== null)).toHaveLength(1);
  });
  it("audits valid handoff", () => {
    expect(auditHandoffManifest(manifest, source, policy).valid).toBe(true);
  });
  it("detects organization tampering", () => {
    expect(auditHandoffManifest({
      ...manifest, organizationId: "other",
    }, source, policy).valid).toBe(false);
  });
  it("detects revision tampering", () => {
    expect(auditHandoffManifest({
      ...manifest, items: manifest.items.map((item, index) =>
        index === 0 ? { ...item, revision: 999 } : item),
    }, source, policy).valid).toBe(false);
  });
  it("detects load tampering", () => {
    expect(auditHandoffManifest({
      ...manifest, recipientLoads: { ...manifest.recipientLoads, "analyst-a": 999 },
    }, source, policy).valid).toBe(false);
  });
  it("detects duplicate case assignment", () => {
    expect(auditHandoffManifest({
      ...manifest, items: [...manifest.items, manifest.items[0]!],
    }, source, policy).valid).toBe(false);
  });
  it("detects unknown recipient", () => {
    expect(auditHandoffManifest({
      ...manifest, items: manifest.items.map((item, index) =>
        index === 0 ? { ...item, recipientId: "unknown" } : item),
    }, source, policy).valid).toBe(false);
  });
  it("detects unassigned inventory tampering", () => {
    expect(auditHandoffManifest({
      ...manifest, unassigned: [],
    }, source, policy).valid).toBe(false);
  });
  it("exports CSV", () => expect(handoffCsv(manifest)).toContain("\r\n"));
  it("neutralizes spreadsheet formula injection", () => {
    const injected = row("=HYPERLINK");
    const output = handoffCsv(buildHandoffManifest(snapshot([injected]), policy));
    expect(output).toContain("'=HYPERLINK");
  });
});
describe("handoff drift", () => {
  const before = buildHandoffManifest(snapshot([a, b]), policy);
  const after = buildHandoffManifest(snapshot([a, c], true, "2026-10-31T13:00:00.000Z"), policy);
  it("detects added cases", () => expect(compareHandoffManifests(before, after).added).toContain(c.key));
  it("detects removed cases", () => expect(compareHandoffManifests(before, after).removed).toContain(b.key));
  it("rejects tenant mismatch", () => expect(() => compareHandoffManifests(before, {
    ...after, organizationId: "other",
  })).toThrow());
  it("flags incomplete comparison", () => expect(compareHandoffManifests({
    ...before, sourceComplete: false,
  }, after).indeterminate).toBe(true));
  it("detects revision changes", () => {
    const changed = buildHandoffManifest(snapshot([row("a", { taskRevision: 3 })],
      true, "2026-10-31T13:00:00.000Z"), policy);
    expect(compareHandoffManifests(
      buildHandoffManifest(snapshot([a]), policy), changed,
    ).revisionChanged).toContain(a.key);
  });
});
describe("evidence requirement policies", () => {
  it("accepts valid requirements", () => {
    expect(validateEvidenceRequirements([requirement])).toHaveLength(1);
  });
  it("rejects duplicate IDs", () => {
    expect(() => validateEvidenceRequirements([requirement, requirement])).toThrow();
  });
  it("rejects invalid fields", () => {
    expect(() => validateEvidenceRequirements([{
      ...requirement, mandatoryFields: ["secret"] as never,
    }])).toThrow();
  });
  it("rejects invalid flags", () => {
    expect(() => validateEvidenceRequirements([{
      ...requirement, requireHumanReview: 1 as never,
    }])).toThrow();
  });
  it("matches all codes with empty selector", () => {
    expect(applicableEvidenceRequirements(a, [requirement])).toHaveLength(1);
  });
  it("filters mismatched diagnostic codes", () => {
    expect(applicableEvidenceRequirements(a, [{
      ...requirement, diagnosticCodes: ["OTHER"],
    }])).toHaveLength(0);
  });
});
describe("evidence packets and readiness", () => {
  const readiness = buildEvidenceReadiness(source, [requirement]);
  it("creates a packet per case", () => expect(readiness.total).toBe(5));
  it("recognizes complete review metadata", () => {
    expect(buildEvidencePacket(source, c, [requirement]).readyForHumanReview).toBe(true);
  });
  it("flags absent human review", () => {
    expect(buildEvidencePacket(source, a, [requirement]).gaps.some(gap =>
      gap.field === "humanReview")).toBe(true);
  });
  it("flags stale review revisions", () => {
    expect(buildEvidencePacket(source, b, [requirement]).gaps.some(gap =>
      gap.field === "revision")).toBe(true);
  });
  it("flags incomplete linked records", () => {
    expect(buildEvidencePacket(source, e, [requirement]).gaps.some(gap =>
      gap.field === "coverage")).toBe(true);
  });
  it("flags incomplete snapshots", () => {
    const partial = snapshot([c], false);
    expect(buildEvidencePacket(partial, c, [requirement]).readyForHumanReview).toBe(false);
  });
  it("rejects case not in snapshot", () => {
    expect(() => buildEvidencePacket(source, row("unknown"), [requirement])).toThrow();
  });
  it("counts blocked packets", () => expect(readiness.blocked).toBe(4));
  it("counts ready packets", () => expect(readiness.ready).toBe(1));
  it("counts missing reviews", () => expect(readiness.missingReview).toBe(3));
  it("counts stale reviews", () => expect(readiness.staleReview).toBe(1));
  it("counts incomplete coverage", () => expect(readiness.incompleteCoverage).toBe(1));
  it("provides review queue", () => expect(evidenceReviewQueue(readiness)).toHaveLength(4));
  it("prioritizes worklist entries", () => expect(evidenceWorklist(source, [requirement])).toHaveLength(4));
  it("exports packet JSON", () => expect(JSON.parse(evidencePacketJson(readiness.packets[0]!)).version).toBe(1));
  it("exports readiness CSV", () => expect(evidenceReadinessCsv(readiness)).toContain("\r\n"));
  it("neutralizes formula injection", () => {
    const injected = row("=HYPERLINK");
    expect(evidenceReadinessCsv(buildEvidenceReadiness(snapshot([injected]), [])))
      .toContain("'=HYPERLINK");
  });
  it("tracks new evidence gaps", () => {
    const old = snapshot([c]);
    const newer = snapshot([row("c", {
      reviewEventId: null, reviewRationale: null, reviewReference: null,
    })], true, "2026-10-31T13:00:00.000Z");
    expect(compareEvidenceReadiness(old, newer, [requirement])[0]?.addedGaps.length)
      .toBeGreaterThan(0);
  });
  it("marks missing case with partial coverage uncertain", () => {
    const later = snapshot([], false, "2026-10-31T13:00:00.000Z");
    expect(compareEvidenceReadiness(snapshot([a]), later, [requirement])[0]?.uncertain).toBe(true);
  });
});
