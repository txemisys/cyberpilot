import { describe, expect, it } from "vitest";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import { planSnapshotRecovery, simulateSnapshotRecovery } from "./work-integrity-snapshot-recovery";

const tenant = "tenant-a";
const at = "2026-11-01T12:00:00.000Z";
const policy = {
  allowRemoval: true, requireComplete: false, rejectQualityBlockers: false,
  maxRestores: 100, maxRemovals: 100,
};
function capture(day: number, organizationId = tenant, complete = true) {
  return {
    organizationId, source: "source-a",
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
    complete, cases: [],
  };
}
describe("snapshot recovery planning", () => {
  it("retains identical captures", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, trusted, tenant, policy);
    expect(plan.executable).toBe(true);
    expect(plan.retained).toBe(1);
    expect(plan.restores).toBe(0);
  });
  it("restores missing captures", () => {
    const trusted = [capture(1), capture(2)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [capture(1)], tenant, policy);
    expect(plan.restores).toBe(1);
    expect(simulateSnapshotRecovery(plan, [capture(1)], manifest).matchesExpectedManifest)
      .toBe(true);
  });
  it("restores modified captures", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [capture(1, tenant, false)],
      tenant, policy);
    expect(plan.restores).toBe(1);
  });
  it("removes unexpected captures when policy allows", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [capture(1), capture(2)],
      tenant, policy);
    expect(plan.removals).toBe(1);
    expect(simulateSnapshotRecovery(plan, [capture(1), capture(2)], manifest)
      .matchesExpectedManifest).toBe(true);
  });
  it("blocks unexpected removals when disallowed", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [capture(1), capture(2)],
      tenant, { ...policy, allowRemoval: false });
    expect(plan.executable).toBe(false);
  });
  it("blocks untrusted recovery payloads", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, [capture(1, tenant, false)],
      [], tenant, policy);
    expect(plan.executable).toBe(false);
  });
  it("blocks cross-organization material", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    expect(() => planSnapshotRecovery(manifest, trusted, [capture(1, "tenant-b")],
      tenant, policy)).toThrow(/Cross-organization/);
  });
  it("enforces restore limits", () => {
    const trusted = [capture(1), capture(2)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [], tenant,
      { ...policy, maxRestores: 1 });
    expect(plan.executable).toBe(false);
  });
  it("rejects simulation of blocked plans", () => {
    const trusted = [capture(1)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [], tenant,
      { ...policy, maxRestores: 0 });
    expect(() => simulateSnapshotRecovery(plan, [], manifest)).toThrow(/blocking/);
  });
  it("does not mistake review completeness for verified remediation", () => {
    const trusted = [capture(1, tenant, false)];
    const manifest = buildSnapshotManifest(trusted, tenant, at);
    const plan = planSnapshotRecovery(manifest, trusted, [], tenant,
      { ...policy, requireComplete: true });
    expect(plan.executable).toBe(false);
  });
});
