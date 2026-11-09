import { describe, expect, it } from "vitest";
import {
  parseOsvRenewalCommand, assertRenewalPrevious,
  evaluateRenewalPlan, assertRenewalExecution,
} from "./assets-osv-renewal";
import type { AssetScope } from "./assets-inventory-service";
import type { RefreshPackageState } from "./assets-osv-refresh-policy";
const org: AssetScope = {
  organizationId: "renewal-org-12345",
  userId: "renewal-admin-12345",
  role: "ADMIN",
};
const now = new Date("2026-11-09T12:00:00.000Z");
const policy = {
  freshnessMinutes: 1440, minimumRetryMinutes: 60,
  maximumQueriesPerDay: 200, maximumInspectionsPerDay: 20,
  maximumPackagesPerRun: 5, historyWindowDays: 90,
  includeIncomplete: true,
};
const bindings = [{
  inventoryProduct: "Example Package",
  ecosystem: "npm", packageName: "example-package",
}];
const input = {
  sourceInspectionId: "inspection-previous-12345",
  requestKey: "renewal-manual-12345",
  inspection: {
    importId: "import-renewal-12345",
    packageBindings: bindings,
    limitPackages: 5, maxPagesPerPackage: 2,
    maxRecordsPerPackage: 50, maxAgeMinutes: 60,
    dryRun: true,
  },
  policy, dryRun: true, confirmOutbound: false,
};
const old = {
  id: input.sourceInspectionId,
  organizationId: org.organizationId,
  inventoryImportId: input.inspection.importId,
  status: "COMPLETE",
  completedAt: new Date("2026-11-02T12:00:00.000Z"),
  reportDigest: "d".repeat(64),
  queryCount: 1,
  queries: [{
    inspectionId: input.sourceInspectionId,
    ecosystem: "npm", packageName: "example-package",
    version: "1.2.3", queryKey: "a".repeat(64),
    checkedAt: new Date("2026-11-02T12:00:00.000Z"),
    providerStatus: "COMPLETE",
    observationCount: 2,
    possibleIds: ["GHSA-aaaa-1111-2222"],
    providerOnlyIds: [],
    unresolvedIds: [],
    withdrawnIds: [],
  }],
};
const rows = [{
  externalId: "asset-12345", softwareName: "Example Package",
  softwareVersion: "1.2.3", versionStatus: "EXACT",
  normalizedProductKey: "example package",
}, {
  externalId: "asset-67890", softwareName: "Example Package",
  softwareVersion: "1.2.3", versionStatus: "EXACT",
  normalizedProductKey: "example package",
}];
function fixture(
  overrides: Partial<typeof input> = {},
  oldOverrides: Partial<typeof old> = {},
  rowOverrides = rows,
  quota = { inspectionsRemaining: 10, requestsRemaining: 100 },
) {
  const command = parseOsvRenewalCommand({ ...input, ...overrides });
  const source = { ...old, ...oldOverrides };
  const plan = evaluateRenewalPlan(org, command, source,
    rowOverrides, quota, now);
  return { command, plan };
}
describe("OSV renewal request and consent validation", () => {
  it("enforces a network-free preview by default", () => {
    const parsed = parseOsvRenewalCommand(input);
    expect(parsed.dryRun).toBe(true);
    expect(parsed.inspection.dryRun).toBe(true);
    expect(parsed.confirmOutbound).toBe(false);
  });
  it.each([
    { sourceInspectionId: "short" },
    { requestKey: "short" },
    { policy: { unknownPolicy: true } },
    { dryRun: "false" },
    { confirmOutbound: "true" },
    { unexpected: "unknown" },
    { expectedPlanDigest: "not-a-digest" },
  ])("rejects malformed or unrecognized command parameters %j", patch => {
    expect(() => parseOsvRenewalCommand({
      ...input, ...patch,
    })).toThrow();
  });
  it("rejects execution without explicit outbound approval", () => {
    expect(() => parseOsvRenewalCommand({
      ...input,
      dryRun: false,
      inspection: { ...input.inspection, dryRun: false },
    })).toThrow();
  });
  it("rejects execution if nested inspection remains a preview", () => {
    expect(() => parseOsvRenewalCommand({
      ...input, dryRun: false, confirmOutbound: true,
      expectedPlanDigest: "c".repeat(64),
    })).toThrow();
  });
  it("rejects a live inspection accidentally passed as preview", () => {
    expect(() => parseOsvRenewalCommand({
      ...input, inspection: { ...input.inspection, dryRun: false },
    })).toThrow();
  });
  it("requires source and target to belong to one organization and import", () => {
    const command = parseOsvRenewalCommand(input);
    expect(() => assertRenewalPrevious(org, command, {
      ...old, organizationId: "another-tenant",
    })).toThrow();
    expect(() => assertRenewalPrevious(org, command, {
      ...old, inventoryImportId: "foreign-import",
    })).toThrow();
    expect(() => assertRenewalPrevious(org, command, {
      ...old, queryCount: 2,
    })).toThrow();
    expect(() => assertRenewalPrevious(org, command, old)).not.toThrow();
  });
});
describe("OSV renewal readiness and approval digests", () => {
  it("selects an old exact version for new authorized inspection", () => {
    const { plan } = fixture();
    expect(plan.validForExecution).toBe(true);
    expect(plan.selectedPackages).toBe(1);
    expect(plan.eligiblePackages).toBe(1);
    expect(plan.deferredPackages).toBe(0);
    expect(plan.maximumHttpPages).toBe(2);
    expect(plan.planDigest).toMatch(/^[0-9a-f]{64}$/);
  });
  it("blocks refreshing a complete observation within the freshness threshold", () => {
    const { plan } = fixture({}, {
      queries: [{ ...old.queries[0]!,
        checkedAt: new Date("2026-11-09T11:00:00.000Z"),
      }],
    });
    expect(plan.validForExecution).toBe(false);
    expect(plan.deferredPackages).toBe(1);
    expect(plan.decisions[0]?.classification).toBe("FRESH_COMPLETE");
  });
  it("prevents retry of incomplete results during the cooldown window", () => {
    const { plan } = fixture({}, {
      queries: [{ ...old.queries[0]!,
        checkedAt: new Date("2026-11-09T11:45:00.000Z"),
        providerStatus: "UPSTREAM_ERROR",
      }],
    });
    expect(plan.validForExecution).toBe(false);
    expect(plan.decisions[0]?.classification).toBe("RETRY_DEFERRED");
  });
  it("allows review of an old failed provider response", () => {
    const { plan } = fixture({}, {
      queries: [{ ...old.queries[0]!,
        checkedAt: new Date("2026-11-09T09:00:00.000Z"),
        providerStatus: "TRUNCATED",
      }],
    });
    expect(plan.validForExecution).toBe(true);
    expect(plan.decisions[0]?.classification).toBe("INCOMPLETE");
  });
  it("obeys explicit exclusion of incomplete results", () => {
    const command = {
      ...input, policy: { ...policy, includeIncomplete: false },
    };
    const { plan } = fixture(command, {
      queries: [{ ...old.queries[0]!,
        providerStatus: "TRUNCATED",
      }],
    });
    expect(plan.validForExecution).toBe(false);
  });
  it("treats newly mapped package identities as requiring review", () => {
    const { plan } = fixture({}, {}, [{
      ...rows[0]!, softwareVersion: "2.0.0",
    }]);
    expect(plan.missingPreviousPackages).toBe(1);
    expect(plan.decisions[0]?.classification).toBe("NEW_PACKAGE");
  });
  it("conservatively blocks partially selected package sets", () => {
    const nextRows = [
      ...rows, { ...rows[0]!, externalId: "asset-abc",
        softwareVersion: "2.0.0" },
    ];
    const { plan } = fixture({
      inspection: { ...input.inspection, limitPackages: 1 },
    }, {}, nextRows);
    expect(plan.unreviewedPackages).toBe(1);
    expect(plan.validForExecution).toBe(false);
  });
  it("blocks execution if an atomic quota counter is exhausted", () => {
    const { plan } = fixture({}, {}, rows, {
      inspectionsRemaining: 0, requestsRemaining: 100,
    });
    expect(plan.validForExecution).toBe(false);
    expect(plan.capacityAvailable).toBe(false);
  });
  it("blocks execution if not enough HTTP pages remain", () => {
    const { plan } = fixture({}, {}, rows, {
      inspectionsRemaining: 10, requestsRemaining: 1,
    });
    expect(plan.validForExecution).toBe(false);
    expect(plan.maximumHttpPages).toBe(2);
  });
  it("rejects execution of an altered plan digest", () => {
    const { plan } = fixture();
    const altered = parseOsvRenewalCommand({
      ...input, dryRun: false,
      inspection: { ...input.inspection, dryRun: false },
      confirmOutbound: true,
      expectedPlanDigest: "b".repeat(64),
    });
    expect(() => assertRenewalExecution(altered, plan)).toThrow();
  });
  it("accepts the approved matching digest only if the plan is currently eligible", () => {
    const { plan } = fixture();
    const command = parseOsvRenewalCommand({
      ...input, dryRun: false,
      inspection: { ...input.inspection, dryRun: false },
      confirmOutbound: true,
      expectedPlanDigest: plan.planDigest,
    });
    expect(() => assertRenewalExecution(command, plan)).not.toThrow();
    expect(() => assertRenewalExecution(command, {
      ...plan, capacityAvailable: false,
      validForExecution: false,
    })).toThrow();
  });
  it("does not bind the approval digest to the moving timestamp or quota counters", () => {
    const a = fixture().plan;
    const b = fixture({}, {}, rows, {
      inspectionsRemaining: 2, requestsRemaining: 25,
    }).plan;
    expect(a.planDigest).toBe(b.planDigest);
    expect(a.generatedAt).toBe(b.generatedAt);
  });
  it("binds authorization to package version, request key and policy", () => {
    const baseline = fixture().plan.planDigest;
    expect(fixture({
      requestKey: "renewal-another-unique-key",
    }).plan.planDigest).not.toBe(baseline);
    expect(fixture({
      policy: { ...policy, freshnessMinutes: 10080 },
    }).plan.planDigest).not.toBe(baseline);
    expect(fixture({}, {}, [{
      ...rows[0]!, softwareVersion: "2.0.0",
    }]).plan.planDigest).not.toBe(baseline);
  });
});
