import { describe, expect, it } from "vitest";
import {
  parseOsvScheduleConfig, parseOsvScheduleCommand,
  scheduleConsentDigest, nextOsvDueAt,
  scheduleRunIdempotencyKey, scheduleEligibility,
} from "./assets-osv-renewal-schedules";
const now = new Date("2026-11-10T12:00:00.000Z");
const base = {
  name: "Weekly OSV package review",
  inventoryImportId: "import-scheduler-12345",
  sourceInspectionId: "inspection-scheduler-12345",
  cadenceMinutes: 10080,
  inspection: {
    importId: "import-scheduler-12345",
    dryRun: true,
    packageBindings: [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }],
    limitPackages: 5,
    maxPagesPerPackage: 2,
    maxRecordsPerPackage: 50,
    maxAgeMinutes: 60,
  },
  policy: {
    freshnessMinutes: 1440, minimumRetryMinutes: 60,
    maximumPackagesPerRun: 5, maximumQueriesPerDay: 200,
    maximumInspectionsPerDay: 20, historyWindowDays: 90,
    includeIncomplete: true,
  },
  allowNewPackages: false,
  allowIncompleteInventory: false,
};
describe("OSV recurring schedule configuration", () => {
  it("normalizes bounded schedule definitions and defaults to false approvals", () => {
    const result = parseOsvScheduleConfig(base);
    expect(result.name).toBe(base.name);
    expect(result.cadenceMinutes).toBe(10080);
    expect(result.inspection.dryRun).toBe(true);
    expect(result.allowNewPackages).toBe(false);
    expect(result.allowIncompleteInventory).toBe(false);
  });
  it("rejects live HTTP execution embedded in a stored definition", () => {
    expect(() => parseOsvScheduleConfig({
      ...base, inspection: { ...base.inspection, dryRun: false },
    })).toThrow();
  });
  it("requires a scheduled inspection to use the same inventory", () => {
    expect(() => parseOsvScheduleConfig({
      ...base, inspection: {
        ...base.inspection, importId: "another-import-12345",
      },
    })).toThrow();
  });
  it.each([
    { cadenceMinutes: 1 },
    { cadenceMinutes: 43201 },
    { cadenceMinutes: 60.5 },
    { name: "X" },
    { name: "foo\u0000bar" },
    { unknownField: true },
    { allowNewPackages: "true" },
    { allowIncompleteInventory: 1 },
    { policy: { freshnessMinutes: 43200 }, cadenceMinutes: 60 },
  ])("fails closed on unsafe policies %j", patch => {
    expect(() => parseOsvScheduleConfig({
      ...base, ...patch,
    })).toThrow();
  });
  it("separates consent by organization and config revision", () => {
    const a = scheduleConsentDigest("organization-one",
      parseOsvScheduleConfig(base));
    const b = scheduleConsentDigest("organization-two",
      parseOsvScheduleConfig(base));
    const c = scheduleConsentDigest("organization-one",
      parseOsvScheduleConfig({ ...base, cadenceMinutes: 1440 }));
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });
  it("keeps consent stable when package mappings are reordered", () => {
    const bindings = [
      ...base.inspection.packageBindings,
      { inventoryProduct: "Other Package",
        ecosystem: "PyPI", packageName: "other-package" },
    ];
    const first = parseOsvScheduleConfig({ ...base,
      inspection: { ...base.inspection, packageBindings: bindings },
    });
    const second = parseOsvScheduleConfig({ ...base,
      inspection: { ...base.inspection, packageBindings: [...bindings].reverse() },
    });
    expect(scheduleConsentDigest("organization-one", first)).toBe(
      scheduleConsentDigest("organization-one", second));
  });
  it("requires exact digest and explicit permission to enable", () => {
    const valid = {
      scheduleId: "osv-schedule-12345",
      expectedRevision: 1, operation: "ENABLE",
      confirmOutbound: true, consentDigest: "a".repeat(64),
    };
    expect(parseOsvScheduleCommand(valid)).toMatchObject(valid);
    expect(() => parseOsvScheduleCommand({
      ...valid, confirmOutbound: false,
    })).toThrow();
    expect(() => parseOsvScheduleCommand({
      ...valid, consentDigest: null,
    })).toThrow();
  });
  it("rejects stale revisions and unauthorized configuration changes", () => {
    const valid = {
      scheduleId: "osv-schedule-12345",
      expectedRevision: 1, operation: "DISABLE",
      confirmOutbound: false, consentDigest: null,
    };
    expect(parseOsvScheduleCommand(valid).operation).toBe("DISABLE");
    expect(() => parseOsvScheduleCommand({
      ...valid, expectedRevision: 0,
    })).toThrow();
    expect(() => parseOsvScheduleCommand({
      ...valid, config: base,
    })).toThrow();
    expect(() => parseOsvScheduleCommand({
      ...valid, operation: "UNKNOWN",
    })).toThrow();
  });
});
describe("OSV durable schedule intervals and eligibility", () => {
  it("sets a new due date strictly after a claimed UTC slot", () => {
    expect(nextOsvDueAt(new Date("2026-11-10T10:00:00.000Z"),
      60, now).toISOString()).toBe("2026-11-10T13:00:00.000Z");
  });
  it("skips delayed intervals rather than generating an unbounded catch-up burst", () => {
    const old = new Date("2026-11-01T12:00:00.000Z");
    const next = nextOsvDueAt(old, 1440, now);
    expect(next.toISOString()).toBe("2026-11-11T12:00:00.000Z");
  });
  it("does not move a schedule which is not yet due", () => {
    const future = new Date("2026-11-11T12:00:00.000Z");
    expect(nextOsvDueAt(future, 60, now)).toEqual(future);
  });
  it("generates slot-scoped idempotency keys across workers", () => {
    const a = scheduleRunIdempotencyKey(
      "schedule-12345", new Date("2026-11-10T12:00:00.000Z"));
    const b = scheduleRunIdempotencyKey(
      "schedule-12345", new Date("2026-11-10T13:00:00.000Z"));
    expect(a).toBe(scheduleRunIdempotencyKey(
      "schedule-12345", new Date("2026-11-10T12:00:00.000Z")));
    expect(a).not.toBe(b);
    expect(a).toMatch(/^scheduled-[a-f0-9]{48}$/);
  });
  it("blocks disabled and unconsented intervals even when overdue", () => {
    const due = new Date("2026-11-10T11:00:00.000Z");
    expect(scheduleEligibility(false, true, due, now)
      .join(" ")).toMatch(/disabled/i);
    expect(scheduleEligibility(true, false, due, now)
      .join(" ")).toMatch(/authorization/i);
  });
  it("allows authorized due interval without interpreting provider status", () => {
    const due = new Date("2026-11-10T11:00:00.000Z");
    expect(scheduleEligibility(true, true, due, now)).toEqual([]);
  });
  it("refuses future and extremely overdue intervals", () => {
    expect(scheduleEligibility(true, true,
      new Date("2026-11-11T11:00:00.000Z"), now)
      .join(" ")).toMatch(/not yet due/i);
    expect(scheduleEligibility(true, true,
      new Date("2026-09-01T11:00:00.000Z"), now)
      .join(" ")).toMatch(/too old/i);
  });
});
