import { describe, expect, it } from "vitest";
import {
  parsePrivacyPolicy, assessPrivacyImport,
  assessPrivacyReadiness,
} from "./assets-privacy-readiness";
import type { PrivacyDataset, PrivacyImport } from "./assets-privacy-readiness";
import { parsePrivacyInspectionCommand } from "./assets-privacy-readiness-service";

const now = new Date("2026-11-10T12:00:00.000Z");
const tenant = "privacy-tenant-12345";
function example(): PrivacyImport {
  return {
    importId: "privacy-import-12345",
    state: "COMMITTED",
    sourceLabel: "Synthetic declared inventory",
    createdAt: new Date("2026-11-01T12:00:00.000Z"),
    retiredAt: null, importedCount: 2,
    payloadDigest: "a".repeat(64),
    hostnamesPresent: 2, ownerHashesPresent: 1,
    deviceCount: 2, inspectionCount: 1,
    oldestInspectionAt: new Date("2026-11-02T12:00:00.000Z"),
    newestInspectionAt: new Date("2026-11-03T12:00:00.000Z"),
    caseCount: 1, openedCaseCount: 1,
    oldestOpenCaseAt: new Date("2026-11-05T12:00:00.000Z"),
    scheduleCount: 0,
  };
}
function dataset(): PrivacyDataset {
  return {
    organizationId: tenant, now,
    imports: [example()], totalImports: 1,
    auditRecords: 2, auditWithUser: 1, auditWithResource: 2,
  };
}
function inspect(data = dataset(), policy = parsePrivacyPolicy()) {
  return assessPrivacyReadiness(data, policy);
}
describe("Fase 4 privacy and retention policy boundary", () => {
  it("uses bounded, conservative policy defaults", () => {
    expect(parsePrivacyPolicy()).toMatchObject({
      minimumRetiredDays: 30, maximumCandidateAgeDays: 365,
      maximumActiveAgeDays: 365, maximumEvidenceAgeDays: 365,
      maximumOpenCaseAgeDays: 90, maxImports: 100,
      requireBackupDeletionProcedure: true,
      requireOwnerHashDisposalReview: true,
      requireHostnameReview: true,
      requireCaseDataRetentionReview: true,
    });
    expect(parsePrivacyInspectionCommand()).toHaveProperty("policy");
  });
  it.each([
    { minimumRetiredDays: 0 }, { maximumCandidateAgeDays: 3651 },
    { maximumActiveAgeDays: 0 }, { maximumEvidenceAgeDays: 0 },
    { maximumOpenCaseAgeDays: -1 }, { maxImports: 0 },
    { maxImports: 501 }, { maxImports: 10.5 },
    { requireBackupDeletionProcedure: "true" },
    { requireOwnerHashDisposalReview: 1 },
    { requireHostnameReview: null },
    { requireCaseDataRetentionReview: 1 },
    { unknownPolicy: true },
  ])("rejects invalid privacy policy %j", patch => {
    expect(() => parsePrivacyPolicy(patch)).toThrow();
  });
  it("rejects an attempt to spoof another organization in the request", () => {
    expect(() => parsePrivacyInspectionCommand({
      organizationId: "foreign-tenant-12345",
    })).toThrow();
  });
  it("identifies pseudonymous owner hashes and hostnames as potential PII", () => {
    const result = inspect();
    expect(result.totalPotentialHostnames).toBe(2);
    expect(result.totalOwnerHashes).toBe(1);
    expect(result.imports[0]?.possiblePersonalData).toBe(true);
    expect(result.gates.find(x => x.id === "OWNER_HASH_PII")?.severity)
      .toBe("REVIEW");
    expect(result.gates.find(x => x.id === "HOSTNAME_PII")?.severity)
      .toBe("REVIEW");
  });
  it("never claims verified legal signoff or erasure", () => {
    const report = inspect();
    expect(report).toMatchObject({
      databasesMutated: false, personalDataErased: false,
      backupDeletionVerified: false, userConsentInferred: false,
    });
    expect(report.readiness.pendingOperatorApproval).toBe(true);
    expect(report.warnings.join(" ")).toMatch(/read-only/i);
  });
  it("flags unresolved cases that exceed configured retention age", () => {
    const data = dataset();
    data.imports[0]!.oldestOpenCaseAt =
      new Date("2026-01-01T00:00:00.000Z");
    const report = inspect(data);
    expect(report.openCasesBeyondPolicy).toBe(1);
    expect(report.gates.find(x => x.id === "CASE_RETENTION")?.severity)
      .toBe("REVIEW");
  });
  it("flags too-old active snapshots without auto-retiring them", () => {
    const data = dataset();
    data.imports[0]!.createdAt =
      new Date("2025-01-01T00:00:00.000Z");
    const report = inspect(data);
    expect(report.activeTooOld).toBe(1);
    expect(report.gates.find(x => x.id === "ACTIVE_INVENTORY_AGE")?.severity)
      .toBe("BLOCK");
    expect(report.imports[0]?.state).toBe("COMMITTED");
  });
  it("does not recommend deletion of snapshots which are still active", () => {
    expect(inspect().imports[0]?.eligibleForSeparatePurgePreview)
      .toBe(false);
  });
  it("offers separate purge only for legitimately retired mature data", () => {
    const data = dataset();
    data.imports[0]!.state = "RETIRED";
    data.imports[0]!.createdAt =
      new Date("2025-01-01T12:00:00.000Z");
    data.imports[0]!.retiredAt =
      new Date("2026-08-01T12:00:00.000Z");
    const report = inspect(data);
    expect(report.imports[0]?.eligibleForSeparatePurgePreview).toBe(true);
    expect(report.retiredMatured).toBe(1);
    expect(report.gates.find(x => x.id === "RETIRED_SNAPSHOT_AGE")?.severity)
      .toBe("REVIEW");
    expect(report.imports[0]?.blockers.length).toBeGreaterThan(0);
  });
  it("rejects incomplete snapshots before privacy impact analysis", () => {
    const data = dataset();
    data.totalImports = 2;
    expect(() => inspect(data)).toThrow();
  });
  it("blocks a corrupt persisted inventory count", () => {
    const data = dataset();
    data.imports[0]!.deviceCount = 1;
    const report = inspect(data);
    expect(report.gates.find(x => x.id === "PURGE_DEPENDENCIES")?.severity)
      .toBe("BLOCK");
  });
  it("blocks an impossible future-dated active snapshot", () => {
    const data = dataset();
    data.imports[0]!.createdAt =
      new Date("2027-01-01T00:00:00.000Z");
    expect(inspect(data).imports[0]!.blockers.join(" "))
      .toMatch(/after evaluation time/i);
  });
  it("detects audited linkage counts that exceed audit totals", () => {
    const data = dataset();
    data.auditWithResource = 3;
    expect(inspect(data).gates.find(x =>
      x.id === "AUDIT_LINKAGE")?.severity).toBe("BLOCK");
  });
  it("represents backup deletion as unverified regardless of import state", () => {
    const data = dataset();
    data.imports = []; data.totalImports = 0;
    const report = inspect(data);
    expect(report.backupDeletionVerified).toBe(false);
    expect(report.gates.find(x => x.id === "BACKUP_PROCESS")?.severity)
      .toBe("REVIEW");
  });
  it("keeps retentions independent of success or failure of other gates", () => {
    const report = inspect();
    expect(report.procedure.map(x => x.stage)).toEqual([
      "CLASSIFY", "APPROVE", "RETIRE", "VERIFY", "PURGE",
      "BACKUP_REVIEW", "CLOSE",
    ]);
    expect(report.procedure.find(x =>
      x.stage === "PURGE")?.destructive).toBe(true);
    expect(report.procedure.every(x => x.requiresHumanApproval)).toBe(true);
  });
  it("reports only local data classes and not live tenant completeness", () => {
    const report = inspect();
    expect(report.imports[0]?.dataProvenance)
      .toBe("CUSTOMER_DECLARED_CSV");
    expect(report.warnings.join(" ")).toMatch(/not exhaustive device/i);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("is deterministic for the same source, policy and evaluation date", () => {
    expect(inspect().digest).toBe(inspect().digest);
  });
  it("does not accept an unsafe partial import collection as complete", () => {
    const data = dataset();
    data.imports.push({ ...example(),
      importId: "privacy-second-12345" });
    expect(() => inspect(data)).toThrow();
  });
});
