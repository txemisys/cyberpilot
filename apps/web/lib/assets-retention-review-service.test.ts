import { describe, expect, it } from "vitest";
import {
  parseRetentionCreate, parseRetentionChange,
  parseRetentionQuery, retentionTarget,
  RETENTION_ACKNOWLEDGEMENTS,
  missingRetentionAcknowledgements,
  assessRetentionExceptions,
  eligibleToDocumentRetention,
} from "./assets-retention-review-service";
import type { PrivacyReadinessReport,
  PrivacyImportAssessment } from "./assets-privacy-readiness";

const hash = "a".repeat(64);
const reason = "Explicit operator reason covering documented policy limitations.";
function create(overrides: Record<string, unknown> = {}) {
  return {
    importId: "import_example1", policy: {},
    reason, exceptions: [],
    acknowledgements: [],
    backupDisposition: "UNVERIFIED",
    personalDataDisposition: "REQUIRES_REVIEW",
    nextReviewAt: null,
    ...overrides,
  };
}
function transition(overrides: Record<string, unknown> = {}) {
  return {
    reviewId: "review_example1",
    expectedRevision: 1,
    expectedPrivacyDigest: hash,
    operation: "START_REVIEW",
    policy: {}, reason, exceptions: [],
    acknowledgements: [],
    backupDisposition: "UNVERIFIED",
    personalDataDisposition: "REQUIRES_REVIEW",
    nextReviewAt: null, ...overrides,
  };
}
const now = new Date("2026-11-11T12:00:00.000Z");
const selected = {
  importId: "import_example1", sourceDigest: hash,
} as PrivacyImportAssessment;
const report = {
  fullyExamined: true,
  gates: [
    { id: "BACKUP_PROCESS", severity: "REVIEW",
      affectedImportIds: ["import_example1"],
      rationale: "Backups and exports are unverified." },
    { id: "HOSTNAME_PII", severity: "REVIEW",
      affectedImportIds: ["import_example1"],
      rationale: "Hostnames may represent personal data." },
    { id: "SCOPE_COMPLETENESS", severity: "PASS",
      affectedImportIds: [],
      rationale: "All declared imports considered." },
    { id: "CASE_RETENTION", severity: "BLOCK",
      affectedImportIds: ["import_other"],
      rationale: "Other inventory retains unresolved cases." },
  ],
} as PrivacyReadinessReport;
function exception(gateId: string) {
  return {
    gateId, reason,
    owner: "retention-owner",
    reviewBy: "2026-12-01T12:00:00.000Z",
    externalTicket: "ticket-12345",
  };
}
describe("Fase 4 administrative privacy exception decisions", () => {
  it("accepts explicitly scoped creation without client tenant overrides", () => {
    expect(parseRetentionCreate(create())).toMatchObject({
      importId: "import_example1", exceptions: [],
      backupDisposition: "UNVERIFIED",
    });
  });
  it.each([
    { importId: "" }, { importId: "../other" },
    { organizationId: "foreign" },
    { actorUserId: "foreign" },
    { legalSignoffVerified: true },
    { backupsErased: true },
    { state: "DOCUMENTED_WITH_EXCEPTIONS" },
    { reason: "short" },
    { exceptions: "[]" },
    { acknowledgements: ["WRONG_ACK"] },
    { acknowledgements: ["BACKUPS_NOT_ERASED", "BACKUPS_NOT_ERASED"] },
    { backupDisposition: "ERASED" },
    { personalDataDisposition: "ANONYMOUS" },
    { nextReviewAt: "tomorrow" },
  ])("rejects unsafe retention create payload %j", extra => {
    expect(() => parseRetentionCreate(create(extra))).toThrow();
  });
  it("accepts explicit reviewed exceptions with an owner and UTC follow-up", () => {
    const command = parseRetentionCreate(create({
      exceptions: [exception("BACKUP_PROCESS")],
      acknowledgements: RETENTION_ACKNOWLEDGEMENTS,
      nextReviewAt: "2026-12-05T12:00:00.000Z",
    }));
    expect(command.exceptions).toHaveLength(1);
    expect(command.exceptions[0]!.owner).toBe("retention-owner");
  });
  it.each([
    { gateId: "backup", reason, owner: "owner",
      reviewBy: "2026-12-01T12:00:00.000Z" },
    { gateId: "BACKUP_PROCESS", reason: "short", owner: "owner",
      reviewBy: "2026-12-01T12:00:00.000Z" },
    { gateId: "BACKUP_PROCESS", reason, owner: "",
      reviewBy: "2026-12-01T12:00:00.000Z" },
    { gateId: "BACKUP_PROCESS", reason, owner: "owner",
      reviewBy: "tomorrow" },
    { gateId: "BACKUP_PROCESS", reason, owner: "owner",
      reviewBy: null },
    { gateId: "BACKUP_PROCESS", reason, owner: "owner",
      reviewBy: "2026-12-01T12:00:00.000Z", legalApproved: true },
  ])("rejects malformed exception %j", bad => {
    expect(() => parseRetentionCreate(
      create({ exceptions: [bad] }))).toThrow();
  });
  it("rejects multiple exceptions for one gate", () => {
    expect(() => parseRetentionCreate(create({
      exceptions: [exception("BACKUP_PROCESS"), exception("BACKUP_PROCESS")],
    }))).toThrow();
  });
  it("requires explicit CAS revision and prior privacy fingerprint", () => {
    expect(parseRetentionChange(transition())).toMatchObject({
      reviewId: "review_example1",
      expectedRevision: 1,
      expectedPrivacyDigest: hash,
    });
  });
  it.each([
    { reviewId: "../bad" }, { reviewId: "" },
    { expectedRevision: 0 }, { expectedRevision: -1 },
    { expectedRevision: 1.2 }, { expectedRevision: "1" },
    { expectedPrivacyDigest: "bad" },
    { expectedPrivacyDigest: hash.toUpperCase() },
    { operation: "AUTO_APPROVE" },
    { operation: "APPROVE_LEGAL" },
    { operation: "DELETE_BACKUPS" },
    { organizationId: "foreign" },
  ])("rejects forged or malformed transition %j", extra => {
    expect(() => parseRetentionChange(transition(extra))).toThrow();
  });
  it("enforces conservative state machine", () => {
    const expected = {
      PENDING: {
        START_REVIEW: "IN_REVIEW", DOCUMENT_EXCEPTIONS: null,
        REJECT: "REJECTED", REOPEN: null,
      },
      IN_REVIEW: {
        START_REVIEW: null, DOCUMENT_EXCEPTIONS: "DOCUMENTED_WITH_EXCEPTIONS",
        REJECT: "REJECTED", REOPEN: null,
      },
      DOCUMENTED_WITH_EXCEPTIONS: {
        START_REVIEW: null, DOCUMENT_EXCEPTIONS: null,
        REJECT: null, REOPEN: "REOPENED",
      },
      REJECTED: {
        START_REVIEW: null, DOCUMENT_EXCEPTIONS: null,
        REJECT: null, REOPEN: "REOPENED",
      },
      REOPENED: {
        START_REVIEW: "IN_REVIEW", DOCUMENT_EXCEPTIONS: null,
        REJECT: "REJECTED", REOPEN: null,
      },
    };
    for (const [state, actions] of Object.entries(expected))
      for (const [action, target] of Object.entries(actions))
        expect(retentionTarget(
          state as Parameters<typeof retentionTarget>[0],
          action as Parameters<typeof retentionTarget>[1],
        )).toBe(target);
  });
  it("never implies legal approval from a documented exception", () => {
    const entries = [exception("BACKUP_PROCESS"),
      exception("HOSTNAME_PII")];
    const options = {
      exceptions: entries,
      acknowledgements: RETENTION_ACKNOWLEDGEMENTS,
      backupDisposition: "PROCEDURE_DOCUMENTED" as const,
      personalDataDisposition: "EXTERNAL_APPROVAL_REQUIRED" as const,
      nextReviewAt: "2026-12-15T12:00:00.000Z",
    };
    const permission = eligibleToDocumentRetention(
      report, selected, options, now);
    expect(permission.eligible).toBe(true);
    expect(permission.noLegalApprovalImplied).toBe(true);
    expect(permission.noBackupErasureImplied).toBe(true);
  });
  it("blocks an exception record missing a required gate", () => {
    const options = {
      exceptions: [exception("BACKUP_PROCESS")],
      acknowledgements: RETENTION_ACKNOWLEDGEMENTS,
      backupDisposition: "PROCEDURE_DOCUMENTED" as const,
      personalDataDisposition: "REQUIRES_REVIEW" as const,
      nextReviewAt: "2026-12-15T12:00:00.000Z",
    };
    const permission = eligibleToDocumentRetention(report, selected,
      options, now);
    expect(permission.eligible).toBe(false);
    expect(permission.unresolved.map(row => row.gateId))
      .toContain("HOSTNAME_PII");
  });
  it("blocks undocumented backup status even with a complete checklist", () => {
    const options = {
      exceptions: [exception("BACKUP_PROCESS"), exception("HOSTNAME_PII")],
      acknowledgements: RETENTION_ACKNOWLEDGEMENTS,
      backupDisposition: "UNVERIFIED" as const,
      personalDataDisposition: "REQUIRES_REVIEW" as const,
      nextReviewAt: "2026-12-15T12:00:00.000Z",
    };
    expect(eligibleToDocumentRetention(report, selected,
      options, now).eligible).toBe(false);
  });
  it("blocks expired exceptions and missing future reviews", () => {
    const options = {
      exceptions: [exception("BACKUP_PROCESS"), {
        ...exception("HOSTNAME_PII"),
        reviewBy: "2026-10-01T12:00:00.000Z",
      }],
      acknowledgements: RETENTION_ACKNOWLEDGEMENTS,
      backupDisposition: "PROCEDURE_DOCUMENTED" as const,
      personalDataDisposition: "REQUIRES_REVIEW" as const,
      nextReviewAt: null,
    };
    const result = eligibleToDocumentRetention(report, selected, options, now);
    expect(result.eligible).toBe(false);
    expect(result.exceptionExpired).toBe(true);
    expect(result.futureFollowup).toBe(false);
  });
  it("rejects exceptions for unrelated imports and fabricated gate IDs", () => {
    expect(() => assessRetentionExceptions(
      report, selected, [exception("CASE_RETENTION")])).toThrow();
    expect(() => assessRetentionExceptions(
      report, selected, [exception("FABRICATED_GATE")])).toThrow();
  });
  it("shows only relevant blocking/review gates for this import", () => {
    const gates = assessRetentionExceptions(report, selected, []);
    expect(gates.map(row => row.gateId))
      .toEqual(["BACKUP_PROCESS", "HOSTNAME_PII"]);
    expect(gates.every(row => row.status === "UNRESOLVED")).toBe(true);
  });
  it("requires each acknowledged limitation explicitly", () => {
    expect(missingRetentionAcknowledgements([]))
      .toEqual(RETENTION_ACKNOWLEDGEMENTS);
    expect(missingRetentionAcknowledgements(
      RETENTION_ACKNOWLEDGEMENTS)).toEqual([]);
  });
  it("rejects invalid list and pagination", () => {
    expect(parseRetentionQuery()).toMatchObject({
      offset: 0, limit: 25, state: null,
    });
    for (const input of [
      { offset: -1 }, { limit: 0 }, { limit: 101 },
      { state: "APPROVED_LEGAL" },
      { importId: "../foreign" },
      { organizationId: "foreign" },
      { dueBefore: "next week" },
    ])
      expect(() => parseRetentionQuery(input)).toThrow();
  });
});
