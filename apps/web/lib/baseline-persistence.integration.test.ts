import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  BaselinePersistenceService, BaselineConflictError,
} from "./baseline-persistence";

describe.skipIf(!process.env.DATABASE_URL)(
  "Persistent organizational Baseline revisions", () => {
    const nonce = randomUUID().slice(0, 8);
    const org = "baseline-org-" + nonce;
    const foreignOrg = "baseline-foreign-" + nonce;
    const admin = "baseline-admin-" + nonce;
    const member = "baseline-member-" + nonce;
    const auditor = "baseline-auditor-" + nonce;
    const other = "baseline-other-" + nonce;
    const service = new BaselinePersistenceService();
    const owner = {
      organizationId: org, userId: admin, role: "OWNER" as const,
    };
    const writer = {
      organizationId: org, userId: member, role: "MEMBER" as const,
    };
    const reader = {
      organizationId: org, userId: auditor, role: "AUDITOR" as const,
    };
    const outsider = {
      organizationId: foreignOrg, userId: other,
      role: "OWNER" as const,
    };
    const answers = [
      { questionId: "mfa", answer: "YES",
        evidenceReference: "audit-doc-12345", notes: "Do not store private notes" },
      { questionId: "backups", answer: "PARTIAL" },
    ];
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: admin, name: "Baseline admin",
          email: "baseline-admin-" + nonce + "@example.invalid" },
        { id: member, name: "Baseline member",
          email: "baseline-member-" + nonce + "@example.invalid" },
        { id: auditor, name: "Baseline auditor",
          email: "baseline-auditor-" + nonce + "@example.invalid" },
        { id: other, name: "Baseline outsider",
          email: "baseline-other-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, slug: org, name: "Baseline org" },
        { id: foreignOrg, slug: foreignOrg, name: "Foreign org" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: admin, role: "OWNER" },
        { organizationId: org, userId: member, role: "MEMBER" },
        { organizationId: org, userId: auditor, role: "AUDITOR" },
        { organizationId: foreignOrg, userId: other, role: "OWNER" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreignOrg] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [admin, member, auditor, other] } },
      });
    });
    it("starts with a missing revision rather than invented health", async () => {
      const initial = await service.execute(owner, { operation: "READ" });
      expect(initial.data).toMatchObject({
        exists: false, revision: 0,
      });
      expect(initial.v1CyberScoreUpdated).toBe(false);
    });
    it("persists scrubbed answers and transactionally audits a draft", async () => {
      const result = await service.execute(owner, {
        operation: "SAVE", expectedRevision: 0,
        responses: answers,
      });
      expect(result.data).toMatchObject({
        created: true, auditWritten: true, historyRevision: 1,
        legacyScoreWrites: 0,
      });
      const row = await db.baselineDraft.findFirstOrThrow({
        where: { organizationId: org },
      });
      expect(row.revision).toBe(1);
      expect(JSON.stringify(row.responses))
        .not.toContain("Do not store private notes");
      expect(JSON.stringify(row.responses)).toContain("audit-doc-12345");
      expect(await db.auditEvent.count({ where: {
        organizationId: org, action: "BASELINE_SAVE",
      } })).toBe(1);
      expect(await db.baselineRevision.count({ where: {
        organizationId: org,
      } })).toBe(1);
    });
    it("rejects stale optimistic revisions without mutating data", async () => {
      await expect(service.execute(writer, {
        operation: "SAVE", expectedRevision: 0,
        responses: [],
      })).rejects.toBeInstanceOf(BaselineConflictError);
      expect(await db.baselineDraft.count({
        where: { organizationId: org, revision: 1 },
      })).toBe(1);
    });
    it("allows a member to update draft and increments revision", async () => {
      const result = await service.execute(writer, {
        operation: "SAVE", expectedRevision: 1,
        responses: [
          { questionId: "mfa", answer: "YES" },
          { questionId: "backups", answer: "NO" },
          { questionId: "restore-tests", answer: "UNKNOWN" },
        ],
      });
      expect(result.data).toMatchObject({
        created: false, historyRevision: 2,
      });
      const rows = await db.baselineRevision.findMany({
        where: { organizationId: org },
        orderBy: { revision: "asc" },
      });
      expect(rows.map(x => x.revision)).toEqual([1, 2]);
      expect(rows[0]!.responsesDigest).not.toBe(rows[1]!.responsesDigest);
    });
    it("allows auditor reads but prohibits authoring", async () => {
      const result = await service.execute(reader, {
        operation: "HISTORY", limit: 10,
      });
      expect((result.data as { revisions: unknown[] }).revisions)
        .toHaveLength(2);
      await expect(service.execute(reader, {
        operation: "SUBMIT", expectedRevision: 2,
        responses: [],
      })).rejects.toThrow(/Auditors/);
    });
    it("submits a preserved declarative report and does not alter v1 scores", async () => {
      const v1 = await db.securityScore.count({
        where: { organizationId: org },
      });
      const data = await service.execute(owner, {
        operation: "SUBMIT", expectedRevision: 2,
        responses: [{ questionId: "backups", answer: "NO" }],
      });
      const payload = data.data as {
        draft: { revision: number; state: string };
        report: { summary: { securityScore: number | null } };
      };
      expect(payload.draft.revision).toBe(3);
      expect(payload.draft.state).toBe("SUBMITTED");
      expect(payload.report.summary.securityScore).toBeNull();
      const record = await db.baselineRevision.findFirstOrThrow({
        where: { organizationId: org, revision: 3 },
      });
      expect(record.reportDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(record.assessmentDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(await db.securityScore.count({
        where: { organizationId: org },
      })).toBe(v1);
    });
    it("rejects edits after submission until explicit reopen", async () => {
      await expect(service.execute(owner, {
        operation: "SAVE", expectedRevision: 3,
        responses: [],
      })).rejects.toThrow(/Reopen/);
      const reopened = await service.execute(owner, {
        operation: "REOPEN", expectedRevision: 3,
      });
      expect(reopened.data).toMatchObject({
        historyRevision: 4,
      });
    });
    it("compares historical revisions without asserting remediation", async () => {
      const response = await service.execute(reader, {
        operation: "COMPARE", revision: 4, earlierRevision: 1,
      });
      const comparison = response.data as {
        changed: Array<{ questionId: string }>;
        remediationProven: boolean; historicalCyberScoreModified: boolean;
      };
      expect(comparison.changed.some(x =>
        x.questionId === "backups")).toBe(true);
      expect(comparison.remediationProven).toBe(false);
      expect(comparison.historicalCyberScoreModified).toBe(false);
    });
    it("isolates all saved revisions by organization", async () => {
      const foreign = await service.execute(outsider, {
        operation: "READ",
      });
      expect(foreign.data).toMatchObject({
        exists: false, revision: 0,
      });
      await expect(service.execute(outsider, {
        operation: "REVISION", revision: 1,
      })).rejects.toThrow();
    });
    it("rejects unstructured references and unexpected fields", async () => {
      await expect(service.execute(owner, {
        operation: "SAVE", expectedRevision: 4,
        responses: [{
          questionId: "mfa", answer: "YES",
          evidenceReference: "https://example.org/?token=secret",
        }],
      })).rejects.toThrow();
      await expect(service.execute(owner, {
        operation: "READ", oauthToken: "not acceptable",
      })).rejects.toThrow();
    });
  },
);
