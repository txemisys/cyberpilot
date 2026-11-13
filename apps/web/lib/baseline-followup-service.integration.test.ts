import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { BaselinePersistenceService } from "./baseline-persistence";
import {
  BaselineFollowUpService, BaselineFollowUpConflict,
} from "./baseline-followup-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "Persistent Baseline follow-up items and immutable events", () => {
    const nonce = randomUUID().slice(0, 8);
    const org = "followup-org-" + nonce;
    const foreignOrg = "followup-other-org-" + nonce;
    const ownerId = "followup-owner-" + nonce;
    const memberId = "followup-member-" + nonce;
    const auditorId = "followup-auditor-" + nonce;
    const outsiderId = "followup-other-" + nonce;
    const persistence = new BaselinePersistenceService();
    const service = new BaselineFollowUpService();
    const owner = {
      organizationId: org, userId: ownerId,
      role: "OWNER" as const,
    };
    const member = {
      organizationId: org, userId: memberId,
      role: "MEMBER" as const,
    };
    const auditor = {
      organizationId: org, userId: auditorId,
      role: "AUDITOR" as const,
    };
    const outsider = {
      organizationId: foreignOrg, userId: outsiderId,
      role: "OWNER" as const,
    };
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: ownerId, name: "Followup owner",
          email: "followup-owner-" + nonce + "@example.invalid" },
        { id: memberId, name: "Followup member",
          email: "followup-member-" + nonce + "@example.invalid" },
        { id: auditorId, name: "Followup auditor",
          email: "followup-auditor-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "Followup outsider",
          email: "followup-outsider-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, slug: org, name: "Followup organization" },
        { id: foreignOrg, slug: foreignOrg,
          name: "Other organization" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: ownerId, role: "OWNER" },
        { organizationId: org, userId: memberId, role: "MEMBER" },
        { organizationId: org, userId: auditorId, role: "AUDITOR" },
        { organizationId: foreignOrg, userId: outsiderId,
          role: "OWNER" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreignOrg] } },
      });
      await db.user.deleteMany({
        where: { id: {
          in: [ownerId, memberId, auditorId, outsiderId],
        } },
      });
    });
    it("refuses to initialize follow-ups before Baseline submission", async () => {
      await expect(service.execute(owner, {
        operation: "INITIALIZE",
      })).rejects.toThrow(/Submit/);
    });
    it("materializes proposed actions from submitted assessment", async () => {
      await persistence.execute(owner, {
        operation: "SUBMIT", expectedRevision: 0,
        responses: [
          { questionId: "backups", answer: "NO" },
          { questionId: "incident-plan", answer: "PARTIAL" },
          { questionId: "mfa", answer: "YES" },
        ],
      });
      const initialized = await service.execute(owner, {
        operation: "INITIALIZE",
      });
      const payload = initialized.data as {
        created: number; preserved: number;
        noExistingActionOverwritten: boolean;
      };
      expect(payload.created).toBeGreaterThan(1);
      expect(payload.preserved).toBe(0);
      expect(payload.noExistingActionOverwritten).toBe(true);
      const rows = await db.baselineFollowUp.findMany({
        where: { organizationId: org },
      });
      expect(rows.length).toBe(payload.created);
      expect(rows.every(x => x.status === "OPEN")).toBe(true);
      expect(await db.baselineFollowUpEvent.count({
        where: { organizationId: org },
      })).toBe(payload.created);
    });
    it("does not overwrite existing action progress on reinitialization", async () => {
      const result = await service.execute(owner, {
        operation: "INITIALIZE",
      });
      const payload = result.data as {
        created: number; preserved: number;
      };
      expect(payload.created).toBe(0);
      expect(payload.preserved).toBeGreaterThan(1);
    });
    it("assigns organization member, due date and opaque evidence reference", async () => {
      const rows = await service.execute(owner, {
        operation: "LIST",
      });
      const item = (rows.data as {
        items: Array<{
          questionId: string; revision: number;
        }>;
      }).items.find(x => x.questionId === "backups")!;
      const update = await service.execute(owner, {
        operation: "UPDATE", questionId: item.questionId,
        expectedRevision: item.revision,
        status: "IN_PROGRESS",
        ownerUserId: memberId,
        dueAt: "2026-12-01T12:00:00.000Z",
        evidenceReference: "doc-backup-12345",
      });
      const changed = (update.data as {
        item: {
          revision: number; status: string; ownerUserId: string;
          evidenceReference: string;
        };
        independentlyValidated: boolean;
      });
      expect(changed.item.status).toBe("IN_PROGRESS");
      expect(changed.item.ownerUserId).toBe(memberId);
      expect(changed.item.evidenceReference).toBe("doc-backup-12345");
      expect(changed.independentlyValidated).toBe(false);
    });
    it("rejects stale updates, foreign owners and unsafe evidence URLs", async () => {
      await expect(service.execute(owner, {
        operation: "UPDATE", questionId: "backups",
        expectedRevision: 1, status: "BLOCKED",
      })).rejects.toBeInstanceOf(BaselineFollowUpConflict);
      await expect(service.execute(owner, {
        operation: "UPDATE", questionId: "backups",
        expectedRevision: 2, ownerUserId: outsiderId,
      })).rejects.toThrow();
      await expect(service.execute(owner, {
        operation: "UPDATE", questionId: "backups",
        expectedRevision: 2,
        evidenceReference: "https://example.org/?token=123",
      })).rejects.toThrow();
    });
    it("records reported completion without asserting security remediation", async () => {
      const result = await service.execute(member, {
        operation: "UPDATE", questionId: "backups",
        expectedRevision: 2,
        status: "COMPLETED_REPORTED",
      });
      const data = result.data as {
        reportedCompletionOnly: boolean;
        independentlyValidated: boolean;
        item: { status: string; independentlyVerified: false };
      };
      expect(data.reportedCompletionOnly).toBe(true);
      expect(data.independentlyValidated).toBe(false);
      expect(data.item.independentlyVerified).toBe(false);
      const events = await service.execute(auditor, {
        operation: "HISTORY", questionId: "backups",
      });
      const records = (events.data as {
        events: Array<{ revision: number }>;
      }).events;
      expect(records.map(x => x.revision)).toEqual([3, 2, 1]);
    });
    it("prohibits auditor mutations and foreign-organization actions", async () => {
      await expect(service.execute(auditor, {
        operation: "INITIALIZE",
      })).rejects.toThrow(/Auditors/);
      await expect(service.execute(outsider, {
        operation: "READ", questionId: "backups",
      })).rejects.toThrow();
      const list = await service.execute(outsider, {
        operation: "LIST",
      });
      expect((list.data as { items: unknown[] }).items).toHaveLength(0);
    });
    it("returns summary but no actual technical verification", async () => {
      const summary = await service.execute(owner, {
        operation: "SUMMARY",
      });
      expect(summary.data).toMatchObject({
        technicallyVerifiedCompleted: 0,
        customerComplianceCertified: false,
        automaticRemediations: 0,
      });
      expect(summary.independentRemediationVerified).toBe(false);
      expect(summary.legacyCyberScoreChanged).toBe(false);
    });
  },
);
