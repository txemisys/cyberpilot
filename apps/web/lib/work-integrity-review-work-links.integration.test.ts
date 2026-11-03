import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  changeReviewWorkAssociation,
  inspectReviewWorkAssociation,
  listReviewWorkAssociations,
} from "./work-integrity-review-work-links";
import type { ReviewScope } from "./work-integrity-persistent-review";

/** Real PostgreSQL test; skipped only when DATABASE_URL is unavailable. */
describe.skipIf(!process.env.DATABASE_URL)(
  "integrity review-work associations PostgreSQL", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const organizationId = "review-link-org-" + suffix;
    const otherOrganizationId = "review-link-other-" + suffix;
    const userId = "review-link-user-" + suffix;
    const otherUserId = "review-link-other-user-" + suffix;
    const captureId = "review-link-capture-" + suffix;
    const taskId = "review-link-task-" + suffix;
    const scope: ReviewScope = { organizationId, userId, role: "ADMIN" };
    const auditor: ReviewScope = { ...scope, role: "AUDITOR" };
    const other: ReviewScope = {
      organizationId: otherOrganizationId,
      userId: otherUserId, role: "ADMIN",
    };
    let workItemId = "";
    let otherWorkItemId = "";
    let linkId = "";
    const command = (action: "LINK" | "UNLINK" | "RELINK", revision: number) => ({
      taskId, workItemId, action, expectedRevision: revision,
      rationale: "This operational work item is explicitly associated with the review.",
    });
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: userId, name: "Review link user",
            email: "review-link-" + suffix + "@example.invalid" },
          { id: otherUserId, name: "Other review link user",
            email: "review-link-other-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: organizationId, name: "Review link test",
            slug: "review-link-" + suffix },
          { id: otherOrganizationId, name: "Other review link test",
            slug: "review-link-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId, userId, role: "ADMIN" },
          { organizationId: otherOrganizationId, userId: otherUserId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId,
          source: "review-link-integration",
          capturedAt: new Date(), complete: true,
          caseCount: 1, digest: "b".repeat(64),
          payload: { cases: [] }, createdById: userId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, organizationId, captureId,
          externalTaskId: "review-link-case",
          title: "Investigate the remediation work",
          severity: "ERROR", required: true,
        },
      });
      const finding = await db.securityFinding.create({
        data: {
          organizationId,
          title: "Review link finding",
          key: "review-link-" + suffix,
          ruleId: "review-link-control",
          description: "Test finding",
          severity: "HIGH",
        },
      });
      const remediation = await db.remediation.create({
        data: {
          organizationId, findingId: finding.id,
          title: "Review link remediation",
          playbookId: "integration-test", mode: "GUIDED",
          summary: "Review link test", steps: [], verification: {},
        },
      });
      const work = await db.remediationWorkItem.create({
        data: {
          organizationId, findingId: finding.id,
          remediationId: remediation.id,
          title: "Review link work",
        },
      });
      workItemId = work.id;
      const otherFinding = await db.securityFinding.create({
        data: {
          organizationId: otherOrganizationId,
          title: "Other finding",
          key: "review-link-other-" + suffix,
          ruleId: "other-review-link-control",
          description: "Other test finding",
          severity: "HIGH",
        },
      });
      const otherRemediation = await db.remediation.create({
        data: {
          organizationId: otherOrganizationId,
          findingId: otherFinding.id,
          title: "Other remediation",
          playbookId: "integration-test", mode: "GUIDED",
          summary: "Other review link test", steps: [], verification: {},
        },
      });
      const otherWork = await db.remediationWorkItem.create({
        data: {
          organizationId: otherOrganizationId,
          findingId: otherFinding.id,
          remediationId: otherRemediation.id,
          title: "Other work",
        },
      });
      otherWorkItemId = otherWork.id;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, otherOrganizationId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, otherUserId] } },
      });
    });
    it("denies write access to auditor", async () => {
      await expect(changeReviewWorkAssociation(auditor, command("LINK", 0)))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("rejects cross-tenant work item references", async () => {
      await expect(changeReviewWorkAssociation(scope, {
        ...command("LINK", 0), workItemId: otherWorkItemId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("rejects cross-tenant task references", async () => {
      await expect(changeReviewWorkAssociation(other, command("LINK", 0)))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("persists an association and a scoped audit", async () => {
      const result = await changeReviewWorkAssociation(scope, command("LINK", 0));
      expect(result.active).toBe(true);
      expect(result.link.revision).toBe(1);
      linkId = result.link.id;
      const audit = await db.auditEvent.findMany({
        where: {
          organizationId, resourceId: linkId,
          action: "integrity.review.work.link",
        },
      });
      expect(audit).toHaveLength(1);
      expect(audit[0]?.actorUserId).toBe(userId);
    });
    it("does not allow duplicate links or stale revisions", async () => {
      await expect(changeReviewWorkAssociation(scope, command("LINK", 0)))
        .rejects.toMatchObject({ code: "CONFLICT" });
      await expect(changeReviewWorkAssociation(scope, command("UNLINK", 0)))
        .rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("lists associations for authorized read-only users", async () => {
      const list = await listReviewWorkAssociations(auditor, { taskId });
      expect(list.total).toBe(1);
      expect(list.links[0]?.id).toBe(linkId);
      await expect(listReviewWorkAssociations(other, { taskId }))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("unlinks and retains the audit trail", async () => {
      const result = await changeReviewWorkAssociation(scope, command("UNLINK", 1));
      expect(result.active).toBe(false);
      expect(result.link.revision).toBe(2);
      const active = await listReviewWorkAssociations(scope, { taskId });
      expect(active.total).toBe(0);
      const all = await listReviewWorkAssociations(scope, {
        taskId, includeInactive: true,
      });
      expect(all.total).toBe(1);
      expect(all.links[0]?.unlinkedAt).not.toBeNull();
    });
    it("relinks without creating a second association", async () => {
      const result = await changeReviewWorkAssociation(scope, command("RELINK", 2));
      expect(result.active).toBe(true);
      expect(result.link.revision).toBe(3);
      expect(await db.integrityReviewWorkLink.count({
        where: { organizationId, taskId, workItemId },
      })).toBe(1);
    });
    it("checks the complete audit revision sequence", async () => {
      const inspection = await inspectReviewWorkAssociation(scope, linkId);
      expect(inspection.consistent).toBe(true);
      expect(inspection.revisions).toHaveLength(3);
      await expect(inspectReviewWorkAssociation(other, linkId))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("detects an audit gap", async () => {
      const audit = await db.auditEvent.findFirstOrThrow({
        where: {
          organizationId, resourceId: linkId,
          action: "integrity.review.work.unlink",
        },
      });
      await db.auditEvent.delete({ where: { id: audit.id } });
      const inspection = await inspectReviewWorkAssociation(scope, linkId);
      expect(inspection.consistent).toBe(false);
      expect(inspection.gaps).toContain("AUDIT_COUNT_MISMATCH");
    });
  },
);
