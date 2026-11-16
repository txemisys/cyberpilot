import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { BaselinePersistenceService } from "./baseline-persistence";
import {
  BaselineTechnicalReviewService, ReviewConflictError,
} from "./baseline-technical-review-service";
import {
  buildBaselineTechnicalReviewReport,
  verifyBaselineTechnicalReviewReport,
  exportBaselineTechnicalReviewReport,
} from "./baseline-technical-review-report";

describe.skipIf(!process.env.DATABASE_URL)(
  "Baseline submitted revision technical review integration", () => {
    const suffix = randomUUID().slice(0, 8);
    const org = "technical-review-" + suffix;
    const outsiderOrg = "technical-other-" + suffix;
    const ownerId = "technical-owner-" + suffix;
    const reviewerId = "technical-auditor-" + suffix;
    const memberId = "technical-member-" + suffix;
    const outsiderId = "technical-outsider-" + suffix;
    const baseline = new BaselinePersistenceService();
    const reviews = new BaselineTechnicalReviewService();
    const owner = {
      organizationId: org, userId: ownerId,
      role: "OWNER" as const,
    };
    const reviewer = {
      organizationId: org, userId: reviewerId,
      role: "AUDITOR" as const,
    };
    const member = {
      organizationId: org, userId: memberId,
      role: "MEMBER" as const,
    };
    const outsider = {
      organizationId: outsiderOrg, userId: outsiderId,
      role: "OWNER" as const,
    };
    let reviewId = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: ownerId, name: "Review owner",
          email: "review-owner-" + suffix + "@example.invalid" },
        { id: reviewerId, name: "Review auditor",
          email: "review-auditor-" + suffix + "@example.invalid" },
        { id: memberId, name: "Review member",
          email: "review-member-" + suffix + "@example.invalid" },
        { id: outsiderId, name: "Review outsider",
          email: "review-outsider-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, slug: org, name: "Review organization" },
        { id: outsiderOrg, slug: outsiderOrg,
          name: "Other organization" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: ownerId, role: "OWNER" },
        { organizationId: org, userId: reviewerId, role: "AUDITOR" },
        { organizationId: org, userId: memberId, role: "MEMBER" },
        { organizationId: outsiderOrg, userId: outsiderId, role: "OWNER" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, outsiderOrg] } },
      });
      await db.user.deleteMany({
        where: { id: {
          in: [ownerId, reviewerId, memberId, outsiderId],
        } },
      });
    });
    it("rejects reviews of non-submitted draft revisions", async () => {
      await baseline.execute(owner, {
        operation: "SAVE", expectedRevision: 0,
        responses: [{ questionId: "mfa", answer: "YES" }],
      });
      await expect(reviews.execute(owner, {
        operation: "CREATE", sourceRevision: 1,
      })).rejects.toThrow(/submitted/);
    });
    it("creates one technical review for a submitted report and its digest", async () => {
      await baseline.execute(owner, {
        operation: "SUBMIT", expectedRevision: 1,
        responses: [
          { questionId: "mfa", answer: "YES" },
          { questionId: "backups", answer: "NO" },
        ],
      });
      const response = await reviews.execute(owner, {
        operation: "CREATE", sourceRevision: 2,
      });
      const data = response.data as {
        review: {
          id: string; reportDigest: string;
          state: string; sourceRevision: number;
          externalCustomerApproval: false;
        };
      };
      reviewId = data.review.id;
      expect(data.review.state).toBe("OPEN");
      expect(data.review.sourceRevision).toBe(2);
      expect(data.review.externalCustomerApproval).toBe(false);
      expect(data.review.reportDigest).toMatch(/^[a-f0-9]{64}$/);
    });
    it("idempotently reuses existing review for the same source snapshot", async () => {
      const result = await reviews.execute(owner, {
        operation: "CREATE", sourceRevision: 2,
      });
      expect(result.data).toMatchObject({
        alreadyExists: true,
      });
      expect(await db.baselineReview.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("auditor can begin technical review, ordinary member cannot", async () => {
      await expect(reviews.execute(member, {
        operation: "START", reviewId,
        expectedRevision: 1,
      })).rejects.toThrow(/reviewer/);
      const result = await reviews.execute(reviewer, {
        operation: "START", reviewId,
        expectedRevision: 1,
        reviewerUserId: reviewerId,
      });
      expect(result.data).toMatchObject({
        auditWritten: true, developmentReviewOnly: true,
        externalCustomerSignoff: false,
      });
    });
    it("requires blocking findings to be addressed before internal completion", async () => {
      await reviews.execute(reviewer, {
        operation: "UPDATE", reviewId,
        expectedRevision: 2,
        findings: [{
          id: "review-finding-12345",
          questionId: "backups",
          kind: "MISSING_EVIDENCE",
          severity: "BLOCKING", status: "OPEN",
          observation: "No dated restore test was attached.",
          proposedAction: "Request dated restore evidence.",
          evidenceReference: "doc-restore-12345",
          reviewerValidatedTechnicalControl: false,
          customerConfirmed: false,
        }],
      });
      await expect(reviews.execute(reviewer, {
        operation: "COMPLETE", reviewId,
        expectedRevision: 3,
      })).rejects.toThrow(/Blocking/);
      const result = await reviews.execute(reviewer, {
        operation: "REQUEST_CHANGES", reviewId,
        expectedRevision: 3,
      });
      expect(result.data).toMatchObject({
        auditWritten: true,
      });
    });
    it("records reviewer handling but never independently verifies remediation", async () => {
      await reviews.execute(reviewer, {
        operation: "START", reviewId,
        expectedRevision: 4,
      });
      await reviews.execute(reviewer, {
        operation: "UPDATE", reviewId,
        expectedRevision: 5,
        findings: [{
          id: "review-finding-12345",
          questionId: "backups",
          kind: "MISSING_EVIDENCE",
          severity: "BLOCKING",
          status: "ACCEPTED_AS_UNKNOWN",
          observation: "No dated restore test was attached.",
          proposedAction: "Keep unknown until independently validated.",
          evidenceReference: null,
          reviewerValidatedTechnicalControl: false,
          customerConfirmed: false,
        }],
      });
      const result = await reviews.execute(reviewer, {
        operation: "COMPLETE", reviewId,
        expectedRevision: 6,
      });
      const data = result.data as {
        review: {
          state: string; blockingIssueCount: number;
          externalCustomerApproval: boolean;
          securityControlsIndependentlyVerified: number;
        };
      };
      expect(data.review.state).toBe("TECHNICALLY_REVIEWED");
      expect(data.review.blockingIssueCount).toBe(0);
      expect(data.review.externalCustomerApproval).toBe(false);
      expect(data.review.securityControlsIndependentlyVerified).toBe(0);
    });
    it("rejects stale writes and records immutable audit history", async () => {
      await expect(reviews.execute(owner, {
        operation: "REOPEN", reviewId,
        expectedRevision: 6,
      })).rejects.toBeInstanceOf(ReviewConflictError);
      const history = await reviews.execute(reviewer, {
        operation: "HISTORY", reviewId,
      });
      const events = (history.data as {
        events: Array<{ revision: number }>;
      }).events;
      expect(events.map(x => x.revision)).toEqual([
        7, 6, 5, 4, 3, 2, 1,
      ]);
      expect(await db.auditEvent.count({
        where: { organizationId: org,
          resourceType: "BASELINE_TECHNICAL_REVIEW" },
      })).toBe(7);
    });
    it("forbids other organizations reading review details", async () => {
      await expect(reviews.execute(outsider, {
        operation: "READ", reviewId,
      })).rejects.toThrow();
      const list = await reviews.execute(outsider, {
        operation: "LIST",
      });
      expect((list.data as { reviews: unknown[] }).reviews)
        .toHaveLength(0);
    });
    it("creates reproducible internal acceptance summary and exports", async () => {
      const list = await reviews.execute(owner, {
        operation: "LIST",
      });
      const records = (list.data as {
        reviews: Parameters<typeof buildBaselineTechnicalReviewReport>[1];
      }).reviews;
      const report = buildBaselineTechnicalReviewReport(
        org, records, new Date().toISOString());
      expect(report.outcomes.technicallyReviewedInternally).toBe(1);
      expect(report.outcomes.externalCustomerApprovals).toBe(0);
      expect(verifyBaselineTechnicalReviewReport(report).valid).toBe(true);
      for (const kind of ["JSON","CSV","MARKDOWN"] as const) {
        const exported = exportBaselineTechnicalReviewReport(report, kind);
        expect(exported.customerSigned).toBe(false);
        expect(exported.content.length).toBeGreaterThan(100);
      }
    });
  },
);
