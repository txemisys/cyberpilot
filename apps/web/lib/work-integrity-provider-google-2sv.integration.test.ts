import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import {
  runGoogle2SvCheck, listProviderChecks,
} from "./work-integrity-provider-google-2sv";
import { getTechnicalEvidenceGate } from "./work-integrity-provider-gates";
import {
  inspectProviderCheck, inspectCaptureProviderChecks,
} from "./work-integrity-provider-inspection";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "provider verification PostgreSQL integration", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const orgId = "provider-org-" + suffix;
    const otherOrgId = "provider-other-" + suffix;
    const userId = "provider-user-" + suffix;
    const otherUserId = "provider-other-user-" + suffix;
    const captureId = "provider-capture-" + suffix;
    const taskId = "provider-task-" + suffix;
    const subject = "admin@example.invalid";
    const customerId = "C123456789";
    const scope: ReviewScope = {
      organizationId: orgId, userId, role: "ADMIN",
    };
    const auditor: ReviewScope = { ...scope, role: "AUDITOR" };
    const other: ReviewScope = {
      organizationId: otherOrgId, userId: otherUserId, role: "ADMIN",
    };
    const token = "private-test-token-1234567890";
    let evidenceId = "";
    const payload = (requestKey: string) => ({
      taskId, evidenceId, subject, expectedCustomerId: customerId,
      requestKey, accessToken: token,
    });
    const response = (enrolled: boolean, enforced: boolean) => ({
      id: "google-user-12345", customerId, primaryEmail: subject,
      isEnrolledIn2Sv: enrolled, isEnforcedIn2Sv: enforced,
      suspended: false, archived: false,
    });
    const fetcher = (body: unknown, status = 200) => vi.fn(
      async () => new Response(JSON.stringify(body), { status }),
    ) as unknown as typeof fetch;
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: userId, name: "Provider user",
            email: "provider-" + suffix + "@example.invalid" },
          { id: otherUserId, name: "Other provider user",
            email: "provider-other-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: orgId, name: "Provider test", slug: "provider-" + suffix },
          { id: otherOrgId, name: "Other provider test",
            slug: "provider-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: orgId, userId, role: "ADMIN" },
          { organizationId: otherOrgId, userId: otherUserId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId: orgId,
          source: "provider-integration",
          capturedAt: new Date(), complete: true,
          caseCount: 1, digest: "d".repeat(64),
          payload: { cases: [] }, createdById: userId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, organizationId: orgId, captureId,
          externalTaskId: "google-user-2sv",
          title: "Verify 2SV enrollment and enforcement",
          severity: "ERROR", required: true,
        },
      });
      const evidence = await db.securityEvidence.create({
        data: {
          organizationId: orgId,
          source: "GOOGLE_WORKSPACE",
          domain: "example.invalid",
          controlId: "google_workspace.user_2sv",
          scope: subject, state: "OBSERVED",
          observedAt: new Date(),
          details: { subject, customerId },
        },
      });
      evidenceId = evidence.id;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, otherOrgId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, otherUserId] } },
      });
    });
    it("rejects unauthorized provider reads and writes", async () => {
      await expect(runGoogle2SvCheck(auditor, payload("auditor-denied")))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(runGoogle2SvCheck(other, payload("other-denied")))
        .rejects.toMatchObject({ code: "MISSING" });
      await expect(listProviderChecks(other, { taskId }))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("does not call provider when customer identity differs", async () => {
      const remote = vi.fn();
      await expect(runGoogle2SvCheck(scope, {
        ...payload("wrong-customer"), expectedCustomerId: "C987654321",
      }, { fetcher: remote as unknown as typeof fetch }))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(remote).not.toHaveBeenCalled();
    });
    it("persists provider FAIL and an audit without OAuth secrets", async () => {
      const remote = fetcher(response(false, true));
      const saved = await runGoogle2SvCheck(
        scope, payload("provider-fail-" + suffix), { fetcher: remote });
      expect(saved.replayed).toBe(false);
      expect(saved.check.outcome).toBe("FAIL");
      const audit = await db.auditEvent.findFirstOrThrow({
        where: {
          organizationId: orgId,
          resourceId: saved.check.id,
          action: "integrity.provider.google_2sv.check",
        },
      });
      expect(JSON.stringify(saved.check)).not.toContain(token);
      expect(JSON.stringify(audit)).not.toContain(token);
      expect(saved.check.responseDigest).toMatch(/^[a-f0-9]{64}$/);
      const gate = await getTechnicalEvidenceGate(scope, { taskId });
      expect(gate.gate).toBe("FAILED");
    });
    it("replays idempotency without a second provider call", async () => {
      const remote = vi.fn();
      const replay = await runGoogle2SvCheck(
        scope, payload("provider-fail-" + suffix),
        { fetcher: remote as unknown as typeof fetch });
      expect(replay.replayed).toBe(true);
      expect(remote).not.toHaveBeenCalled();
      await expect(runGoogle2SvCheck(scope, {
        ...payload("provider-fail-" + suffix),
        subject: "other@example.invalid",
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("persists provider PASS and allows auditor inspection", async () => {
      const saved = await runGoogle2SvCheck(
        scope, payload("provider-pass-" + suffix),
        { fetcher: fetcher(response(true, true)) });
      expect(saved.check.outcome).toBe("PASS");
      const gate = await getTechnicalEvidenceGate(auditor, { taskId });
      expect(gate.gate).toBe("PROVIDER_PASS");
      expect(gate.sourceVerified).toBe(true);
      const history = await listProviderChecks(auditor, { taskId });
      expect(history.total).toBe(2);
      expect(history.checks[0]?.outcome).toBe("PASS");
      const inspection = await inspectProviderCheck(auditor, saved.check.id);
      expect(inspection.auditConsistent).toBe(true);
      expect(inspection.evidenceMatches).toBe(true);
      await expect(inspectProviderCheck(other, saved.check.id))
        .rejects.toMatchObject({ code: "MISSING" });
      const portfolio = await inspectCaptureProviderChecks(
        auditor, { captureId });
      expect(portfolio.total).toBe(2);
      expect(portfolio.summary.consistent).toBe(2);
    });
    it("does not count a historical PASS after evidence changes", async () => {
      await db.securityEvidence.update({
        where: { id: evidenceId },
        data: { state: "ERROR" },
      });
      const gate = await getTechnicalEvidenceGate(scope, { taskId });
      expect(gate.gate).toBe("STALE");
      expect(gate.sourceVerified).toBe(false);
      const history = await listProviderChecks(scope, { taskId });
      expect(history.total).toBe(2);
      const inspection = await inspectCaptureProviderChecks(
        scope, { captureId });
      expect(inspection.summary.inconsistent).toBe(2);
    });
    it("never updates review or remediation states", async () => {
      const task = await db.integrityReviewTask.findFirstOrThrow({
        where: { id: taskId, organizationId: orgId },
      });
      expect(task.disposition).toBe("OPEN");
      expect(task.revision).toBe(1);
    });
  },
);
