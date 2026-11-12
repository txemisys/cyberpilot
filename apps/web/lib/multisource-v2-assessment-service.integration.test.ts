import { randomUUID } from "node:crypto";
import { describe, beforeAll, afterAll, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  MultiSourceV2AssessmentService,
  createSyntheticV2Assessment,
  parseV2ServiceCommand,
} from "./multisource-v2-assessment-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "CyberScore v2 opt-in PostgreSQL integration without Microsoft 365", () => {
    const nonce = randomUUID().slice(0, 8);
    const org = "v2-organization-" + nonce;
    const otherOrg = "v2-foreign-org-" + nonce;
    const owner = "v2-owner-" + nonce;
    const reader = "v2-reader-" + nonce;
    const outsider = "v2-outsider-" + nonce;
    const createdAt = "2026-11-12T10:00:00.000Z";
    const nextAt = "2026-11-13T10:00:00.000Z";
    const service = new MultiSourceV2AssessmentService();
    const admin = {
      organizationId: org, actorUserId: owner,
      role: "OWNER" as const,
    };
    const member = {
      organizationId: org, actorUserId: reader,
      role: "MEMBER" as const,
    };
    const foreign = {
      organizationId: otherOrg,
      actorUserId: outsider,
      role: "OWNER" as const,
    };
    const invoke = (scope: typeof admin | typeof member |
      typeof foreign, operation: string,
      opts: Record<string, unknown> = {}) =>
      service.execute(scope, { operation, ...opts });
    let snapshotId = "";
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: owner, name: "Core v2 owner",
            email: "v2owner-" + nonce + "@example.invalid" },
          { id: reader, name: "Core v2 member",
            email: "v2member-" + nonce + "@example.invalid" },
          { id: outsider, name: "Core v2 outsider",
            email: "v2outsider-" + nonce + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: org, slug: org, name: "M365-less small business" },
          { id: otherOrg, slug: otherOrg,
            name: "Independent tenant" },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: org, userId: owner,
            role: "OWNER" },
          { organizationId: org, userId: reader,
            role: "MEMBER" },
          { organizationId: otherOrg, userId: outsider,
            role: "OWNER" },
        ],
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, otherOrg] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [owner, reader, outsider] } },
      });
    });
    it("creates a read-only preview with a null score and partial coverage", async () => {
      const response = await invoke(admin, "PREVIEW", {
        evaluatedAt: createdAt,
      });
      const data = response.data as ReturnType<
        typeof createSyntheticV2Assessment>;
      expect(response.liveProviderRequests).toBe(0);
      expect(response.historicalV1ScoresModified).toBe(false);
      expect(data.score.score).toBe(null);
      expect(data.coverage.verifiedControls).toBe(0);
      expect(data.report.summary.noMicrosoft365RequiredToGenerate)
        .toBe(true);
      expect(data.report.sources.some((source: { source: string }) =>
        source.source === "MICROSOFT_365")).toBe(false);
    });
    it("rejects storing a v2 snapshot from a non-admin member", async () => {
      await expect(invoke(member, "STORE", {
        evaluatedAt: createdAt,
      })).rejects.toThrow(/admin/);
    });
    it("persists a separate nullable v2 score and transactional audit", async () => {
      const oldV1Count = await db.securityScore.count({
        where: { organizationId: org },
      });
      const stored = await invoke(admin, "STORE", {
        evaluatedAt: createdAt,
      });
      const data = stored.data as {
        created: boolean;
        summary: { snapshotId: string; numericScore: number | null;
          coveragePercent: number };
        legacyV1WriteCount: number;
      };
      expect(data.created).toBe(true);
      snapshotId = data.summary.snapshotId;
      expect(data.summary.numericScore).toBe(null);
      expect(data.legacyV1WriteCount).toBe(0);
      const row = await db.multiSourceV2Assessment.findFirstOrThrow({
        where: { organizationId: org, snapshotId },
      });
      expect(row.sourceClass).toBe("SYNTHETIC_FIXTURE");
      expect(row.modelId).toBe("cyberpilot.multisource.v2");
      expect(row.score).toBeNull();
      const events = await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "MULTISOURCE_V2_FIXTURE_STORED",
        },
      });
      expect(events).toBe(1);
      expect(await db.securityScore.count({
        where: { organizationId: org },
      })).toBe(oldV1Count);
    });
    it("stores only one snapshot for repeated same-time request", async () => {
      const response = await invoke(admin, "STORE", {
        evaluatedAt: createdAt,
      });
      const data = response.data as {
        created: boolean;
      };
      expect(data.created).toBe(false);
      expect(await db.multiSourceV2Assessment.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("allows member to read scoped summary, never another tenant", async () => {
      const own = await invoke(member, "READ", { snapshotId });
      expect(own.organizationId).toBe(org);
      await expect(invoke(foreign, "READ", {
        snapshotId,
      })).rejects.toThrow();
    });
    it("returns a separated chronological history with no v1 reads", async () => {
      const result = await invoke(member, "LIST", {
        limit: 20, offset: 0,
      });
      const data = result.data as {
        items: Array<{
          snapshotId: string; modelId: string;
        }>; legacyScoreRead: boolean; otherTenantsIncluded: boolean;
      };
      expect(data.items).toHaveLength(1);
      expect(data.items[0]!.snapshotId).toBe(snapshotId);
      expect(data.legacyScoreRead).toBe(false);
      expect(data.otherTenantsIncluded).toBe(false);
    });
    it("exports an auditable report without raw OAuth data", async () => {
      const data = await invoke(member, "EXPORT", {
        snapshotId, exportFormat: "MARKDOWN",
      });
      const report = data.data as {
        content: string; containsOauthTokens: boolean;
        historicalV1CyberScoreModified: boolean;
      };
      expect(report.content).toContain("Multi-source");
      expect(report.content).not.toContain("example.invalid@");
      expect(report.containsOauthTokens).toBe(false);
      expect(report.historicalV1CyberScoreModified).toBe(false);
    });
    it("compares stored v2 snapshots without asserting risk remediation", async () => {
      await invoke(admin, "STORE", { evaluatedAt: nextAt });
      const second = createSyntheticV2Assessment(org, nextAt);
      const result = await invoke(admin, "COMPARE", {
        baselineId: snapshotId,
        currentId: second.manifest.snapshotId,
      });
      const data = result.data as {
        verifiedRemediation: boolean; historicalV1Recalculated: boolean;
        trend: { remediationVerified: boolean;
          organizationId: string };
      };
      expect(data.verifiedRemediation).toBe(false);
      expect(data.historicalV1Recalculated).toBe(false);
      expect(data.trend.organizationId).toBe(org);
      expect(data.trend.remediationVerified).toBe(false);
    });
    it("rejects unexpected operations and overlarge pagination", () => {
      expect(() => parseV2ServiceCommand({
        operation: "LIVE_SYNC",
      })).toThrow();
      expect(() => parseV2ServiceCommand({
        operation: "LIST", limit: 10000,
      })).toThrow();
      expect(() => parseV2ServiceCommand({
        operation: "PREVIEW",
        oauthToken: "should-not-be-accepted",
      })).toThrow();
    });
  },
);
