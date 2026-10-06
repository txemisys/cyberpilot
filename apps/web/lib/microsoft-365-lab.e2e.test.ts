import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { db } from "@cyberpilot/database";

import { seedMicrosoft365Lab } from "./microsoft-365-lab";
import {
  snapshotSecurityScore,
  syncMicrosoft365Integration,
} from "./microsoft-365-sync";
import { executeLabRoleAssignmentRemoval } from "./remediation-execution";

async function resetDatabase() {
  await db.auditEvent.deleteMany();
  await db.remediation.deleteMany();
  await db.securityScore.deleteMany();
  await db.securityFinding.deleteMany();
  await db.domain.deleteMany();
  await db.directoryRoleAssignment.deleteMany();
  await db.directoryRoleDefinition.deleteMany();
  await db.directoryIdentity.deleteMany();
  await db.integrationConsentState.deleteMany();
  await db.integration.deleteMany();
  await db.membership.deleteMany();
  await db.organization.deleteMany();
  await db.session.deleteMany();
  await db.account.deleteMany();
  await db.verification.deleteMany();
  await db.user.deleteMany();
}

describe("Microsoft 365 Lab remediation E2E", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await resetDatabase();
    await db.$disconnect();
  });

  it("moves the deterministic Lab from CyberScore 11 to 70 after verified guest GA remediation", async () => {
    const user = await db.user.create({
      data: {
        name: "E2E Owner",
        email: "e2e-owner@cyberpilot.local",
      },
    });

    const organization = await db.organization.create({
      data: {
        name: "E2E Workspace",
        slug: "e2e-workspace",
        memberships: {
          create: {
            userId: user.id,
            role: "OWNER",
          },
        },
      },
    });

    const integration = await seedMicrosoft365Lab(organization.id);
    const initial = await syncMicrosoft365Integration(integration.id);

    expect(initial.cyberScore).toBe(11);
    expect(initial.scoreCoverage).toBe("COMPLETE");

    const initialOpenFindings = await db.securityFinding.findMany({
      where: {
        organizationId: organization.id,
        status: "OPEN",
      },
      select: {
        ruleId: true,
      },
    });

    expect(initialOpenFindings).toHaveLength(5);
    expect(initialOpenFindings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "M365_GUEST_GLOBAL_ADMIN",
        "M365_GLOBAL_ADMIN_COUNT_HIGH",
        "M365_ADMIN_MFA_NOT_CAPABLE",
        "DOMAIN_DMARC_MONITORING_ONLY",
        "DOMAIN_M365_DKIM_SELECTORS_PARTIAL",
      ]),
    );

    const remediation = await db.remediation.findFirstOrThrow({
      where: {
        organizationId: organization.id,
        mode: "AUTOMATED",
        finding: {
          ruleId: "M365_GUEST_GLOBAL_ADMIN",
          status: "OPEN",
        },
      },
      select: {
        id: true,
        actionPayload: true,
      },
    });

    const payload = remediation.actionPayload as {
      roleAssignmentId?: unknown;
      userId?: unknown;
      roleDefinitionId?: unknown;
    } | null;

    expect(payload).not.toBeNull();
    expect(typeof payload?.roleAssignmentId).toBe("string");
    expect(typeof payload?.userId).toBe("string");
    expect(typeof payload?.roleDefinitionId).toBe("string");

    await db.remediation.update({
      where: { id: remediation.id },
      data: {
        status: "APPROVED",
        approvedByUserId: user.id,
        approvedAt: new Date(),
      },
    });

    const executionEvidence = await executeLabRoleAssignmentRemoval(
      integration.id,
      {
        roleAssignmentId: payload!.roleAssignmentId as string,
        userId: payload!.userId as string,
        roleDefinitionId: payload!.roleDefinitionId as string,
      },
    );

    await db.remediation.update({
      where: { id: remediation.id },
      data: {
        status: "VERIFIED",
        executionEvidence,
        completedAt: new Date(),
        verifiedAt: new Date(),
      },
    });

    const afterRemediation = await syncMicrosoft365Integration(integration.id);

    expect(afterRemediation.cyberScore).toBe(70);
    expect(afterRemediation.scoreCoverage).toBe("COMPLETE");

    const removedAssignment = await db.directoryRoleAssignment.findUnique({
      where: {
        integrationId_externalId: {
          integrationId: integration.id,
          externalId: "lab-assignment-guest-ga",
        },
      },
    });

    expect(removedAssignment).toBeNull();

    const resolvedFindings = await db.securityFinding.findMany({
      where: {
        organizationId: organization.id,
        status: "RESOLVED",
        ruleId: {
          in: ["M365_GUEST_GLOBAL_ADMIN", "M365_GLOBAL_ADMIN_COUNT_HIGH"],
        },
      },
      select: {
        ruleId: true,
      },
    });

    expect(resolvedFindings.map((finding) => finding.ruleId).sort()).toEqual([
      "M365_GLOBAL_ADMIN_COUNT_HIGH",
      "M365_GUEST_GLOBAL_ADMIN",
    ]);

    const finalOpenFindings = await db.securityFinding.findMany({
      where: {
        organizationId: organization.id,
        status: "OPEN",
      },
      select: {
        ruleId: true,
      },
    });

    expect(finalOpenFindings).toHaveLength(3);
    expect(finalOpenFindings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "M365_ADMIN_MFA_NOT_CAPABLE",
        "DOMAIN_DMARC_MONITORING_ONLY",
        "DOMAIN_M365_DKIM_SELECTORS_PARTIAL",
      ]),
    );

    const history = await db.securityScore.findMany({
      where: { organizationId: organization.id },
      orderBy: { calculatedAt: "asc" },
      select: { score: true },
    });

    expect(history.map((snapshot) => snapshot.score)).toEqual([11, 70]);

    const independentSnapshot = await snapshotSecurityScore(organization.id);
    expect(independentSnapshot.score).toBe(70);
  });
});
