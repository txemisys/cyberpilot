import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { db } from "@cyberpilot/database";

import { seedMicrosoft365Lab } from "./microsoft-365-lab";
import {
  snapshotSecurityScore,
  syncMicrosoft365Integration,
} from "./microsoft-365-sync";
import { executeLabRoleAssignmentRemoval } from "./remediation-execution";
import { getPriorityNavigation } from "./priority-navigation";

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


describe("Microsoft 365 LAB shared sync entry point", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await resetDatabase();
    await db.$disconnect();
  });

  it("re-evaluates a connected LAB integration through the shared sync engine", async () => {
    const organization = await db.organization.create({
      data: {
        name: "Shared LAB Workspace",
        slug: "shared-lab-workspace",
      },
    });

    const integration = await seedMicrosoft365Lab(organization.id);

    const result = await syncMicrosoft365Integration(integration.id);

    expect(result.users).toBeGreaterThan(0);
    expect(result.cyberScore).toBeGreaterThanOrEqual(0);
    expect(result.cyberScore).toBeLessThanOrEqual(100);
    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });
});


describe("Microsoft 365 LAB recovery state", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await resetDatabase();
    await db.$disconnect();
  });

  it("clears the prior error event correlation on a successful LAB re-evaluation", async () => {
    const organization = await db.organization.create({
      data: { name: "LAB Recovery", slug: "lab-recovery" },
    });
    const integration = await seedMicrosoft365Lab(organization.id);

    await db.integration.update({
      where: { id: integration.id },
      data: {
        lastErrorAt: new Date(),
        lastErrorCode: "SYNC_FAILED",
        lastErrorEventId: "11111111-1111-4111-8111-111111111111",
      },
    });

    await syncMicrosoft365Integration(integration.id);

    const recovered = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        lastErrorAt: true,
        lastErrorCode: true,
        lastErrorEventId: true,
        lastSyncAt: true,
      },
    });

    expect(recovered.lastErrorAt).toBeNull();
    expect(recovered.lastErrorCode).toBeNull();
    expect(recovered.lastErrorEventId).toBeNull();
    expect(recovered.lastSyncAt).toBeInstanceOf(Date);
  });
});

describe("Top Action remediation navigation with LAB evidence", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await resetDatabase();
    await db.$disconnect();
  });

  it("links an actual open LAB finding to its active database playbook", async () => {
    const organization = await db.organization.create({
      data: { name: "Priority LAB", slug: "priority-lab" },
    });
    const integration = await seedMicrosoft365Lab(organization.id);
    await syncMicrosoft365Integration(integration.id);

    const finding = await db.securityFinding.findFirstOrThrow({
      where: {
        organizationId: organization.id,
        ruleId: "M365_GUEST_GLOBAL_ADMIN",
        status: "OPEN",
      },
      select: { id: true, lastSeenAt: true },
    });
    const remediations = await db.remediation.findMany({
      where: {
        organizationId: organization.id,
        findingId: finding.id,
        finding: { status: "OPEN" },
        status: { in: ["PROPOSED", "APPROVED", "EXECUTING"] },
      },
      select: {
        id: true,
        status: true,
        createdAt: true,
        finding: { select: { id: true, status: true } },
      },
    });
    const navigation = getPriorityNavigation(finding.id, [finding], remediations);
    expect(navigation.playbook).toBeDefined();
    expect(navigation.href).toBe(`#remediation-${navigation.playbook!.id}`);
    expect(getPriorityNavigation(finding.id, [finding], []).href).toBe(
      `#finding-${finding.id}`,
    );
  });
});
