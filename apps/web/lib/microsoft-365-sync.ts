import { db } from "@cyberpilot/database";
import { MicrosoftGraphClient } from "@cyberpilot/integrations/microsoft-365";

const GLOBAL_ADMIN_TEMPLATE_ID =
  "62e90394-69f5-4237-9190-012177145e10";
const WRITE_CONCURRENCY = 10;

function mapIdentityType(userType?: string | null) {
  if (userType === "Member") return "MEMBER" as const;
  if (userType === "Guest") return "GUEST" as const;
  return "UNKNOWN" as const;
}

async function forEachWithConcurrency<T>(
  items: T[],
  concurrency: number,
  operation: (item: T) => Promise<unknown>,
) {
  for (let index = 0; index < items.length; index += concurrency) {
    const batch = items.slice(index, index + concurrency);
    await Promise.all(batch.map(operation));
  }
}

export async function syncMicrosoft365Integration(integrationId: string) {
  const integration = await db.integration.findUnique({
    where: { id: integrationId },
    select: {
      id: true,
      organizationId: true,
      externalTenantId: true,
      status: true,
    },
  });

  if (
    !integration ||
    integration.status !== "CONNECTED" ||
    !integration.externalTenantId
  ) {
    throw new Error("Microsoft 365 integration is not connected.");
  }

  const graph = new MicrosoftGraphClient(integration.externalTenantId);

  const [organization, users, roleDefinitions, roleAssignments] =
    await Promise.all([
      graph.getOrganization(),
      graph.listUsers(),
      graph.listRoleDefinitions(),
      graph.listRoleAssignments(),
    ]);

  if (
    organization.id.toLowerCase() !== integration.externalTenantId.toLowerCase()
  ) {
    throw new Error("Microsoft tenant verification failed during sync.");
  }

  const observedAt = new Date();
  const userIds = new Set(users.map((user) => user.id));
  const roleDefinitionIds = new Set(roleDefinitions.map((role) => role.id));
  const persistedRoleAssignments = roleAssignments.filter((assignment) =>
    roleDefinitionIds.has(assignment.roleDefinitionId),
  );
  const roleAssignmentIds = new Set(
    persistedRoleAssignments.map((assignment) => assignment.id),
  );

  await forEachWithConcurrency(users, WRITE_CONCURRENCY, async (user) => {
    await db.directoryIdentity.upsert({
      where: {
        integrationId_externalId: {
          integrationId: integration.id,
          externalId: user.id,
        },
      },
      create: {
        integrationId: integration.id,
        externalId: user.id,
        displayName: user.displayName ?? null,
        userPrincipalName: user.userPrincipalName ?? null,
        accountEnabled: user.accountEnabled ?? null,
        identityType: mapIdentityType(user.userType),
        createdAtProvider: user.createdDateTime
          ? new Date(user.createdDateTime)
          : null,
        observedAt,
      },
      update: {
        displayName: user.displayName ?? null,
        userPrincipalName: user.userPrincipalName ?? null,
        accountEnabled: user.accountEnabled ?? null,
        identityType: mapIdentityType(user.userType),
        createdAtProvider: user.createdDateTime
          ? new Date(user.createdDateTime)
          : null,
        observedAt,
      },
    });
  });

  await forEachWithConcurrency(
    roleDefinitions,
    WRITE_CONCURRENCY,
    async (role) => {
      await db.directoryRoleDefinition.upsert({
        where: {
          integrationId_externalId: {
            integrationId: integration.id,
            externalId: role.id,
          },
        },
        create: {
          integrationId: integration.id,
          externalId: role.id,
          templateId: role.templateId ?? null,
          displayName: role.displayName,
          isBuiltIn: role.isBuiltIn ?? null,
          observedAt,
        },
        update: {
          templateId: role.templateId ?? null,
          displayName: role.displayName,
          isBuiltIn: role.isBuiltIn ?? null,
          observedAt,
        },
      });
    },
  );

  await forEachWithConcurrency(
    persistedRoleAssignments,
    WRITE_CONCURRENCY,
    async (assignment) => {
      await db.directoryRoleAssignment.upsert({
        where: {
          integrationId_externalId: {
            integrationId: integration.id,
            externalId: assignment.id,
          },
        },
        create: {
          integrationId: integration.id,
          externalId: assignment.id,
          principalExternalId: assignment.principalId,
          roleDefinitionExternalId: assignment.roleDefinitionId,
          directoryScopeId: assignment.directoryScopeId ?? null,
          observedAt,
        },
        update: {
          principalExternalId: assignment.principalId,
          roleDefinitionExternalId: assignment.roleDefinitionId,
          directoryScopeId: assignment.directoryScopeId ?? null,
          observedAt,
        },
      });
    },
  );

  await db.$transaction(async (tx) => {
    if (roleAssignmentIds.size === 0) {
      await tx.directoryRoleAssignment.deleteMany({
        where: {
          integrationId: integration.id,
        },
      });
    } else {
      await tx.directoryRoleAssignment.deleteMany({
        where: {
          integrationId: integration.id,
          externalId: {
            notIn: [...roleAssignmentIds],
          },
        },
      });
    }

    if (userIds.size === 0) {
      await tx.directoryIdentity.deleteMany({
        where: {
          integrationId: integration.id,
        },
      });
    } else {
      await tx.directoryIdentity.deleteMany({
        where: {
          integrationId: integration.id,
          externalId: {
            notIn: [...userIds],
          },
        },
      });
    }

    if (roleDefinitionIds.size === 0) {
      await tx.directoryRoleDefinition.deleteMany({
        where: {
          integrationId: integration.id,
        },
      });
    } else {
      await tx.directoryRoleDefinition.deleteMany({
        where: {
          integrationId: integration.id,
          externalId: {
            notIn: [...roleDefinitionIds],
          },
        },
      });
    }

    await tx.integration.update({
      where: { id: integration.id },
      data: {
        displayName: organization.displayName ?? null,
        lastSyncAt: observedAt,
        lastErrorAt: null,
        lastErrorCode: null,
      },
    });
  });

  await evaluateMicrosoft365Findings(integration.id);

  return {
    users: users.length,
    roleDefinitions: roleDefinitions.length,
    roleAssignments: persistedRoleAssignments.length,
    observedAt,
  };
}

async function evaluateMicrosoft365Findings(integrationId: string) {
  const integration = await db.integration.findUnique({
    where: { id: integrationId },
    select: {
      id: true,
      organizationId: true,
      identities: {
        select: {
          externalId: true,
          displayName: true,
          userPrincipalName: true,
          accountEnabled: true,
          identityType: true,
        },
      },
      roleDefinitions: {
        select: {
          externalId: true,
          templateId: true,
          displayName: true,
        },
      },
      roleAssignments: {
        select: {
          principalExternalId: true,
          roleDefinitionExternalId: true,
          directoryScopeId: true,
        },
      },
    },
  });

  if (!integration) {
    throw new Error("Integration not found.");
  }

  const identities = new Map(
    integration.identities.map((identity) => [identity.externalId, identity]),
  );
  const roles = new Map(
    integration.roleDefinitions.map((role) => [role.externalId, role]),
  );

  const globalAdminAssignments = integration.roleAssignments.filter(
    (assignment) =>
      roles.get(assignment.roleDefinitionExternalId)?.templateId ===
      GLOBAL_ADMIN_TEMPLATE_ID,
  );

  const activeGlobalAdminUsers = globalAdminAssignments
    .map((assignment) => identities.get(assignment.principalExternalId))
    .filter(
      (identity): identity is NonNullable<typeof identity> =>
        Boolean(identity && identity.accountEnabled !== false),
    );

  const globalAdminUsers = new Map(
    activeGlobalAdminUsers.map((identity) => [identity.externalId, identity]),
  );

  const observedFindingKeys = new Set<string>();
  const now = new Date();

  if (globalAdminUsers.size >= 5) {
    const key = "m365:global-admin-count-high";
    observedFindingKeys.add(key);

    await db.securityFinding.upsert({
      where: {
        organizationId_key: {
          organizationId: integration.organizationId,
          key,
        },
      },
      create: {
        organizationId: integration.organizationId,
        integrationId: integration.id,
        key,
        ruleId: "M365_GLOBAL_ADMIN_COUNT_HIGH",
        title: "Too many Global Administrators",
        description:
          "Microsoft recommends assigning the Global Administrator role to fewer than five people.",
        severity: "HIGH",
        evidence: {
          activeGlobalAdministratorCount: globalAdminUsers.size,
          threshold: 5,
        },
        lastSeenAt: now,
      },
      update: {
        status: "OPEN",
        severity: "HIGH",
        evidence: {
          activeGlobalAdministratorCount: globalAdminUsers.size,
          threshold: 5,
        },
        lastSeenAt: now,
        resolvedAt: null,
      },
    });
  }

  for (const identity of globalAdminUsers.values()) {
    if (identity.identityType !== "GUEST") {
      continue;
    }

    const key = `m365:guest-global-admin:${identity.externalId}`;
    observedFindingKeys.add(key);

    await db.securityFinding.upsert({
      where: {
        organizationId_key: {
          organizationId: integration.organizationId,
          key,
        },
      },
      create: {
        organizationId: integration.organizationId,
        integrationId: integration.id,
        key,
        ruleId: "M365_GUEST_GLOBAL_ADMIN",
        title: "Guest user is a Global Administrator",
        description:
          "A guest identity has the Global Administrator role. Microsoft guidance recommends that guests are not assigned highly privileged directory roles.",
        severity: "CRITICAL",
        evidence: {
          userId: identity.externalId,
          displayName: identity.displayName,
          userPrincipalName: identity.userPrincipalName,
        },
        lastSeenAt: now,
      },
      update: {
        status: "OPEN",
        severity: "CRITICAL",
        evidence: {
          userId: identity.externalId,
          displayName: identity.displayName,
          userPrincipalName: identity.userPrincipalName,
        },
        lastSeenAt: now,
        resolvedAt: null,
      },
    });
  }

  const findingFilter =
    observedFindingKeys.size > 0
      ? {
          key: {
            notIn: [...observedFindingKeys],
          },
        }
      : {};

  await db.securityFinding.updateMany({
    where: {
      organizationId: integration.organizationId,
      integrationId: integration.id,
      ruleId: {
        in: ["M365_GLOBAL_ADMIN_COUNT_HIGH", "M365_GUEST_GLOBAL_ADMIN"],
      },
      status: "OPEN",
      ...findingFilter,
    },
    data: {
      status: "RESOLVED",
      resolvedAt: now,
    },
  });
}
