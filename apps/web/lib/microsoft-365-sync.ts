import { db } from "@cyberpilot/database";
import { observeDomainSecurity } from "@cyberpilot/integrations/domain-security";
import {
  MicrosoftGraphClient,
  MicrosoftGraphError,
  type MicrosoftUserRegistrationDetails,
} from "@cyberpilot/integrations/microsoft-365";
import {
  DOMAIN_RULE_IDS,
  evaluateDomainSecurityFindings,
  evaluateM365IdentityFindings,
  M365_RULE_IDS,
} from "@cyberpilot/risk-engine";

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

  let registrationDetails: MicrosoftUserRegistrationDetails[] = [];
  let mfaEvidenceStatus:
    | "AVAILABLE"
    | "PERMISSION_REQUIRED"
    | "ERROR" = "AVAILABLE";

  try {
    registrationDetails = await graph.listUserRegistrationDetails();
  } catch (error) {
    if (error instanceof MicrosoftGraphError && error.status === 403) {
      mfaEvidenceStatus = "PERMISSION_REQUIRED";
    } else {
      mfaEvidenceStatus = "ERROR";
    }
  }

  if (
    organization.id.toLowerCase() !== integration.externalTenantId.toLowerCase()
  ) {
    throw new Error("Microsoft tenant verification failed during sync.");
  }

  const observedAt = new Date();
  const verifiedDomains = (organization.verifiedDomains ?? []).flatMap(
    (domain) =>
      domain.name
        ? [
            {
              name: domain.name.trim().toLowerCase(),
              isDefault: domain.isDefault === true,
              isInitial: domain.isInitial === true,
            },
          ]
        : [],
  );

  const domainObservations = await Promise.all(
    verifiedDomains.map(async (domain) => ({
      domain,
      observation: await observeDomainSecurity(domain.name),
    })),
  );

  const registrationByUserId = new Map(
    registrationDetails.map((registration) => [registration.id, registration]),
  );
  const userIds = new Set(users.map((user) => user.id));
  const roleDefinitionIds = new Set(roleDefinitions.map((role) => role.id));
  const persistedRoleAssignments = roleAssignments.filter((assignment) =>
    roleDefinitionIds.has(assignment.roleDefinitionId),
  );
  const roleAssignmentIds = new Set(
    persistedRoleAssignments.map((assignment) => assignment.id),
  );
  const domainNames = new Set(verifiedDomains.map((domain) => domain.name));

  await forEachWithConcurrency(users, WRITE_CONCURRENCY, async (user) => {
    const registration = registrationByUserId.get(user.id);

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
        isAdmin: registration?.isAdmin ?? null,
        isMfaRegistered: registration?.isMfaRegistered ?? null,
        isMfaCapable: registration?.isMfaCapable ?? null,
        isPasswordlessCapable: registration?.isPasswordlessCapable ?? null,
        methodsRegistered: registration?.methodsRegistered ?? [],
        authenticationObservedAt: registration ? observedAt : null,
        authenticationUpdatedAt: registration?.lastUpdatedDateTime
          ? new Date(registration.lastUpdatedDateTime)
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
        isAdmin: registration?.isAdmin ?? null,
        isMfaRegistered: registration?.isMfaRegistered ?? null,
        isMfaCapable: registration?.isMfaCapable ?? null,
        isPasswordlessCapable: registration?.isPasswordlessCapable ?? null,
        methodsRegistered: registration?.methodsRegistered ?? [],
        authenticationObservedAt: registration ? observedAt : null,
        authenticationUpdatedAt: registration?.lastUpdatedDateTime
          ? new Date(registration.lastUpdatedDateTime)
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


  await forEachWithConcurrency(
    domainObservations,
    WRITE_CONCURRENCY,
    async ({ domain, observation }) => {
      await db.domain.upsert({
        where: {
          organizationId_name: {
            organizationId: integration.organizationId,
            name: domain.name,
          },
        },
        create: {
          organizationId: integration.organizationId,
          integrationId: integration.id,
          name: domain.name,
          isDefault: domain.isDefault,
          isInitial: domain.isInitial,
          spfStatus: observation.spf.status,
          spfRecords: observation.spf.records,
          dmarcStatus: observation.dmarc.status,
          dmarcPolicy: observation.dmarc.policy,
          dmarcRecords: observation.dmarc.records,
          dkimStatus: observation.dkim.status,
          dkimSelectors: observation.dkim.selectors,
          dnsObservedAt: observedAt,
        },
        update: {
          integrationId: integration.id,
          isDefault: domain.isDefault,
          isInitial: domain.isInitial,
          spfStatus: observation.spf.status,
          spfRecords: observation.spf.records,
          dmarcStatus: observation.dmarc.status,
          dmarcPolicy: observation.dmarc.policy,
          dmarcRecords: observation.dmarc.records,
          dkimStatus: observation.dkim.status,
          dkimSelectors: observation.dkim.selectors,
          dnsObservedAt: observedAt,
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


    if (domainNames.size === 0) {
      await tx.domain.deleteMany({
        where: {
          integrationId: integration.id,
        },
      });
    } else {
      await tx.domain.deleteMany({
        where: {
          integrationId: integration.id,
          name: {
            notIn: [...domainNames],
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
        mfaEvidenceStatus,
        mfaEvidenceCheckedAt: observedAt,
      },
    });
  });

  await evaluateMicrosoft365Findings(integration.id);

  return {
    users: users.length,
    roleDefinitions: roleDefinitions.length,
    roleAssignments: persistedRoleAssignments.length,
    authenticationRegistrations: registrationDetails.length,
    domains: domainObservations.length,
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
          isAdmin: true,
          isMfaRegistered: true,
          isMfaCapable: true,
          isPasswordlessCapable: true,
          methodsRegistered: true,
          authenticationObservedAt: true,
          authenticationUpdatedAt: true,
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
        },
      },
      domains: {
        select: {
          name: true,
          isInitial: true,
          spfStatus: true,
          dmarcStatus: true,
          dmarcPolicy: true,
          dkimStatus: true,
        },
      },
    },
  });

  if (!integration) {
    throw new Error("Integration not found.");
  }

  const identityFindings = evaluateM365IdentityFindings({
    identities: integration.identities.map((identity) => ({
      ...identity,
      methodsRegistered: Array.isArray(identity.methodsRegistered)
        ? identity.methodsRegistered.filter(
            (method): method is string => typeof method === "string",
          )
        : [],
    })),
    roleDefinitions: integration.roleDefinitions,
    roleAssignments: integration.roleAssignments,
  });

  const domainFindings = evaluateDomainSecurityFindings(integration.domains);
  const findings = [...identityFindings, ...domainFindings];

  const now = new Date();
  const observedFindingKeys = findings.map((finding) => finding.key);

  for (const finding of findings) {
    await db.securityFinding.upsert({
      where: {
        organizationId_key: {
          organizationId: integration.organizationId,
          key: finding.key,
        },
      },
      create: {
        organizationId: integration.organizationId,
        integrationId: integration.id,
        key: finding.key,
        ruleId: finding.rule.id,
        title: finding.rule.title,
        description: finding.rule.description,
        severity: finding.rule.severity,
        evidence: finding.evidence,
        lastSeenAt: now,
      },
      update: {
        status: "OPEN",
        ruleId: finding.rule.id,
        title: finding.rule.title,
        description: finding.rule.description,
        severity: finding.rule.severity,
        evidence: finding.evidence,
        lastSeenAt: now,
        resolvedAt: null,
      },
    });
  }

  await db.securityFinding.updateMany({
    where: {
      organizationId: integration.organizationId,
      integrationId: integration.id,
      ruleId: {
        in: [...M365_RULE_IDS, ...DOMAIN_RULE_IDS],
      },
      status: "OPEN",
      ...(observedFindingKeys.length > 0
        ? {
            key: {
              notIn: observedFindingKeys,
            },
          }
        : {}),
    },
    data: {
      status: "RESOLVED",
      resolvedAt: now,
    },
  });
}
