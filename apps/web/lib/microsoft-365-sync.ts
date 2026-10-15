import { db, type Prisma } from "@cyberpilot/database";
import { randomUUID } from "node:crypto";
import { observeDomainSecurity } from "@cyberpilot/integrations/domain-security";
import {
  MicrosoftGraphClient,
  MicrosoftGraphError,
  MicrosoftGraphPayloadError,
  type MicrosoftUserRegistrationDetails,
} from "@cyberpilot/integrations/microsoft-365";
import {
  calculateCyberScore,
  evaluateDomainSecurityFindings,
  evaluateM365IdentityFindings,
  getRemediationPlaybook,
  getResolvableFindingKeys,
} from "@cyberpilot/risk-engine";

const GLOBAL_ADMIN_TEMPLATE_ID =
  "62e90394-69f5-4237-9190-012177145e10";
const SYNC_LEASE_MS = 30 * 60 * 1000;

export class Microsoft365SyncInProgressError extends Error {
  constructor() {
    super("A Microsoft 365 sync is already in progress for this integration.");
    this.name = "Microsoft365SyncInProgressError";
  }
}

async function acquireMicrosoft365SyncLease(integrationId: string) {
  const now = new Date();
  const leaseToken = randomUUID();

  await db.integrationSyncLease.deleteMany({
    where: {
      integrationId,
      expiresAt: {
        lt: now,
      },
    },
  });

  try {
    await db.integrationSyncLease.create({
      data: {
        integrationId,
        leaseToken,
        expiresAt: new Date(now.getTime() + SYNC_LEASE_MS),
      },
    });
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "P2002"
    ) {
      throw new Microsoft365SyncInProgressError();
    }

    throw error;
  }

  return async () => {
    await db.integrationSyncLease.deleteMany({
      where: {
        integrationId,
        leaseToken,
      },
    });
  };
}

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

export type Microsoft365SyncFailureCode =
  | "GRAPH_AUTHORIZATION_FAILED"
  | "GRAPH_PAYLOAD_INVALID"
  | "GRAPH_THROTTLED"
  | "GRAPH_UNAVAILABLE"
  | "TENANT_MISMATCH"
  | "SYNC_FAILED";

export function getMicrosoft365SyncFailureCode(
  error: unknown,
): Microsoft365SyncFailureCode {
  if (error instanceof MicrosoftGraphPayloadError) {
    return "GRAPH_PAYLOAD_INVALID";
  }

  if (error instanceof MicrosoftGraphError) {
    if (error.status === 401 || error.status === 403) {
      return "GRAPH_AUTHORIZATION_FAILED";
    }

    if (error.status === 429) {
      return "GRAPH_THROTTLED";
    }

    if ([500, 502, 503, 504].includes(error.status)) {
      return "GRAPH_UNAVAILABLE";
    }
  }

  if (
    error instanceof Error &&
    error.message === "Microsoft tenant verification failed during sync."
  ) {
    return "TENANT_MISMATCH";
  }

  return "SYNC_FAILED";
}

export async function syncMicrosoft365Integration(integrationId: string) {
  const releaseLease = await acquireMicrosoft365SyncLease(integrationId);

  try {
    return await syncMicrosoft365IntegrationUnlocked(integrationId);
  } catch (error) {
    if (!(error instanceof Microsoft365SyncInProgressError)) {
      await db.integration.updateMany({
        where: { id: integrationId },
        data: {
          lastErrorAt: new Date(),
          lastErrorCode: getMicrosoft365SyncFailureCode(error),
        },
      });
    }

    throw error;
  } finally {
    await releaseLease();
  }
}

async function syncMicrosoft365IntegrationUnlocked(integrationId: string) {
  const integration = await db.integration.findUnique({
    where: { id: integrationId },
    select: {
      id: true,
      organizationId: true,
      externalTenantId: true,
      status: true,
      mode: true,
    },
  });

  if (!integration || integration.status !== "CONNECTED") {
    throw new Error("Microsoft 365 integration is not connected.");
  }

  if (integration.mode === "LAB") {
    return syncMicrosoft365LabIntegration(
      integration.id,
      integration.organizationId,
    );
  }

  if (!integration.externalTenantId) {
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
  const roleDefinitionIds = new Set(roleDefinitions.map((role) => role.id));
  const persistedRoleAssignments = roleAssignments.filter((assignment) =>
    roleDefinitionIds.has(assignment.roleDefinitionId),
  );
  const domainNames = new Set(verifiedDomains.map((domain) => domain.name));

  const identitySnapshot = users.map((user) => {
    const registration = registrationByUserId.get(user.id);

    return {
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
    };
  });

  const roleDefinitionSnapshot = roleDefinitions.map((role) => ({
    integrationId: integration.id,
    externalId: role.id,
    templateId: role.templateId ?? null,
    displayName: role.displayName,
    isBuiltIn: role.isBuiltIn ?? null,
    observedAt,
  }));

  const roleAssignmentSnapshot = persistedRoleAssignments.map((assignment) => ({
    integrationId: integration.id,
    externalId: assignment.id,
    principalExternalId: assignment.principalId,
    roleDefinitionExternalId: assignment.roleDefinitionId,
    directoryScopeId: assignment.directoryScopeId ?? null,
    observedAt,
  }));

  const scoreSnapshot = await db.$transaction(
    async (tx) => {
      await tx.directoryRoleAssignment.deleteMany({
        where: { integrationId: integration.id },
      });
      await tx.directoryRoleDefinition.deleteMany({
        where: { integrationId: integration.id },
      });
      await tx.directoryIdentity.deleteMany({
        where: { integrationId: integration.id },
      });

      if (identitySnapshot.length > 0) {
        await tx.directoryIdentity.createMany({
          data: identitySnapshot,
        });
      }

      if (roleDefinitionSnapshot.length > 0) {
        await tx.directoryRoleDefinition.createMany({
          data: roleDefinitionSnapshot,
        });
      }

      if (roleAssignmentSnapshot.length > 0) {
        await tx.directoryRoleAssignment.createMany({
          data: roleAssignmentSnapshot,
        });
      }

      for (const { domain, observation } of domainObservations) {
        await tx.domain.upsert({
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
      }

      await tx.domain.deleteMany({
        where: {
          integrationId: integration.id,
          ...(domainNames.size > 0
            ? { name: { notIn: [...domainNames] } }
            : {}),
        },
      });

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

      await evaluateMicrosoft365Findings(integration.id, tx);
      return snapshotSecurityScore(integration.organizationId, tx);
    },
    {
      maxWait: 10_000,
      timeout: 60_000,
    },
  );

  return {
    users: users.length,
    roleDefinitions: roleDefinitions.length,
    roleAssignments: persistedRoleAssignments.length,
    authenticationRegistrations: registrationDetails.length,
    domains: domainObservations.length,
    cyberScore: scoreSnapshot.score,
    scoreCoverage: scoreSnapshot.coverage,
    observedAt,
  };
}

export async function evaluateMicrosoft365Findings(
  integrationId: string,
  client: Prisma.TransactionClient | typeof db = db,
) {
  const integration = await client.integration.findUnique({
    where: { id: integrationId },
    select: {
      id: true,
      organizationId: true,
      mfaEvidenceStatus: true,
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
          externalId: true,
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
    const persistedFinding = await client.securityFinding.upsert({
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

    await ensureRemediationProposal(
      {
        organizationId: integration.organizationId,
        findingId: persistedFinding.id,
        ruleId: finding.rule.id,
        evidence: finding.evidence,
      },
      client,
    );
  }

  const openFindings = await client.securityFinding.findMany({
    where: {
      organizationId: integration.organizationId,
      integrationId: integration.id,
      status: "OPEN",
    },
    select: {
      key: true,
    },
  });

  const resolvableFindingKeys = getResolvableFindingKeys({
    openFindingKeys: openFindings.map((finding) => finding.key),
    observedFindingKeys,
    mfaEvidenceStatus: integration.mfaEvidenceStatus,
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
    domains: integration.domains,
  });

  if (resolvableFindingKeys.length > 0) {
    await client.securityFinding.updateMany({
      where: {
        organizationId: integration.organizationId,
        integrationId: integration.id,
        status: "OPEN",
        key: {
          in: resolvableFindingKeys,
        },
      },
      data: {
        status: "RESOLVED",
        resolvedAt: now,
      },
    });
  }
}


export async function snapshotSecurityScore(
  organizationId: string,
  client: Prisma.TransactionClient | typeof db = db,
) {
  const [findings, integration, domains] = await Promise.all([
    client.securityFinding.findMany({
      where: {
        organizationId,
        status: "OPEN",
      },
      select: {
        id: true,
        ruleId: true,
        severity: true,
        title: true,
        description: true,
      },
    }),
    client.integration.findUnique({
      where: {
        organizationId_provider: {
          organizationId,
          provider: "MICROSOFT_365",
        },
      },
      select: {
        mfaEvidenceStatus: true,
      },
    }),
    client.domain.findMany({
      where: {
        organizationId,
        isInitial: false,
      },
      select: {
        spfStatus: true,
        dmarcStatus: true,
        dkimStatus: true,
      },
    }),
  ]);

  const score = calculateCyberScore(findings);
  const domainCoverageIsPartial = domains.some(
    (domain) =>
      domain.spfStatus === "ERROR" ||
      domain.dmarcStatus === "ERROR" ||
      domain.dkimStatus === "ERROR",
  );

  const coverage =
    integration?.mfaEvidenceStatus === "PERMISSION_REQUIRED" ||
    integration?.mfaEvidenceStatus === "ERROR" ||
    domainCoverageIsPartial ||
    score.unsupportedFindingCount > 0
      ? ("PARTIAL" as const)
      : ("COMPLETE" as const);

  return client.securityScore.create({
    data: {
      organizationId,
      modelVersion: "v0",
      score: score.score,
      riskPoints: score.totalRiskPoints,
      coverage,
      supportedFindingCount: score.supportedFindingCount,
      unsupportedFindingCount: score.unsupportedFindingCount,
      details: {
        contributions: score.contributions,
        topActions: score.topActions.map((action) => ({
          findingId: action.id,
          ruleId: action.ruleId,
          severity: action.severity,
          riskPoints: action.riskPoints,
        })),
      },
    },
  });
}


async function ensureRemediationProposal(
  input: {
    organizationId: string;
    findingId: string;
    ruleId: string;
    evidence: Record<string, import("@cyberpilot/risk-engine").JsonValue>;
  },
  client: Prisma.TransactionClient | typeof db = db,
) {
  const playbook = getRemediationPlaybook(input.ruleId);

  if (!playbook) {
    return;
  }

  const existing = await client.remediation.findFirst({
    where: {
      findingId: input.findingId,
      playbookId: playbook.id,
      status: {
        in: ["PROPOSED", "APPROVED", "EXECUTING"],
      },
    },
    select: {
      id: true,
    },
  });

  if (existing) {
    return;
  }

  const roleAssignmentId =
    typeof input.evidence.roleAssignmentId === "string"
      ? input.evidence.roleAssignmentId
      : null;
  const userId =
    typeof input.evidence.userId === "string" ? input.evidence.userId : null;
  const roleDefinitionId =
    typeof input.evidence.roleDefinitionId === "string"
      ? input.evidence.roleDefinitionId
      : null;

  const actionPayload =
    playbook.actionType === "M365_DELETE_DIRECTORY_ROLE_ASSIGNMENT"
      ? roleAssignmentId
        ? {
            roleAssignmentId,
            roleDefinitionId,
            userId,
          }
        : null
      : null;

  await client.remediation.create({
    data: {
      organizationId: input.organizationId,
      findingId: input.findingId,
      playbookId: playbook.id,
      mode:
        playbook.mode === "AUTOMATED" && actionPayload
          ? "AUTOMATED"
          : "GUIDED",
      title: playbook.title,
      summary: playbook.summary,
      steps: playbook.steps,
      verification: playbook.verification,
      actionType: actionPayload ? playbook.actionType ?? null : null,
      ...(actionPayload ? { actionPayload } : {}),
    },
  });
}


async function syncMicrosoft365LabIntegration(
  integrationId: string,
  organizationId: string,
) {
  const observedAt = new Date();

  await db.integration.update({
    where: {
      id: integrationId,
    },
    data: {
      lastSyncAt: observedAt,
      lastErrorAt: null,
      lastErrorCode: null,
      mfaEvidenceStatus: "AVAILABLE",
      mfaEvidenceCheckedAt: observedAt,
      remediationStatus: "AVAILABLE",
      remediationCheckedAt: observedAt,
    },
  });

  await db.directoryIdentity.updateMany({
    where: {
      integrationId,
    },
    data: {
      observedAt,
    },
  });

  await db.directoryRoleDefinition.updateMany({
    where: {
      integrationId,
    },
    data: {
      observedAt,
    },
  });

  await db.directoryRoleAssignment.updateMany({
    where: {
      integrationId,
    },
    data: {
      observedAt,
    },
  });

  await evaluateMicrosoft365Findings(integrationId);
  const scoreSnapshot = await snapshotSecurityScore(organizationId);

  const [users, roleDefinitions, roleAssignments, domains] = await Promise.all([
    db.directoryIdentity.count({ where: { integrationId } }),
    db.directoryRoleDefinition.count({ where: { integrationId } }),
    db.directoryRoleAssignment.count({ where: { integrationId } }),
    db.domain.count({ where: { integrationId } }),
  ]);

  return {
    users,
    roleDefinitions,
    roleAssignments,
    authenticationRegistrations: users,
    domains,
    cyberScore: scoreSnapshot.score,
    scoreCoverage: scoreSnapshot.coverage,
    observedAt,
  };
}
