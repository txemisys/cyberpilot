import { db } from "@cyberpilot/database";

const GLOBAL_ADMIN_TEMPLATE_ID =
  "62e90394-69f5-4237-9190-012177145e10";

const LAB_IDENTITIES = [
  {
    externalId: "lab-user-owner",
    displayName: "Alicia Owner",
    userPrincipalName: "alicia@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: true,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: true,
    methodsRegistered: ["passKeyDeviceBound"],
  },
  {
    externalId: "lab-user-admin-no-mfa",
    displayName: "Bruno Admin",
    userPrincipalName: "bruno@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: true,
    isMfaRegistered: false,
    isMfaCapable: false,
    isPasswordlessCapable: false,
    methodsRegistered: [],
  },
  {
    externalId: "lab-user-ga-2",
    displayName: "Carla Global Admin",
    userPrincipalName: "carla@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: true,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    methodsRegistered: ["microsoftAuthenticatorPush"],
  },
  {
    externalId: "lab-user-ga-3",
    displayName: "Diego Global Admin",
    userPrincipalName: "diego@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: true,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    methodsRegistered: ["microsoftAuthenticatorPush"],
  },
  {
    externalId: "lab-user-ga-4",
    displayName: "Elena Global Admin",
    userPrincipalName: "elena@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: true,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    methodsRegistered: ["microsoftAuthenticatorPush"],
  },
  {
    externalId: "lab-user-guest-ga",
    displayName: "Guest Vendor Admin",
    userPrincipalName: "guest_vendor#EXT#@cyberpilot-lab.example",
    accountEnabled: true,
    identityType: "GUEST" as const,
    isAdmin: true,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    methodsRegistered: ["microsoftAuthenticatorPush"],
  },
];

const LAB_GLOBAL_ADMIN_ASSIGNMENTS = [
  ["lab-assignment-owner", "lab-user-owner"],
  ["lab-assignment-ga-2", "lab-user-ga-2"],
  ["lab-assignment-ga-3", "lab-user-ga-3"],
  ["lab-assignment-ga-4", "lab-user-ga-4"],
  ["lab-assignment-guest-ga", "lab-user-guest-ga"],
] as const;

export async function seedMicrosoft365Lab(organizationId: string) {
  const existing = await db.integration.findUnique({
    where: {
      organizationId_provider: {
        organizationId,
        provider: "MICROSOFT_365",
      },
    },
    select: {
      id: true,
      mode: true,
      status: true,
    },
  });

  if (existing?.mode === "LIVE" && existing.status === "CONNECTED") {
    throw new Error("A live Microsoft 365 tenant is already connected.");
  }

  const observedAt = new Date();

  return db.$transaction(async (tx) => {
    const integration = await tx.integration.upsert({
      where: {
        organizationId_provider: {
          organizationId,
          provider: "MICROSOFT_365",
        },
      },
      create: {
        organizationId,
        provider: "MICROSOFT_365",
        mode: "LAB",
        status: "CONNECTED",
        externalTenantId: `lab:${organizationId}`,
        displayName: "CyberPilot Microsoft 365 Lab",
        connectedAt: observedAt,
        mfaEvidenceStatus: "AVAILABLE",
        mfaEvidenceCheckedAt: observedAt,
        remediationStatus: "AVAILABLE",
        remediationCheckedAt: observedAt,
      },
      update: {
        mode: "LAB",
        status: "CONNECTED",
        externalTenantId: `lab:${organizationId}`,
        displayName: "CyberPilot Microsoft 365 Lab",
        connectedAt: observedAt,
        lastSyncAt: null,
        lastErrorAt: null,
        lastErrorCode: null,
        mfaEvidenceStatus: "AVAILABLE",
        mfaEvidenceCheckedAt: observedAt,
        remediationStatus: "AVAILABLE",
        remediationCheckedAt: observedAt,
      },
    });

    await tx.securityScore.deleteMany({
      where: {
        organizationId,
      },
    });

    await tx.securityFinding.deleteMany({
      where: {
        organizationId,
        integrationId: integration.id,
      },
    });

    await tx.directoryRoleAssignment.deleteMany({
      where: {
        integrationId: integration.id,
      },
    });

    await tx.directoryIdentity.deleteMany({
      where: {
        integrationId: integration.id,
      },
    });

    await tx.directoryRoleDefinition.deleteMany({
      where: {
        integrationId: integration.id,
      },
    });

    await tx.domain.deleteMany({
      where: {
        integrationId: integration.id,
      },
    });

    await tx.directoryRoleDefinition.create({
      data: {
        integrationId: integration.id,
        externalId: "lab-role-global-admin",
        templateId: GLOBAL_ADMIN_TEMPLATE_ID,
        displayName: "Global Administrator",
        isBuiltIn: true,
        observedAt,
      },
    });

    await tx.directoryIdentity.createMany({
      data: LAB_IDENTITIES.map((identity) => ({
        integrationId: integration.id,
        ...identity,
        authenticationObservedAt: observedAt,
        authenticationUpdatedAt: observedAt,
        observedAt,
      })),
    });

    await tx.directoryRoleAssignment.createMany({
      data: LAB_GLOBAL_ADMIN_ASSIGNMENTS.map(
        ([externalId, principalExternalId]) => ({
          integrationId: integration.id,
          externalId,
          principalExternalId,
          roleDefinitionExternalId: "lab-role-global-admin",
          directoryScopeId: "/",
          observedAt,
        }),
      ),
    });

    await tx.domain.createMany({
      data: [
        {
          organizationId,
          integrationId: integration.id,
          name: "cyberpilot-lab.onmicrosoft.com",
          isDefault: false,
          isInitial: true,
          spfStatus: "PRESENT",
          spfRecords: ["v=spf1 -all"],
          dmarcStatus: "ENFORCING",
          dmarcPolicy: "reject",
          dmarcRecords: ["v=DMARC1; p=reject"],
          dkimStatus: "PUBLISHED",
          dkimSelectors: {
            selector1: ["selector1-lab"],
            selector2: ["selector2-lab"],
          },
          dnsObservedAt: observedAt,
        },
        {
          organizationId,
          integrationId: integration.id,
          name: "cyberpilot-lab.example",
          isDefault: true,
          isInitial: false,
          spfStatus: "PRESENT",
          spfRecords: ["v=spf1 include:spf.protection.outlook.com -all"],
          dmarcStatus: "MONITORING",
          dmarcPolicy: "none",
          dmarcRecords: ["v=DMARC1; p=none; rua=mailto:dmarc@cyberpilot-lab.example"],
          dkimStatus: "PARTIAL",
          dkimSelectors: {
            selector1: ["selector1-lab"],
            selector2: [],
          },
          dnsObservedAt: observedAt,
        },
      ],
    });

    return integration;
  });
}
