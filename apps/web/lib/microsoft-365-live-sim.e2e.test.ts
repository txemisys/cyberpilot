import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

import { db } from "@cyberpilot/database";
import { MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES } from "@cyberpilot/integrations/microsoft-365";

import { syncMicrosoft365Integration } from "./microsoft-365-sync";

const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const GLOBAL_ADMIN_ROLE_ID = "role-global-admin";

function accessToken(roles: string[]) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ roles })).toString("base64url");
  return `${header}.${payload}.`;
}

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
  await db.integrationSyncLease.deleteMany();
  await db.integration.deleteMany();
  await db.membership.deleteMany();
  await db.organization.deleteMany();
  await db.session.deleteMany();
  await db.account.deleteMany();
  await db.verification.deleteMany();
  await db.user.deleteMany();
}

function mockMicrosoftGraph() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.includes("login.microsoftonline.com")) {
        return new Response(
          JSON.stringify({
            access_token: accessToken([
              ...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
            ]),
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/organization?")) {
        return new Response(
          JSON.stringify({
            value: [
              {
                id: TENANT_ID,
                displayName: "Synthetic LIVE Tenant",
                verifiedDomains: [],
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/users?")) {
        return new Response(
          JSON.stringify({
            value: [
              {
                id: "user-1",
                displayName: "Owner",
                userPrincipalName: "owner@example.test",
                accountEnabled: true,
                userType: "Member",
              },
              {
                id: "user-2",
                displayName: "Admin Two",
                userPrincipalName: "admin2@example.test",
                accountEnabled: true,
                userType: "Member",
              },
              {
                id: "user-3",
                displayName: "Admin Three",
                userPrincipalName: "admin3@example.test",
                accountEnabled: true,
                userType: "Member",
              },
              {
                id: "user-4",
                displayName: "Admin Four",
                userPrincipalName: "admin4@example.test",
                accountEnabled: true,
                userType: "Member",
              },
              {
                id: "user-guest",
                displayName: "Guest Global Admin",
                userPrincipalName: "guest#EXT#@example.test",
                accountEnabled: true,
                userType: "Guest",
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/roleManagement/directory/roleDefinitions?")) {
        return new Response(
          JSON.stringify({
            value: [
              {
                id: GLOBAL_ADMIN_ROLE_ID,
                displayName: "Global Administrator",
                templateId: "62e90394-69f5-4237-9190-012177145e10",
                isBuiltIn: true,
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/roleManagement/directory/roleAssignments?")) {
        return new Response(
          JSON.stringify({
            value: [
              "user-1",
              "user-2",
              "user-3",
              "user-4",
              "user-guest",
            ].map((principalId, index) => ({
              id: `assignment-${index + 1}`,
              principalId,
              roleDefinitionId: GLOBAL_ADMIN_ROLE_ID,
              directoryScopeId: "/",
            })),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/reports/authenticationMethods/userRegistrationDetails")) {
        return new Response(
          JSON.stringify({
            value: [
              {
                id: "user-1",
                userPrincipalName: "owner@example.test",
                isAdmin: true,
                isMfaRegistered: true,
                isMfaCapable: true,
                isPasswordlessCapable: true,
                methodsRegistered: ["passKeyDeviceBound"],
              },
              {
                id: "user-2",
                userPrincipalName: "admin2@example.test",
                isAdmin: true,
                isMfaRegistered: false,
                isMfaCapable: false,
                isPasswordlessCapable: false,
                methodsRegistered: [],
              },
              ...["user-3", "user-4", "user-guest"].map((id) => ({
                id,
                userPrincipalName: `${id}@example.test`,
                isAdmin: true,
                isMfaRegistered: true,
                isMfaCapable: true,
                isPasswordlessCapable: false,
                methodsRegistered: ["microsoftAuthenticatorPush"],
              })),
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      throw new Error(`Unexpected mocked Microsoft request: ${url}`);
    }),
  );
}

describe("Microsoft 365 LIVE Graph simulation E2E", () => {
  beforeEach(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterAll(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
    await db.$disconnect();
  });

  it("runs the normal LIVE sync path against Microsoft-shaped Graph responses", async () => {
    mockMicrosoftGraph();

    const organization = await db.organization.create({
      data: {
        name: "Synthetic LIVE Workspace",
        slug: "synthetic-live-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    const result = await syncMicrosoft365Integration(integration.id);

    expect(result.users).toBe(5);
    expect(result.roleDefinitions).toBe(1);
    expect(result.roleAssignments).toBe(5);
    expect(result.authenticationRegistrations).toBe(5);
    expect(result.domains).toBe(0);
    expect(result.scoreCoverage).toBe("COMPLETE");
    expect(result.cyberScore).toBeLessThan(100);

    const persisted = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        mode: true,
        status: true,
        displayName: true,
        lastSyncAt: true,
        mfaEvidenceStatus: true,
      },
    });

    expect(persisted).toMatchObject({
      mode: "LIVE",
      status: "CONNECTED",
      displayName: "Synthetic LIVE Tenant",
      mfaEvidenceStatus: "AVAILABLE",
    });
    expect(persisted.lastSyncAt).toBeInstanceOf(Date);

    const identities = await db.directoryIdentity.findMany({
      where: { integrationId: integration.id },
      orderBy: { externalId: "asc" },
      select: {
        externalId: true,
        identityType: true,
        isAdmin: true,
        isMfaCapable: true,
      },
    });

    expect(identities).toHaveLength(5);
    expect(
      identities.find((identity) => identity.externalId === "user-guest"),
    ).toMatchObject({
      identityType: "GUEST",
      isAdmin: true,
      isMfaCapable: true,
    });
    expect(
      identities.find((identity) => identity.externalId === "user-2"),
    ).toMatchObject({
      identityType: "MEMBER",
      isAdmin: true,
      isMfaCapable: false,
    });

    const openFindings = await db.securityFinding.findMany({
      where: {
        organizationId: organization.id,
        status: "OPEN",
      },
      select: {
        ruleId: true,
      },
    });

    expect(openFindings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "M365_GLOBAL_ADMIN_COUNT_HIGH",
        "M365_GUEST_GLOBAL_ADMIN",
        "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
      ]),
    );

    const scoreSnapshots = await db.securityScore.findMany({
      where: { organizationId: organization.id },
      select: { score: true, coverage: true },
    });

    expect(scoreSnapshots).toHaveLength(1);
    expect(scoreSnapshots[0]?.coverage).toBe("COMPLETE");
  });

  it("preserves partial coverage when AuditLog evidence is forbidden", async () => {
    mockMicrosoftGraph();

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.includes("login.microsoftonline.com")) {
        return new Response(
          JSON.stringify({
            access_token: accessToken([
              ...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
            ]),
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/reports/authenticationMethods/userRegistrationDetails")) {
        return new Response(JSON.stringify({ error: { code: "Forbidden" } }), {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }

      if (url.includes("/organization?")) {
        return new Response(
          JSON.stringify({
            value: [{ id: TENANT_ID, displayName: "Partial Tenant", verifiedDomains: [] }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.includes("/users?")) {
        return new Response(JSON.stringify({ value: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      if (
        url.includes("/roleManagement/directory/roleDefinitions?") ||
        url.includes("/roleManagement/directory/roleAssignments?")
      ) {
        return new Response(JSON.stringify({ value: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      throw new Error(`Unexpected mocked Microsoft request: ${url}`);
    });

    const organization = await db.organization.create({
      data: {
        name: "Partial LIVE Workspace",
        slug: "partial-live-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    const result = await syncMicrosoft365Integration(integration.id);

    expect(result.scoreCoverage).toBe("PARTIAL");

    const persisted = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: { mfaEvidenceStatus: true },
    });

    expect(persisted.mfaEvidenceStatus).toBe("PERMISSION_REQUIRED");
  });
});


describe("Microsoft 365 LIVE change reconciliation", () => {
  beforeEach(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterAll(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
    await db.$disconnect();
  });

  it("removes stale identities and role assignments on the second LIVE sync", async () => {
    let generation = 1;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([
                ...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
              ]),
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/organization?")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: TENANT_ID,
                  displayName: "Changing Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/users?")) {
          const value =
            generation === 1
              ? [
                  {
                    id: "user-keep",
                    displayName: "Keep User",
                    userPrincipalName: "keep@example.test",
                    accountEnabled: true,
                    userType: "Member",
                  },
                  {
                    id: "user-remove",
                    displayName: "Remove User",
                    userPrincipalName: "remove@example.test",
                    accountEnabled: true,
                    userType: "Guest",
                  },
                ]
              : [
                  {
                    id: "user-keep",
                    displayName: "Keep User Updated",
                    userPrincipalName: "keep@example.test",
                    accountEnabled: true,
                    userType: "Member",
                  },
                ];

          return new Response(JSON.stringify({ value }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (url.includes("/roleManagement/directory/roleDefinitions?")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: GLOBAL_ADMIN_ROLE_ID,
                  displayName: "Global Administrator",
                  templateId: "62e90394-69f5-4237-9190-012177145e10",
                  isBuiltIn: true,
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/roleManagement/directory/roleAssignments?")) {
          const value =
            generation === 1
              ? [
                  {
                    id: "assignment-keep",
                    principalId: "user-keep",
                    roleDefinitionId: GLOBAL_ADMIN_ROLE_ID,
                    directoryScopeId: "/",
                  },
                  {
                    id: "assignment-remove",
                    principalId: "user-remove",
                    roleDefinitionId: GLOBAL_ADMIN_ROLE_ID,
                    directoryScopeId: "/",
                  },
                ]
              : [
                  {
                    id: "assignment-keep",
                    principalId: "user-keep",
                    roleDefinitionId: GLOBAL_ADMIN_ROLE_ID,
                    directoryScopeId: "/",
                  },
                ];

          return new Response(JSON.stringify({ value }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (url.includes("/reports/authenticationMethods/userRegistrationDetails")) {
          const value =
            generation === 1
              ? [
                  {
                    id: "user-keep",
                    isAdmin: true,
                    isMfaRegistered: true,
                    isMfaCapable: true,
                    isPasswordlessCapable: false,
                    methodsRegistered: ["microsoftAuthenticatorPush"],
                  },
                  {
                    id: "user-remove",
                    isAdmin: true,
                    isMfaRegistered: true,
                    isMfaCapable: true,
                    isPasswordlessCapable: false,
                    methodsRegistered: ["microsoftAuthenticatorPush"],
                  },
                ]
              : [
                  {
                    id: "user-keep",
                    isAdmin: true,
                    isMfaRegistered: true,
                    isMfaCapable: true,
                    isPasswordlessCapable: false,
                    methodsRegistered: ["microsoftAuthenticatorPush"],
                  },
                ];

          return new Response(JSON.stringify({ value }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: {
        name: "Changing LIVE Workspace",
        slug: "changing-live-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    await syncMicrosoft365Integration(integration.id);

    expect(
      await db.directoryIdentity.count({ where: { integrationId: integration.id } }),
    ).toBe(2);
    expect(
      await db.directoryRoleAssignment.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(2);

    generation = 2;
    await syncMicrosoft365Integration(integration.id);

    const identities = await db.directoryIdentity.findMany({
      where: { integrationId: integration.id },
      select: { externalId: true, displayName: true },
    });
    const assignments = await db.directoryRoleAssignment.findMany({
      where: { integrationId: integration.id },
      select: { externalId: true },
    });

    expect(identities).toEqual([
      { externalId: "user-keep", displayName: "Keep User Updated" },
    ]);
    expect(assignments).toEqual([{ externalId: "assignment-keep" }]);
  });
});


describe("Microsoft 365 sync isolation and idempotency", () => {
  beforeEach(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterAll(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
    await db.$disconnect();
  });

  it("rejects a second sync while an active lease exists", async () => {
    const organization = await db.organization.create({
      data: {
        name: "Locked Workspace",
        slug: "locked-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: "22222222-2222-2222-2222-222222222222",
        connectedAt: new Date(),
      },
    });

    await db.integrationSyncLease.create({
      data: {
        integrationId: integration.id,
        leaseToken: "existing-lease",
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    await expect(syncMicrosoft365Integration(integration.id)).rejects.toMatchObject({
      name: "Microsoft365SyncInProgressError",
    });

    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(1);
  });

  it("takes over an expired lease and releases it after sync", async () => {
    mockMicrosoftGraph();

    const organization = await db.organization.create({
      data: {
        name: "Expired Lease Workspace",
        slug: "expired-lease-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    await db.integrationSyncLease.create({
      data: {
        integrationId: integration.id,
        leaseToken: "expired-lease",
        expiresAt: new Date(Date.now() - 1_000),
      },
    });

    await expect(syncMicrosoft365Integration(integration.id)).resolves.toMatchObject({
      users: 5,
    });

    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });

  it("keeps another organization's evidence untouched during sync", async () => {
    mockMicrosoftGraph();

    const [organizationA, organizationB] = await Promise.all([
      db.organization.create({
        data: { name: "Tenant A", slug: "tenant-a" },
      }),
      db.organization.create({
        data: { name: "Tenant B", slug: "tenant-b" },
      }),
    ]);

    const integrationA = await db.integration.create({
      data: {
        organizationId: organizationA.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    const integrationB = await db.integration.create({
      data: {
        organizationId: organizationB.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: "33333333-3333-3333-3333-333333333333",
        connectedAt: new Date(),
      },
    });

    await db.directoryIdentity.create({
      data: {
        integrationId: integrationB.id,
        externalId: "tenant-b-user",
        displayName: "Tenant B User",
        userPrincipalName: "user@tenant-b.test",
        accountEnabled: true,
      },
    });

    await db.securityFinding.create({
      data: {
        organizationId: organizationB.id,
        integrationId: integrationB.id,
        key: "tenant-b-sentinel",
        ruleId: "TENANT_B_SENTINEL",
        title: "Tenant B Sentinel",
        description: "Must remain untouched by Tenant A sync.",
        severity: "LOW",
      },
    });

    await syncMicrosoft365Integration(integrationA.id);

    expect(
      await db.directoryIdentity.findUnique({
        where: {
          integrationId_externalId: {
            integrationId: integrationB.id,
            externalId: "tenant-b-user",
          },
        },
      }),
    ).not.toBeNull();

    expect(
      await db.securityFinding.findUnique({
        where: {
          organizationId_key: {
            organizationId: organizationB.id,
            key: "tenant-b-sentinel",
          },
        },
      }),
    ).not.toBeNull();
  });

  it("is inventory-idempotent for identical consecutive LIVE syncs", async () => {
    mockMicrosoftGraph();

    const organization = await db.organization.create({
      data: {
        name: "Idempotent Workspace",
        slug: "idempotent-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        connectedAt: new Date(),
      },
    });

    await syncMicrosoft365Integration(integration.id);

    const firstCounts = await Promise.all([
      db.directoryIdentity.count({ where: { integrationId: integration.id } }),
      db.directoryRoleDefinition.count({
        where: { integrationId: integration.id },
      }),
      db.directoryRoleAssignment.count({
        where: { integrationId: integration.id },
      }),
      db.securityFinding.count({
        where: { organizationId: organization.id, status: "OPEN" },
      }),
    ]);

    await syncMicrosoft365Integration(integration.id);

    const secondCounts = await Promise.all([
      db.directoryIdentity.count({ where: { integrationId: integration.id } }),
      db.directoryRoleDefinition.count({
        where: { integrationId: integration.id },
      }),
      db.directoryRoleAssignment.count({
        where: { integrationId: integration.id },
      }),
      db.securityFinding.count({
        where: { organizationId: organization.id, status: "OPEN" },
      }),
    ]);

    expect(secondCounts).toEqual(firstCounts);
    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });
});
