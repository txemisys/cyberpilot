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


describe("Microsoft 365 LIVE atomic publication", () => {
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

  it("rolls back all inventory changes when a write fails mid-sync", async () => {
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
                  displayName: "New Tenant Name",
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
                  id: "new-valid-user",
                  displayName: "New Valid User",
                  userPrincipalName: "valid@example.test",
                  accountEnabled: true,
                  userType: "Member",
                },
                {
                  id: "new-invalid-user",
                  displayName: "New Invalid User",
                  userPrincipalName: "invalid@example.test",
                  accountEnabled: true,
                  userType: "Member",
                  createdDateTime: "not-a-date",
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (
          url.includes("/roleManagement/directory/roleDefinitions?") ||
          url.includes("/roleManagement/directory/roleAssignments?") ||
          url.includes("/reports/authenticationMethods/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: {
        name: "Atomic Workspace",
        slug: "atomic-workspace",
      },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        displayName: "Previous Tenant Name",
        connectedAt: new Date(),
      },
    });

    await db.directoryIdentity.create({
      data: {
        integrationId: integration.id,
        externalId: "previous-user",
        displayName: "Previous User",
        userPrincipalName: "previous@example.test",
        accountEnabled: true,
      },
    });

    await expect(syncMicrosoft365Integration(integration.id)).rejects.toThrow();

    const identities = await db.directoryIdentity.findMany({
      where: { integrationId: integration.id },
      orderBy: { externalId: "asc" },
      select: {
        externalId: true,
        displayName: true,
      },
    });

    expect(identities).toEqual([
      {
        externalId: "previous-user",
        displayName: "Previous User",
      },
    ]);

    const persistedIntegration = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        displayName: true,
        lastSyncAt: true,
      },
    });

    expect(persistedIntegration).toEqual({
      displayName: "Previous Tenant Name",
      lastSyncAt: null,
    });

    expect(
      await db.securityScore.count({
        where: { organizationId: organization.id },
      }),
    ).toBe(0);

    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });
});


describe("Microsoft 365 LIVE failure state and recovery", () => {
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

  it("persists a safe failure code and clears it after a successful retry", async () => {
    let failWithMalformedPayload = true;

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
                  displayName: "Recovery Tenant",
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
              value: failWithMalformedPayload
                ? [{ id: "", displayName: "Malformed" }]
                : [
                    {
                      id: "recovered-user",
                      displayName: "Recovered User",
                      userPrincipalName: "recovered@example.test",
                      accountEnabled: true,
                      userType: "Member",
                    },
                  ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (
          url.includes("/roleManagement/directory/roleDefinitions?") ||
          url.includes("/roleManagement/directory/roleAssignments?") ||
          url.includes("/reports/authenticationMethods/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: {
        name: "Recovery Workspace",
        slug: "recovery-workspace",
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

    await expect(syncMicrosoft365Integration(integration.id)).rejects.toMatchObject({
      name: "MicrosoftGraphPayloadError",
    });

    const failed = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        lastErrorAt: true,
        lastErrorCode: true,
        lastErrorEventId: true,
        lastSyncAt: true,
      },
    });

    expect(failed.lastErrorAt).toBeInstanceOf(Date);
    expect(failed.lastErrorCode).toBe("GRAPH_PAYLOAD_INVALID");
    expect(failed.lastErrorEventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(failed.lastSyncAt).toBeNull();

    failWithMalformedPayload = false;

    await expect(syncMicrosoft365Integration(integration.id)).resolves.toMatchObject({
      users: 1,
    });

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


describe("Microsoft 365 LIVE snapshot preservation across failures", () => {
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

  it("keeps the last valid snapshot after Graph returns malformed data, then replaces it on recovery", async () => {
    mockMicrosoftGraph();
    const healthyFetch = vi.mocked(fetch).getMockImplementation()!;
    let graphHealthy = true;
    vi.mocked(fetch).mockImplementation(async (input: string | URL | Request, init?: RequestInit) => {
      if (!graphHealthy && String(input).includes("/users?")) {
        return new Response(JSON.stringify({ value: [{ id: "", displayName: "Invalid" }] }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return healthyFetch(input, init);
    });

    const organization = await db.organization.create({
      data: { name: "LIVE Retained Evidence", slug: "live-retained-evidence" },
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
    const before = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: { lastSyncAt: true },
    });
    const initialIdentities = await db.directoryIdentity.findMany({
      where: { integrationId: integration.id }, orderBy: { externalId: "asc" },
      select: { externalId: true },
    });
    const initialScore = await db.securityScore.findFirstOrThrow({
      where: { organizationId: organization.id },
      orderBy: { calculatedAt: "desc" },
      select: { id: true, score: true },
    });
    expect(initialIdentities.length).toBeGreaterThan(0);

    graphHealthy = false;
    await expect(syncMicrosoft365Integration(integration.id)).rejects.toMatchObject({
      name: "MicrosoftGraphPayloadError",
    });
    const failed = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: { lastSyncAt: true, lastErrorCode: true },
    });
    expect(failed.lastSyncAt?.getTime()).toBe(before.lastSyncAt?.getTime());
    expect(failed.lastErrorCode).toBe("GRAPH_PAYLOAD_INVALID");
    expect(await db.directoryIdentity.findMany({
      where: { integrationId: integration.id }, orderBy: { externalId: "asc" },
      select: { externalId: true },
    })).toEqual(initialIdentities);
    expect(await db.securityScore.count({
      where: { organizationId: organization.id },
    })).toBe(1);
    expect(await db.securityScore.findUnique({
      where: { id: initialScore.id }, select: { score: true },
    })).toEqual({ score: initialScore.score });

    graphHealthy = true;
    await expect(syncMicrosoft365Integration(integration.id)).resolves.toMatchObject({ users: 5 });
    const recovered = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: { lastSyncAt: true, lastErrorCode: true, lastErrorAt: true },
    });
    expect(recovered.lastSyncAt).toBeInstanceOf(Date);
    expect(recovered.lastErrorAt).toBeNull();
    expect(recovered.lastErrorCode).toBeNull();
    expect(await db.directoryIdentity.count({
      where: { integrationId: integration.id },
    })).toBe(5);
    expect(await db.securityScore.count({
      where: { organizationId: organization.id },
    })).toBe(2);
    expect(await db.integrationSyncLease.count({
      where: { integrationId: integration.id },
    })).toBe(0);
  });
});

describe("Microsoft 365 LIVE bulk snapshot scale", () => {
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

  it("publishes a 2500-user LIVE snapshot atomically without duplication", async () => {
    const users = Array.from({ length: 2500 }, (_, index) => ({
      id: `bulk-user-${index}`,
      displayName: `Bulk User ${index}`,
      userPrincipalName: `bulk-user-${index}@example.test`,
      accountEnabled: true,
      userType: "Member",
    }));

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
                  displayName: "Bulk Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/users?")) {
          return new Response(JSON.stringify({ value: users }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (
          url.includes("/roleManagement/directory/roleDefinitions?") ||
          url.includes("/roleManagement/directory/roleAssignments?") ||
          url.includes("/reports/authenticationMethods/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: {
        name: "Bulk Workspace",
        slug: "bulk-workspace",
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

    const first = await syncMicrosoft365Integration(integration.id);

    expect(first.users).toBe(2500);
    expect(
      await db.directoryIdentity.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(2500);

    const second = await syncMicrosoft365Integration(integration.id);

    expect(second.users).toBe(2500);
    expect(
      await db.directoryIdentity.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(2500);
    expect(
      await db.securityScore.count({
        where: { organizationId: organization.id },
      }),
    ).toBe(2);
  });
});


describe("Microsoft 365 sync lease heartbeat", () => {
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

  it("renews the lease while a LIVE sync is waiting on Microsoft Graph", async () => {
    let releaseUsers!: () => void;
    const usersGate = new Promise<void>((resolve) => {
      releaseUsers = resolve;
    });

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

        if (url.includes("/users?")) {
          await usersGate;
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (url.includes("/organization?")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: TENANT_ID,
                  displayName: "Heartbeat Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (
          url.includes("/roleManagement/directory/roleDefinitions?") ||
          url.includes("/roleManagement/directory/roleAssignments?") ||
          url.includes("/reports/authenticationMethods/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: { name: "Heartbeat Workspace", slug: "heartbeat-workspace" },
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

    const syncPromise = syncMicrosoft365Integration(integration.id);

    let firstLease = await db.integrationSyncLease.findUnique({
      where: { integrationId: integration.id },
      select: { expiresAt: true },
    });

    for (let attempt = 0; attempt < 20 && !firstLease; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      firstLease = await db.integrationSyncLease.findUnique({
        where: { integrationId: integration.id },
        select: { expiresAt: true },
      });
    }

    expect(firstLease).not.toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 120));

    const renewedLease = await db.integrationSyncLease.findUniqueOrThrow({
      where: { integrationId: integration.id },
      select: { expiresAt: true },
    });

    expect(renewedLease.expiresAt.getTime()).toBeGreaterThan(
      firstLease!.expiresAt.getTime(),
    );

    releaseUsers();
    await expect(syncPromise).resolves.toMatchObject({ users: 0 });

    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });
});


describe("Microsoft 365 LIVE paginated scale", () => {
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

  it("publishes 10000 users from ten Graph pages without duplication", async () => {
    const pageSize = 1000;
    const pageCount = 10;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));

        if (url.hostname.includes("login.microsoftonline.com")) {
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

        if (url.pathname.endsWith("/organization")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: TENANT_ID,
                  displayName: "Paginated Scale Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.pathname.endsWith("/users")) {
          const page = Number(url.searchParams.get("page") ?? "0");
          const offset = page * pageSize;
          const value = Array.from({ length: pageSize }, (_, index) => {
            const id = offset + index;

            return {
              id: `scale-user-${id}`,
              displayName: `Scale User ${id}`,
              userPrincipalName: `scale-user-${id}@example.test`,
              accountEnabled: true,
              userType: "Member",
            };
          });

          return new Response(
            JSON.stringify({
              value,
              ...(page < pageCount - 1
                ? {
                    "@odata.nextLink":
                      `https://graph.microsoft.com/v1.0/users?page=${page + 1}`,
                  }
                : {}),
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (
          url.pathname.endsWith("/roleDefinitions") ||
          url.pathname.endsWith("/roleAssignments") ||
          url.pathname.endsWith("/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url.toString()}`);
      }),
    );

    const organization = await db.organization.create({
      data: {
        name: "Paginated Scale Workspace",
        slug: "paginated-scale-workspace",
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

    const first = await syncMicrosoft365Integration(integration.id);

    expect(first.users).toBe(10_000);
    expect(
      await db.directoryIdentity.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(10_000);

    const second = await syncMicrosoft365Integration(integration.id);

    expect(second.users).toBe(10_000);
    expect(
      await db.directoryIdentity.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(10_000);
  });
});


describe("Microsoft 365 sync lease fencing", () => {
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

  it("prevents a stale sync from publishing after another owner takes the lease", async () => {
    let releaseUsers!: () => void;
    const usersGate = new Promise<void>((resolve) => {
      releaseUsers = resolve;
    });

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

        if (url.includes("/users?")) {
          await usersGate;
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: "new-user",
                  displayName: "New User",
                  userPrincipalName: "new-user@example.test",
                  accountEnabled: true,
                  userType: "Member",
                },
              ],
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
                  displayName: "Fencing Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (
          url.includes("/roleManagement/directory/roleDefinitions?") ||
          url.includes("/roleManagement/directory/roleAssignments?") ||
          url.includes("/reports/authenticationMethods/userRegistrationDetails")
        ) {
          return new Response(JSON.stringify({ value: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected mocked Microsoft request: ${url}`);
      }),
    );

    const organization = await db.organization.create({
      data: { name: "Fencing Workspace", slug: "fencing-workspace" },
    });

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: TENANT_ID,
        displayName: "Previous Tenant Snapshot",
        connectedAt: new Date(),
      },
    });

    await db.directoryIdentity.create({
      data: {
        integrationId: integration.id,
        externalId: "previous-user",
        displayName: "Previous User",
        userPrincipalName: "previous-user@example.test",
        accountEnabled: true,
      },
    });

    const syncPromise = syncMicrosoft365Integration(integration.id);

    let activeLease = await db.integrationSyncLease.findUnique({
      where: { integrationId: integration.id },
      select: { leaseToken: true },
    });

    for (let attempt = 0; attempt < 20 && !activeLease; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      activeLease = await db.integrationSyncLease.findUnique({
        where: { integrationId: integration.id },
        select: { leaseToken: true },
      });
    }

    expect(activeLease).not.toBeNull();

    await db.integrationSyncLease.delete({
      where: { integrationId: integration.id },
    });

    await db.integrationSyncLease.create({
      data: {
        integrationId: integration.id,
        leaseToken: "replacement-owner",
        expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      },
    });

    releaseUsers();

    await expect(syncPromise).rejects.toMatchObject({
      name: "Microsoft365SyncLeaseLostError",
    });

    expect(
      await db.directoryIdentity.findMany({
        where: { integrationId: integration.id },
        orderBy: { externalId: "asc" },
        select: { externalId: true, displayName: true },
      }),
    ).toEqual([
      {
        externalId: "previous-user",
        displayName: "Previous User",
      },
    ]);

    const persisted = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        displayName: true,
        lastSyncAt: true,
        lastErrorCode: true,
        lastErrorEventId: true,
      },
    });

    expect(persisted.displayName).toBe("Previous Tenant Snapshot");
    expect(persisted.lastSyncAt).toBeNull();
    expect(persisted.lastErrorCode).toBe("SYNC_LEASE_LOST");
    expect(persisted.lastErrorEventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );

    const replacementLease = await db.integrationSyncLease.findUniqueOrThrow({
      where: { integrationId: integration.id },
      select: { leaseToken: true },
    });

    expect(replacementLease.leaseToken).toBe("replacement-owner");
  });
});
