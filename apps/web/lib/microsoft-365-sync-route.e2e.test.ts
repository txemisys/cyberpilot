import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { db } from "@cyberpilot/database";

vi.mock("./auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(),
    },
  },
}));

import { auth } from "./auth";
import { seedMicrosoft365Lab } from "./microsoft-365-lab";
import { POST } from "../app/api/organizations/[slug]/integrations/microsoft-365/sync/route";

async function resetDatabase() {
  await db.requestRateLimit.deleteMany();
  await db.auditEvent.deleteMany();
  await db.remediation.deleteMany();
  await db.securityScore.deleteMany();
  await db.securityFinding.deleteMany();
  await db.domain.deleteMany();
  await db.directoryRoleAssignment.deleteMany();
  await db.directoryRoleDefinition.deleteMany();
  await db.directoryIdentity.deleteMany();
  await db.integrationSyncLease.deleteMany();
  await db.integrationConsentState.deleteMany();
  await db.integration.deleteMany();
  await db.membership.deleteMany();
  await db.organization.deleteMany();
  await db.session.deleteMany();
  await db.account.deleteMany();
  await db.verification.deleteMany();
  await db.user.deleteMany();
}

async function createOwnerWorkspace(slug: string) {
  const user = await db.user.create({
    data: {
      name: "Route Test Owner",
      email: `${slug}@cyberpilot.local`,
    },
  });

  const organization = await db.organization.create({
    data: {
      name: `Route Test ${slug}`,
      slug,
      memberships: {
        create: {
          userId: user.id,
          role: "OWNER",
        },
      },
    },
  });

  vi.mocked(auth.api.getSession).mockResolvedValue({
    user: {
      id: user.id,
    },
  } as Awaited<ReturnType<typeof auth.api.getSession>>);

  return { user, organization };
}

function request(slug: string) {
  return new NextRequest(
    `http://localhost/api/organizations/${slug}/integrations/microsoft-365/sync`,
    { method: "POST" },
  );
}

function makeLivePreflightInvalid() {
  delete process.env.M365_GRAPH_CLIENT_ID;
  delete process.env.M365_GRAPH_CLIENT_SECRET;
  delete process.env.M365_GRAPH_REDIRECT_URI;
  delete process.env.MICROSOFT_CLIENT_ID;
  process.env.LAB_AUTH_ENABLED = "true";
}

describe("Microsoft 365 shared sync route mode gates", () => {
  beforeEach(async () => {
    await resetDatabase();
    vi.clearAllMocks();
    makeLivePreflightInvalid();
  });

  afterAll(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
    delete process.env.LAB_AUTH_ENABLED;
    await db.$disconnect();
  });

  it("allows LAB re-evaluation even when LIVE pilot configuration is invalid", async () => {
    const { organization } = await createOwnerWorkspace("route-lab");
    const integration = await seedMicrosoft365Lab(organization.id);

    const response = await POST(request(organization.slug), {
      params: Promise.resolve({ slug: organization.slug }),
    });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain("sync=completed");

    const persisted = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        mode: true,
        lastSyncAt: true,
        lastErrorAt: true,
      },
    });

    expect(persisted.mode).toBe("LAB");
    expect(persisted.lastSyncAt).toBeInstanceOf(Date);
    expect(persisted.lastErrorAt).toBeNull();

    expect(
      await db.auditEvent.count({
        where: {
          organizationId: organization.id,
          action: "integration.microsoft_365.sync_completed",
        },
      }),
    ).toBe(1);
  });

  it("keeps the first-LIVE static configuration gate enforced", async () => {
    const { organization } = await createOwnerWorkspace("route-live");

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LIVE",
        status: "CONNECTED",
        externalTenantId: "11111111-1111-1111-1111-111111111111",
        connectedAt: new Date(),
      },
    });

    const response = await POST(request(organization.slug), {
      params: Promise.resolve({ slug: organization.slug }),
    });

    expect(response.status).toBe(503);
    await expect(response.text()).resolves.toBe(
      "First LIVE read-only configuration gate failed.",
    );

    const persisted = await db.integration.findUniqueOrThrow({
      where: { id: integration.id },
      select: {
        lastSyncAt: true,
        lastErrorAt: true,
      },
    });

    expect(persisted.lastSyncAt).toBeNull();
    expect(persisted.lastErrorAt).toBeNull();
    expect(
      await db.integrationSyncLease.count({
        where: { integrationId: integration.id },
      }),
    ).toBe(0);
  });
});


describe("Microsoft 365 sync error correlation metadata", () => {
  beforeEach(async () => {
    await resetDatabase();
    vi.clearAllMocks();
  });

  afterAll(async () => {
    await resetDatabase();
    vi.restoreAllMocks();
  });

  it("stores only safe correlation identifiers in failure audit metadata", async () => {
    const { user, organization } = await createOwnerWorkspace("route-correlation");

    const integration = await db.integration.create({
      data: {
        organizationId: organization.id,
        provider: "MICROSOFT_365",
        mode: "LAB",
        status: "CONNECTED",
        connectedAt: new Date(),
        lastErrorAt: new Date(),
        lastErrorCode: "SYNC_FAILED",
        lastErrorEventId: "11111111-1111-4111-8111-111111111111",
      },
    });

    await db.auditEvent.create({
      data: {
        organizationId: organization.id,
        actorType: "USER",
        actorUserId: user.id,
        action: "integration.microsoft_365.sync_failed",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          failureCode: integration.lastErrorCode,
          eventId: integration.lastErrorEventId,
        },
      },
    });

    const audit = await db.auditEvent.findFirstOrThrow({
      where: {
        organizationId: organization.id,
        action: "integration.microsoft_365.sync_failed",
      },
      select: { metadata: true },
    });

    expect(audit.metadata).toEqual({
      failureCode: "SYNC_FAILED",
      eventId: "11111111-1111-4111-8111-111111111111",
    });
  });
});
