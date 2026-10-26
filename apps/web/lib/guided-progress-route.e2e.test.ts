import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { db } from "@cyberpilot/database";

vi.mock("./auth", () => ({
  auth: { api: { getSession: vi.fn() } },
}));

import { auth } from "./auth";
import { seedMicrosoft365Lab } from "./microsoft-365-lab";
import { syncMicrosoft365Integration } from "./microsoft-365-sync";
import { POST } from "../app/api/organizations/[slug]/remediations/[remediationId]/progress/route";

async function reset() {
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

async function setup() {
  const user = await db.user.create({ data: { name: "Owner", email: "guided-route-owner@cyberpilot.local" } });
  const outsider = await db.user.create({ data: { name: "Outsider", email: "guided-route-outsider@cyberpilot.local" } });
  const organization = await db.organization.create({
    data: { name: "Guided Route Lab", slug: "guided-route-lab", memberships: { create: { userId: user.id, role: "OWNER" } } },
  });
  const other = await db.organization.create({ data: { name: "Other Lab", slug: "guided-route-other" } });
  const integration = await seedMicrosoft365Lab(organization.id);
  await syncMicrosoft365Integration(integration.id);
  const remediation = await db.remediation.findFirstOrThrow({
    where: { organizationId: organization.id, mode: "GUIDED", status: "PROPOSED" },
    select: { id: true, findingId: true },
  });
  await db.remediation.update({ where: { id: remediation.id }, data: { status: "APPROVED", approvedAt: new Date() } });
  const sessionFor = (id: string | null) => vi.mocked(auth.api.getSession).mockResolvedValue(
    id ? ({ user: { id } } as Awaited<ReturnType<typeof auth.api.getSession>>) : null
  );
  function send(slug = organization.slug, id = remediation.id, stepIndex = "0") {
    const body = new FormData();
    body.set("stepIndex", stepIndex);
    return POST(new NextRequest(`http://localhost/api/organizations/${slug}/remediations/${id}/progress`, { method: "POST", body }), {
      params: Promise.resolve({ slug, remediationId: id }),
    });
  }
  return { user, outsider, organization, other, remediation, sessionFor, send };
}

describe("guided remediation progress HTTP authorization", () => {
  beforeEach(async () => { await reset(); vi.clearAllMocks(); });
  afterAll(async () => { await reset(); vi.restoreAllMocks(); await db.$disconnect(); });

  it("rejects unauthenticated and nonmember requests without writing audits", async () => {
    const context = await setup();
    context.sessionFor(null);
    expect((await context.send()).status).toBe(303);
    context.sessionFor(context.outsider.id);
    expect((await context.send()).status).toBe(404);
    expect(await db.auditEvent.count({ where: { action: "remediation.guided_step_attested" } })).toBe(0);
  });

  it("forbids read-only members and cross-tenant remediation identifiers", async () => {
    const context = await setup();
    await db.membership.create({ data: { userId: context.outsider.id, organizationId: context.organization.id, role: "MEMBER" } });
    context.sessionFor(context.outsider.id);
    expect((await context.send()).status).toBe(403);
    context.sessionFor(context.user.id);
    expect((await context.send(context.other.slug)).status).toBe(404);
    expect((await context.send(context.organization.slug, "unrelated-remediation")).status).toBe(409);
    expect(await db.auditEvent.count({ where: { action: "remediation.guided_step_attested" } })).toBe(0);
  });

  it("rejects invalid steps, and persists authorized acknowledgement without resolving a finding", async () => {
    const context = await setup();
    context.sessionFor(context.user.id);
    expect((await context.send(context.organization.slug, context.remediation.id, "-1")).status).toBe(400);
    expect((await context.send(context.organization.slug, context.remediation.id, "9999")).status).toBe(400);
    const response = await context.send();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain(`#remediation-${context.remediation.id}`);
    expect(await db.auditEvent.count({
      where: { organizationId: context.organization.id, action: "remediation.guided_step_attested", resourceId: context.remediation.id },
    })).toBe(1);
    expect((await db.securityFinding.findUniqueOrThrow({ where: { id: context.remediation.findingId } })).status).toBe("OPEN");
    expect((await db.remediation.findUniqueOrThrow({ where: { id: context.remediation.id } })).status).toBe("APPROVED");
  });
});
