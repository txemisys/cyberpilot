import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { db } from "@cyberpilot/database";

vi.mock("./auth", () => ({
  auth: { api: { getSession: vi.fn() } },
}));

import { auth } from "./auth";
import { seedMicrosoft365Lab } from "./microsoft-365-lab";
import { syncMicrosoft365Integration } from "./microsoft-365-sync";
import { getGuidedVerificationReadiness } from "./guided-verification";
import { buildExecutiveReport } from "./executive-report";
import { POST as syncRoute } from "../app/api/organizations/[slug]/integrations/microsoft-365/sync/route";
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
    expect((await context.send()).status).toBe(303);
    expect(await db.guidedRemediationStep.count({
      where: { organizationId: context.organization.id, remediationId: context.remediation.id, stepIndex: 0 },
    })).toBe(1);
    expect(await db.auditEvent.count({
      where: { organizationId: context.organization.id, action: "remediation.guided_step_attested", resourceId: context.remediation.id },
    })).toBe(1);
    expect((await db.securityFinding.findUniqueOrThrow({ where: { id: context.remediation.findingId } })).status).toBe("OPEN");
    expect((await db.remediation.findUniqueOrThrow({ where: { id: context.remediation.id } })).status).toBe("APPROVED");
  });
  it("runs the LAB pilot from finding to guided progress, re-evaluation and executive evidence", async () => {
    const context = await setup();
    context.sessionFor(context.user.id);
    const remediation = await db.remediation.findUniqueOrThrow({
      where: { id: context.remediation.id },
      select: { steps: true, status: true, findingId: true },
    });
    const steps = Array.isArray(remediation.steps)
      ? remediation.steps.filter((step): step is string => typeof step === "string")
      : [];
    expect(steps.length).toBeGreaterThan(0);

    const before = await db.securityScore.findFirstOrThrow({
      where: { organizationId: context.organization.id },
      orderBy: { calculatedAt: "desc" },
    });
    const openBefore = await db.securityFinding.count({
      where: { organizationId: context.organization.id, status: "OPEN" },
    });
    expect(getGuidedVerificationReadiness(steps.length, new Set())).toBe("IN_PROGRESS");

    for (let index = 0; index < steps.length; index++) {
      expect((await context.send(context.organization.slug, context.remediation.id, String(index))).status).toBe(303);
    }
    const progress = await db.guidedRemediationStep.findMany({
      where: { organizationId: context.organization.id, remediationId: context.remediation.id },
      select: { stepIndex: true },
    });
    expect(progress).toHaveLength(steps.length);
    expect(getGuidedVerificationReadiness(
      steps.length,
      new Set(progress.map((record) => record.stepIndex)),
    )).toBe("READY");

    // Confirmed work is not evidence of resolved risk.
    expect((await db.securityFinding.findUniqueOrThrow({
      where: { id: remediation.findingId },
    })).status).toBe("OPEN");

    const response = await syncRoute(
      new NextRequest(`http://localhost/api/organizations/${context.organization.slug}/integrations/microsoft-365/sync`, {
        method: "POST",
      }),
      { params: Promise.resolve({ slug: context.organization.slug }) },
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain("sync=completed");

    const after = await db.securityScore.findFirstOrThrow({
      where: { organizationId: context.organization.id },
      orderBy: { calculatedAt: "desc" },
    });
    const findings = await db.securityFinding.findMany({
      where: { organizationId: context.organization.id, status: "OPEN" },
      select: {
        id: true, ruleId: true, title: true, description: true, severity: true,
        firstSeenAt: true, lastSeenAt: true,
      },
    });
    const report = buildExecutiveReport({
      organizationName: context.organization.name,
      integrationMode: "LAB",
      integrationDisplayName: "Synthetic pilot",
      lastSyncAt: new Date(),
      snapshot: after,
      previousSnapshot: before,
      baselineSnapshot: before,
      scoreHistory: [after, before],
      findings,
      domains: [],
      remediations: [],
    });
    expect(report.isLab).toBe(true);
    expect(after.score).toBe(before.score);
    expect(report.scoreDelta).toBe(0);
    expect(report.currentRisk.score).toBe(after.score);
    expect(findings).toHaveLength(openBefore);
    expect((await db.securityFinding.findUniqueOrThrow({
      where: { id: remediation.findingId },
    })).status).toBe("OPEN");
  });

});
