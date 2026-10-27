import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { db } from "@cyberpilot/database";

vi.mock("./auth", () => ({ auth: { api: { getSession: vi.fn() } } }));
vi.mock("@cyberpilot/integrations/microsoft-365", () => ({
  getMicrosoftGraphScannerConfiguration: () => ({ configured: true }),
}));

import { auth } from "./auth";
import { GET } from "../app/api/organizations/[slug]/integrations/microsoft-365/connect/route";

const slug = "consent-boundary-lab";
const envKeys = [
  "BETTER_AUTH_URL", "LAB_AUTH_ENABLED", "MICROSOFT_CLIENT_ID",
  "M365_GRAPH_CLIENT_ID", "M365_GRAPH_CLIENT_SECRET", "M365_GRAPH_REDIRECT_URI",
] as const;
const original = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));

function setConfig() {
  process.env.BETTER_AUTH_URL = "https://pilot.cyberpilot.example";
  process.env.LAB_AUTH_ENABLED = "false";
  process.env.MICROSOFT_CLIENT_ID = "browser-login-app";
  process.env.M365_GRAPH_CLIENT_ID = "readonly-scanner-app";
  process.env.M365_GRAPH_CLIENT_SECRET = "test-only-scanner-secret";
  process.env.M365_GRAPH_REDIRECT_URI =
    "https://pilot.cyberpilot.example/api/integrations/microsoft-365/callback";
}

async function reset() {
  await db.requestRateLimit.deleteMany();
  await db.auditEvent.deleteMany();
  await db.integrationConsentState.deleteMany();
  await db.membership.deleteMany();
  await db.organization.deleteMany();
  await db.session.deleteMany();
  await db.account.deleteMany();
  await db.verification.deleteMany();
  await db.user.deleteMany();
}

async function setup() {
  const owner = await db.user.create({
    data: { name: "Consent owner", email: "consent-owner@cyberpilot.local" },
  });
  const member = await db.user.create({
    data: { name: "Consent reader", email: "consent-reader@cyberpilot.local" },
  });
  await db.organization.create({
    data: {
      name: "Consent boundary",
      slug,
      memberships: {
        create: [
          { userId: owner.id, role: "OWNER" },
          { userId: member.id, role: "MEMBER" },
        ],
      },
    },
  });
  const authenticate = (userId: string | null) =>
    vi.mocked(auth.api.getSession).mockResolvedValue(
      userId ? ({ user: { id: userId } } as Awaited<ReturnType<typeof auth.api.getSession>>) : null,
    );
  const start = (organizationSlug = slug) =>
    GET(
      new NextRequest(`http://localhost/api/organizations/${organizationSlug}/integrations/microsoft-365/connect`),
      { params: Promise.resolve({ slug: organizationSlug }) },
    );
  return { owner, member, authenticate, start };
}

describe("Microsoft 365 scanner consent boundaries", () => {
  beforeEach(async () => { await reset(); vi.clearAllMocks(); setConfig(); });
  afterAll(async () => {
    await reset();
    for (const key of envKeys) {
      const value = original[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    vi.restoreAllMocks();
    await db.$disconnect();
  });

  it("denies anonymous, outsider and read-only users without creating consent state", async () => {
    const { owner, member, authenticate, start } = await setup();
    authenticate(null);
    expect((await start()).status).toBe(307);
    authenticate(member.id);
    expect((await start()).status).toBe(403);
    authenticate(owner.id);
    expect((await start("some-other-organization")).status).toBe(404);
    expect(await db.integrationConsentState.count()).toBe(0);
    expect(await db.auditEvent.count({
      where: { action: "integration.microsoft_365.consent_started" },
    })).toBe(0);
  });

  it("fails closed before consent when scanner preflight is unsafe", async () => {
    const { owner, authenticate, start } = await setup();
    authenticate(owner.id);
    process.env.LAB_AUTH_ENABLED = "true";
    expect((await start()).status).toBe(503);
    expect(await db.integrationConsentState.count()).toBe(0);
    expect(await db.auditEvent.count({
      where: { action: "integration.microsoft_365.consent_started" },
    })).toBe(0);
  });

  it("creates short-lived one-time hashed state and redirects only to scanner admin consent", async () => {
    const { owner, authenticate, start } = await setup();
    authenticate(owner.id);
    const response = await start();
    expect(response.status).toBe(307);
    const destination = new URL(response.headers.get("location")!);
    expect(destination.origin).toBe("https://login.microsoftonline.com");
    expect(destination.pathname).toBe("/organizations/v2.0/adminconsent");
    expect(destination.searchParams.get("client_id")).toBe("readonly-scanner-app");
    expect(destination.searchParams.get("scope")).toBe("https://graph.microsoft.com/.default");
    expect(destination.searchParams.get("redirect_uri")).toBe(
      "https://pilot.cyberpilot.example/api/integrations/microsoft-365/callback",
    );
    const rawState = destination.searchParams.get("state");
    expect(rawState?.length).toBeGreaterThan(24);
    const stored = await db.integrationConsentState.findFirstOrThrow({
      select: { nonceHash: true, purpose: true, consumedAt: true, expiresAt: true },
    });
    expect(stored.purpose).toBe("SCANNER");
    expect(stored.consumedAt).toBeNull();
    expect(stored.nonceHash).not.toBe(rawState);
    expect(stored.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(stored.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 10 * 60 * 1000);
    expect(await db.auditEvent.count({
      where: { action: "integration.microsoft_365.consent_started" },
    })).toBe(1);
  });
});
