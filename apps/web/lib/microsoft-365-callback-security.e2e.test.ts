import { createHash } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { db } from "@cyberpilot/database";

vi.mock("./auth", () => ({ auth: { api: { getSession: vi.fn() } } }));
const graphOrganization = vi.hoisted(() => vi.fn());
vi.mock("@cyberpilot/integrations/microsoft-365", () => ({
  assertMicrosoftTenantId: vi.fn(),
  MicrosoftGraphClient: vi.fn().mockImplementation(() => ({
    getOrganization: graphOrganization,
  })),
}));

import { auth } from "./auth";
import { GET } from "../app/api/integrations/microsoft-365/callback/route";

const tenant = "11111111-1111-4111-8111-111111111111";
const rawState = "one-time-consent-callback-state";
const nonceHash = createHash("sha256").update(rawState).digest("hex");

async function reset() {
  await db.auditEvent.deleteMany();
  await db.integrationConsentState.deleteMany();
  await db.membership.deleteMany();
  await db.organization.deleteMany();
  await db.session.deleteMany();
  await db.account.deleteMany();
  await db.verification.deleteMany();
  await db.user.deleteMany();
}

async function setup(options: { expired?: boolean; consumed?: boolean; purpose?: "SCANNER" | "REMEDIATION" } = {}) {
  const owner = await db.user.create({ data: { name: "Callback owner", email: "callback-owner@cyberpilot.local" } });
  const outsider = await db.user.create({ data: { name: "Callback outsider", email: "callback-other@cyberpilot.local" } });
  const org = await db.organization.create({ data: { name: "Callback LAB", slug: "callback-lab" } });
  const record = await db.integrationConsentState.create({
    data: {
      organizationId: org.id, userId: owner.id, provider: "MICROSOFT_365",
      purpose: options.purpose ?? "SCANNER", nonceHash,
      expiresAt: new Date(Date.now() + (options.expired ? -60_000 : 600_000)),
      consumedAt: options.consumed ? new Date() : null,
    },
  });
  const authenticate = (id: string | null) => vi.mocked(auth.api.getSession).mockResolvedValue(
    id ? ({ user: { id } } as Awaited<ReturnType<typeof auth.api.getSession>>) : null,
  );
  const callback = (query = `state=${rawState}&admin_consent=True&tenant=${tenant}`) =>
    GET(new NextRequest(`http://localhost/api/integrations/microsoft-365/callback?${query}`));
  return { owner, outsider, org, record, authenticate, callback };
}

describe("Microsoft 365 scanner callback security", () => {
  beforeEach(async () => { await reset(); vi.clearAllMocks(); graphOrganization.mockRejectedValue(new Error("Mocked Graph service failure")); });
  afterAll(async () => { await reset(); vi.restoreAllMocks(); await db.$disconnect(); });

  it("rejects missing, mismatched and anonymous states before any write", async () => {
    const c = await setup();
    c.authenticate(null);
    expect(new URL((await c.callback()).headers.get("location")!).pathname).toBe("/login");
    c.authenticate(c.owner.id);
    for (const query of ["admin_consent=True", "state=not-the-state&admin_consent=True"]) {
      const response = await c.callback(query);
      expect(new URL(response.headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
    }
    expect((await db.integrationConsentState.findUniqueOrThrow({ where: { id: c.record.id } })).consumedAt).toBeNull();
    expect(await db.integration.count()).toBe(0);
  });

  it("rejects expired, previously consumed and wrong-purpose consent states", async () => {
    for (const options of [{ expired: true }, { consumed: true }, { purpose: "REMEDIATION" as const }]) {
      await reset();
      const c = await setup(options);
      c.authenticate(c.owner.id);
      const response = await c.callback();
      expect(new URL(response.headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
      expect(await db.integration.count()).toBe(0);
    }
  });

  it("binds callback state to initiating user and prevents another user from consuming it", async () => {
    const c = await setup();
    c.authenticate(c.outsider.id);
    const response = await c.callback();
    expect(new URL(response.headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
    expect((await db.integrationConsentState.findUniqueOrThrow({ where: { id: c.record.id } })).consumedAt).toBeNull();
    expect(await db.auditEvent.count()).toBe(0);
  });

  it("consumes denied consent exactly once and never connects a tenant", async () => {
    const c = await setup();
    c.authenticate(c.owner.id);
    const query = `state=${rawState}&error=access_denied&tenant=${tenant}`;
    const first = await c.callback(query);
    expect(new URL(first.headers.get("location")!).searchParams.get("code")).toBe("consent_denied");
    expect((await db.integrationConsentState.findUniqueOrThrow({ where: { id: c.record.id } })).consumedAt).not.toBeNull();
    expect(await db.auditEvent.count({ where: { action: "integration.microsoft_365.consent_denied" } })).toBe(1);
    const replay = await c.callback(query);
    expect(new URL(replay.headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
    expect(await db.auditEvent.count({ where: { action: "integration.microsoft_365.consent_denied" } })).toBe(1);
    expect(await db.integration.count()).toBe(0);
  });
  it("rejects a tenant when Graph returns a different organization ID", async () => {
    const c = await setup();
    c.authenticate(c.owner.id);
    graphOrganization.mockResolvedValue({ id: "22222222-2222-4222-8222-222222222222", displayName: "Wrong tenant" });
    const response = await c.callback();
    expect(new URL(response.headers.get("location")!).searchParams.get("code")).toBe("tenant_verification_failed");
    expect(graphOrganization).toHaveBeenCalledOnce();
    expect(await db.integration.count()).toBe(0);
    expect((await db.integrationConsentState.findUniqueOrThrow({ where: { id: c.record.id } })).consumedAt).not.toBeNull();
    expect(new URL((await c.callback()).headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
  });

  it("fails closed and audits a Graph lookup failure without saving a connected integration", async () => {
    const c = await setup();
    c.authenticate(c.owner.id);
    const response = await c.callback();
    expect(new URL(response.headers.get("location")!).searchParams.get("code")).toBe("connection_failed");
    expect(graphOrganization).toHaveBeenCalledOnce();
    expect(await db.integration.count()).toBe(0);
    expect(await db.auditEvent.count({
      where: { action: "integration.microsoft_365.connection_failed", organizationId: c.org.id },
    })).toBe(1);
    expect(new URL((await c.callback()).headers.get("location")!).searchParams.get("code")).toBe("invalid_state");
    expect(graphOrganization).toHaveBeenCalledOnce();
  });

});
