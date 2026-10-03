import { db } from "@cyberpilot/database";
import { createHash, randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../../lib/auth";

const CONSENT_TTL_MS = 10 * 60 * 1000;

function hashState(state: string) {
  return createHash("sha256").update(state).digest("hex");
}

type RouteContext = {
  params: Promise<{
    slug: string;
  }>;
};

export async function GET(request: NextRequest, { params }: RouteContext) {
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const { slug } = await params;

  const membership = await db.membership.findFirst({
    where: {
      userId: session.user.id,
      organization: {
        slug,
      },
    },
    select: {
      role: true,
      organization: {
        select: {
          id: true,
          slug: true,
        },
      },
    },
  });

  if (!membership) {
    return new Response("Not found.", { status: 404 });
  }

  if (membership.role !== "OWNER" && membership.role !== "ADMIN") {
    return new Response("Forbidden.", { status: 403 });
  }

  const integration = await db.integration.findUnique({
    where: {
      organizationId_provider: {
        organizationId: membership.organization.id,
        provider: "MICROSOFT_365",
      },
    },
    select: {
      id: true,
      externalTenantId: true,
      status: true,
      mode: true,
    },
  });

  if (
    !integration ||
    integration.status !== "CONNECTED" ||
    integration.mode !== "LIVE" ||
    !integration.externalTenantId
  ) {
    return new Response("Microsoft 365 must be connected first.", {
      status: 409,
    });
  }

  const clientId = process.env.M365_REMEDIATION_CLIENT_ID;
  const redirectUri = process.env.M365_REMEDIATION_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return new Response("Microsoft 365 remediation is not configured.", {
      status: 503,
    });
  }

  const state = randomBytes(32).toString("base64url");
  const nonceHash = hashState(state);
  const expiresAt = new Date(Date.now() + CONSENT_TTL_MS);

  await db.$transaction([
    db.integrationConsentState.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    }),
    db.integrationConsentState.create({
      data: {
        organizationId: membership.organization.id,
        userId: session.user.id,
        provider: "MICROSOFT_365",
        purpose: "REMEDIATION",
        nonceHash,
        expiresAt,
      },
    }),
    db.integration.update({
      where: {
        id: integration.id,
      },
      data: {
        remediationStatus: "UNKNOWN",
        remediationCheckedAt: null,
      },
    }),
    db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.remediation_consent_started",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          provider: "MICROSOFT_365",
          tenantId: integration.externalTenantId,
        },
      },
    }),
  ]);

  const consentUrl = new URL(
    `https://login.microsoftonline.com/${integration.externalTenantId}/v2.0/adminconsent`,
  );

  consentUrl.searchParams.set("client_id", clientId);
  consentUrl.searchParams.set(
    "scope",
    "https://graph.microsoft.com/.default",
  );
  consentUrl.searchParams.set("redirect_uri", redirectUri);
  consentUrl.searchParams.set("state", state);

  return NextResponse.redirect(consentUrl);
}
