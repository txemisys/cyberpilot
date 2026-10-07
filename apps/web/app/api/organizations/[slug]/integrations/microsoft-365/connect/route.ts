import { db } from "@cyberpilot/database";
import { getMicrosoftGraphScannerConfiguration } from "@cyberpilot/integrations/microsoft-365";
import { createHash, randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";
import {
  consumePersistentRateLimit,
  rateLimitedResponse,
} from "../../../../../../../lib/rate-limit";
import {
  consumePersistentRateLimit,
  rateLimitedResponse,
} from "../../../../../../../lib/rate-limit";

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

  const rateLimit = await consumePersistentRateLimit({
    scope: "m365-scanner-consent",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 4,
    windowMs: 5 * 60 * 1000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }

  const rateLimit = await consumePersistentRateLimit({
    scope: "m365-scanner-consent",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 4,
    windowMs: 300000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }


  const clientId = process.env.M365_GRAPH_CLIENT_ID;
  const redirectUri = process.env.M365_GRAPH_REDIRECT_URI;
  const scannerConfiguration = getMicrosoftGraphScannerConfiguration();

  if (!scannerConfiguration.configured || !clientId || !redirectUri) {
    return new Response("Microsoft 365 integration is not configured.", {
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
        purpose: "SCANNER",
        nonceHash,
        expiresAt,
      },
    }),
    db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.consent_started",
        resourceType: "integration",
        metadata: {
          provider: "MICROSOFT_365",
        },
      },
    }),
  ]);

  const consentUrl = new URL(
    "https://login.microsoftonline.com/organizations/v2.0/adminconsent",
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
