import { db } from "@cyberpilot/database";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";
import { validateFirstLivePilotConfiguration } from "../../../../../../../lib/first-live-preflight";
import {
  consumePersistentRateLimit,
  rateLimitedResponse,
} from "../../../../../../../lib/rate-limit";
import {
  Microsoft365SyncInProgressError,
  syncMicrosoft365Integration,
} from "../../../../../../../lib/microsoft-365-sync";
import { reportOperationalEvent } from "../../../../../../../lib/operational-logging";

type RouteContext = {
  params: Promise<{
    slug: string;
  }>;
};

export async function POST(request: NextRequest, { params }: RouteContext) {
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url), 303);
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
    scope: "m365-sync",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 4,
    windowMs: 5 * 60 * 1000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }

  const firstLiveConfig = validateFirstLivePilotConfiguration(process.env);

  if (!firstLiveConfig.ok) {
    return new Response("First LIVE read-only configuration gate failed.", {
      status: 503,
    });
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
      mode: true,
      status: true,
    },
  });

  if (
    !integration ||
    integration.mode !== "LIVE" ||
    integration.status !== "CONNECTED"
  ) {
    return new Response("A connected LIVE Microsoft 365 tenant is required.", {
      status: 409,
    });
  }

  const latestProbe = await db.auditEvent.findFirst({
    where: {
      organizationId: membership.organization.id,
      action: "integration.microsoft_365.readonly_probe",
    },
    orderBy: {
      occurredAt: "desc",
    },
    select: {
      metadata: true,
    },
  });

  const probeResult =
    latestProbe?.metadata &&
    typeof latestProbe.metadata === "object" &&
    !Array.isArray(latestProbe.metadata)
      ? (latestProbe.metadata as Record<string, unknown>).result
      : null;

  if (probeResult !== "READY") {
    return new Response(
      "A successful read-only Microsoft access probe is required before the first LIVE sync.",
      { status: 409 },
    );
  }

  try {
    const result = await syncMicrosoft365Integration(integration.id);

    await db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.sync_completed",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          users: result.users,
          roleDefinitions: result.roleDefinitions,
          roleAssignments: result.roleAssignments,
          authenticationRegistrations: result.authenticationRegistrations,
          domains: result.domains,
          cyberScore: result.cyberScore,
          scoreCoverage: result.scoreCoverage,
        },
      },
    });

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("sync", "completed");

    return NextResponse.redirect(url, 303);
  } catch (error) {
    if (error instanceof Microsoft365SyncInProgressError) {
      return new Response("A Microsoft 365 sync is already in progress.", {
        status: 409,
      });
    }

    reportOperationalEvent({
      event: "integration.microsoft_365.sync_failed",
      organizationId: membership.organization.id,
      resourceId: integration.id,
      metadata: {
        failureCode: "SYNC_FAILED",
      },
      error,
    });

    await db.integration.update({
      where: {
        id: integration.id,
      },
      data: {
        lastErrorAt: new Date(),
        lastErrorCode: "SYNC_FAILED",
      },
    });

    await db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.sync_failed",
        resourceType: "integration",
        resourceId: integration.id,
      },
    });

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("sync", "failed");

    return NextResponse.redirect(url, 303);
  }
}
