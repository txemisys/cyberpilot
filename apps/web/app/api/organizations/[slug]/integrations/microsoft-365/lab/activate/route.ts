import { db } from "@cyberpilot/database";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../../lib/auth";
import {
  consumePersistentRateLimit,
  rateLimitedResponse,
} from "../../../../../../../../lib/rate-limit";
import { seedMicrosoft365Lab } from "../../../../../../../../lib/microsoft-365-lab";
import { syncMicrosoft365Integration } from "../../../../../../../../lib/microsoft-365-sync";

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
    scope: "m365-lab-activate",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 4,
    windowMs: 300000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }


  try {
    const integration = await seedMicrosoft365Lab(membership.organization.id);
    const result = await syncMicrosoft365Integration(integration.id);

    await db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.lab_activated",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          mode: "LAB",
          users: result.users,
          roleAssignments: result.roleAssignments,
          cyberScore: result.cyberScore,
        },
      },
    });

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("m365-lab", "ready");

    return NextResponse.redirect(url, 303);
  } catch (error) {
    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("m365-lab", "error");
    url.searchParams.set(
      "code",
      error instanceof Error && error.message.includes("live Microsoft 365")
        ? "live_tenant_connected"
        : "lab_activation_failed",
    );

    return NextResponse.redirect(url, 303);
  }
}
