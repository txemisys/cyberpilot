import { db } from "@cyberpilot/database";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";
import { syncMicrosoft365Integration } from "../../../../../../../lib/microsoft-365-sync";

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

  const integration = await db.integration.findUnique({
    where: {
      organizationId_provider: {
        organizationId: membership.organization.id,
        provider: "MICROSOFT_365",
      },
    },
    select: {
      id: true,
      status: true,
    },
  });

  if (!integration || integration.status !== "CONNECTED") {
    return new Response("Microsoft 365 is not connected.", { status: 409 });
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
        },
      },
    });

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("sync", "completed");

    return NextResponse.redirect(url, 303);
  } catch {
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
