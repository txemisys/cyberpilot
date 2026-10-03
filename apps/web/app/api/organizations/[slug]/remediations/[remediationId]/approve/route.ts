import { db } from "@cyberpilot/database";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";

type RouteContext = {
  params: Promise<{
    slug: string;
    remediationId: string;
  }>;
};

export async function POST(request: NextRequest, { params }: RouteContext) {
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url), 303);
  }

  const { slug, remediationId } = await params;

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

  const remediation = await db.remediation.findFirst({
    where: {
      id: remediationId,
      organizationId: membership.organization.id,
      status: "PROPOSED",
      finding: {
        status: "OPEN",
      },
    },
    select: {
      id: true,
      playbookId: true,
      mode: true,
    },
  });

  if (!remediation) {
    return new Response("Remediation is no longer approvable.", {
      status: 409,
    });
  }

  const approvedAt = new Date();

  await db.$transaction([
    db.remediation.update({
      where: {
        id: remediation.id,
      },
      data: {
        status: "APPROVED",
        approvedByUserId: session.user.id,
        approvedAt,
      },
    }),
    db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "remediation.approved",
        resourceType: "remediation",
        resourceId: remediation.id,
        metadata: {
          playbookId: remediation.playbookId,
          mode: remediation.mode,
        },
      },
    }),
  ]);

  const url = new URL(
    `/organizations/${membership.organization.slug}`,
    request.url,
  );
  url.searchParams.set("remediation", "approved");

  return NextResponse.redirect(url, 303);
}
