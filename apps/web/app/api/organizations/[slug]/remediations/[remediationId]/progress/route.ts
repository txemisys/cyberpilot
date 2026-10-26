import { db } from "@cyberpilot/database";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";
import { parseGuidedStepIndex } from "../../../../../../../lib/guided-progress";
import {
  consumePersistentRateLimit,
  rateLimitedResponse,
} from "../../../../../../../lib/rate-limit";

type RouteContext = {
  params: Promise<{ slug: string; remediationId: string }>;
};

/** Progress is an audit marker, not evidence that a security finding is resolved. */
export async function POST(request: NextRequest, { params }: RouteContext) {
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url), 303);
  }

  const { slug, remediationId } = await params;
  const membership = await db.membership.findFirst({
    where: { userId: session.user.id, organization: { slug } },
    select: { role: true, organization: { select: { id: true, slug: true } } },
  });
  if (!membership) return new Response("Not found.", { status: 404 });
  if (membership.role !== "OWNER" && membership.role !== "ADMIN") {
    return new Response("Forbidden.", { status: 403 });
  }

  const rateLimit = await consumePersistentRateLimit({
    scope: "guided-remediation-progress",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 20,
    windowMs: 60 * 1000,
  });
  if (!rateLimit.allowed) return rateLimitedResponse(rateLimit.retryAfterSeconds);

  const remediation = await db.remediation.findFirst({
    where: {
      id: remediationId,
      organizationId: membership.organization.id,
      mode: "GUIDED",
      status: "APPROVED",
      finding: { status: "OPEN" },
    },
    select: { id: true, steps: true, playbookId: true },
  });
  if (!remediation) return new Response("Guided remediation is not active.", { status: 409 });

  const steps = Array.isArray(remediation.steps)
    ? remediation.steps.filter((step): step is string => typeof step === "string")
    : [];
  const form = await request.formData();
  const stepIndex = parseGuidedStepIndex(form.get("stepIndex"), steps.length);
  if (stepIndex === null) {
    return new Response("Invalid step.", { status: 400 });
  }

  await db.$transaction(async (tx) => {
    // The database unique key makes repeated and concurrent submissions idempotent.
    const inserted = await tx.guidedRemediationStep.createMany({
      data: [{
        organizationId: membership.organization.id,
        remediationId: remediation.id,
        stepIndex,
        actorUserId: session.user.id,
      }],
      skipDuplicates: true,
    });
    if (inserted.count === 1) {
      await tx.auditEvent.create({
        data: {
          organizationId: membership.organization.id,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "remediation.guided_step_attested",
          resourceType: "remediation",
          resourceId: remediation.id,
          metadata: { playbookId: remediation.playbookId, stepIndex },
        },
      });
    }
  });

  const url = new URL(`/organizations/${membership.organization.slug}`, request.url);
  url.hash = `remediation-${remediation.id}`;
  return NextResponse.redirect(url, 303);
}
