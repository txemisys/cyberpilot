import { db } from "@cyberpilot/database";
import {
  MicrosoftRemediationClient,
  MicrosoftRemediationError,
} from "@cyberpilot/integrations/microsoft-365";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../../lib/auth";
import { syncMicrosoft365Integration } from "../../../../../../../lib/microsoft-365-sync";

type RouteContext = {
  params: Promise<{
    slug: string;
    remediationId: string;
  }>;
};

function readActionPayload(payload: unknown) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }

  const value = payload as Record<string, unknown>;

  if (
    typeof value.roleAssignmentId !== "string" ||
    typeof value.userId !== "string" ||
    typeof value.roleDefinitionId !== "string"
  ) {
    return null;
  }

  return {
    roleAssignmentId: value.roleAssignmentId,
    userId: value.userId,
    roleDefinitionId: value.roleDefinitionId,
  };
}

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
      mode: "AUTOMATED",
      status: "APPROVED",
      finding: {
        status: "OPEN",
      },
    },
    select: {
      id: true,
      actionType: true,
      actionPayload: true,
      playbookId: true,
      findingId: true,
    },
  });

  if (!remediation) {
    return new Response("Remediation is no longer executable.", {
      status: 409,
    });
  }

  if (remediation.actionType !== "M365_DELETE_DIRECTORY_ROLE_ASSIGNMENT") {
    return new Response("Unsupported remediation action.", { status: 409 });
  }

  const payload = readActionPayload(remediation.actionPayload);

  if (!payload) {
    return new Response("Remediation evidence is incomplete.", { status: 409 });
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
      remediationStatus: true,
    },
  });

  if (
    !integration ||
    integration.status !== "CONNECTED" ||
    integration.remediationStatus !== "AVAILABLE" ||
    !integration.externalTenantId
  ) {
    return new Response(
      "Microsoft 365 remediation permission is not available.",
      { status: 409 },
    );
  }

  const claimed = await db.remediation.updateMany({
    where: {
      id: remediation.id,
      status: "APPROVED",
    },
    data: {
      status: "EXECUTING",
      startedAt: new Date(),
    },
  });

  if (claimed.count !== 1) {
    return new Response("Remediation execution already changed state.", {
      status: 409,
    });
  }

  const client = new MicrosoftRemediationClient(integration.externalTenantId);

  try {
    const currentAssignment = await client.getDirectoryRoleAssignment(
      payload.roleAssignmentId,
    );

    if (currentAssignment) {
      if (
        currentAssignment.principalId !== payload.userId ||
        currentAssignment.roleDefinitionId !== payload.roleDefinitionId
      ) {
        throw new Error("REMEDIATION_EVIDENCE_MISMATCH");
      }

      await client.deleteDirectoryRoleAssignment(payload.roleAssignmentId);
    }

    const verification = await client.getDirectoryRoleAssignment(
      payload.roleAssignmentId,
    );

    if (verification) {
      throw new Error("REMEDIATION_VERIFICATION_FAILED");
    }

    const completedAt = new Date();

    await db.$transaction([
      db.remediation.update({
        where: {
          id: remediation.id,
        },
        data: {
          status: "VERIFIED",
          completedAt,
          verifiedAt: completedAt,
          executionEvidence: {
            roleAssignmentId: payload.roleAssignmentId,
            principalId: payload.userId,
            roleDefinitionId: payload.roleDefinitionId,
            verifiedAbsent: true,
          },
        },
      }),
      db.auditEvent.create({
        data: {
          organizationId: membership.organization.id,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "remediation.verified",
          resourceType: "remediation",
          resourceId: remediation.id,
          metadata: {
            playbookId: remediation.playbookId,
            actionType: remediation.actionType,
            roleAssignmentId: payload.roleAssignmentId,
          },
        },
      }),
    ]);

    try {
      await syncMicrosoft365Integration(integration.id);
    } catch {
      await db.auditEvent.create({
        data: {
          organizationId: membership.organization.id,
          actorType: "SYSTEM",
          action: "remediation.post_verification_sync_failed",
          resourceType: "remediation",
          resourceId: remediation.id,
        },
      });
    }

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("remediation", "verified");

    return NextResponse.redirect(url, 303);
  } catch (error) {
    const permissionRevoked =
      error instanceof MicrosoftRemediationError && error.status === 403;
    const failureCode =
      error instanceof Error && error.message.startsWith("REMEDIATION_")
        ? error.message
        : permissionRevoked
          ? "M365_REMEDIATION_PERMISSION_REQUIRED"
          : "M365_REMEDIATION_FAILED";

    await db.$transaction([
      ...(permissionRevoked
        ? [
            db.integration.update({
              where: {
                id: integration.id,
              },
              data: {
                remediationStatus: "PERMISSION_REQUIRED",
                remediationCheckedAt: new Date(),
              },
            }),
          ]
        : []),
      db.remediation.update({
        where: {
          id: remediation.id,
        },
        data: {
          status: "FAILED",
          failureCode,
          completedAt: new Date(),
        },
      }),
      db.auditEvent.create({
        data: {
          organizationId: membership.organization.id,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "remediation.failed",
          resourceType: "remediation",
          resourceId: remediation.id,
          metadata: {
            playbookId: remediation.playbookId,
            actionType: remediation.actionType,
            failureCode,
          },
        },
      }),
    ]);

    const url = new URL(
      `/organizations/${membership.organization.slug}`,
      request.url,
    );
    url.searchParams.set("remediation", "failed");

    return NextResponse.redirect(url, 303);
  }
}
