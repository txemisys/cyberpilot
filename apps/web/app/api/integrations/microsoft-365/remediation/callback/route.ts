import { db } from "@cyberpilot/database";
import {
  assertMicrosoftTenantId,
  MicrosoftRemediationClient,
  MicrosoftRemediationError,
} from "@cyberpilot/integrations/microsoft-365";
import { createHash } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../../lib/auth";
import { reportOperationalEvent } from "../../../../../../lib/operational-logging";

function hashState(state: string) {
  return createHash("sha256").update(state).digest("hex");
}

function remediationError(
  request: NextRequest,
  slug: string,
  code: string,
) {
  const url = new URL(`/organizations/${slug}`, request.url);
  url.searchParams.set("remediation-consent", "error");
  url.searchParams.set("code", code);
  return NextResponse.redirect(url);
}

export async function GET(request: NextRequest) {
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const microsoftError = request.nextUrl.searchParams.get("error");
  const state = request.nextUrl.searchParams.get("state");
  const tenantId = request.nextUrl.searchParams.get("tenant");
  const adminConsent = request.nextUrl.searchParams.get("admin_consent");

  if (!state) {
    return NextResponse.redirect(new URL("/dashboard?code=invalid_state", request.url));
  }

  const consent = await db.integrationConsentState.findUnique({
    where: {
      nonceHash: hashState(state),
    },
    select: {
      id: true,
      purpose: true,
      userId: true,
      organizationId: true,
      expiresAt: true,
      consumedAt: true,
      organization: {
        select: {
          slug: true,
        },
      },
    },
  });

  if (
    !consent ||
    consent.purpose !== "REMEDIATION" ||
    consent.userId !== session.user.id ||
    consent.consumedAt ||
    consent.expiresAt <= new Date()
  ) {
    return NextResponse.redirect(new URL("/dashboard?code=invalid_state", request.url));
  }

  const consumed = await db.integrationConsentState.updateMany({
    where: {
      id: consent.id,
      consumedAt: null,
      expiresAt: {
        gt: new Date(),
      },
    },
    data: {
      consumedAt: new Date(),
    },
  });

  if (consumed.count !== 1) {
    return remediationError(request, consent.organization.slug, "invalid_state");
  }

  const integration = await db.integration.findUnique({
    where: {
      organizationId_provider: {
        organizationId: consent.organizationId,
        provider: "MICROSOFT_365",
      },
    },
    select: {
      id: true,
      externalTenantId: true,
      status: true,
    },
  });

  if (
    !integration ||
    integration.status !== "CONNECTED" ||
    !integration.externalTenantId
  ) {
    return remediationError(
      request,
      consent.organization.slug,
      "scanner_not_connected",
    );
  }

  if (microsoftError || adminConsent?.toLowerCase() !== "true") {
    await db.$transaction([
      db.integration.update({
        where: {
          id: integration.id,
        },
        data: {
          remediationStatus: "PERMISSION_REQUIRED",
          remediationCheckedAt: new Date(),
        },
      }),
      db.auditEvent.create({
        data: {
          organizationId: consent.organizationId,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "integration.microsoft_365.remediation_consent_denied",
          resourceType: "integration",
          resourceId: integration.id,
          metadata: {
            errorCode: microsoftError ?? "consent_not_granted",
          },
        },
      }),
    ]);

    return remediationError(
      request,
      consent.organization.slug,
      "consent_denied",
    );
  }

  if (!tenantId) {
    return remediationError(
      request,
      consent.organization.slug,
      "missing_tenant",
    );
  }

  try {
    assertMicrosoftTenantId(tenantId);

    if (tenantId.toLowerCase() !== integration.externalTenantId.toLowerCase()) {
      await db.integration.update({
        where: {
          id: integration.id,
        },
        data: {
          remediationStatus: "ERROR",
          remediationCheckedAt: new Date(),
        },
      });

      return remediationError(
        request,
        consent.organization.slug,
        "tenant_mismatch",
      );
    }

    const remediation = new MicrosoftRemediationClient(tenantId);
    await remediation.probeDirectoryRoleManagement();

    const checkedAt = new Date();

    await db.$transaction([
      db.integration.update({
        where: {
          id: integration.id,
        },
        data: {
          remediationStatus: "AVAILABLE",
          remediationCheckedAt: checkedAt,
        },
      }),
      db.auditEvent.create({
        data: {
          organizationId: consent.organizationId,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "integration.microsoft_365.remediation_available",
          resourceType: "integration",
          resourceId: integration.id,
          metadata: {
            tenantId,
            checkedAt: checkedAt.toISOString(),
          },
        },
      }),
    ]);

    const destination = new URL(
      `/organizations/${consent.organization.slug}`,
      request.url,
    );
    destination.searchParams.set("remediation-consent", "available");

    return NextResponse.redirect(destination);
  } catch (error) {
    const status =
      error instanceof MicrosoftRemediationError && error.status === 403
        ? "PERMISSION_REQUIRED"
        : "ERROR";
    const code =
      status === "PERMISSION_REQUIRED"
        ? "permission_required"
        : "verification_failed";

    reportOperationalEvent({
      event: "integration.microsoft_365.remediation_verification_failed",
      organizationId: consent.organizationId,
      resourceId: integration.id,
      metadata: {
        failureCode: code,
        capabilityStatus: status,
      },
      error,
    });

    await db.$transaction([
      db.integration.update({
        where: {
          id: integration.id,
        },
        data: {
          remediationStatus: status,
          remediationCheckedAt: new Date(),
        },
      }),
      db.auditEvent.create({
        data: {
          organizationId: consent.organizationId,
          actorType: "USER",
          actorUserId: session.user.id,
          action: "integration.microsoft_365.remediation_verification_failed",
          resourceType: "integration",
          resourceId: integration.id,
          metadata: {
            failureCode: code,
          },
        },
      }),
    ]);

    return remediationError(request, consent.organization.slug, code);
  }
}
