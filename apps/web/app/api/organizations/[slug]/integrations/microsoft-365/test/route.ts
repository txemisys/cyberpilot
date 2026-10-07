import { db } from "@cyberpilot/database";
import {
  getMicrosoftGraphScannerConfiguration,
  MicrosoftGraphClient,
} from "@cyberpilot/integrations/microsoft-365";
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
    scope: "m365-readonly-probe",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 6,
    windowMs: 5 * 60 * 1000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }

  const rateLimit = await consumePersistentRateLimit({
    scope: "m365-readonly-probe",
    organizationId: membership.organization.id,
    userId: session.user.id,
    limit: 6,
    windowMs: 300000,
  });

  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }


  const scannerConfiguration = getMicrosoftGraphScannerConfiguration();
  const redirectConfigured = Boolean(process.env.M365_GRAPH_REDIRECT_URI);

  if (!scannerConfiguration.configured || !redirectConfigured) {
    return new Response("Microsoft 365 scanner is not fully configured.", {
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
      externalTenantId: true,
    },
  });

  if (
    !integration ||
    integration.mode !== "LIVE" ||
    integration.status !== "CONNECTED" ||
    !integration.externalTenantId
  ) {
    return new Response("A connected LIVE Microsoft 365 tenant is required.", {
      status: 409,
    });
  }

  const graph = new MicrosoftGraphClient(integration.externalTenantId);
  const probe = await graph.probeReadOnlyAccess();
  const checks = Object.values(probe.checks);
  const hasPermissionRequired = checks.some(
    (check) => check.status === "PERMISSION_REQUIRED",
  );
  const hasError = checks.some((check) => check.status === "ERROR");
  const result = hasError ? "ERROR" : hasPermissionRequired ? "PARTIAL" : "READY";
  const mfaStatus = probe.checks.authenticationRegistration.status;

  await db.$transaction([
    db.integration.update({
      where: {
        id: integration.id,
      },
      data: {
        mfaEvidenceStatus:
          mfaStatus === "AVAILABLE"
            ? "AVAILABLE"
            : mfaStatus === "PERMISSION_REQUIRED"
              ? "PERMISSION_REQUIRED"
              : "ERROR",
        mfaEvidenceCheckedAt: new Date(),
        lastErrorAt: result === "READY" ? null : new Date(),
        lastErrorCode:
          result === "READY" ? null : `M365_READONLY_PROBE_${result}`,
      },
    }),
    db.auditEvent.create({
      data: {
        organizationId: membership.organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.readonly_probe",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          result,
          checks: probe.checks,
        },
      },
    }),
  ]);

  const url = new URL(
    `/organizations/${membership.organization.slug}`,
    request.url,
  );
  url.searchParams.set("m365-readonly", result.toLowerCase());

  return NextResponse.redirect(url, 303);
}
