import { db } from "@cyberpilot/database";
import {
  assertMicrosoftTenantId,
  MicrosoftGraphClient,
} from "@cyberpilot/integrations/microsoft-365";
import { createHash } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

import { auth } from "../../../../../lib/auth";

function hashState(state: string) {
  return createHash("sha256").update(state).digest("hex");
}

function dashboardError(request: NextRequest, code: string) {
  const url = new URL("/dashboard", request.url);
  url.searchParams.set("m365", "error");
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
    return dashboardError(request, "invalid_state");
  }

  const nonceHash = hashState(state);

  const consent = await db.integrationConsentState.findUnique({
    where: {
      nonceHash,
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
    consent.purpose !== "SCANNER" ||
    consent.userId !== session.user.id ||
    consent.consumedAt ||
    consent.expiresAt <= new Date()
  ) {
    return dashboardError(request, "invalid_state");
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
    return dashboardError(request, "invalid_state");
  }

  if (microsoftError || adminConsent?.toLowerCase() !== "true") {
    await db.auditEvent.create({
      data: {
        organizationId: consent.organizationId,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.consent_denied",
        resourceType: "integration",
        metadata: {
          provider: "MICROSOFT_365",
          errorCode: microsoftError ?? "consent_not_granted",
        },
      },
    });

    return dashboardError(request, "consent_denied");
  }

  if (!tenantId) {
    return dashboardError(request, "missing_tenant");
  }

  try {
    assertMicrosoftTenantId(tenantId);

    const existingTenant = await db.integration.findFirst({
      where: {
        provider: "MICROSOFT_365",
        externalTenantId: tenantId,
        NOT: {
          organizationId: consent.organizationId,
        },
      },
      select: {
        id: true,
      },
    });

    if (existingTenant) {
      return dashboardError(request, "tenant_already_connected");
    }

    const graph = new MicrosoftGraphClient(tenantId);
    const microsoftOrganization = await graph.getOrganization();

    if (microsoftOrganization.id.toLowerCase() !== tenantId.toLowerCase()) {
      return dashboardError(request, "tenant_verification_failed");
    }

    const integration = await db.integration.upsert({
      where: {
        organizationId_provider: {
          organizationId: consent.organizationId,
          provider: "MICROSOFT_365",
        },
      },
      create: {
        organizationId: consent.organizationId,
        provider: "MICROSOFT_365",
        status: "CONNECTED",
        externalTenantId: tenantId,
        displayName: microsoftOrganization.displayName ?? null,
        connectedAt: new Date(),
      },
      update: {
        status: "CONNECTED",
        externalTenantId: tenantId,
        displayName: microsoftOrganization.displayName ?? null,
        connectedAt: new Date(),
        lastErrorAt: null,
        lastErrorCode: null,
      },
    });

    await db.auditEvent.create({
      data: {
        organizationId: consent.organizationId,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.connected",
        resourceType: "integration",
        resourceId: integration.id,
        metadata: {
          tenantId,
        },
      },
    });

    const destination = new URL(
      `/organizations/${consent.organization.slug}`,
      request.url,
    );
    destination.searchParams.set("integration", "microsoft-365-connected");

    return NextResponse.redirect(destination);
  } catch {
    await db.auditEvent.create({
      data: {
        organizationId: consent.organizationId,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "integration.microsoft_365.connection_failed",
        resourceType: "integration",
        metadata: {
          provider: "MICROSOFT_365",
        },
      },
    });

    return dashboardError(request, "connection_failed");
  }
}
