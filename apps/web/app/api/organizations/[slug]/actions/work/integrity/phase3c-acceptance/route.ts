import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readPhase3CAcceptance } from "../../../../../../../../lib/work-integrity-phase3c-acceptance";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function parameters(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const ints = new Set([
    "offset", "limit", "minimumProviderAgeHours", "maxNotificationAgeHours",
  ]);
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate acceptance filter.");
    if (ints.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric acceptance filter.");
      raw[key] = Number(value);
    } else if (key === "includeClosed") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean acceptance filter.");
      raw[key] = value === "true";
    } else {
      if (value.length > 200)
        throw new WorkInputError("INVALID", "Acceptance parameter too long.");
      raw[key] = value;
    }
  }
  return raw;
}
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code],
      headers,
    });
  return NextResponse.json({ error: "Phase 3C acceptance unavailable." }, {
    status: 500, headers,
  });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const report = await readPhase3CAcceptance({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, parameters(request));
    return NextResponse.json(report, { headers });
  } catch (error) {
    return failure(error);
  }
}
