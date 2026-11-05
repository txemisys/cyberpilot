import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegritySlaReport } from "../../../../../../../../lib/work-integrity-sla-report";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409,
      }[error.code],
      headers,
    });
  return NextResponse.json({
    error: "Operational integrity report failed.",
  }, { status: 500, headers });
}
function parseQuery(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const integerFields = new Set([
    "offset", "limit", "responseMinutes",
    "resolutionMinutes", "notificationReadMinutes",
    "escalationAckMinutes",
  ]);
  const booleanFields = new Set(["includeClosed", "includeResolved"]);
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (integerFields.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric filter.");
      raw[key] = Number(value);
    } else if (booleanFields.has(key)) {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean filter.");
      raw[key] = value === "true";
    } else raw[key] = value;
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const result = await readIntegritySlaReport({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, parseQuery(request));
    return NextResponse.json(result, { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
