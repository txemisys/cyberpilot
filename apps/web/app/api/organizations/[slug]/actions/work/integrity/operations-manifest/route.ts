import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegrityOperationsManifest } from "../../../../../../../../lib/work-integrity-operations-manifest";
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
    error: "Integrity operations query failed.",
  }, { status: 500, headers });
}
function queryFor(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (["offset", "limit"].includes(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid pagination integer.");
      raw[key] = Number(value);
    } else if (key.startsWith("include")) {
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
    return NextResponse.json(await readIntegrityOperationsManifest({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, queryFor(request)), { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
