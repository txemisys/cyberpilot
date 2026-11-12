import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectOfficialOsvQuota } from "../../../../../../lib/assets-osv-atomic-quota";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code], headers });
  return NextResponse.json({
    error: "OSV quota inspection is unavailable.",
  }, { status: 503, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const values = [...request.nextUrl.searchParams.entries()];
    if (values.some(([key]) => key !== "limit") ||
        values.filter(([key]) => key === "limit").length > 1)
      throw new WorkInputError("INVALID", "Unexpected quota parameters.");
    const raw = request.nextUrl.searchParams.get("limit");
    if (raw && !/^[1-9][0-9]{0,2}$/.test(raw))
      throw new WorkInputError("INVALID", "Invalid quota page limit.");
    const result = await inspectOfficialOsvQuota({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, new Date(), raw ? Number(raw) : 50);
    return NextResponse.json(result, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
