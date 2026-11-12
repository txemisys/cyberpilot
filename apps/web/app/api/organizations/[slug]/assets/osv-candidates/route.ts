import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectOsvInventoryCandidates } from "../../../../../../lib/assets-osv-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[cause.code], headers,
    });
  return NextResponse.json({
    error: "OSV asset correlation is unavailable.",
  }, { status: 500, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const size = request.headers.get("content-length");
    if (size && (!/^\d+$/.test(size) || Number(size) > 1048576))
      throw new WorkInputError("INVALID",
        "OSV correlation request is too large.");
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 1048576)
      throw new WorkInputError("INVALID",
        "OSV correlation request exceeds 1 MiB.");
    let payload: unknown;
    try {
      payload = JSON.parse(body);
    } catch {
      throw new WorkInputError("INVALID", "Invalid OSV JSON request.");
    }
    const response = await inspectOsvInventoryCandidates({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, payload);
    return NextResponse.json(response, { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
