import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectOfficialOsv } from "../../../../../../lib/assets-osv-official-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type RouteContext = { params: Promise<{ slug: string }> };
const responseHeaders = {
  "Cache-Control": "private, no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};
function deny(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers: responseHeaders,
    });
  return NextResponse.json({
    error: "Official OSV inspection could not be completed.",
  }, { status: 503, headers: responseHeaders });
}
export async function POST(request: NextRequest, { params }: RouteContext) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const declaredSize = request.headers.get("content-length");
    if (declaredSize &&
        (!/^[0-9]+$/.test(declaredSize) || Number(declaredSize) > 65536))
      throw new WorkInputError("INVALID", "OSV request exceeds 64 KiB.");
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > 65536)
      throw new WorkInputError("INVALID", "OSV request exceeds 64 KiB.");
    let payload: unknown;
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new WorkInputError("INVALID", "OSV request must be JSON.");
    }
    const result = await inspectOfficialOsv({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, payload);
    return NextResponse.json(result, { headers: responseHeaders });
  } catch (error) {
    return deny(error);
  }
}
