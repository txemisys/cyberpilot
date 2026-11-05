import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { reconcileIntegrityEvents } from "../../../../../../../../lib/work-integrity-event-notifications";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(error: unknown) {
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
  if (error instanceof SyntaxError)
    return NextResponse.json({
      code: "INVALID", error: "Malformed request JSON.",
    }, { status: 400, headers });
  return NextResponse.json({
    error: "Event reconciliation failed.",
  }, { status: 500, headers });
}
async function scopeFor(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const scope = await scopeFor((await params).slug);
    const length = request.headers.get("content-length");
    if (length && Number(length) > 16384)
      throw new WorkInputError("INVALID", "Request body too large.");
    const input: unknown = await request.json();
    return NextResponse.json(
      await reconcileIntegrityEvents(scope, input), { headers },
    );
  } catch (error) {
    return fail(error);
  }
}
