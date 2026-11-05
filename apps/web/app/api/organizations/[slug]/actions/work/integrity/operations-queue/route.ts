import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegrityOperationsQueue } from "../../../../../../../../lib/work-integrity-operations-queue";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function query(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (key in raw) throw new WorkInputError("INVALID", "Duplicate queue filter.");
    if (["offset", "limit", "warningHours", "errorHours", "infoHours", "soonHours"].includes(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid queue integer.");
      raw[key] = Number(value);
    } else raw[key] = value;
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess((await params).slug);
    const result = await readIntegrityOperationsQueue({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query(request));
    return NextResponse.json(result, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ code: error.code, error: error.message }, {
        status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
        headers,
      });
    return NextResponse.json({ error: "Operations queue unavailable." }, { status: 500, headers });
  }
}
