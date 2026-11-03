import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegrityOperationsMetrics } from "../../../../../../../../lib/work-integrity-operations-metrics";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const raw: Record<string, unknown> = {};
    for (const [key, value] of request.nextUrl.searchParams.entries()) {
      if (key in raw) throw new WorkInputError("INVALID", "Duplicate metrics filter.");
      if (key === "limit") {
        if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value)))
          throw new WorkInputError("INVALID", "Invalid limit.");
        raw[key] = Number(value);
      } else raw[key] = value;
    }
    const { session, membership } = await requireOrganizationAccess((await params).slug);
    return NextResponse.json(await readIntegrityOperationsMetrics({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, raw), { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ code: error.code, error: error.message }, {
        status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
        headers,
      });
    return NextResponse.json({ error: "Operations metrics unavailable." }, { status: 500, headers });
  }
}
