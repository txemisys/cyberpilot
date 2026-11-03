import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { inspectReviewWorkReadiness } from "../../../../../../../../lib/work-integrity-provider-work-readiness";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const scope = {
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    };
    const query: Record<string, unknown> = {};
    for (const [key, value] of request.nextUrl.searchParams.entries()) {
      if (Object.prototype.hasOwnProperty.call(query, key))
        throw new WorkInputError("INVALID", "Duplicate query parameter.");
      if (["offset", "limit", "maxAgeMinutes"].includes(key)) {
        if (!/^(0|[1-9][0-9]*)$/.test(value) ||
            !Number.isSafeInteger(Number(value)))
          throw new WorkInputError("INVALID", "Invalid numeric parameter.");
        query[key] = Number(value);
      } else if (key === "includeInactive") {
        if (value !== "true" && value !== "false")
          throw new WorkInputError("INVALID", "Invalid inactive filter.");
        query[key] = value === "true";
      } else query[key] = value;
    }
    return NextResponse.json(
      await inspectReviewWorkReadiness(scope, query), { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({
        code: error.code, error: error.message,
      }, {
        status: {
          INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
        }[error.code], headers,
      });
    return NextResponse.json({
      error: "Remediation readiness unavailable.",
    }, { status: 500, headers });
  }
}
