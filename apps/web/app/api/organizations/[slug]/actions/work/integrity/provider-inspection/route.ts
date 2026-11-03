import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  inspectProviderCheck, inspectCaptureProviderChecks,
} from "../../../../../../../../lib/work-integrity-provider-inspection";
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
        throw new WorkInputError("INVALID", "Duplicate inspection parameter.");
      if (key === "offset" || key === "limit") {
        if (!/^(0|[1-9][0-9]*)$/.test(value))
          throw new WorkInputError("INVALID", "Invalid pagination.");
        query[key] = Number(value);
      } else query[key] = value;
    }
    if (query.checkId !== undefined) {
      if (Object.keys(query).some(key => key !== "checkId") ||
          typeof query.checkId !== "string")
        throw new WorkInputError("INVALID", "Invalid check inspection.");
      return NextResponse.json({
        inspection: await inspectProviderCheck(scope, query.checkId),
      }, { headers });
    }
    return NextResponse.json(
      await inspectCaptureProviderChecks(scope, query),
      { headers },
    );
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
      error: "Provider check inspection unavailable.",
    }, { status: 500, headers });
  }
}
