import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  loadCaptureReviewLineage,
} from "../../../../../../../../lib/work-integrity-capture-lineage";
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
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  console.error("Integrity lineage request failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to load integrity lineage.",
  }, { status: 500, headers });
}
function parseQuery(request: NextRequest) {
  const query: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(query, key))
      throw new WorkInputError("INVALID", "Duplicate lineage parameter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid pagination.");
      query[key] = Number(value);
    } else if (key === "includeInactive") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid includeInactive flag.");
      query[key] = value === "true";
    } else query[key] = value;
  }
  return query;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const scope = {
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    };
    return NextResponse.json(
      await loadCaptureReviewLineage(scope, parseQuery(request)),
      { headers },
    );
  } catch (error) { return fail(error); }
}
