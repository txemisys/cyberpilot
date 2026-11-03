import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  registerPersistentReviewBatch,
  loadPersistentReviewDashboard,
} from "../../../../../../../../lib/work-integrity-persistent-review-operations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      error: error.message, code: error.code,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  if (error instanceof SyntaxError)
    return NextResponse.json({
      error: "Malformed JSON.", code: "INVALID",
    }, { status: 400, headers });
  console.error("Persistent review operations failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to process review operations.",
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
function parseQuery(request: NextRequest) {
  const query: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (key in query)
      throw new WorkInputError("INVALID", "Duplicate query field.");
    if (key === "includeOwners" || key === "includeOverdue") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid dashboard boolean.");
      query[key] = value === "true";
    } else if (key === "maximumOwners" || key === "overdueAfterHours") {
      if (!/^(0|[1-9][0-9]*)$/.test(value))
        throw new WorkInputError("INVALID", "Invalid dashboard integer.");
      query[key] = Number(value);
    } else {
      query[key] = value;
    }
  }
  return query;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    return NextResponse.json(
      await loadPersistentReviewDashboard(scope, parseQuery(request)),
      { headers },
    );
  } catch (error) { return errorResponse(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const body: unknown = await request.json();
    return NextResponse.json({
      batch: await registerPersistentReviewBatch(scope, body),
    }, { status: 201, headers });
  } catch (error) { return errorResponse(error); }
}
