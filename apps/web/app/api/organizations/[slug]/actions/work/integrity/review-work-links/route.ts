import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  changeReviewWorkAssociation,
  inspectReviewWorkAssociation,
  listReviewWorkAssociations,
} from "../../../../../../../../lib/work-integrity-review-work-links";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code];
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status, headers });
  }
  if (error instanceof SyntaxError)
    return NextResponse.json({
      code: "INVALID", error: "Malformed JSON.",
    }, { status: 400, headers });
  console.error("Integrity work association failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to process review work association.",
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
    if (Object.prototype.hasOwnProperty.call(query, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
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
    const scope = await scopeFor(slug);
    const query = parseQuery(request);
    if (query.inspectId !== undefined) {
      if (Object.keys(query).some(key => key !== "inspectId"))
        throw new WorkInputError("INVALID", "Invalid inspection query.");
      if (typeof query.inspectId !== "string")
        throw new WorkInputError("INVALID", "Association ID required.");
      return NextResponse.json({
        inspection: await inspectReviewWorkAssociation(scope, query.inspectId),
      }, { headers });
    }
    return NextResponse.json(await listReviewWorkAssociations(scope, query),
      { headers });
  } catch (error) { return fail(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const input: unknown = await request.json();
    const result = await changeReviewWorkAssociation(scope, input);
    return NextResponse.json(result, {
      status: result.action === "LINK" ? 201 : 200,
      headers,
    });
  } catch (error) { return fail(error); }
}
