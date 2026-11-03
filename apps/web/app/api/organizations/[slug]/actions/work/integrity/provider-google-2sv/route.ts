import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  listProviderChecks, runGoogle2SvCheck,
} from "../../../../../../../../lib/work-integrity-provider-google-2sv";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
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
  if (error instanceof SyntaxError)
    return NextResponse.json({
      code: "INVALID", error: "Malformed JSON.",
    }, { status: 400, headers });
  // Never log exception objects: OAuth secrets may be present in HTTP errors.
  console.error("Google provider verification request failed");
  return NextResponse.json({
    error: "Unable to complete provider verification.",
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
    } else query[key] = value;
  }
  return query;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    return NextResponse.json(await listProviderChecks(
      await scopeFor(slug), parseQuery(request),
    ), { headers });
  } catch (error) { return fail(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const length = Number(request.headers.get("content-length") ?? 0);
    if (length > 16000)
      throw new WorkInputError("INVALID", "Request body too large.");
    const input: unknown = await request.json();
    const result = await runGoogle2SvCheck(scope, input);
    return NextResponse.json(result, {
      status: result.replayed ? 200 : 201,
      headers,
    });
  } catch (error) { return fail(error); }
}
