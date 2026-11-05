import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegrityCaptureCohorts } from "../../../../../../../../lib/work-integrity-capture-cohorts";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function parameters(request: NextRequest): Record<string, unknown> {
  const raw: Record<string, unknown> = {};
  const integers = new Set(["offset","limit","overdueHours"]);
  const booleans = new Set(["includeEmpty"]);
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (integers.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric query parameter.");
      raw[key] = Number(value);
    } else if (booleans.has(key)) {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean query parameter.");
      raw[key] = value === "true";
    } else {
      if (value.length > 200)
        throw new WorkInputError("INVALID", "Query parameter is too long.");
      raw[key] = value;
    }
  }
  return raw;
}
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code],
      headers,
    });
  return NextResponse.json({ error: "Capture cohort report unavailable." }, {
    status: 500, headers,
  });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const result = await readIntegrityCaptureCohorts({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, parameters(request));
    return NextResponse.json(result, { headers });
  } catch (error) {
    return failure(error);
  }
}
