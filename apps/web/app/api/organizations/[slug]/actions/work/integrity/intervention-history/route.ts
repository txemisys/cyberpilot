import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readInterventionHistory } from "../../../../../../../../lib/work-integrity-intervention-history";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
};
function query(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const integerFields = new Set(["offset", "limit"]);
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate intervention history filter.");
    if (integerFields.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid integer filter.");
      raw[key] = Number(value);
    } else if (key === "includeReplays") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean filter.");
      raw[key] = value === "true";
    } else {
      if (value.length > 200)
        throw new WorkInputError("INVALID", "Filter exceeds maximum length.");
      raw[key] = value;
    }
  }
  return raw;
}
function failed(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  return NextResponse.json({ error: "Intervention history unavailable." }, {
    status: 500, headers,
  });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const result = await readInterventionHistory({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query(request));
    return NextResponse.json(result, { headers });
  } catch (error) {
    return failed(error);
  }
}
