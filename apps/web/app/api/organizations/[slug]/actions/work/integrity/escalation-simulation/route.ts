import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { readIntegrityEscalationSimulation } from "../../../../../../../../lib/work-integrity-escalation-simulation";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409,
      }[error.code],
      headers,
    });
  return NextResponse.json({
    error: "Operational investigation failed.",
  }, { status: 500, headers });
}
function parseQuery(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const integerFields = new Set([
    "offset", "limit", "horizonHours",
    "warningHours", "errorHours", "infoHours",
    "repeatHours", "maxLevel", "minAgeHours", "maxAgeDays",
  ]);
  const booleanFields = new Set([
    "includeClosed", "includeRead", "includeDismissed",
  ]);
  const policy: Record<string, number> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key) ||
        Object.prototype.hasOwnProperty.call(policy, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (integerFields.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric filter.");
      if (["warningHours", "errorHours", "infoHours",
        "repeatHours", "maxLevel"].includes(key))
        policy[key] = Number(value);
      else raw[key] = Number(value);
    } else if (booleanFields.has(key)) {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean filter.");
      raw[key] = value === "true";
    } else raw[key] = value;
  }
  if (Object.keys(policy).length) raw.policy = policy;
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const result = await readIntegrityEscalationSimulation({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, parseQuery(request));
    return NextResponse.json(result, { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
