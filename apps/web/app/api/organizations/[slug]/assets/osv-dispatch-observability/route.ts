import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectSignedDispatchOperations } from "../../../../../../lib/assets-osv-dispatch-observability";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[cause.code], headers });
  return NextResponse.json({
    error: "OSV signed dispatch telemetry is unavailable.",
  }, { status: 503, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await params).slug);
    const policy: Record<string, number> = {};
    for (const [name, value] of request.nextUrl.searchParams) {
      if (![
        "lookbackHours", "maximumRecent", "alertAfterMinutes",
        "alertFailureThreshold", "alertUnsettledThreshold",
      ].includes(name) ||
          policy[name] !== undefined ||
          !/^[1-9][0-9]*$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID",
          "Unknown, repeated or malformed OSV dispatch diagnostic parameter.");
      policy[name] = Number(value);
    }
    const report = await inspectSignedDispatchOperations({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, policy);
    return NextResponse.json(report, { headers });
  } catch (cause) {
    return fail(cause);
  }
}
