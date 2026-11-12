import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  inspectOsvWorkerReadiness, hypotheticalWorkerIdentity,
} from "../../../../../../lib/assets-osv-worker-readiness";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code], headers });
  return NextResponse.json({
    error: "OSV worker readiness service unavailable.",
  }, { status: 503, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await params).slug);
    const scope = {
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    };
    const raw: Record<string, unknown> = {};
    for (const [key, value] of request.nextUrl.searchParams) {
      if (raw[key] !== undefined || ![
        "maxSchedules", "lookbackHours", "staleClaimMinutes",
        "maximumPendingPerOrg", "requireNoStalledRuns",
        "requireNoUnsettledQuota",
      ].includes(key))
        throw new WorkInputError("INVALID",
          "Unknown or duplicate readiness parameter.");
      if (key === "requireNoStalledRuns" ||
          key === "requireNoUnsettledQuota") {
        if (value !== "true" && value !== "false")
          throw new WorkInputError("INVALID", "Invalid readiness boolean.");
        raw[key] = value === "true";
      } else {
        if (!/^[1-9][0-9]*$/.test(value) ||
            !Number.isSafeInteger(Number(value)))
          throw new WorkInputError("INVALID", "Invalid readiness integer.");
        raw[key] = Number(value);
      }
    }
    const result = await inspectOsvWorkerReadiness(scope, raw);
    return NextResponse.json({
      ...result,
      proposedWorkerContract: hypotheticalWorkerIdentity(
        scope.organizationId),
    }, { headers });
  } catch (cause) {
    return failure(cause);
  }
}
