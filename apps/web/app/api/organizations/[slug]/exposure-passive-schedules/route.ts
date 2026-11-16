import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  ExposurePassiveScheduleService, PassiveScheduleConflict,
} from "../../../../../lib/exposure-passive-schedule-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function error(code: string, status: number) {
  return NextResponse.json({
    code,
    networkRequestsExecuted: 0,
    activePortScans: 0,
    independentCustomerApproval: false,
    securityCertificationProvided: false,
  }, { status, headers });
}
export async function POST(request: NextRequest,
  context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return error("CROSS_ORIGIN_DENIED", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return error("JSON_REQUIRED", 415);
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) ||
      Number(declared) > 8192))
    return error("REQUEST_TOO_LARGE", 413);
  try {
    const { session, membership } =
      await requireOrganizationAccess((await context.params).slug);
    const body = await request.text();
    if (Buffer.byteLength(body) > 8192)
      return error("REQUEST_TOO_LARGE", 413);
    let payload: unknown;
    try { payload = JSON.parse(body); }
    catch { return error("INVALID_JSON", 400); }
    const result = await new ExposurePassiveScheduleService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, payload);
    if (result.networkRequestsExecuted !== 0 ||
        result.activeScansPerformed !== 0 ||
        result.legalConsentProven ||
        result.historicalCyberScoreChanged)
      return error("UNSUPPORTED_SECURITY_CLAIM", 500);
    return NextResponse.json(result, { headers });
  } catch (reason) {
    if (reason instanceof PassiveScheduleConflict)
      return error("SCHEDULE_REVISION_CONFLICT", 409);
    if (reason instanceof Error &&
        reason.message.startsWith("Exposure schedule:"))
      return error("INVALID_SCHEDULE_COMMAND", 400);
    return error("SCHEDULE_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return error("USE_AUTHENTICATED_POST", 405);
}
export async function DELETE() {
  return error("USE_VERSIONED_REVOKE", 405);
}
