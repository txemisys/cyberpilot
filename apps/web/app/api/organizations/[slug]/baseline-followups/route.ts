import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  BaselineFollowUpService, BaselineFollowUpConflict,
} from "../../../../../lib/baseline-followup-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 8192;
function failure(code: string, status: number) {
  return NextResponse.json({
    code,
    customerSecurityCertified: false,
    v1CyberScoreChanged: false,
    externalAccountWrites: 0,
  }, { status, headers });
}
export async function POST(request: NextRequest,
  context: Context) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return failure("JSON_ONLY", 415);
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return failure("CROSS_ORIGIN_REQUEST_DENIED", 403);
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) ||
      Number(declared) > MAX_BYTES))
    return failure("REQUEST_EXCEEDS_LIMIT", 413);
  try {
    const { session, membership } =
      await requireOrganizationAccess((await context.params).slug);
    const content = await request.text();
    if (Buffer.byteLength(content) > MAX_BYTES)
      return failure("REQUEST_EXCEEDS_LIMIT", 413);
    let command: unknown;
    try { command = JSON.parse(content); }
    catch { return failure("JSON_MALFORMED", 400); }
    const data = await new BaselineFollowUpService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, command);
    if (data.externalActionsExecuted !== 0 ||
        data.independentRemediationVerified ||
        data.customerSecurityCertified ||
        data.legacyCyberScoreChanged)
      return failure("FALSE_SECURITY_PROOF", 500);
    return NextResponse.json(data, { headers });
  } catch (cause) {
    if (cause instanceof BaselineFollowUpConflict)
      return failure("REVISION_CONFLICT", 409);
    if (cause instanceof Error &&
        cause.message.startsWith("Baseline follow-up:"))
      return failure("FOLLOWUP_COMMAND_REJECTED", 400);
    return failure("FOLLOWUP_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return failure("USE_AUTHENTICATED_POST", 405);
}
export async function DELETE() {
  return failure("DELETE_NOT_SUPPORTED", 405);
}
