import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  ExposureAuthorizationConflict,
  ExposureAuthorizationService,
} from "../../../../../lib/exposure-authorization-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const limit = 8192;
const failure = (code: string, status: number) =>
  NextResponse.json({
    code, authorizationVerifiedExternally: false,
    networkRequestsPerformed: 0,
    activeScanningAuthorized: false,
  }, { status, headers });
export async function POST(request: NextRequest,
  context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return failure("ORIGIN_NOT_ALLOWED", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return failure("JSON_CONTENT_TYPE_REQUIRED", 415);
  const size = request.headers.get("content-length");
  if (size && (!/^\d+$/.test(size) || Number(size) > limit))
    return failure("REQUEST_TOO_LARGE", 413);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    const text = await request.text();
    if (Buffer.byteLength(text) > limit)
      return failure("REQUEST_TOO_LARGE", 413);
    let command: unknown;
    try { command = JSON.parse(text); }
    catch { return failure("INVALID_JSON", 400); }
    const result = await new ExposureAuthorizationService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, command);
    if (result.httpRequestsMade !== 0 ||
        result.dnsQueriesMade > 1 ||
        (result.operation !== "VERIFY_DNS" && result.dnsQueriesMade !== 0) ||
        result.portScansMade !== 0 ||
        result.signedCustomerApproval ||
        result.legacyCyberScoreModified)
      return failure("FALSE_EXTERNAL_PROOF_CLAIM", 500);
    return NextResponse.json(result, { headers });
  } catch (error) {
    if (error instanceof ExposureAuthorizationConflict)
      return failure("AUTHORIZATION_REVISION_CONFLICT", 409);
    if (error instanceof Error &&
        error.message.startsWith("Exposure authorization:"))
      return failure("AUTHORIZATION_COMMAND_REJECTED", 400);
    return failure("AUTHORIZATION_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return failure("USE_SCOPED_AUTHENTICATED_POST", 405);
}
export async function DELETE() {
  return failure("USE_AUDITED_REVOKE_OPERATION", 405);
}
