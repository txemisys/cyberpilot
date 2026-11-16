import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposurePassiveAdmissionService } from
  "../../../../../lib/exposure-passive-admission";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 64 * 1024;
function failure(code: string, status: number) {
  return NextResponse.json({
    code,
    networkRequestsPerformed: 0,
    independentLegalConsentEstablished: false,
    activeScanningStarted: false,
    customerSecurityCertified: false,
    historicalCyberScoreChanged: false,
  }, { status, headers });
}
export async function POST(request: NextRequest,
  context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return failure("CROSS_ORIGIN_REJECTED", 403);
  const type = request.headers.get("content-type")?.split(";")[0]?.trim();
  if (type !== "application/json")
    return failure("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) ||
      Number(length) > MAX_BYTES))
    return failure("REQUEST_TOO_LARGE", 413);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > MAX_BYTES)
      return failure("REQUEST_TOO_LARGE", 413);
    let command: unknown;
    try { command = JSON.parse(raw); }
    catch { return failure("INVALID_JSON", 400); }
    const outcome = await new ExposurePassiveAdmissionService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, command);
    if (outcome.noNetworkRequests !== true ||
        outcome.credentialsStored !== false ||
        outcome.legacyCyberScoreModified !== false ||
        outcome.customerCertifiedSecure !== false)
      return failure("COLLECTION_BOUNDARY_INVALID", 500);
    return NextResponse.json(outcome, { headers });
  } catch (error) {
    if (error instanceof Error &&
        error.message.startsWith("Exposure admission:"))
      return failure("PASSIVE_ADMISSION_DENIED", 400);
    return failure("PASSIVE_ADMISSION_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return failure("AUTHENTICATED_POST_REQUIRED", 405);
}
export async function PUT() {
  return failure("NETWORK_EXECUTION_UNAVAILABLE", 405);
}
export async function DELETE() {
  return failure("NO_DESTRUCTIVE_NETWORK_ACTIONS", 405);
}
