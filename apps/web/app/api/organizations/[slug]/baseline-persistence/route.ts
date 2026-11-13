import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  BaselinePersistenceService, BaselineConflictError,
} from "../../../../../lib/baseline-persistence";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_REQUEST_BYTES = 90000;
function failure(code: string, status: number) {
  return NextResponse.json({
    code,
    customerSecurityCertified: false,
    legacyCyberScoreModified: false,
    liveProviderRequests: 0,
  }, { status, headers });
}
function allowedOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  return origin === new URL(request.url).origin;
}
function lengthAllowed(request: NextRequest) {
  const reported = request.headers.get("content-length");
  return !reported || (/^\d+$/.test(reported) &&
    Number(reported) <= MAX_REQUEST_BYTES);
}
async function parseBody(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw Error("BAD_CONTENT_TYPE");
  if (!lengthAllowed(request))
    throw Error("BODY_TOO_LARGE");
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > MAX_REQUEST_BYTES)
    throw Error("BODY_TOO_LARGE");
  try { return JSON.parse(text) as unknown; }
  catch { throw Error("INVALID_JSON"); }
}
export async function POST(request: NextRequest,
  context: Context) {
  if (!allowedOrigin(request)) return failure("ORIGIN_REJECTED", 403);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    const command = await parseBody(request);
    const data = await new BaselinePersistenceService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, command);
    if (data.v1CyberScoreUpdated ||
        data.externalApprovalInferred ||
        data.securityActionsExecuted !== 0 ||
        data.storedRawNotes)
      return failure("UNSAFE_REPORT_GUARANTEE", 500);
    return NextResponse.json(data, {
      status: 200, headers,
    });
  } catch (cause) {
    if (cause instanceof BaselineConflictError)
      return failure("BASELINE_REVISION_CONFLICT", 409);
    if (cause instanceof Error && (
        cause.message === "BODY_TOO_LARGE"))
      return failure("BASELINE_REQUEST_TOO_LARGE", 413);
    if (cause instanceof Error && (
        cause.message === "BAD_CONTENT_TYPE"))
      return failure("BASELINE_JSON_REQUIRED", 415);
    if (cause instanceof Error && (
        cause.message === "INVALID_JSON"))
      return failure("BASELINE_JSON_INVALID", 400);
    if (cause instanceof Error &&
        cause.message.startsWith("Baseline storage:"))
      return failure("BASELINE_COMMAND_INVALID", 400);
    return failure("BASELINE_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return failure("USE_AUTHENTICATED_POST", 405);
}
export async function PUT() {
  return failure("USE_AUTHENTICATED_POST", 405);
}
export async function DELETE() {
  return failure("NO_DESTRUCTIVE_BASELINE_ENDPOINT", 405);
}
