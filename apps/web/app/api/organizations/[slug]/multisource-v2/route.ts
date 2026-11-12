import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { MultiSourceV2AssessmentService } from
  "../../../../../lib/multisource-v2-assessment-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_INPUT_BYTES = 8192;
function reportFailure(cause: unknown) {
  const error = cause instanceof Error ? cause.message :
    "Multi-source v2 assessment unavailable.";
  const expected = error.startsWith("Multi-source v2:");
  return NextResponse.json({
    code: expected ? "INVALID_OR_UNAVAILABLE" : "SERVICE_UNAVAILABLE",
    error: expected ? error :
      "Multi-source v2 assessment unavailable.",
    customerSecurityCertified: false,
    historicalCyberScoreModified: false,
  }, { status: expected ? 400 : 503, headers });
}
export async function POST(request: NextRequest,
  context: Context) {
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    const contentType = request.headers.get("content-type")
      ?.split(";")[0]?.trim().toLowerCase();
    if (contentType !== "application/json")
      return NextResponse.json({
        error: "JSON request required.",
      }, { status: 415, headers });
    const declared = request.headers.get("content-length");
    if (declared && (!/^\d+$/.test(declared) ||
        Number(declared) > MAX_INPUT_BYTES))
      return NextResponse.json({
        error: "Assessment request exceeds 8 KiB.",
      }, { status: 413, headers });
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_INPUT_BYTES)
      return NextResponse.json({
        error: "Assessment request exceeds 8 KiB.",
      }, { status: 413, headers });
    let command: unknown;
    try {
      command = JSON.parse(raw);
    } catch {
      return NextResponse.json({
        error: "Malformed assessment JSON.",
      }, { status: 400, headers });
    }
    const result = await new MultiSourceV2AssessmentService()
      .execute({
        organizationId: membership.organization.id,
        actorUserId: session.user.id,
        role: membership.role,
      }, command);
    if (result.liveProviderRequests !== 0 ||
        result.historicalV1ScoresModified ||
        result.customerSecurityCertified)
      throw new Error("Invalid provider or historical guarantee.");
    return NextResponse.json(result,
      { status: 200, headers });
  } catch (cause) {
    return reportFailure(cause);
  }
}
export async function GET() {
  return NextResponse.json({
    error: "Use authenticated POST for scoped v2 operations.",
  }, { status: 405, headers });
}
export async function DELETE() {
  return NextResponse.json({
    error: "V2 preview API does not perform destructive operations.",
  }, { status: 405, headers });
}
export async function PUT() {
  return NextResponse.json({
    error: "Use authenticated POST for scoped v2 operations.",
  }, { status: 405, headers });
}
