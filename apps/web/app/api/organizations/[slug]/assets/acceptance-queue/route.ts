import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  inspectAcceptanceQueue, verifyAcceptanceQueue,
  acceptanceQueueActionPlan,
} from "../../../../../../lib/assets-phase4-acceptance-queue";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[cause.code], headers });
  return NextResponse.json({
    error: "Phase 4 acceptance queue is unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "JSON content type required.");
    const declared = request.headers.get("content-length");
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > 8192))
      throw new WorkInputError("INVALID", "Queue request exceeds 8 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 8192)
      throw new WorkInputError("INVALID", "Queue request exceeds 8 KiB.");
    let options: unknown;
    try { options = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID", "Malformed queue JSON."); }
    const report = await inspectAcceptanceQueue({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, options);
    const verification = verifyAcceptanceQueue(report);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Acceptance queue report failed integrity checks.");
    return NextResponse.json({
      report, verification,
      actionPlan: acceptanceQueueActionPlan(report),
    }, { headers });
  } catch (cause) { return failure(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "Use POST with an explicit bounded inspection policy.",
  }, { status: 405, headers });
}
