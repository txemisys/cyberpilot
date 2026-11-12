import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  inspectPhase4Handoff, verifyPhase4Handoff,
  phase4HandoffChecklist, phase4HandoffManifest,
} from "../../../../../../lib/assets-phase4-handoff-package";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[cause.code], headers });
  return NextResponse.json({
    error: "Phase 4 evidence handoff unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "Expected JSON content type.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 131072))
      throw new WorkInputError("INVALID", "Handoff request exceeds 128 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 131072)
      throw new WorkInputError("INVALID", "Handoff request exceeds 128 KiB.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID", "Malformed JSON."); }
    const report = await inspectPhase4Handoff({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, input);
    const verification = verifyPhase4Handoff(report);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Handoff package failed independent digest validation.");
    return NextResponse.json({
      report, verification,
      manifest: phase4HandoffManifest(report),
      checklist: phase4HandoffChecklist(report),
    }, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
export async function GET() {
  return NextResponse.json({
    error: "POST a scoped handoff package selection.",
  }, { status: 405, headers });
}
