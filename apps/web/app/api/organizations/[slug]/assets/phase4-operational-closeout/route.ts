import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  inspectOperationalCloseout, verifyOperationalCloseout,
  operationalCloseoutExport,
} from "../../../../../../lib/assets-phase4-operational-closeout";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({ code: cause.code, error: cause.message }, {
      headers, status: { INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409 }[cause.code],
    });
  return NextResponse.json({
    error: "Operational closeout evidence service unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "Expected JSON content type.");
    const size = request.headers.get("content-length");
    if (size && (!/^\d+$/.test(size) || Number(size) > 131072))
      throw new WorkInputError("INVALID", "Request exceeds 128 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 131072)
      throw new WorkInputError("INVALID", "Request exceeds 128 KiB.");
    let raw: unknown;
    try { raw = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID", "Malformed closeout JSON."); }
    const report = await inspectOperationalCloseout({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, raw);
    const verification = verifyOperationalCloseout(report);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Operational closeout integrity check failed.");
    return NextResponse.json({
      report, verification,
      export: operationalCloseoutExport(report),
    }, { headers });
  } catch (cause) {
    return failure(cause);
  }
}
export async function GET() {
  return NextResponse.json({
    error: "POST an explicitly scoped offline evidence selection.",
  }, { status: 405, headers });
}
