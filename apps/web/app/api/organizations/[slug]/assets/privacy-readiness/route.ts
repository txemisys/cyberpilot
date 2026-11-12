import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectAssetPrivacyReadiness } from "../../../../../../lib/assets-privacy-readiness-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { headers, status: {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409,
    }[cause.code] });
  return NextResponse.json({
    error: "Asset privacy readiness inspection is unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID",
        "Asset privacy inspection requires JSON.");
    const declared = request.headers.get("content-length");
    if (declared && (!/^[0-9]+$/.test(declared) ||
        Number(declared) > 8192))
      throw new WorkInputError("INVALID",
        "Asset privacy inspection exceeds 8 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 8192)
      throw new WorkInputError("INVALID",
        "Asset privacy inspection exceeds 8 KiB.");
    let parsed: unknown;
    try { parsed = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID",
      "Invalid privacy inspection JSON."); }
    const report = await inspectAssetPrivacyReadiness({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, parsed);
    return NextResponse.json(report, { headers });
  } catch (cause) { return fail(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "POST an explicit bounded privacy-readiness policy.",
  }, { status: 405, headers });
}
