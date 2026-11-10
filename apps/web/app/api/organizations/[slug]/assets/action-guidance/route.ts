import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  inspectAssetActionGuidance, validateAdvicePresentation,
} from "../../../../../../lib/assets-action-guidance-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409,
    }[error.code], headers });
  return NextResponse.json({
    error: "Asset guidance inspection is unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "Asset guidance requires JSON.");
    const length = request.headers.get("content-length");
    if (length && (!/^[0-9]+$/.test(length) ||
        Number(length) > 65536))
      throw new WorkInputError("INVALID",
        "Asset guidance input exceeds 64 KiB.");
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > 65536)
      throw new WorkInputError("INVALID",
        "Asset guidance input exceeds 64 KiB.");
    let input: unknown;
    try { input = JSON.parse(raw); }
    catch { throw new WorkInputError("INVALID",
      "Invalid asset guidance JSON."); }
    const result = await inspectAssetActionGuidance({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, input);
    const verification = validateAdvicePresentation(result);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Generated asset advice failed internal evidence verification.");
    return NextResponse.json({
      ...result, verification,
    }, { headers });
  } catch (cause) { return failure(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "Use POST with explicit inventory, inspection and package mappings.",
  }, { status: 405, headers });
}
