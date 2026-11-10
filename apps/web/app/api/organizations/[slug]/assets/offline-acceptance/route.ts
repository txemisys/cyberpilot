import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectAssetOfflineAcceptance } from "../../../../../../lib/assets-offline-acceptance-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { headers, status: {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409,
    }[cause.code] });
  return NextResponse.json({
    error: "Offline asset acceptance assessment is unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID",
        "Offline acceptance requires application/json.");
    const length = request.headers.get("content-length");
    if (length && (!/^[0-9]+$/.test(length) ||
        Number(length) > 65536))
      throw new WorkInputError("INVALID",
        "Offline acceptance request exceeds 64 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 65536)
      throw new WorkInputError("INVALID",
        "Offline acceptance request exceeds 64 KiB.");
    let value: unknown;
    try { value = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID",
      "Malformed offline acceptance JSON."); }
    const assessment = await inspectAssetOfflineAcceptance({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, value);
    return NextResponse.json(assessment, { headers });
  } catch (cause) { return failure(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "POST an explicit inventory, inspection and mapping for offline acceptance.",
  }, { status: 405, headers });
}
