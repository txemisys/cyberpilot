import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  previewOsvRenewal, executeOsvRenewal,
} from "../../../../../../lib/assets-osv-renewal";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  return NextResponse.json({
    error: "OSV renewal request is currently unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await params).slug);
    const declared = request.headers.get("content-length");
    if (declared && (!/^[0-9]+$/.test(declared) || Number(declared) > 65536))
      throw new WorkInputError("INVALID", "OSV renewal request exceeds 64 KiB.");
    const source = await request.text();
    if (Buffer.byteLength(source, "utf8") > 65536)
      throw new WorkInputError("INVALID", "OSV renewal request exceeds 64 KiB.");
    let input: unknown;
    try { input = JSON.parse(source); }
    catch { throw new WorkInputError("INVALID", "OSV renewal request must be JSON."); }
    if (!input || typeof input !== "object" || Array.isArray(input))
      throw new WorkInputError("INVALID", "Expected OSV renewal object.");
    const raw = input as Record<string, unknown>;
    const scope = {
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    };
    const result = raw.dryRun === false ?
      await executeOsvRenewal(scope, raw) :
      await previewOsvRenewal(scope, raw);
    return NextResponse.json(result, {
      status: raw.dryRun === false ? 201 : 200, headers,
    });
  } catch (cause) {
    return errorResponse(cause);
  }
}
