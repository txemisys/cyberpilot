import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  previewOsvQuotaRecovery, markStalledOsvQuotaUnknown,
} from "../../../../../../lib/assets-osv-quota-recovery";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code], headers });
  return NextResponse.json({
    error: "OSV recovery request is unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const raw: Record<string, number> = {};
    for (const [key, value] of request.nextUrl.searchParams) {
      if (!["minimumAgeMinutes", "maximumListed"].includes(key) ||
          raw[key] !== undefined || !/^[1-9][0-9]*$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID",
          "Invalid OSV quota recovery preview parameter.");
      raw[key] = Number(value);
    }
    const report = await previewOsvQuotaRecovery(current, raw);
    return NextResponse.json(report, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const length = request.headers.get("content-length");
    if (length && (!/^[0-9]+$/.test(length) || Number(length) > 8192))
      throw new WorkInputError("INVALID", "OSV recovery request too large.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 8192)
      throw new WorkInputError("INVALID", "OSV recovery request too large.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID", "Invalid recovery JSON."); }
    const report = await markStalledOsvQuotaUnknown(current, input);
    return NextResponse.json(report, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
