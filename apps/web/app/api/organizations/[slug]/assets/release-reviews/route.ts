import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  listAssetReleaseReviews, createAssetReleaseReview,
  transitionAssetReleaseReview,
} from "../../../../../../lib/assets-release-review-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message },
      { status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers });
  return NextResponse.json({
    error: "Release review is temporarily unavailable.",
  }, { status: 503, headers });
}
async function scopeFor(context: Context) {
  const { session, membership } = await requireOrganizationAccess(
    (await context.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
async function json(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "JSON content type required.");
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > 131072))
    throw new WorkInputError("INVALID", "Release request exceeds 128 KiB.");
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 131072)
    throw new WorkInputError("INVALID", "Release request exceeds 128 KiB.");
  try { return JSON.parse(body) as unknown; }
  catch { throw new WorkInputError("INVALID", "Malformed release JSON."); }
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const scope = await scopeFor(context);
    const url = new URL(request.url);
    const options: Record<string, unknown> = {};
    for (const [key, value] of url.searchParams.entries()) {
      if (key in options)
        throw new WorkInputError("INVALID", "Duplicate query parameter.");
      options[key] = ["offset", "limit"].includes(key)
        ? Number(value) : value;
    }
    return NextResponse.json(
      await listAssetReleaseReviews(scope, options), { headers });
  } catch (error) { return failure(error); }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await createAssetReleaseReview(
      await scopeFor(context), await json(request)),
    { status: 201, headers });
  } catch (error) { return failure(error); }
}
export async function PATCH(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await transitionAssetReleaseReview(
      await scopeFor(context), await json(request)), { headers });
  } catch (error) { return failure(error); }
}
export async function PUT() {
  return NextResponse.json({
    error: "Release decisions require PATCH and a matching CAS revision.",
  }, { status: 405, headers });
}
