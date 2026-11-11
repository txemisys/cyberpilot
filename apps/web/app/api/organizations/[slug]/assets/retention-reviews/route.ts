import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  listAssetRetentionReviews, createAssetRetentionReview,
  transitionAssetRetentionReview, inspectRetentionReviewReadiness,
} from "../../../../../../lib/assets-retention-review-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({ code: cause.code, error: cause.message },
      { headers, status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[cause.code] });
  return NextResponse.json({
    error: "Administrative retention review is currently unavailable.",
  }, { status: 503, headers });
}
async function scope(context: Context) {
  const { session, membership } = await requireOrganizationAccess(
    (await context.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
async function json(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "Retention review requires JSON.");
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) ||
      Number(declared) > 131072))
    throw new WorkInputError("INVALID", "Retention request exceeds 128 KiB.");
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 131072)
    throw new WorkInputError("INVALID", "Retention request exceeds 128 KiB.");
  try { return JSON.parse(body) as unknown; }
  catch {
    throw new WorkInputError("INVALID", "Malformed retention JSON.");
  }
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const options: Record<string, unknown> = {};
    const url = new URL(request.url);
    for (const [key, value] of url.searchParams.entries()) {
      if (Object.prototype.hasOwnProperty.call(options, key))
        throw new WorkInputError("INVALID", "Duplicate retention query field.");
      options[key] = key === "offset" || key === "limit"
        ? Number(value) : value;
    }
    return NextResponse.json(await listAssetRetentionReviews(
      await scope(context), options), { headers });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await createAssetRetentionReview(
      await scope(context), await json(request)),
    { status: 201, headers });
  } catch (cause) { return failure(cause); }
}
export async function PATCH(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await transitionAssetRetentionReview(
      await scope(context), await json(request)), { headers });
  } catch (cause) { return failure(cause); }
}
export async function PUT(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await inspectRetentionReviewReadiness(
      await scope(context), await json(request)), { headers });
  } catch (cause) { return failure(cause); }
}
