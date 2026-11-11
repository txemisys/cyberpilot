import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  createIndependentEvidenceReview, reviseIndependentEvidenceReview,
  listIndependentEvidenceReviews, independenceReconciliationPlan,
} from "../../../../../../lib/assets-evidence-independent-review";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  return NextResponse.json({
    error: "Independent evidence review temporarily unavailable.",
  }, { status: 503, headers });
}
async function scope(context: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await context.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
async function readJson(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "JSON content type required.");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 65536))
    throw new WorkInputError("INVALID", "Evidence review exceeds 64 KiB.");
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 65536)
    throw new WorkInputError("INVALID", "Evidence review exceeds 64 KiB.");
  try { return JSON.parse(body) as unknown; }
  catch { throw new WorkInputError("INVALID", "Malformed review JSON."); }
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const params = new URL(request.url).searchParams;
    const options: Record<string, unknown> = {};
    for (const [key, value] of params.entries()) {
      if (Object.prototype.hasOwnProperty.call(options, key))
        throw new WorkInputError("INVALID", "Duplicate review query property.");
      options[key] = ["includeStale", "includeOperatorReason"].includes(key)
        ? value === "true" ? true : value === "false" ? false : value
        : value;
    }
    const report = await listIndependentEvidenceReviews(
      await scope(context), options);
    return NextResponse.json({
      report, plan: independenceReconciliationPlan(report),
    }, { headers });
  } catch (error) { return failure(error); }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await createIndependentEvidenceReview(
      await scope(context), await readJson(request)),
    { status: 201, headers });
  } catch (error) { return failure(error); }
}
export async function PATCH(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await reviseIndependentEvidenceReview(
      await scope(context), await readJson(request)), { headers });
  } catch (error) { return failure(error); }
}
export async function PUT() {
  return NextResponse.json({
    error: "Use PATCH with matching source and review revisions.",
  }, { status: 405, headers });
}
