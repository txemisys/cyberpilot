import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  listAssetAdviceCases, openAssetAdviceCase,
  changeAssetAdviceCase, changeAssetAdviceStep,
} from "../../../../../../lib/assets-action-case-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError) return NextResponse.json({
    code: cause.code, error: cause.message,
  }, { status: {
    INVALID: 400, FORBIDDEN: 403,
    MISSING: 404, CONFLICT: 409,
  }[cause.code], headers });
  return NextResponse.json({
    error: "Asset review case service unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { membership, session } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
async function body(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "Review cases require JSON.");
  const length = request.headers.get("content-length");
  if (length && (!/^[0-9]+$/.test(length) ||
      Number(length) > 65536))
    throw new WorkInputError("INVALID",
      "Review case request exceeds 64 KiB.");
  const source = await request.text();
  if (Buffer.byteLength(source, "utf8") > 65536)
    throw new WorkInputError("INVALID",
      "Review case request exceeds 64 KiB.");
  try { return JSON.parse(source) as unknown; }
  catch { throw new WorkInputError("INVALID",
    "Invalid review case JSON."); }
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const owner = await scope((await params).slug);
    const query: Record<string, unknown> = {};
    for (const [key, value] of request.nextUrl.searchParams) {
      if (!["offset", "limit", "status",
        "importId", "inspectionId"].includes(key) ||
        query[key] !== undefined || value.length > 150)
        throw new WorkInputError("INVALID", "Invalid review case filter.");
      if (key === "offset" || key === "limit") {
        if (!/^(0|[1-9][0-9]*)$/.test(value) ||
            !Number.isSafeInteger(Number(value)))
          throw new WorkInputError("INVALID",
            "Invalid review case pagination.");
        query[key] = Number(value);
      } else query[key] = value;
    }
    return NextResponse.json(await listAssetAdviceCases(
      owner, query), { headers });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const owner = await scope((await params).slug);
    return NextResponse.json(await openAssetAdviceCase(
      owner, await body(request)), { headers, status: 201 });
  } catch (cause) { return failure(cause); }
}
export async function PATCH(request: NextRequest, { params }: Context) {
  try {
    const owner = await scope((await params).slug);
    return NextResponse.json(await changeAssetAdviceCase(
      owner, await body(request)), { headers });
  } catch (cause) { return failure(cause); }
}
export async function PUT(request: NextRequest, { params }: Context) {
  try {
    const owner = await scope((await params).slug);
    return NextResponse.json(await changeAssetAdviceStep(
      owner, await body(request)), { headers });
  } catch (cause) { return failure(cause); }
}
