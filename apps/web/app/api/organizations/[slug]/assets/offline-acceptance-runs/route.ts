import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  createOperatorAcceptanceRun, changeOperatorAcceptanceRun,
  listOperatorAcceptanceRuns, inspectOperatorRunStatus,
} from "../../../../../../lib/assets-offline-acceptance-run-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[cause.code], headers,
    });
  return NextResponse.json({
    error: "Operator acceptance workflow unavailable.",
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
async function input(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "JSON content type required.");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 131072))
    throw new WorkInputError("INVALID", "Request exceeds 128 KiB.");
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 131072)
    throw new WorkInputError("INVALID", "Request exceeds 128 KiB.");
  try { return JSON.parse(body) as unknown; }
  catch { throw new WorkInputError("INVALID", "Malformed operator JSON."); }
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const options: Record<string, unknown> = {};
    const query = new URL(request.url).searchParams;
    for (const [key, value] of query.entries()) {
      if (Object.prototype.hasOwnProperty.call(options, key))
        throw new WorkInputError("INVALID", "Duplicate query property.");
      options[key] = key === "offset" || key === "limit"
        ? Number(value) : value;
    }
    return NextResponse.json(
      await listOperatorAcceptanceRuns(await scope(context), options),
      { headers });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await createOperatorAcceptanceRun(
      await scope(context), await input(request)),
    { status: 201, headers });
  } catch (cause) { return failure(cause); }
}
export async function PATCH(request: NextRequest, context: Context) {
  try {
    return NextResponse.json(await changeOperatorAcceptanceRun(
      await scope(context), await input(request)), { headers });
  } catch (cause) { return failure(cause); }
}
export async function PUT(request: NextRequest, context: Context) {
  try {
    const params = new URL(request.url).searchParams;
    if (params.size !== 1 || !params.has("runId"))
      throw new WorkInputError("INVALID", "Exact runId is required.");
    return NextResponse.json(await inspectOperatorRunStatus(
      await scope(context), params.get("runId") ?? ""), { headers });
  } catch (cause) { return failure(cause); }
}
