import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  createOsvSchedule, listOsvSchedules, changeOsvSchedule,
  previewDueOsvSchedule, executeDueOsvSchedule, listOsvScheduleRuns,
} from "../../../../../../lib/assets-osv-renewal-schedules";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      error: error.message, code: error.code,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  return NextResponse.json({
    error: "The OSV schedule service is unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
function filters(request: NextRequest) {
  const raw: Record<string, string> = {};
  for (const [key, value] of request.nextUrl.searchParams) {
    if (!["scheduleId", "view"].includes(key) ||
        Object.prototype.hasOwnProperty.call(raw, key) ||
        value.length > 150)
      throw new WorkInputError("INVALID",
        "Invalid or repeated schedule query parameter.");
    raw[key] = value;
  }
  return raw;
}
async function payload(request: NextRequest) {
  const length = request.headers.get("content-length");
  if (length && (!/^[0-9]+$/.test(length) || Number(length) > 65536))
    throw new WorkInputError("INVALID",
      "OSV schedule request exceeds 64 KiB.");
  const source = await request.text();
  if (Buffer.byteLength(source, "utf8") > 65536)
    throw new WorkInputError("INVALID",
      "OSV schedule request exceeds 64 KiB.");
  try { return JSON.parse(source) as unknown; }
  catch { throw new WorkInputError("INVALID", "OSV schedule request requires JSON."); }
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const query = filters(request);
    const view = query.view ?? "list";
    if (view === "list") {
      if (query.scheduleId)
        throw new WorkInputError("INVALID", "Schedule ID does not apply to list.");
      return NextResponse.json(await listOsvSchedules(current), { headers });
    }
    if (!query.scheduleId)
      throw new WorkInputError("INVALID", "A schedule ID is required.");
    if (view === "preview")
      return NextResponse.json(await previewDueOsvSchedule(current, {
        scheduleId: query.scheduleId,
      }), { headers });
    if (view === "history")
      return NextResponse.json(await listOsvScheduleRuns(
        current, query.scheduleId), { headers });
    throw new WorkInputError("INVALID", "Unknown schedule view.");
  } catch (cause) {
    return failure(cause);
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const raw = await payload(request);
    return NextResponse.json(
      await createOsvSchedule(current, raw),
      { status: 201, headers },
    );
  } catch (cause) {
    return failure(cause);
  }
}
export async function PATCH(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const raw = await payload(request);
    return NextResponse.json(
      await changeOsvSchedule(current, raw),
      { headers },
    );
  } catch (cause) {
    return failure(cause);
  }
}
export async function PUT(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const raw = await payload(request);
    return NextResponse.json(
      await executeDueOsvSchedule(current, raw),
      { headers },
    );
  } catch (cause) {
    return failure(cause);
  }
}
