import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  listDispatchAlerts, scanDispatchAlerts, transitionDispatchAlert,
} from "../../../../../../lib/assets-osv-dispatch-alerts";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const responseHeaders = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, {
      status: { INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409 }[cause.code],
      headers: responseHeaders,
    });
  return NextResponse.json({
    error: "OSV dispatch incident workflow unavailable.",
  }, { status: 503, headers: responseHeaders });
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    userId: session.user.id, role: membership.role,
    organizationId: membership.organization.id,
  };
}
async function parseBody(request: NextRequest, maximum = 8192) {
  const length = request.headers.get("content-length");
  if (length && (!/^[0-9]+$/.test(length) ||
      Number(length) > maximum))
    throw new WorkInputError("INVALID", "Incident request exceeds size limit.");
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "Incident request must be JSON.");
  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > maximum)
    throw new WorkInputError("INVALID", "Incident request exceeds size limit.");
  try { return JSON.parse(raw) as unknown; }
  catch { throw new WorkInputError("INVALID", "Invalid incident JSON."); }
}
function params(request: NextRequest) {
  const values: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams) {
    if (!["offset", "limit", "state", "severity"].includes(key) ||
        values[key] !== undefined ||
        value.length > 32)
      throw new WorkInputError("INVALID", "Invalid incident filter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric incident filter.");
      values[key] = Number(value);
    } else values[key] = value;
  }
  return values;
}
export async function GET(request: NextRequest, { params: context }: Context) {
  try {
    const current = await scope((await context).slug);
    return NextResponse.json(await listDispatchAlerts(
      current, params(request)), { headers: responseHeaders });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, { params: context }: Context) {
  try {
    const current = await scope((await context).slug);
    const policy = await parseBody(request);
    return NextResponse.json(await scanDispatchAlerts(
      current, policy), { headers: responseHeaders });
  } catch (cause) { return failure(cause); }
}
export async function PATCH(request: NextRequest, { params: context }: Context) {
  try {
    const current = await scope((await context).slug);
    const command = await parseBody(request);
    return NextResponse.json(await transitionDispatchAlert(
      current, command), { headers: responseHeaders });
  } catch (cause) { return failure(cause); }
}
