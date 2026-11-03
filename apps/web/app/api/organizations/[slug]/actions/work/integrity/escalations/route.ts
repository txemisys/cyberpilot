import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { listEscalations, previewEscalations, openEscalation, transitionEscalation, summarizeEscalations } from "../../../../../../../../lib/work-integrity-escalations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store" };
function fail(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  return NextResponse.json({ error: "Escalation operation failed." }, { status: 500, headers });
}
async function scopeFor(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return { organizationId: membership.organization.id, userId: session.user.id, role: membership.role };
}
function queryFor(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid pagination.");
      raw[key] = Number(value);
    } else raw[key] = value;
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const scope = await scopeFor((await params).slug);
    const query = queryFor(request);
    if (query.mode === "summary") {
      delete query.mode;
      if (Object.keys(query).length)
        throw new WorkInputError("INVALID", "Summary cannot be filtered.");
      return NextResponse.json(await summarizeEscalations(scope), { headers });
    }
    if (query.mode === "preview") {
      delete query.mode;
      return NextResponse.json(await previewEscalations(scope, query), { headers });
    }
    return NextResponse.json(await listEscalations(scope, query), { headers });
  } catch (error) { return fail(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const scope = await scopeFor((await params).slug);
    const input: unknown = await request.json();
    const result = await openEscalation(scope, input);
    return NextResponse.json(result, { status: result.replayed ? 200 : 201, headers });
  } catch (error) { return fail(error); }
}
export async function PATCH(request: NextRequest, { params }: Context) {
  try {
    const scope = await scopeFor((await params).slug);
    const input: unknown = await request.json();
    return NextResponse.json(await transitionEscalation(scope, input), { headers });
  } catch (error) { return fail(error); }
}
