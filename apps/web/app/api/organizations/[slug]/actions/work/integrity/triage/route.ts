import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { listIntegrityTriage, saveIntegrityTriage } from "../../../../../../../../lib/work-integrity-triage";

type Route = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function respondError(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400,
      FORBIDDEN: 403,
      MISSING: 404,
      CONFLICT: 409,
    }[error.code];
    return NextResponse.json(
      { error: error.message, code: error.code },
      { status, headers },
    );
  }
  console.error("Integrity triage operation failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json(
    { error: "Unable to process diagnostic review." },
    { status: 500, headers },
  );
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
export async function GET(request: NextRequest, { params }: Route) {
  try {
    const { slug } = await params;
    const context = await scope(slug);
    const query = Object.fromEntries(request.nextUrl.searchParams.entries());
    return NextResponse.json(await listIntegrityTriage(context, query), { headers });
  } catch (error) {
    return respondError(error);
  }
}
export async function POST(request: NextRequest, { params }: Route) {
  try {
    const { slug } = await params;
    const context = await scope(slug);
    const raw: unknown = await request.json();
    const event = await saveIntegrityTriage(context, raw);
    return NextResponse.json({ event }, { status: 201, headers });
  } catch (error) {
    if (error instanceof SyntaxError)
      return NextResponse.json({ error: "Malformed JSON." }, { status: 400, headers });
    return respondError(error);
  }
}
