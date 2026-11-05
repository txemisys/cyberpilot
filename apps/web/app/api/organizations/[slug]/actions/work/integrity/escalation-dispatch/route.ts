import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { dispatchCaptureEscalations } from "../../../../../../../../lib/work-integrity-escalation-dispatch";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store" };
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const input: unknown = await request.json();
    const result = await dispatchCaptureEscalations({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, input);
    return NextResponse.json(result, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ code: error.code, error: error.message }, {
        status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
        headers,
      });
    return NextResponse.json({ error: "Escalation dispatch failed." }, { status: 500, headers });
  }
}
