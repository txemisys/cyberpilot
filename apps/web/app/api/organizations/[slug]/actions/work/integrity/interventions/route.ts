import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { executeIntegrityInterventions } from "../../../../../../../../lib/work-integrity-interventions";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError) {
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  }
  return NextResponse.json({ error: "Intervention operation unavailable." }, {
    status: 500, headers,
  });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const input: unknown = await request.json();
    const result = await executeIntegrityInterventions({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, input);
    return NextResponse.json(result, { headers });
  } catch (error) {
    return failure(error);
  }
}
