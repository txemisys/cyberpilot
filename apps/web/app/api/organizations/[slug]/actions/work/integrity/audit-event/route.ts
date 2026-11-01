import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditEventDetail } from "../../../../../../../../lib/work-integrity-audit-event-detail";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const query = request.nextUrl.searchParams;
    if ([...query.keys()].some(key => key !== "eventId") ||
        query.getAll("eventId").length !== 1)
      throw new WorkInputError("INVALID", "Exactly one event identifier is required.");
    const { session, membership } = await requireOrganizationAccess(slug);
    const detail = await loadAuditEventDetail({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query.get("eventId"));
    return NextResponse.json(detail, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    console.error("Source audit event inspection failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to inspect stored audit event." },
      { status: 500, headers });
  }
}
