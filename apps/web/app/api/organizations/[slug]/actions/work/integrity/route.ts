import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadWorkIntegrity } from "../../../../../../../lib/work-integrity";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type RouteContext = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
export async function GET(request: NextRequest, { params }: RouteContext) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const values = Object.fromEntries(request.nextUrl.searchParams.entries());
    const report = await loadWorkIntegrity({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, values);
    return NextResponse.json(report, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 :
        error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ error: error.message, code: error.code },
        { status, headers });
    }
    console.error("Work integrity review failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to complete integrity review." },
      { status: 500, headers });
  }
}
