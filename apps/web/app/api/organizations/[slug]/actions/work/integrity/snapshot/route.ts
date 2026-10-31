import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadIntegrityCases } from "../../../../../../../../lib/work-integrity-cases";
import { casePageSnapshot } from "../../../../../../../../lib/work-integrity-live-queue";

/**
 * Download the actual authenticated case-page capture in the exact schema
 * accepted by the comparison endpoint. This endpoint never writes an audit
 * event and never claims coverage beyond the bounded work-item cursor page.
 */
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Disposition": 'attachment; filename="integrity-case-snapshot.json"',
};
const permitted = new Set([
  "limit", "cursor", "state", "severity", "search",
  "includeInfo", "includeHistorical",
]);
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const params = request.nextUrl.searchParams;
    for (const key of params.keys()) {
      if (!permitted.has(key) || params.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unknown or repeated capture filter.");
    }
    const input = Object.fromEntries(params.entries());
    const cases = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, { includeInfo: "true", includeHistorical: "true", ...input });
    const snapshot = casePageSnapshot(membership.organization.id, cases);
    return NextResponse.json(snapshot, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ error: error.message, code: error.code },
        { status, headers: {
          "Cache-Control": "private, no-store",
          "X-Content-Type-Options": "nosniff",
        } });
    }
    console.error("Integrity case capture failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to capture operational cases." },
      { status: 500, headers: {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      } });
  }
}
