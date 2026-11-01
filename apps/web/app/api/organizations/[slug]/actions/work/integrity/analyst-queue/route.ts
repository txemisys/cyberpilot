import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadIntegrityCases } from "../../../../../../../../lib/work-integrity-cases";
import { buildLiveIntegrityPage, liveIntegrityCsv } from "../../../../../../../../lib/work-integrity-live-queue";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const allowed = new Set([
  "state", "severity", "search", "limit", "cursor",
  "includeInfo", "includeHistorical", "priority", "reviewed",
  "offset", "pageSize", "format",
]);
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const search = request.nextUrl.searchParams;
    for (const key of search.keys()) {
      if (!allowed.has(key) || search.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unknown or repeated analyst queue filter.");
    }
    const values = Object.fromEntries(search.entries());
    if (values.format && !["json", "csv"].includes(values.format))
      throw new WorkInputError("INVALID", "Unsupported analyst queue export format.");
    const page = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, { includeInfo: "true", includeHistorical: "true", ...values });
    let report: ReturnType<typeof buildLiveIntegrityPage>;
    try {
      report = buildLiveIntegrityPage(membership.organization.id, page, values);
    } catch (error) {
      if (error instanceof Error)
        throw new WorkInputError("INVALID", error.message);
      throw error;
    }
    if (values.format === "csv") {
      return new NextResponse(liveIntegrityCsv(report), {
        headers: {
          ...headers,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-analyst-queue.csv"',
        },
      });
    }
    return NextResponse.json(report, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ error: error.message, code: error.code },
        { status, headers });
    }
    console.error("Integrity analyst queue failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to load analyst queue." },
      { status: 500, headers });
  }
}
