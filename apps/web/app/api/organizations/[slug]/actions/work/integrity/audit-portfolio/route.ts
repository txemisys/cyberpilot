import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { auditPortfolioCsv, loadAuditPortfolio } from "../../../../../../../../lib/work-integrity-audit-portfolio";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const search = request.nextUrl.searchParams;
    const fields = new Set(["limit", "cursor", "onlyReviewed", "historyLimit", "format"]);
    const raw: Record<string, unknown> = {};
    for (const key of search.keys()) {
      if (!fields.has(key) || search.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unknown or repeated portfolio filter.");
      raw[key] = search.get(key);
    }
    const format = raw.format ?? "json";
    delete raw.format;
    if (format !== "json" && format !== "csv")
      throw new WorkInputError("INVALID", "Unsupported portfolio download format.");
    const report = await loadAuditPortfolio({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, raw);
    if (format === "csv") {
      return new NextResponse(auditPortfolioCsv(report), {
        headers: {
          ...headers, "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="audit-review-portfolio.csv"',
        },
      });
    }
    return NextResponse.json(report, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 :
          error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    console.error("Work audit portfolio request failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to inspect work audit portfolio." }, {
      status: 500, headers,
    });
  }
}
