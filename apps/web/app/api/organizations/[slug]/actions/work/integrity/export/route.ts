import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { loadWorkIntegrity } from "../../../../../../../../lib/work-integrity";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import {
  buildIntegrityTriage,
  selectIntegrityRows,
  summarizeIntegrityReview,
  workIntegrityCsv,
  workIntegrityJson,
} from "../../../../../../../../lib/work-integrity-export";

type Context = { params: Promise<{ slug: string }> };
const common = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; sandbox",
};
function parseExportOptions(url: URL) {
  const format = url.searchParams.get("format") ?? "csv";
  if (!["csv", "json"].includes(format))
    throw new WorkInputError("INVALID", "Format must be csv or json.");
  const severity = url.searchParams.get("severity") ?? "all";
  if (!["all", "critical", "attention", "info"].includes(severity))
    throw new WorkInputError("INVALID", "Severity filter not supported.");
  const includeEmpty = url.searchParams.get("includeEmpty") ?? "false";
  if (!["true", "false"].includes(includeEmpty))
    throw new WorkInputError("INVALID", "includeEmpty must be true or false.");
  return {
    format: format as "csv" | "json",
    severity: severity as "all" | "critical" | "attention" | "info",
    includeEmpty: includeEmpty === "true",
  };
}
/**
 * Export exactly the filtered cursor page. This is intentional: it prevents
 * a request from silently becoming an unbounded, cross-tenant scan.
 */
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const options = parseExportOptions(request.nextUrl);
    const query = Object.fromEntries(request.nextUrl.searchParams.entries());
    // Export supports information filtering independently of page display.
    const report = await loadWorkIntegrity({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, {
      limit: query.limit ?? "25",
      cursor: query.cursor,
      includeInfo: query.includeInfo ?? "true",
    });
    const rows = selectIntegrityRows(report, {
      severity: options.severity,
      includeEmpty: options.includeEmpty,
      includeExplanation: true,
      codes: null,
    });
    const summaries = {
      statistics: summarizeIntegrityReview(report),
      suggestedReviewOrder: buildIntegrityTriage(rows),
    };
    if (options.format === "json") {
      return new NextResponse(JSON.stringify({
        ...JSON.parse(workIntegrityJson(report, rows)) as object,
        ...summaries,
        nextCursor: report.nextCursor,
      }, null, 2), {
        headers: {
          ...common,
          "Content-Type": "application/json; charset=utf-8",
          "Content-Disposition": 'attachment; filename="cyberpilot-work-integrity.json"',
        },
      });
    }
    return new NextResponse(workIntegrityCsv(report, rows), {
      headers: {
        ...common,
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="cyberpilot-work-integrity.csv"',
      },
    });
  } catch (error) {
    if (error instanceof WorkInputError) {
      return NextResponse.json(
        { error: error.message, code: error.code },
        { status: error.code === "FORBIDDEN" ? 403 : 400, headers: common },
      );
    }
    console.error("Integrity export failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json(
      { error: "Work integrity export failed." },
      { status: 500, headers: common },
    );
  }
}
