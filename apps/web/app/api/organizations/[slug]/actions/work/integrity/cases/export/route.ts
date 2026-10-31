import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { loadIntegrityCases } from "../../../../../../../../../lib/work-integrity-cases";
import { serializeCaseCsv, serializeCaseJson } from "../../../../../../../../../lib/work-integrity-case-export";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; sandbox",
};
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const query = Object.fromEntries(request.nextUrl.searchParams.entries());
    const format = query.format ?? "csv";
    if (format !== "csv" && format !== "json")
      throw new WorkInputError("INVALID", "Format must be csv or json.");
    for (const key of request.nextUrl.searchParams.keys())
      if (!["state", "severity", "search", "limit", "cursor",
        "includeInfo", "includeHistorical", "format"].includes(key) ||
        request.nextUrl.searchParams.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unsupported or repeated case export filter.");
    const result = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query);
    const isCsv = format === "csv";
    return new NextResponse(isCsv ? serializeCaseCsv(result) : serializeCaseJson(result), {
      headers: {
        ...headers,
        "Content-Type": isCsv ? "text/csv; charset=utf-8" : "application/json; charset=utf-8",
        "Content-Disposition": isCsv
          ? 'attachment; filename="cyberpilot-integrity-cases.csv"'
          : 'attachment; filename="cyberpilot-integrity-cases.json"',
      },
    });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 : 400, headers,
      });
    console.error("Integrity case export error", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Case export failed." }, { status: 500, headers });
  }
}
