import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditLedger, auditLedgerCsv } from "../../../../../../../../lib/work-integrity-audit-ledger";

import { inspectLedgerInsights, ledgerInsightsCsv } from "../../../../../../../../lib/work-integrity-ledger-insights";

import { reconstructDecisionPaths, decisionPathCsv } from "../../../../../../../../lib/work-integrity-ledger-decision-path";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const query = request.nextUrl.searchParams;
    const allowed = new Set([
      "limit", "cursor", "workItemId", "actorUserId",
      "decision", "includeMalformed", "format",
    ]);
    const input: Record<string, unknown> = {};
    for (const key of query.keys()) {
      if (!allowed.has(key) || query.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unknown or repeated ledger option.");
      input[key] = query.get(key);
    }
    const format = input.format ?? "json";
    delete input.format;
    if (format !== "json" && format !== "csv" && format !== "insights-csv" && format !== "paths-csv")
      throw new WorkInputError("INVALID", "Unsupported ledger export format.");
    const page = await loadAuditLedger({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, input);
    const insights = inspectLedgerInsights(page);
    const decisionPaths = reconstructDecisionPaths(page);
    if (format === "paths-csv") return new NextResponse(decisionPathCsv(decisionPaths), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-decision-paths.csv"',
      },
    });
    if (format === "insights-csv") return new NextResponse(ledgerInsightsCsv(insights), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-insights.csv"',
      },
    });
    if (format === "csv") return new NextResponse(auditLedgerCsv(page), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-ledger.csv"',
      },
    });
    return NextResponse.json({ ...page, insights, decisionPaths }, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) return NextResponse.json({
      error: error.message, code: error.code,
    }, {
      status: error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 :
        error.code === "CONFLICT" ? 409 : 400,
      headers,
    });
    console.error("Audit ledger query failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to read audit event ledger." },
      { status: 500, headers });
  }
}
