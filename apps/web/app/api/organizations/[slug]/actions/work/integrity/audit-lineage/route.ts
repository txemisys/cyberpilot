import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditLineage, auditLineageCsv } from "../../../../../../../../lib/work-integrity-audit-lineage";

import { planLineageActions, lineageActionsCsv } from "../../../../../../../../lib/work-integrity-audit-lineage-actions";

import { summarizeAuditLineage } from "../../../../../../../../lib/work-integrity-audit-lineage-summary";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const raw: Record<string, unknown> = {};
    for (const key of request.nextUrl.searchParams.keys()) {
      if (!["eventId", "maxDepth", "includeRationale", "format"].includes(key) ||
          request.nextUrl.searchParams.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Invalid audit lineage query parameter.");
      raw[key] = request.nextUrl.searchParams.get(key);
    }
    const format = raw.format ?? "json";
    delete raw.format;
    if (format !== "json" && format !== "csv" && format !== "actions-csv")
      throw new WorkInputError("INVALID", "Unsupported audit lineage format.");
    const report = await loadAuditLineage({
      organizationId: membership.organization.id, userId: session.user.id,
      role: membership.role,
    }, raw);
    const actionPlan = planLineageActions(report);
    if (format === "actions-csv") return new NextResponse(lineageActionsCsv(actionPlan), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-lineage-actions.csv"',
      },
    });
    if (format === "csv") return new NextResponse(auditLineageCsv(report), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-lineage.csv"',
      },
    });
    return NextResponse.json({ ...report, actionPlan, summary: summarizeAuditLineage(report) }, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    console.error("Audit lineage reconstruction failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to reconstruct stored audit lineage." },
      { status: 500, headers });
  }
}
