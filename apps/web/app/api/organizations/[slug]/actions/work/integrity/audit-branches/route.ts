import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditBranches, auditBranchesCsv } from "../../../../../../../../lib/work-integrity-audit-branch-explorer";

import { planBranchActions, branchActionsCsv } from "../../../../../../../../lib/work-integrity-audit-branch-actions";

import { summarizeBranchTopology } from "../../../../../../../../lib/work-integrity-audit-branch-topology";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const input: Record<string, unknown> = {};
    for (const key of request.nextUrl.searchParams.keys()) {
      if (!["workItemId", "limit", "includeRationale", "format"].includes(key) ||
          request.nextUrl.searchParams.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unsupported or repeated audit branch option.");
      input[key] = request.nextUrl.searchParams.get(key);
    }
    const format = input.format ?? "json";
    delete input.format;
    if (format !== "json" && format !== "csv" && format !== "actions-csv")
      throw new WorkInputError("INVALID", "Invalid source audit branch format.");
    const report = await loadAuditBranches({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, input);
    const actionPlan = planBranchActions(report);
    if (format === "actions-csv") return new NextResponse(branchActionsCsv(actionPlan), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-branch-followups.csv"',
      },
    });
    if (format === "csv") return new NextResponse(auditBranchesCsv(report), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-branches.csv"',
      },
    });
    return NextResponse.json({ ...report, actionPlan, topology: summarizeBranchTopology(report) }, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    console.error("Source audit branch inspection failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to inspect source audit branches." },
      { status: 500, headers });
  }
}
