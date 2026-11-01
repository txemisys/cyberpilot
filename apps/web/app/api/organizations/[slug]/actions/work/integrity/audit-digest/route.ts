import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditDigest, auditDigestCsv } from "../../../../../../../../lib/work-integrity-audit-digest";

import { planAuditReviewWorkload, reviewWorkloadCsv } from "../../../../../../../../lib/work-integrity-audit-digest-review";

import { analyzeAuditDigestTrends, auditTrendCsv } from "../../../../../../../../lib/work-integrity-audit-digest-trends";

import { reconcileAuditDigest, auditReconciliationCsv } from "../../../../../../../../lib/work-integrity-audit-digest-reconciliation";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const search = request.nextUrl.searchParams;
    const accepted = new Set(["from", "to", "limit", "actorUserId", "workItemId", "format"]);
    const raw: Record<string, unknown> = {};
    for (const key of search.keys()) {
      if (!accepted.has(key) || search.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Unsupported or duplicate audit digest parameter.");
      raw[key] = search.get(key);
    }
    const format = raw.format ?? "json";
    delete raw.format;
    if (format !== "json" && format !== "csv" && format !== "workload-csv" && format !== "trends-csv" && format !== "reconciliation-csv")
      throw new WorkInputError("INVALID", "Unknown audit digest format.");
    const result = await loadAuditDigest({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, raw);
    const workload = planAuditReviewWorkload(result);
    const reconciliation = reconcileAuditDigest(result);
    if (format === "reconciliation-csv") return new NextResponse(auditReconciliationCsv(reconciliation), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-reconciliation.csv"',
      },
    });
    const trends = analyzeAuditDigestTrends(result);
    if (format === "trends-csv") return new NextResponse(auditTrendCsv(trends), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-trends.csv"',
      },
    });
    if (format === "workload-csv") return new NextResponse(reviewWorkloadCsv(workload), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-followups.csv"',
      },
    });
    if (format === "csv") return new NextResponse(auditDigestCsv(result), {
      headers: {
        ...headers, "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="integrity-audit-digest.csv"',
      },
    });
    return NextResponse.json({ ...result, workload, trends, reconciliation }, { headers });
  } catch (error) {
    if (error instanceof WorkInputError)
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    console.error("Audit digest failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to read audit digest." },
      { status: 500, headers });
  }
}
