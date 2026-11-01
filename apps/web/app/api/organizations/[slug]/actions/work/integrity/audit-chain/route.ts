import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadAuditChain, auditChainCsv } from "../../../../../../../../lib/work-integrity-audit-chain";

type Context = { params: Promise<{ slug: string }> };
const privateHeaders = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function inputFromRequest(request: NextRequest): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  const accepted = new Set(["workItemId", "limit", "includeEvents", "format"]);
  for (const key of request.nextUrl.searchParams.keys()) {
    if (!accepted.has(key) || request.nextUrl.searchParams.getAll(key).length !== 1)
      throw new WorkInputError("INVALID", "Unknown or repeated audit chain query parameter.");
    values[key] = request.nextUrl.searchParams.get(key);
  }
  return values;
}
/**
 * Review actual stored tenant-specific triage audit links. All organization
 * identity is derived from the authenticated session; the client supplies
 * only the local work item and bounded view preferences.
 */
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const values = inputFromRequest(request);
    const format = values.format ?? "json";
    if (format !== "json" && format !== "csv")
      throw new WorkInputError("INVALID", "Unsupported audit chain format.");
    delete values.format;
    const report = await loadAuditChain({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, values);
    if (format === "csv") {
      return new NextResponse(auditChainCsv(report), {
        headers: {
          ...privateHeaders,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-audit-chain.csv"',
        },
      });
    }
    return NextResponse.json(report, { headers: privateHeaders });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 :
        error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ error: error.message, code: error.code },
        { status, headers: privateHeaders });
    }
    console.error("Audit chain investigation failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({
      error: "Unable to inspect the organization's audit chain.",
    }, { status: 500, headers: privateHeaders });
  }
}
