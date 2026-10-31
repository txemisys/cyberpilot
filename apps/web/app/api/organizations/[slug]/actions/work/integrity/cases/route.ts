import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { loadIntegrityCases } from "../../../../../../../../lib/work-integrity-cases";

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
    for (const key of ["state", "severity", "search", "limit", "cursor", "includeInfo", "includeHistorical"]) {
      if (search.getAll(key).length > 1)
        throw new WorkInputError("INVALID", `Repeated case filter: ${key}.`);
    }
    const cases = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, Object.fromEntries(search.entries()));
    return NextResponse.json(cases, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 : error.code === "MISSING" ? 404 : 400,
        headers,
      });
    }
    console.error("Integrity cases failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to load operational cases." }, {
      status: 500, headers,
    });
  }
}
