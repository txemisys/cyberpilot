import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import { inspectIntegrityLineage } from "../../../../../../../../../lib/work-integrity-evidence-lineage";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity lineage inspection failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to inspect evidence lineage." },
    { status: 500, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    const search = request.nextUrl.searchParams;
    const allowed = ["captureId", "from", "to", "origin", "depth"];
    for (const key of search.keys()) {
      if (!allowed.includes(key) || search.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Invalid lineage query parameter.");
    }
    const captureId = search.get("captureId");
    if (!captureId || !/^[a-zA-Z0-9_-]{5,100}$/.test(captureId))
      throw new WorkInputError("INVALID", "Invalid capture ID.");
    const from = search.get("from") ?? undefined;
    const to = search.get("to") ?? undefined;
    const origin = search.get("origin") ?? undefined;
    if (!!from !== !!to)
      throw new WorkInputError("INVALID", "Both path endpoints are required.");
    const rawDepth = search.get("depth");
    if (rawDepth !== null && (!origin || !/^(0|[1-9][0-9]*)$/.test(rawDepth)))
      throw new WorkInputError("INVALID", "Invalid neighborhood depth.");
    const depth = rawDepth === null ? undefined : Number(rawDepth);
    if (depth !== undefined && (!Number.isSafeInteger(depth) || depth > 20))
      throw new WorkInputError("INVALID", "Neighborhood depth out of range.");
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, captureId);
    const result = inspectIntegrityLineage(captureId, state.events, {
      from, to, origin, depth,
    });
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
