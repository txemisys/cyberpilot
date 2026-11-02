import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import {
  executeIntegrityBatch, parseIntegrityBatchExecutionRequest,
} from "../../../../../../../../../lib/work-integrity-link-batch";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError) {
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  }
  console.error("Integrity batch execution failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to execute integrity batch." },
    { status: 500, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!["OWNER", "ADMIN"].includes(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization administrator required.");
    if (!/^application\/json(?:\s*;|\s*$)/i.test(
      request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 100000))
      throw new WorkInputError("INVALID", "Batch request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Batch request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const parsed = parseIntegrityBatchExecutionRequest(input);
    const result = await executeIntegrityBatch({
      organizationId: membership.organization.id,
      actorUserId: session.user.id, role: membership.role,
    }, parsed);
    return NextResponse.json({ result }, {
      status: result.failed > 0 ? 207 : 200, headers,
    });
  } catch (error) { return failure(error); }
}
