import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import {
  parseIntegrityEvidenceCoveragePolicy,
  evaluateIntegrityEvidenceCoverageEvents,
} from "../../../../../../../../../lib/work-integrity-evidence-coverage";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity evidence coverage failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to evaluate evidence coverage." },
    { status: 500, headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    if (!/^application\/json(?:\s*;|\s*$)/i.test(
      request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 100000))
      throw new WorkInputError("INVALID", "Coverage request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Coverage request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const policy = parseIntegrityEvidenceCoveragePolicy(input);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, policy.captureId);
    const result = evaluateIntegrityEvidenceCoverageEvents(
      policy.captureId, state.events, policy);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
