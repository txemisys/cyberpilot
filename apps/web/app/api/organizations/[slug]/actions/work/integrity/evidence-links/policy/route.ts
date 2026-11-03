import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import {
  parseIntegrityReviewPolicy, evaluateIntegrityEvents,
} from "../../../../../../../../../lib/work-integrity-review-policy";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity review policy failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to evaluate integrity policy." },
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
      throw new WorkInputError("INVALID", "Policy request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Policy request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    if (!input || typeof input !== "object" || Array.isArray(input))
      throw new WorkInputError("INVALID", "Expected policy evaluation object.");
    const raw = input as Record<string, unknown>;
    if (Object.keys(raw).some(key => !["captureId", "policy"].includes(key)) ||
        typeof raw.captureId !== "string")
      throw new WorkInputError("INVALID", "Invalid policy evaluation input.");
    const policy = parseIntegrityReviewPolicy(raw.policy);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, raw.captureId);
    const evaluation = evaluateIntegrityEvents(raw.captureId, state.events, policy);
    return NextResponse.json({ evaluation }, { headers });
  } catch (error) { return failure(error); }
}
