import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  BaselineTechnicalReviewService, ReviewConflictError,
} from "../../../../../lib/baseline-technical-review-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BODY = 40 * 1024;
function rejected(code: string, status: number) {
  return NextResponse.json({
    code, externalLegalApproval: false,
    customerSecurityCertified: false,
    independentRemediationVerified: false,
    existingCyberScoreMutated: false,
  }, { status, headers });
}
export async function POST(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return rejected("CROSS_ORIGIN_DENIED", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return rejected("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) ||
      Number(length) > MAX_BODY))
    return rejected("BODY_TOO_LARGE", 413);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    const text = await request.text();
    if (Buffer.byteLength(text) > MAX_BODY)
      return rejected("BODY_TOO_LARGE", 413);
    let command: unknown;
    try { command = JSON.parse(text); }
    catch { return rejected("INVALID_JSON", 400); }
    const result = await new BaselineTechnicalReviewService().execute({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, command);
    if (result.legalAcceptanceRecorded ||
        result.independentEvidenceVerified ||
        result.remediationExecuted ||
        result.legacyCyberScoreModified)
      return rejected("UNSUPPORTED_SECURITY_CLAIM", 500);
    return NextResponse.json(result, { headers });
  } catch (error) {
    if (error instanceof ReviewConflictError)
      return rejected("REVIEW_REVISION_CONFLICT", 409);
    if (error instanceof Error &&
        error.message.startsWith("Baseline review:"))
      return rejected("INVALID_REVIEW_COMMAND", 400);
    return rejected("REVIEW_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return rejected("AUTHENTICATED_POST_REQUIRED", 405);
}
export async function DELETE() {
  return rejected("INTERNAL_REVIEW_AUDIT_IS_IMMUTABLE", 405);
}
