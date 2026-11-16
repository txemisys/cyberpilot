import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  ConsentReviewError, ExposureIndependentConsentService,
} from "../../../../../lib/exposure-independent-consent-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const limit = 24 * 1024;
function rejected(code: string, status: number) {
  return NextResponse.json({
    code, detachedCustomerApprovalSigned: false,
    legalConsentEstablished: false, networkRequestsStarted: 0,
    securityScoreMutated: false, executableLeaseIssued: false,
  }, { status, headers });
}
export async function POST(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return rejected("ORIGIN_REJECTED", 403);
  const type = request.headers.get("content-type")?.split(";")[0]?.trim();
  if (type !== "application/json")
    return rejected("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > limit))
    return rejected("BODY_TOO_LARGE", 413);
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug,
    );
    const raw = await request.text();
    if (Buffer.byteLength(raw) > limit)
      return rejected("BODY_TOO_LARGE", 413);
    let command: unknown;
    try { command = JSON.parse(raw); }
    catch { return rejected("JSON_INVALID", 400); }
    const result = await new ExposureIndependentConsentService()
      .execute({
        organizationId: membership.organization.id,
        userId: session.user.id, role: membership.role,
      }, command);
    if (result.executableLeaseIssued ||
        result.networkCollectionStarted ||
        result.legalCustomerApprovalSignedByCyberPilot ||
        result.scoreMutated)
      return rejected("UNSUPPORTED_LEGAL_OR_SECURITY_CLAIM", 500);
    return NextResponse.json(result, { headers });
  } catch (err) {
    if (err instanceof ConsentReviewError)
      return rejected("CONSENT_COMMAND_DENIED", 400);
    return rejected("CONSENT_SERVICE_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return rejected("AUTHENTICATED_POST_REQUIRED", 405);
}
export async function PUT() {
  return rejected("CONSENT_ISSUER_NOT_AVAILABLE", 405);
}
export async function DELETE() {
  return rejected("SIGNED_CONSENT_CANNOT_BE_DELETED_HERE", 405);
}
