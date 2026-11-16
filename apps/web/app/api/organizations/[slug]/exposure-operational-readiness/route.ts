import { NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  collectExposureOperationalCloseout,
  ExposureCloseoutAccessError,
} from "../../../../../lib/exposure-operational-closeout-service";
import {
  verifyExposureOperationalCloseout,
  exportExposureOperationalCloseout,
} from "../../../../../lib/exposure-operational-closeout";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function rejected(code: string, status: number) {
  return NextResponse.json({
    code, externallyAuthorizedCollection: false,
    independentConsentCertified: false,
    providerNetworkCalls: 0,
    externalRiskImprovementProven: false,
  }, { status, headers });
}
export async function GET(request: Request, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return rejected("CROSS_ORIGIN_DENIED", 403);
  const format = new URL(request.url).searchParams.get("format");
  if (format && !["JSON","CSV","MARKDOWN"].includes(format))
    return rejected("INVALID_FORMAT", 400);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    if (!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return rejected("REVIEW_ROLE_REQUIRED", 403);
    const report = await collectExposureOperationalCloseout({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    });
    const verification = verifyExposureOperationalCloseout(
      report, membership.organization.id,
    );
    if (!verification.valid)
      return rejected("REPORT_INTEGRITY_INVALID", 500);
    if (!format) return NextResponse.json({
      report, verification,
      externallyAuthorizedCollection: false,
      independentConsentCertified: false,
      providerNetworkCalls: 0,
      writeOperations: 0,
    }, { headers });
    const artifact = exportExposureOperationalCloseout(
      report, format as "JSON" | "CSV" | "MARKDOWN",
    );
    return NextResponse.json({
      filename: artifact.filename,
      mime: artifact.mime,
      content: artifact.content,
      digest: report.digest,
      containsCredentials: false,
      legalApprovalSigned: false,
      liveNetworkAuthorized: false,
      claimsRemediation: false,
    }, { headers });
  } catch (cause) {
    if (cause instanceof ExposureCloseoutAccessError)
      return rejected("MEMBERSHIP_NOT_AUTHORIZED", 403);
    return rejected("EXPOSURE_READINESS_UNAVAILABLE", 503);
  }
}
export async function POST() {
  return rejected("READ_ONLY_OPERATION", 405);
}
export async function PATCH() {
  return rejected("READ_ONLY_OPERATION", 405);
}
export async function DELETE() {
  return rejected("READ_ONLY_OPERATION", 405);
}
