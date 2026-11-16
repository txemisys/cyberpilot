import { NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  collectBaselineDevelopmentDossier,
  BaselineDossierAccessError,
} from "../../../../../lib/baseline-development-dossier-service";
import {
  exportBaselineDevelopmentDossier,
  verifyBaselineDevelopmentDossier,
} from "../../../../../lib/baseline-development-dossier";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function error(code: string, status: number) {
  return NextResponse.json({
    code, organizationEvidenceDisclosed: false,
    customerApprovalRecorded: false,
    externalScanTriggered: false,
    CyberScoreUpdated: false,
  }, { status, headers });
}
export async function GET(
  request: Request, context: Context,
) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return error("CROSS_ORIGIN_DENIED", 403);
  const format = new URL(request.url).searchParams.get("format");
  if (format && !["JSON","CSV","MARKDOWN"].includes(format))
    return error("FORMAT_NOT_SUPPORTED", 400);
  try {
    const { membership, session } =
      await requireOrganizationAccess((await context.params).slug);
    if (!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return error("REVIEWER_ROLE_REQUIRED", 403);
    const report = await collectBaselineDevelopmentDossier({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    });
    const verified = verifyBaselineDevelopmentDossier(
      report, membership.organization.id,
    );
    if (!verified.valid) return error("INTEGRITY_FAILURE", 500);
    if (!format) return NextResponse.json({
      report, verification: verified,
      liveProviderQueries: 0, writeOperations: 0,
      customerApprovalRecorded: false,
    }, { headers });
    const artifact = exportBaselineDevelopmentDossier(
      report, format as "JSON" | "CSV" | "MARKDOWN",
    );
    return NextResponse.json({
      filename: artifact.filename,
      mime: artifact.mime,
      text: artifact.text,
      digest: report.digest,
      containsCredentials: false,
      includesLegalSignature: false,
      customerApprovalRecorded: false,
      securityCertificationClaimed: false,
    }, { headers });
  } catch (cause) {
    if (cause instanceof BaselineDossierAccessError)
      return error("SCOPE_OR_MEMBERSHIP_DENIED", 403);
    return error("DOSSIER_READ_UNAVAILABLE", 503);
  }
}
export async function POST() {
  return error("READ_ONLY_DOSSIER", 405);
}
export async function PATCH() {
  return error("READ_ONLY_DOSSIER", 405);
}
export async function DELETE() {
  return error("READ_ONLY_DOSSIER", 405);
}
