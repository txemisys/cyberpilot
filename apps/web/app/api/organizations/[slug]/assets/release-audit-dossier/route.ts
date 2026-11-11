import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  inspectReleaseAuditDossier, auditIncidentPlaybook,
  verifyReleaseAuditDossier,
} from "../../../../../../lib/assets-release-audit-dossier";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409 }[error.code], headers });
  return NextResponse.json({
    error: "Release audit dossier could not be generated.",
  }, { status: 503, headers });
}
function checkJson(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID", "JSON content type is required.");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 8192))
    throw new WorkInputError("INVALID", "Audit request exceeds 8 KiB.");
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await context.params).slug);
    checkJson(request);
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 8192)
      throw new WorkInputError("INVALID", "Audit request exceeds 8 KiB.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch {
      throw new WorkInputError("INVALID", "Malformed release audit JSON.");
    }
    const dossier = await inspectReleaseAuditDossier({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, input);
    const verification = verifyReleaseAuditDossier(dossier);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Release audit report failed independent fingerprint checks.");
    return NextResponse.json({
      dossier, verification,
      playbook: auditIncidentPlaybook(dossier),
    }, { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
export async function GET() {
  return NextResponse.json({
    error: "POST an explicit review ID; audit history is not a public list.",
  }, { status: 405, headers });
}
