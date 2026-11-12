import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  inspectAcceptanceAuditReconciliation,
  verifyAuditReconciliation,
  auditReconciliationManifest,
  auditReconciliationPlaybook,
} from "../../../../../../lib/assets-acceptance-audit-reconciliation";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[cause.code], headers });
  return NextResponse.json({
    error: "Acceptance audit reconstruction unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "JSON content type required.");
    const declared = request.headers.get("content-length");
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > 8192))
      throw new WorkInputError("INVALID", "Audit query exceeds 8 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 8192)
      throw new WorkInputError("INVALID", "Audit query exceeds 8 KiB.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch { throw new WorkInputError("INVALID", "Malformed JSON."); }
    const report = await inspectAcceptanceAuditReconciliation({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, input);
    const verification = verifyAuditReconciliation(report);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "Audit reconciliation report failed validation.");
    return NextResponse.json({
      report, verification,
      manifest: auditReconciliationManifest(report),
      playbook: auditReconciliationPlaybook(report),
    }, { headers });
  } catch (cause) { return failure(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "Use POST with exact scoped run ID.",
  }, { status: 405, headers });
}
