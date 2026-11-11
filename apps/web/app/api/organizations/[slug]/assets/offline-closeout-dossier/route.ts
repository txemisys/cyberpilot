import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import { inspectOfflineCloseoutDossier, verifyCloseoutDossier,
  closeoutIssuePlaybook, closeoutEvidenceManifest,
} from "../../../../../../lib/assets-offline-closeout-dossier";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function responseForError(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({ code: cause.code, error: cause.message }, {
      status: { INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409 }[cause.code], headers,
    });
  return NextResponse.json({
    error: "Offline closeout evidence evaluation unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { session, membership } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      throw new WorkInputError("INVALID", "Closeout accepts JSON only.");
    const declared = request.headers.get("content-length");
    if (declared && (!/^\d+$/.test(declared) ||
        Number(declared) > 131072))
      throw new WorkInputError("INVALID", "Closeout request exceeds 128 KiB.");
    const text = await request.text();
    if (Buffer.byteLength(text, "utf8") > 131072)
      throw new WorkInputError("INVALID", "Closeout request exceeds 128 KiB.");
    let input: unknown;
    try { input = JSON.parse(text); }
    catch { throw new WorkInputError("INVALID", "Malformed closeout JSON."); }
    const dossier = await inspectOfflineCloseoutDossier({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, input);
    const verification = verifyCloseoutDossier(dossier);
    if (!verification.valid)
      throw new WorkInputError("CONFLICT",
        "The assembled evidence dossier failed independent validation.");
    return NextResponse.json({
      dossier, verification,
      manifest: closeoutEvidenceManifest(dossier),
      playbook: closeoutIssuePlaybook(dossier),
    }, { headers });
  } catch (cause) { return responseForError(cause); }
}
export async function GET() {
  return NextResponse.json({
    error: "Send a scoped evidence selection via POST.",
  }, { status: 405, headers });
}
