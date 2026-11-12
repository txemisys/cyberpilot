import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  GoogleOfflineWorkspace, googleOfflineWorkspaceManifest,
} from "../../../../../../lib/google-workspace-offline-workspace";
import { GoogleLabError } from
  "@cyberpilot/integrations/google-workspace";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 1048576;
function responseError(error: unknown) {
  if (error instanceof GoogleLabError) {
    const status = {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409, EXPIRED: 410,
    }[error.code];
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status, headers });
  }
  return NextResponse.json({
    code: "UNAVAILABLE",
    error: "Google Workspace offline operation unavailable.",
  }, { status: 503, headers });
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug);
    const media = request.headers.get("content-type")?.split(";")[0]
      ?.trim().toLowerCase();
    if (media !== "application/json")
      throw new GoogleLabError("INVALID",
        "Google Workspace offline API accepts JSON only.");
    const declared = request.headers.get("content-length");
    if (declared !== null &&
        (!/^\d+$/.test(declared) || Number(declared) > MAX_BYTES))
      throw new GoogleLabError("INVALID",
        "Google Workspace offline request exceeds 1 MiB.");
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_BYTES)
      throw new GoogleLabError("INVALID",
        "Google Workspace offline request exceeds 1 MiB.");
    let input: unknown;
    try { input = JSON.parse(raw); }
    catch {
      throw new GoogleLabError("INVALID",
        "Malformed Google Workspace offline JSON.");
    }
    const report = await new GoogleOfflineWorkspace().execute({
      organizationId: membership.organization.id,
      actorUserId: session.user.id,
      role: membership.role,
    }, input);
    return NextResponse.json({
      report, manifest: googleOfflineWorkspaceManifest(report),
    }, { status: 200, headers });
  } catch (error) {
    return responseError(error);
  }
}
export async function GET() {
  return NextResponse.json({
    error: "Use POST with an authenticated scoped offline operation.",
  }, { status: 405, headers });
}
export async function PUT() {
  return NextResponse.json({
    error: "Method not allowed; only scoped POST operations are supported.",
  }, { status: 405, headers });
}
export async function DELETE() {
  return NextResponse.json({
    error: "Google Workspace offline API never deletes provider accounts.",
  }, { status: 405, headers });
}
