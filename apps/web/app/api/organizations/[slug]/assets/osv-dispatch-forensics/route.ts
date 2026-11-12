import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  inspectOsvForensicTimeline,
} from "../../../../../../lib/assets-osv-dispatch-forensics";
import { WorkInputError, canManageWork } from "../../../../../../lib/remediation-work-input";
import { verifyOsvForensicReport } from "../../../../../../lib/assets-osv-forensic-verification";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(cause: unknown) {
  if (cause instanceof WorkInputError) return NextResponse.json({
    error: cause.message, code: cause.code,
  }, { headers, status: {
    INVALID: 400, FORBIDDEN: 403,
    MISSING: 404, CONFLICT: 409,
  }[cause.code] });
  return NextResponse.json({
    error: "OSV dispatch forensic evidence is unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { membership, session } = await requireOrganizationAccess(slug);
  if (!canManageWork(membership.role))
    throw new WorkInputError("FORBIDDEN",
      "Administrator access required for forensic export.");
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
async function body(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID",
      "OSV forensic inspection requires JSON.");
  const length = request.headers.get("content-length");
  if (length && (!/^[0-9]+$/.test(length) ||
      Number(length) > 8192))
    throw new WorkInputError("INVALID",
      "OSV forensic request exceeds 8 KiB.");
  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > 8192)
    throw new WorkInputError("INVALID",
      "OSV forensic request exceeds 8 KiB.");
  try { return JSON.parse(raw) as unknown; }
  catch { throw new WorkInputError("INVALID",
    "Invalid OSV forensic request JSON."); }
}
export async function GET(_request: NextRequest, { params }: Context) {
  try {
    const user = await scope((await params).slug);
    const report = await inspectOsvForensicTimeline(user);
    return NextResponse.json({
      ...report, verification: verifyOsvForensicReport(report),
    }, { headers });
  } catch (cause) { return fail(cause); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const user = await scope((await params).slug);
    const command = await body(request);
    const report = await inspectOsvForensicTimeline(user, command);
    return NextResponse.json({
      ...report, verification: verifyOsvForensicReport(report),
    }, { headers });
  } catch (cause) { return fail(cause); }
}
