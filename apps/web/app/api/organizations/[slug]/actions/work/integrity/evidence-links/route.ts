import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import {
  linkIntegrityCaseToWork, listIntegrityWorkLinks,
} from "../../../../../../../../lib/work-integrity-evidence-links";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ error: error.message, code: error.code }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity evidence linking failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to process evidence link." }, { status: 500, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    const search = request.nextUrl.searchParams;
    if ([...search.keys()].some(key => key !== "captureId") ||
        search.getAll("captureId").length !== 1)
      throw new WorkInputError("INVALID", "Exactly one capture ID is required.");
    const links = await listIntegrityWorkLinks(
      membership.organization.id, search.get("captureId")!,
    );
    return NextResponse.json({ links }, { headers });
  } catch (error) { return failure(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!/^application\/json(?:\s*;|\s*$)/i.test(request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 10000))
      throw new WorkInputError("INVALID", "Evidence link body too large.");
    const body = await request.text();
    if (body.length > 10000) throw new WorkInputError("INVALID", "Evidence link body too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const link = await linkIntegrityCaseToWork({
      organizationId: membership.organization.id,
      actorUserId: session.user.id, role: membership.role,
    }, input);
    return NextResponse.json({ link }, { status: 201, headers });
  } catch (error) { return failure(error); }
}
