import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { applyWorkBatch, previewWorkBatch } from "../../../../../../../lib/remediation-work-batch";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";
import type { WorkContext } from "../../../../../../../lib/remediation-work-store";

type Route = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function handleError(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400,
      FORBIDDEN: 403,
      MISSING: 404,
      CONFLICT: 409,
    }[error.code];
    return NextResponse.json(
      { code: error.code, error: error.message },
      { status, headers },
    );
  }
  console.error("Batch work operation failed",
    error instanceof Error ? error.name : "unknown error");
  return NextResponse.json(
    { error: "Unable to process work batch." },
    { status: 500, headers },
  );
}
async function context(slug: string): Promise<WorkContext> {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
export async function POST(request: NextRequest, { params }: Route) {
  try {
    const { slug } = await params;
    const scope = await context(slug);
    const size = Number(request.headers.get("content-length"));
    if (size > 32768)
      return NextResponse.json(
        { error: "Batch request is too large." },
        { status: 413, headers },
      );
    const raw: unknown = await request.json();
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      return NextResponse.json(
        { error: "Expected a JSON object." },
        { status: 400, headers },
      );
    if ("mode" in raw && raw.mode === "preview")
      return NextResponse.json(await previewWorkBatch(scope, raw), { headers });
    return NextResponse.json(await applyWorkBatch(scope, raw), { headers });
  } catch (error) {
    if (error instanceof SyntaxError)
      return NextResponse.json(
        { error: "Malformed JSON." },
        { status: 400, headers },
      );
    return handleError(error);
  }
}
