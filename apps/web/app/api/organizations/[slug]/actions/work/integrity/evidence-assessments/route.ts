import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  recordEvidenceAssessment,
  listEvidenceAssessments,
  inspectAssessmentEvidence,
} from "../../../../../../../../lib/work-integrity-evidence-assessment";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code];
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status, headers });
  }
  if (error instanceof SyntaxError)
    return NextResponse.json({
      code: "INVALID", error: "Malformed JSON.",
    }, { status: 400, headers });
  console.error("Integrity assessment request failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to process evidence assessment.",
  }, { status: 500, headers });
}
async function context(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
function query(request: NextRequest) {
  const result: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(result, key))
      throw new WorkInputError("INVALID", "Duplicate query parameter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid pagination.");
      result[key] = Number(value);
    } else result[key] = value;
  }
  return result;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await context(slug);
    const value = query(request);
    if (value.view === "inspect") {
      if (Object.keys(value).some(key => !["view", "assessmentId"].includes(key)))
        throw new WorkInputError("INVALID", "Unknown inspection parameter.");
      if (typeof value.assessmentId !== "string")
        throw new WorkInputError("INVALID", "Assessment ID required.");
      return NextResponse.json({
        inspection: await inspectAssessmentEvidence(scope, value.assessmentId),
      }, { headers });
    }
    if (value.view !== undefined && value.view !== "list")
      throw new WorkInputError("INVALID", "Unknown assessment view.");
    delete value.view;
    return NextResponse.json(await listEvidenceAssessments(scope, value),
      { headers });
  } catch (error) { return failure(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await context(slug);
    const body: unknown = await request.json();
    const result = await recordEvidenceAssessment(scope, body);
    return NextResponse.json(result, {
      status: result.replayed ? 200 : 201,
      headers,
    });
  } catch (error) { return failure(error); }
}
