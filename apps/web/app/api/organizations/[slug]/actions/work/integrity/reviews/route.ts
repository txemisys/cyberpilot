import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import {
  createPersistentReview,
  listPersistentReviews,
  getPersistentReview,
  listPersistentReviewEvents,
  applyPersistentReviewCommand,
} from "../../../../../../../../lib/work-integrity-persistent-review";
import { inspectPersistedReviewLedger } from "../../../../../../../../lib/work-integrity-persistent-review-ledger";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      error: error.message, code: error.code,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403,
        MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  if (error instanceof SyntaxError)
    return NextResponse.json({
      error: "Malformed JSON.", code: "INVALID",
    }, { status: 400, headers });
  console.error("Persistent integrity review operation failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to process integrity review.",
  }, { status: 500, headers });
}
async function scopeFor(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
function queryObject(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate query field.");
    raw[key] = value;
  }
  return raw;
}
function optionalBoolean(value: unknown) {
  if (value === undefined) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new WorkInputError("INVALID", "Invalid required query value.");
}
function optionalInteger(value: unknown) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value))
    throw new WorkInputError("INVALID", "Invalid pagination integer.");
  const result = Number(value);
  if (!Number.isSafeInteger(result))
    throw new WorkInputError("INVALID", "Invalid pagination integer.");
  return result;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const raw = queryObject(request);
    if (raw.view === "ledger") {
      if (Object.keys(raw).some(x => !["view", "taskId"].includes(x)))
        throw new WorkInputError("INVALID", "Unknown ledger query field.");
      if (typeof raw.taskId !== "string")
        throw new WorkInputError("INVALID", "Review task ID required.");
      return NextResponse.json({
        ledger: await inspectPersistedReviewLedger(scope, raw.taskId),
      }, { headers });
    }
    if (raw.view === "events") {
      const keys = Object.keys(raw);
      if (keys.some(x => !["view", "taskId", "offset", "limit"].includes(x)))
        throw new WorkInputError("INVALID", "Unknown event query field.");
      return NextResponse.json(await listPersistentReviewEvents(scope, {
        taskId: raw.taskId,
        offset: optionalInteger(raw.offset),
        limit: optionalInteger(raw.limit),
      }), { headers });
    }
    if (raw.view === "detail") {
      if (Object.keys(raw).some(x => !["view", "taskId"].includes(x)))
        throw new WorkInputError("INVALID", "Unknown detail query field.");
      if (typeof raw.taskId !== "string")
        throw new WorkInputError("INVALID", "Review task ID required.");
      return NextResponse.json({
        task: await getPersistentReview(scope, raw.taskId),
      }, { headers });
    }
    if (raw.view !== undefined && raw.view !== "list")
      throw new WorkInputError("INVALID", "Unknown review view.");
    if (Object.keys(raw).some(x => ![
      "view", "captureId", "disposition", "required",
      "offset", "limit",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown review query field.");
    return NextResponse.json(await listPersistentReviews(scope, {
      captureId: raw.captureId,
      disposition: raw.disposition,
      required: optionalBoolean(raw.required),
      offset: optionalInteger(raw.offset),
      limit: optionalInteger(raw.limit),
    }), { headers });
  } catch (error) { return errorResponse(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const body: unknown = await request.json();
    return NextResponse.json({
      task: await createPersistentReview(scope, body),
    }, { status: 201, headers });
  } catch (error) { return errorResponse(error); }
}
export async function PATCH(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const scope = await scopeFor(slug);
    const body: unknown = await request.json();
    const result = await applyPersistentReviewCommand(scope, body);
    return NextResponse.json(result, { headers });
  } catch (error) { return errorResponse(error); }
}
