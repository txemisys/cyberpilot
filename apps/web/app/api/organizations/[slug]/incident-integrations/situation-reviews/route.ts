import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  createPersistedSituationReview, mutatePersistedSituationReview,
  readPersistedSituationReview, listPersistedSituationReviews,
  comparePersistedSituationReview, SituationReviewServiceError,
} from "../../../../../../lib/incident-situation-review-service";
import type { SituationSelection } from "../../../../../../lib/incident-situation-service";
import type { SituationReviewCommand } from "../../../../../../lib/incident-situation-review-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
function denied(code: string, status: number) {
  return NextResponse.json({
    code, providerWrites: 0, independentlyContained: false,
  }, { status, headers });
}
async function actor(context: Context) {
  const { membership, session } =
    await requireOrganizationAccess((await context.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function failure(error: unknown) {
  if (error instanceof SituationReviewServiceError) {
    const status = /ROLE|MEMBERSHIP|ACTOR|TENANT/.test(error.code) ? 403 :
      /NOT_FOUND/.test(error.code) ? 404 :
      /CAS|RACE|DRIFT|CONCURRENT|CONFLICT/.test(error.code) ? 409 : 400;
    return denied(error.code, status);
  }
  return denied("SITUATION_REVIEW_UNAVAILABLE", 503);
}
function record(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
function objectKeys(x: Record<string, unknown>, keys: string[]) {
  return Object.keys(x).every(key => keys.includes(key));
}
async function body(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json") throw Error("REVIEW_JSON_REQUIRED");
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    throw Error("REVIEW_CROSS_ORIGIN");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 16000))
    throw Error("REVIEW_BODY_TOO_LARGE");
  const text = await request.text();
  if (Buffer.byteLength(text) > 16000)
    throw Error("REVIEW_BODY_TOO_LARGE");
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw Error("REVIEW_JSON_INVALID"); }
  if (!record(value)) throw Error("REVIEW_BODY_INVALID");
  return value;
}
function selection(x: unknown): SituationSelection {
  if (!record(x) || !objectKeys(x,
      ["incidentId", "evidence", "assets", "remediation", "consistency"]) ||
      typeof x.incidentId !== "string" ||
      !["FAIL_CLOSED", "PARTIAL_READ"].includes(String(x.consistency)) ||
      !["evidence", "assets", "remediation"].every(key =>
        x[key] === null || record(x[key])))
    throw Error("REVIEW_SELECTION_INVALID");
  return {
    incidentId: x.incidentId,
    consistency: x.consistency as SituationSelection["consistency"],
    evidence: x.evidence as SituationSelection["evidence"],
    assets: x.assets as SituationSelection["assets"],
    remediation: x.remediation as SituationSelection["remediation"],
  };
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const current = await actor(context);
    if (current.role === "MEMBER") return denied("REVIEWER_REQUIRED", 403);
    const query = new URL(request.url).searchParams;
    if ([...query.keys()].some(key =>
      !["mode", "reviewId", "incidentId", "offset", "limit"].includes(key)))
      return denied("QUERY_FIELD_INVALID", 400);
    const mode = query.get("mode") ?? "detail";
    if (mode === "detail") {
      const reviewId = query.get("reviewId");
      if (!reviewId) return denied("REVIEW_ID_REQUIRED", 400);
      const data = await readPersistedSituationReview(current, reviewId);
      return NextResponse.json({ data, providerWrites: 0 }, { headers });
    }
    if (mode === "index") {
      const incidentId = query.get("incidentId");
      if (!incidentId) return denied("INCIDENT_ID_REQUIRED", 400);
      const offset = query.get("offset") ?? "0";
      const limit = query.get("limit") ?? "30";
      if (!/^\d{1,5}$/.test(offset) || !/^\d{1,3}$/.test(limit))
        return denied("REVIEW_PAGING_INVALID", 400);
      const data = await listPersistedSituationReviews(
        current, incidentId, Number(offset), Number(limit),
      );
      return NextResponse.json({ data, providerWrites: 0 }, { headers });
    }
    return denied("REVIEW_MODE_INVALID", 400);
  } catch (error) {
    return failure(error);
  }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const current = await actor(context);
    if (!["OWNER", "ADMIN"].includes(current.role))
      return denied("REVIEW_WRITE_ROLE_REQUIRED", 403);
    const value = await body(request);
    if (!objectKeys(value, ["reviewId", "selection"]) ||
        typeof value.reviewId !== "string")
      return denied("REVIEW_REQUEST_INVALID", 400);
    const data = await createPersistedSituationReview(current,
      selection(value.selection), value.reviewId);
    return NextResponse.json({ data, providerWrites: 0 },
      { status: data.created ? 201 : 200, headers });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("REVIEW_"))
      return denied(error.message, 400);
    return failure(error);
  }
}
export async function PATCH(request: NextRequest, context: Context) {
  try {
    const current = await actor(context);
    if (!["OWNER", "ADMIN"].includes(current.role))
      return denied("REVIEW_WRITE_ROLE_REQUIRED", 403);
    const value = await body(request);
    if (!objectKeys(value, ["reviewId", "decision", "incidentId",
      "expectedRevision", "expectedSituationDigest", "explanation",
      "concernId", "conclusion", "evidenceReferences", "supersededBy"]) ||
      typeof value.reviewId !== "string" ||
      typeof value.incidentId !== "string" ||
      typeof value.expectedRevision !== "number" ||
      typeof value.expectedSituationDigest !== "string" ||
      !["BEGIN_REVIEW", "RECORD_FINDING", "RETURN_FOR_EVIDENCE",
        "ACKNOWLEDGE", "REOPEN", "SUPERSEDE"].includes(String(value.decision)))
      return denied("REVIEW_MUTATION_INVALID", 400);
    const command = value as unknown as Omit<SituationReviewCommand,
      "organizationId" | "actorId" | "role" | "at"> & { reviewId: string };
    const data = await mutatePersistedSituationReview(current, command);
    return NextResponse.json({ data, providerWrites: 0 }, { headers });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("REVIEW_"))
      return denied(error.message, 400);
    return failure(error);
  }
}
export async function PUT() { return denied("REVIEW_METHOD_DENIED", 405); }
export async function DELETE() { return denied("REVIEW_DELETE_FORBIDDEN", 405); }
