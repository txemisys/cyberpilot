import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import {
  reviewIntegrityLinks, buildIntegrityReviewMatrix,
  filterIntegrityAssociations, paginateIntegrityAssociations,
  type LinkReviewFilter,
} from "../../../../../../../../../lib/work-integrity-link-review";
import {
  parseIntegrityPlanRequest, planIntegrityLinkOperations,
  previewIntegrityPlan, partitionIntegrityPlan,
} from "../../../../../../../../../lib/work-integrity-link-plan";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code];
    return NextResponse.json({ code: error.code, error: error.message }, { status, headers });
  }
  console.error("Integrity review failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to review integrity associations." },
    { status: 500, headers });
}
function single(search: URLSearchParams, allowed: readonly string[]) {
  for (const key of search.keys()) {
    if (!allowed.includes(key) || search.getAll(key).length !== 1)
      throw new WorkInputError("INVALID", "Unexpected or repeated query parameter.");
  }
}
function integer(value: string | null, fallback: number, min: number, max: number) {
  if (value === null) return fallback;
  if (!/^(0|[1-9][0-9]*)$/.test(value))
    throw new WorkInputError("INVALID", "Invalid numeric query parameter.");
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < min || result > max)
    throw new WorkInputError("INVALID", "Numeric query parameter out of range.");
  return result;
}
function filters(search: URLSearchParams): LinkReviewFilter {
  const filter: LinkReviewFilter = {};
  const caseKey = search.get("caseKey");
  const workItemId = search.get("workItemId");
  const actorUserId = search.get("actorUserId");
  const state = search.get("state");
  const since = search.get("since");
  const until = search.get("until");
  if (caseKey !== null) {
    if (!caseKey || caseKey.length > 1500) throw new WorkInputError("INVALID", "Invalid case key.");
    filter.caseKey = caseKey;
  }
  if (workItemId !== null) {
    if (!workItemId || workItemId.length > 100)
      throw new WorkInputError("INVALID", "Invalid work item.");
    filter.workItemId = workItemId;
  }
  if (actorUserId !== null) {
    if (!actorUserId || actorUserId.length > 100)
      throw new WorkInputError("INVALID", "Invalid actor.");
    filter.actorUserId = actorUserId;
  }
  if (state !== null) {
    if (state !== "ACTIVE" && state !== "WITHDRAWN")
      throw new WorkInputError("INVALID", "Invalid association state.");
    filter.state = state;
  }
  if (since !== null) filter.since = since;
  if (until !== null) filter.until = until;
  return filter;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    const search = request.nextUrl.searchParams;
    single(search, ["captureId", "view", "offset", "limit",
      "caseKey", "workItemId", "actorUserId", "state", "since", "until"]);
    const captureId = search.get("captureId");
    if (!captureId) throw new WorkInputError("INVALID", "Capture ID required.");
    const view = search.get("view") ?? "report";
    if (!["report", "matrix", "associations", "findings"].includes(view))
      throw new WorkInputError("INVALID", "Unknown review view.");
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, captureId);
    const report = reviewIntegrityLinks(captureId, state.events);
    if (view === "matrix")
      return NextResponse.json({
        schemaVersion: 1, captureId, matrix: buildIntegrityReviewMatrix(report),
      }, { headers });
    if (view === "report")
      return NextResponse.json({ report }, { headers });
    if (view === "findings") {
      const offset = integer(search.get("offset"), 0, 0, 1000000);
      const limit = integer(search.get("limit"), 100, 1, 1000);
      return NextResponse.json({
        captureId, total: report.findings.length,
        findings: report.findings.slice(offset, offset + limit),
        pagination: {
          offset, limit, hasMore: offset + limit < report.findings.length,
        },
      }, { headers });
    }
    const filtered = filterIntegrityAssociations(report.associations, filters(search));
    const page = paginateIntegrityAssociations(filtered,
      integer(search.get("offset"), 0, 0, 1000000),
      integer(search.get("limit"), 100, 1, 1000));
    return NextResponse.json({ captureId, page }, { headers });
  } catch (error) { return failure(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    if (!/^application\/json(?:\s*;|\s*$)/i.test(
      request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 100000))
      throw new WorkInputError("INVALID", "Planning request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Planning request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const planRequest = parseIntegrityPlanRequest(input);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, planRequest.captureId);
    const report = reviewIntegrityLinks(planRequest.captureId, state.events);
    const plan = planIntegrityLinkOperations(planRequest, state.events);
    return NextResponse.json({
      plan, partition: partitionIntegrityPlan(plan),
      preview: previewIntegrityPlan(report, plan),
    }, { headers });
  } catch (error) { return failure(error); }
}
