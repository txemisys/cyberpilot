import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import {
  parseIntegrityWatchpoints, evaluateIntegrityWatchpoints,
  buildIntegrityReviewWatchHistory,
} from "../../../../../../../../../lib/work-integrity-review-watch";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ error: error.message, code: error.code }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity watch evaluation failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to evaluate integrity watchpoints." },
    { status: 500, headers });
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
      throw new WorkInputError("INVALID", "Watchpoint request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Watchpoint request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    if (!input || typeof input !== "object" || Array.isArray(input))
      throw new WorkInputError("INVALID", "Expected watchpoint evaluation object.");
    const raw = input as Record<string, unknown>;
    if (Object.keys(raw).some(key =>
      !["captureId", "watchpoints", "evaluatedAt", "view"].includes(key)) ||
      typeof raw.captureId !== "string")
      throw new WorkInputError("INVALID", "Invalid watchpoint evaluation input.");
    const watchpoints = parseIntegrityWatchpoints(raw.watchpoints);
    const view = raw.view ?? "summary";
    if (view !== "summary" && view !== "history")
      throw new WorkInputError("INVALID", "Unknown watchpoint view.");
    if (view === "summary" && raw.evaluatedAt !== undefined)
      throw new WorkInputError("INVALID", "Evaluation time requires history view.");
    if (view === "history" &&
        (typeof raw.evaluatedAt !== "string" ||
         !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(raw.evaluatedAt) ||
         !Number.isFinite(Date.parse(raw.evaluatedAt)) ||
         new Date(raw.evaluatedAt).toISOString() !== raw.evaluatedAt))
      throw new WorkInputError("INVALID", "Invalid evaluation timestamp.");
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, raw.captureId);
    if (view === "history") {
      const result = buildIntegrityReviewWatchHistory(
        raw.captureId, state.events, watchpoints, raw.evaluatedAt as string);
      return NextResponse.json({ result }, { headers });
    }
    const result = evaluateIntegrityWatchpoints(
      raw.captureId, state.events, watchpoints);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
