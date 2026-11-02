import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import { reviewIntegrityLinks } from "../../../../../../../../../lib/work-integrity-link-review";
import {
  parseIntegrityEvidenceQuery, queryIntegrityEvidence,
  inspectIntegrityEvidenceGraph,
} from "../../../../../../../../../lib/work-integrity-evidence-graph";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ error: error.message, code: error.code }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity evidence graph failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to inspect integrity evidence." },
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
      throw new WorkInputError("INVALID", "Evidence graph request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Evidence graph request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const query = parseIntegrityEvidenceQuery(input);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, query.captureId);
    const report = reviewIntegrityLinks(query.captureId, state.events);
    const result = queryIntegrityEvidence(report, state.events, query);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
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
      throw new WorkInputError("INVALID", "Exactly one capture ID required.");
    const captureId = search.get("captureId")!;
    if (!/^[a-zA-Z0-9_-]{5,100}$/.test(captureId))
      throw new WorkInputError("INVALID", "Invalid capture ID.");
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, captureId);
    const result = inspectIntegrityEvidenceGraph(captureId, state.events);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
