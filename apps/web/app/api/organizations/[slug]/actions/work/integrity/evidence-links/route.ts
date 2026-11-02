import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import {
  linkIntegrityCaseToWork, listIntegrityWorkLinkHistory, listIntegrityWorkLinkHistoryPage,
  listCompleteIntegrityWorkLinkState, unlinkIntegrityCaseFromWork,
} from "../../../../../../../../lib/work-integrity-evidence-links";

import { analyzeIntegrityLinkEvents, parseLinkAnalyticsQuery } from "../../../../../../../../lib/work-integrity-link-analytics";

import { buildIntegrityLinkExport, parseIntegrityLinkExportOptions } from "../../../../../../../../lib/work-integrity-link-export";

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
    const allowed = new Set(["captureId", "view", "limit", "cursorAt", "cursorId", "sort", "offset", "caseKey", "workItemId", "actorUserId", "action", "since", "until", "format", "kind", "maxRows"]);
    if ([...search.keys()].some(key => !allowed.has(key)) ||
        search.getAll("captureId").length !== 1 ||
        ["view", "limit", "cursorAt", "cursorId"].some(key => search.getAll(key).length > 1))
      throw new WorkInputError("INVALID", "Invalid history query parameters.");
    const organizationId = membership.organization.id;
    const captureId = search.get("captureId")!;
    const view = search.get("view") ?? "history";
    if (view === "export") {
      if (["cursorAt", "cursorId", "offset", "limit"].some(key => search.has(key)) ||
          [...search.keys()].some(key => search.getAll(key).length !== 1))
        throw new WorkInputError("INVALID", "Invalid export query parameters.");
      const raw: Record<string, unknown> = {};
      for (const key of ["format", "kind", "caseKey", "workItemId",
        "actorUserId", "action", "since", "until", "sort"]) {
        const value = search.get(key);
        if (value !== null) raw[key] = value;
      }
      const maxRows = search.get("maxRows");
      if (maxRows !== null) {
        if (!/^[1-9][0-9]*$/.test(maxRows))
          throw new WorkInputError("INVALID", "Invalid export row limit.");
        raw.maxRows = Number(maxRows);
      }
      const options = parseIntegrityLinkExportOptions(raw);
      const state = await listCompleteIntegrityWorkLinkState(organizationId, captureId);
      const result = buildIntegrityLinkExport(state.events, options, captureId);
      return new NextResponse(result.content, {
        headers: {
          ...headers,
          "Content-Type": result.contentType,
          "Content-Disposition": `attachment; filename="${result.filename}"`,
          "X-Export-Rows": String(result.rows),
          "X-Export-Truncated": String(result.truncated),
        },
      });
    }
    if (view === "analytics") {
      const raw: Record<string, unknown> = {};
      for (const key of ["sort", "caseKey", "workItemId", "actorUserId", "action", "since", "until"]) {
        const value = search.get(key);
        if (value !== null) raw[key] = value;
      }
      for (const key of ["offset", "limit"]) {
        const value = search.get(key);
        if (value !== null) {
          if (!/^(0|[1-9][0-9]*)$/.test(value))
            throw new WorkInputError("INVALID", "Invalid numeric analytics parameter.");
          raw[key] = Number(value);
        }
      }
      if (["cursorAt", "cursorId"].some(key => search.has(key)) ||
          [...search.keys()].some(key => search.getAll(key).length !== 1))
        throw new WorkInputError("INVALID", "Invalid analytics parameters.");
      const query = parseLinkAnalyticsQuery(raw);
      const state = await listCompleteIntegrityWorkLinkState(organizationId, captureId);
      return NextResponse.json({ analytics: analyzeIntegrityLinkEvents(state.events, query) }, { headers });
    }
    if (view === "history" || view === "state") {
      if (["limit", "cursorAt", "cursorId"].some(key => search.has(key)))
        throw new WorkInputError("INVALID", "Pagination is only supported for page view.");
      if (view === "history")
        return NextResponse.json({
          history: await listIntegrityWorkLinkHistory(organizationId, captureId),
        }, { headers });
      const { active, withdrawn } = await listCompleteIntegrityWorkLinkState(organizationId, captureId);
      return NextResponse.json({ state: { active, withdrawn } }, { headers });
    }
    if (view !== "page") throw new WorkInputError("INVALID", "Invalid history view.");
    const at = search.get("cursorAt");
    const id = search.get("cursorId");
    if ((at === null) !== (id === null))
      throw new WorkInputError("INVALID", "Both cursor fields are required.");
    const limit = search.get("limit");
    if (limit !== null && !/^[1-9][0-9]{0,3}$/.test(limit))
      throw new WorkInputError("INVALID", "Invalid history page limit.");
    const page = await listIntegrityWorkLinkHistoryPage(
      organizationId, captureId,
      at !== null && id !== null ? { occurredAt: at, auditId: id } : undefined,
      limit === null ? 100 : Number(limit),
    );
    return NextResponse.json({ page }, { headers });
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

export async function DELETE(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!/^application\/json(?:\s*;|\s*$)/i.test(request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON required.");
    const body = await request.text();
    if (body.length > 10000)
      throw new WorkInputError("INVALID", "Unlink body too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const result = await unlinkIntegrityCaseFromWork({
      organizationId: membership.organization.id,
      actorUserId: session.user.id, role: membership.role,
    }, input);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
