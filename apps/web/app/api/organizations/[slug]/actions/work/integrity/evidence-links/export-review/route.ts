import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import {
  buildIntegrityReviewExport, parseIntegrityReviewExportOptions,
  reviewExportManifest,
} from "../../../../../../../../../lib/work-integrity-review-export";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ error: error.message, code: error.code }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity review export failed", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to export integrity review." },
    { status: 500, headers });
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    const search = request.nextUrl.searchParams;
    const allowed = ["captureId", "format", "kind", "maxRows", "checkpoint", "manifest"];
    for (const key of search.keys()) {
      if (!allowed.includes(key) || (key !== "checkpoint" && search.getAll(key).length !== 1))
        throw new WorkInputError("INVALID", "Unknown or repeated export parameter.");
    }
    const captureId = search.get("captureId");
    if (!captureId) throw new WorkInputError("INVALID", "Capture ID required.");
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, captureId);
    if (search.get("manifest") === "true") {
      if (["format", "kind", "maxRows", "checkpoint"].some(key => search.has(key)))
        throw new WorkInputError("INVALID", "Manifest cannot include export options.");
      return NextResponse.json({
        manifest: reviewExportManifest(captureId, state.events),
      }, { headers });
    }
    if (search.has("manifest"))
      throw new WorkInputError("INVALID", "Invalid manifest flag.");
    const raw: Record<string, unknown> = {};
    if (search.has("format")) raw.format = search.get("format");
    if (search.has("kind")) raw.kind = search.get("kind");
    if (search.has("maxRows")) {
      const maxRows = search.get("maxRows")!;
      if (!/^[1-9][0-9]*$/.test(maxRows))
        throw new WorkInputError("INVALID", "Invalid export row limit.");
      raw.maxRows = Number(maxRows);
    }
    if (search.has("checkpoint")) raw.checkpoints = search.getAll("checkpoint");
    const options = parseIntegrityReviewExportOptions(raw);
    const result = buildIntegrityReviewExport(captureId, state.events, options);
    return new NextResponse(result.content, {
      headers: {
        ...headers, "Content-Type": result.contentType,
        "Content-Disposition": `attachment; filename="${result.filename}"`,
        "X-Export-Rows": String(result.rows),
        "X-Export-Total-Rows": String(result.totalRows),
        "X-Export-Truncated": String(result.truncated),
      },
    });
  } catch (error) { return failure(error); }
}
