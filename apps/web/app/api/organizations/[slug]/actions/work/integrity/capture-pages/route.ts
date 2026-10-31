import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import {
  parseCaptureTraversalOptions, traverseIntegrityCapture,
} from "../../../../../../../../lib/work-integrity-capture-traversal";

type Context = { params: Promise<{ slug: string }> };
const common = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    const search = request.nextUrl.searchParams;
    for (const key of search.keys()) {
      if (search.getAll(key).length !== 1)
        throw new WorkInputError("INVALID", "Repeated full-capture option.");
    }
    let options: ReturnType<typeof parseCaptureTraversalOptions>;
    try {
      options = parseCaptureTraversalOptions(Object.fromEntries(search.entries()));
    } catch (error) {
      throw new WorkInputError("INVALID",
        error instanceof Error ? error.message : "Invalid capture options.");
    }
    const result = await traverseIntegrityCapture({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, options);
    return NextResponse.json({ ...result.snapshot, traversal: {
      pagesRead: result.pagesRead,
      workItemsExamined: result.workItemsExamined,
      casesCollected: result.casesCollected,
      hasMore: result.hasMore,
      nextCursor: result.nextCursor,
      historyComplete: result.historyComplete,
      linkedCoverageComplete: result.linkedCoverageComplete,
      duplicateCases: result.duplicateCases,
      warnings: result.warnings,
    } }, {
      headers: {
        ...common,
        "Content-Disposition": 'attachment; filename="integrity-multi-page-capture.json"',
      },
    });
  } catch (error) {
    if (error instanceof WorkInputError) {
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers: common,
      });
    }
    console.error("Multi-page integrity capture failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to capture multiple work pages." }, {
      status: 500, headers: common,
    });
  }
}
