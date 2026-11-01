import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { parseTimelineInput } from "../../../../../../../../lib/work-integrity-case-timeline";
import { planContinuityActions, continuityActionsCsv } from "../../../../../../../../lib/work-integrity-continuity-actions";
import {
  analyzeReviewContinuity, reviewContinuityCsv,
} from "../../../../../../../../lib/work-integrity-review-continuity";

type Context = { params: Promise<{ slug: string }> };
const common = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 5_000_000;
async function readBoundedJson(request: NextRequest): Promise<unknown> {
  if (!/^application\/json(?:\s*;|\s*$)/i.test(
    request.headers.get("content-type") ?? "",
  )) throw new WorkInputError("INVALID", "Continuity analysis requires JSON.");
  const statedLength = request.headers.get("content-length");
  if (statedLength !== null &&
      (!/^\d+$/.test(statedLength) || Number(statedLength) > MAX_BYTES))
    throw new WorkInputError("INVALID", "Continuity input exceeds allowed size.");
  const reader = request.body?.getReader();
  if (!reader) throw new WorkInputError("INVALID", "Missing continuity data.");
  let length = 0;
  const parts: Uint8Array[] = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES)
        throw new WorkInputError("INVALID", "Continuity input exceeds allowed size.");
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(length);
  let cursor = 0;
  for (const part of parts) {
    buffer.set(part, cursor);
    cursor += part.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
  } catch {
    throw new WorkInputError("INVALID", "Continuity input is not valid UTF-8 JSON.");
  }
}
/**
 * Cross-capture event continuity operates only under current authenticated
 * membership. Uploaded tenant IDs are checked against the trusted server ID.
 * Analysis is read-only and never approves work or mutates audit records.
 */
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!session.user.id || !canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Work review permission required.");
    const query = request.nextUrl.searchParams;
    if ([...query.keys()].some(key => key !== "format") ||
        query.getAll("format").length > 1)
      throw new WorkInputError("INVALID", "Invalid continuity option.");
    const format = query.get("format") ?? "json";
    if (format !== "json" && format !== "csv" && format !== "actions-csv")
      throw new WorkInputError("INVALID", "Unsupported continuity format.");
    const body = await readBoundedJson(request);
    let report: ReturnType<typeof analyzeReviewContinuity>;
    try {
      const captures = parseTimelineInput(body, membership.organization.id);
      report = analyzeReviewContinuity(captures);
    } catch (error) {
      throw new WorkInputError("INVALID", error instanceof Error
        ? error.message : "Invalid continuity capture.");
    }
    const actionPlan = planContinuityActions(report);
    if (format === "actions-csv") {
      return new NextResponse(continuityActionsCsv(actionPlan), {
        headers: {
          ...common,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-review-actions.csv"',
        },
      });
    }
    if (format === "csv") {
      return new NextResponse(reviewContinuityCsv(report), {
        headers: {
          ...common,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-review-continuity.csv"',
        },
      });
    }
    return NextResponse.json({ ...report, actionPlan }, { headers: common });
  } catch (error) {
    if (error instanceof WorkInputError) {
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 :
          error.code === "CONFLICT" ? 409 : 400,
        headers: common,
      });
    }
    console.error("Review continuity analysis failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to analyze review continuity." }, {
      status: 500, headers: common,
    });
  }
}
