import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import {
  buildIntegrityTimeline, integrityTimelineCsv, parseTimelineInput,
} from "../../../../../../../../lib/work-integrity-case-timeline";

type Context = { params: Promise<{ slug: string }> };
const common = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 5_000_000;

async function readBoundedTimeline(request: NextRequest): Promise<unknown> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType))
    throw new WorkInputError("INVALID", "Timeline requires JSON input.");
  const stated = request.headers.get("content-length");
  if (stated !== null && (!/^\d+$/.test(stated) || Number(stated) > MAX_BYTES))
    throw new WorkInputError("INVALID", "Timeline input is too large.");
  const reader = request.body?.getReader();
  if (!reader) throw new WorkInputError("INVALID", "Missing timeline body.");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES)
        throw new WorkInputError("INVALID", "Timeline input is too large.");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const data = new Uint8Array(length);
  let at = 0;
  for (const part of chunks) {
    data.set(part, at);
    at += part.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  } catch {
    throw new WorkInputError("INVALID", "Invalid UTF-8 JSON timeline.");
  }
}

/**
 * Offline longitudinal analysis: the authenticated organization is taken
 * exclusively from server membership, never from uploaded snapshot fields.
 * No diagnostic writes, reviews, or remediation state transitions occur.
 */
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!session.user.id || !canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Work review access required.");
    const search = request.nextUrl.searchParams;
    if ([...search.keys()].some(key => key !== "format") ||
        search.getAll("format").length > 1)
      throw new WorkInputError("INVALID", "Invalid timeline export option.");
    const format = search.get("format") ?? "json";
    if (format !== "json" && format !== "csv")
      throw new WorkInputError("INVALID", "Unsupported timeline format.");
    const payload = await readBoundedTimeline(request);
    let report: ReturnType<typeof buildIntegrityTimeline>;
    try {
      const captures = parseTimelineInput(payload, membership.organization.id);
      report = buildIntegrityTimeline(captures);
    } catch (error) {
      throw new WorkInputError("INVALID",
        error instanceof Error ? error.message : "Timeline capture is invalid.");
    }
    if (format === "csv") {
      return new NextResponse(integrityTimelineCsv(report), {
        headers: {
          ...common,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-case-timeline.csv"',
        },
      });
    }
    return NextResponse.json(report, { headers: common });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ error: error.message, code: error.code },
        { status, headers: common });
    }
    console.error("Integrity timeline failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to analyze integrity timeline." },
      { status: 500, headers: common });
  }
}
