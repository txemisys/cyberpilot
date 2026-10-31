import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { compareIntegrityCaptures, integrityComparisonCsv } from "../../../../../../../../lib/work-integrity-live-comparison";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BODY_BYTES = 4_000_000;
async function boundedJson(request: NextRequest): Promise<unknown> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType))
    throw new WorkInputError("INVALID", "Comparison requires application/json.");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES))
    throw new WorkInputError("INVALID", "Comparison request exceeds the size limit.");
  const reader = request.body?.getReader();
  if (!reader) throw new WorkInputError("INVALID", "Comparison body is missing.");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES)
        throw new WorkInputError("INVALID", "Comparison request exceeds the size limit.");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let position = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, position);
    position += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new WorkInputError("INVALID", "Comparison JSON is invalid.");
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!session.user.id || !canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Work review access required.");
    const format = request.nextUrl.searchParams.get("format") ?? "json";
    if (request.nextUrl.searchParams.size > (request.nextUrl.searchParams.has("format") ? 1 : 0) ||
        !["csv", "json"].includes(format))
      throw new WorkInputError("INVALID", "Unsupported comparison export format.");
    const payload = await boundedJson(request);
    let result: ReturnType<typeof compareIntegrityCaptures>;
    try {
      result = compareIntegrityCaptures(payload, membership.organization.id);
    } catch (error) {
      if (error instanceof Error)
        throw new WorkInputError("INVALID", error.message);
      throw error;
    }
    if (format === "csv") {
      return new NextResponse(integrityComparisonCsv(result), {
        headers: {
          ...headers,
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-capture-comparison.csv"',
        },
      });
    }
    return NextResponse.json(result, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      return NextResponse.json({ error: error.message, code: error.code }, {
        status: error.code === "FORBIDDEN" ? 403 :
          error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400,
        headers,
      });
    }
    console.error("Integrity capture comparison failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to compare operational captures." },
      { status: 500, headers });
  }
}
