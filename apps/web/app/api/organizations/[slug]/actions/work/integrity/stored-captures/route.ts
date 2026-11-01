import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { compareLatestStoredIntegrityCaptures, compareStoredIntegrityCaptureIds } from "../../../../../../../../lib/work-integrity-persistent-comparisons";
import {
  canManageWork, canReadWork, WorkInputError,
} from "../../../../../../../../lib/remediation-work-input";
import {
  ingestStoredIntegrityCaptures, pageStoredIntegrityCaptures,
  readStoredIntegrityCapture,
} from "../../../../../../../../lib/work-integrity-persistent-captures";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 5_000_000;

function failure(error: unknown): NextResponse {
  if (error instanceof WorkInputError)
    return NextResponse.json({ error: error.message, code: error.code }, {
      status: error.code === "FORBIDDEN" ? 403 : 400, headers,
    });
  console.error("Stored integrity capture operation failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Unable to process stored captures." },
    { status: 500, headers });
}

export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Capture read access denied.");
    const query = request.nextUrl.searchParams;
    if ([...query.keys()].some(key => !["id", "limit", "cursor", "source", "compareTo", "compareLatest"].includes(key) ||
      query.getAll(key).length !== 1))
      throw new WorkInputError("INVALID", "Invalid capture query.");
    const id = query.get("id");
    const compareTo = query.get("compareTo");
    const compareLatest = query.get("compareLatest");
    if (compareLatest !== null) {
      if (compareLatest !== "true" || !query.get("source") ||
          [...query.keys()].some(key => key !== "compareLatest" && key !== "source"))
        throw new WorkInputError("INVALID", "Latest comparison requires only a source.");
      const result = await compareLatestStoredIntegrityCaptures(
        membership.organization.id, query.get("source")!,
      );
      return NextResponse.json({ comparison: result }, { headers });
    }
    if (compareTo !== null) {
      if (id === null || [...query.keys()].some(key => key !== "id" && key !== "compareTo") ||
          !/^[a-zA-Z0-9_-]{5,100}$/.test(id) ||
          !/^[a-zA-Z0-9_-]{5,100}$/.test(compareTo))
        throw new WorkInputError("INVALID", "Comparison requires two capture IDs.");
      const result = await compareStoredIntegrityCaptureIds(
        membership.organization.id, id, compareTo,
      );
      return NextResponse.json({ comparison: result }, { headers });
    }
    if (id !== null && (query.has("cursor") || query.has("source") || query.has("limit")))
      throw new WorkInputError("INVALID", "Capture detail cannot be combined with history filters.");
    if (id !== null) {
      if (!/^[a-zA-Z0-9_-]{5,100}$/.test(id))
        throw new WorkInputError("INVALID", "Invalid capture ID.");
      const capture = await readStoredIntegrityCapture(membership.organization.id, id);
      if (!capture) return NextResponse.json({ error: "Capture not found." },
        { status: 404, headers });
      return NextResponse.json({ capture }, { headers });
    }
    const rawLimit = query.get("limit") ?? "50";
    if (!/^\d{1,3}$/.test(rawLimit))
      throw new WorkInputError("INVALID", "Invalid history limit.");
    const limit = Number(rawLimit);
    if (limit < 1 || limit > 100)
      throw new WorkInputError("INVALID", "History limit out of range.");
    const page = await pageStoredIntegrityCaptures(
      membership.organization.id, limit,
      query.get("cursor") ?? undefined, query.get("source") ?? undefined,
    );
    return NextResponse.json({
      ...page,
      limitations: [
        "Stored captures are historical diagnostic observations, not verified security controls.",
        "Capture completeness is recorded as declared and is not independently authenticated.",
      ],
    }, { headers });
  } catch (error) {
    return failure(error);
  }
}

export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!canManageWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Capture ingestion requires an organization administrator.");
    const contentType = request.headers.get("content-type") ?? "";
    if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const lengthHeader = request.headers.get("content-length");
    if (lengthHeader && (!/^\d+$/.test(lengthHeader) || Number(lengthHeader) > MAX_BYTES))
      throw new WorkInputError("INVALID", "Request body exceeds limit.");
    if (!request.body)
      throw new WorkInputError("INVALID", "Missing request body.");
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BYTES)
          throw new WorkInputError("INVALID", "Request body exceeds limit.");
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let input: unknown;
    try {
      input = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new WorkInputError("INVALID", "Malformed JSON request.");
    }
    if (!input || typeof input !== "object" || Array.isArray(input))
      throw new WorkInputError("INVALID", "Expected JSON object.");
    const body = input as Record<string, unknown>;
    if (Object.keys(body).some(key => key !== "captures") ||
        !Array.isArray(body.captures))
      throw new WorkInputError("INVALID", "Expected captures array.");
    const result = await ingestStoredIntegrityCaptures({
      organizationId: membership.organization.id,
      actorUserId: session.user.id,
    }, body.captures);
    return NextResponse.json({
      ...result,
      limitations: [
        "Captured diagnostics do not independently establish security effectiveness.",
        "Only authorized organization administrators can persist snapshots.",
      ],
    }, { status: 201, headers });
  } catch (error) {
    return failure(error);
  }
}
