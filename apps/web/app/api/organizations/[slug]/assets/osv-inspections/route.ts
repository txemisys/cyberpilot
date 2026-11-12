import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  listOsvInspections, readOsvInspection, persistOsvInspection,
} from "../../../../../../lib/assets-osv-inspection-ledger";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({
      code: error.code, error: error.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  return NextResponse.json({
    error: "OSV ledger operation is unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
function query(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const accepted = new Set([
    "importId", "inspectionId", "status", "offset", "limit",
  ]);
  for (const [key, value] of request.nextUrl.searchParams) {
    if (!accepted.has(key) || Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Unknown or repeated ledger filter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid ledger numeric parameter.");
      raw[key] = Number(value);
    } else {
      if (value.length > 150)
        throw new WorkInputError("INVALID", "Ledger filter is too long.");
      raw[key] = value;
    }
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const filters = query(request);
    const result = filters.inspectionId ?
      await readOsvInspection(current, filters) :
      await listOsvInspections(current, filters);
    return NextResponse.json(result, { headers });
  } catch (error) {
    return errorResponse(error);
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const length = request.headers.get("content-length");
    if (length && (!/^[0-9]+$/.test(length) || Number(length) > 65536))
      throw new WorkInputError("INVALID", "OSV ledger request too large.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 65536)
      throw new WorkInputError("INVALID", "OSV ledger request too large.");
    let input: unknown;
    try {
      input = JSON.parse(body);
    } catch {
      throw new WorkInputError("INVALID", "OSV ledger requires JSON.");
    }
    return NextResponse.json(
      await persistOsvInspection(current, input),
      { headers, status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
