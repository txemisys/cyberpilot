import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectOsvHistoryDelta } from "../../../../../../lib/assets-osv-refresh-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const safeHeaders = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError) {
    const status = {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code];
    return NextResponse.json({
      error: error.message, code: error.code,
    }, { status, headers: safeHeaders });
  }
  return NextResponse.json({
    error: "OSV history service is unavailable.",
  }, { status: 503, headers: safeHeaders });
}
function parse(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const allowed = new Set("previousInspectionId,currentInspectionId,offset,limit".split(","));
  const numeric = new Set([
    "freshnessMinutes", "minimumRetryMinutes", "maximumQueriesPerDay",
    "maximumInspectionsPerDay", "maximumPackagesPerRun",
    "historyWindowDays", "offset", "limit",
  ]);
  for (const [key, value] of request.nextUrl.searchParams) {
    if (!allowed.has(key) || Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Unknown or duplicate OSV query.");
    if (numeric.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric OSV query.");
      raw[key] = Number(value);
    } else if (key === "includeIncomplete") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean OSV query.");
      raw[key] = value === "true";
    } else {
      if (value.length > 150)
        throw new WorkInputError("INVALID", "OSV filter is too long.");
      raw[key] = value;
    }
  }
  
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const { session, membership } =
      await requireOrganizationAccess((await params).slug);
    const scope = {
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    };
    const result = await inspectOsvHistoryDelta(scope, parse(request));
    return NextResponse.json(result, { headers: safeHeaders });
  } catch (error) {
    return failure(error);
  }
}
