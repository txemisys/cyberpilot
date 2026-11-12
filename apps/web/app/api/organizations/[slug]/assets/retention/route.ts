import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { inspectAssetRetention, purgeAssetInventory } from "../../../../../../lib/assets-inventory-retention";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[error.code], headers,
    });
  return NextResponse.json({ error: "Asset operation unavailable." }, {
    status: 500, headers,
  });
}
async function organizationScope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
function parseQuery(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  const allowed = new Set("minimumRetiredDays,maximumCandidateAgeDays,limit,offset".split(","));
  const ints = new Set(["offset", "limit",
    "minimumRetiredDays", "maximumCandidateAgeDays"]);
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (!allowed.has(key) || Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Invalid or duplicate asset filter.");
    if (ints.has(key)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) ||
          !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid numeric filter.");
      raw[key] = Number(value);
    } else if (key === "includeUnchanged") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid boolean filter.");
      raw[key] = value === "true";
    } else {
      if (value.length > 120)
        throw new WorkInputError("INVALID", "Asset filter too long.");
      raw[key] = value;
    }
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const scope = await organizationScope((await params).slug);
    return NextResponse.json(
      await inspectAssetRetention(scope, parseQuery(request)), { headers });
  } catch (error) {
    return failure(error);
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const scope = await organizationScope((await params).slug);
    const body: unknown = await request.json();
    return NextResponse.json(await purgeAssetInventory(scope, body), { headers });
  } catch (error) {
    return failure(error);
  }
}
