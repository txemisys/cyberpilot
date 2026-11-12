import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { listAssetInventoryDevices } from "../../../../../../lib/assets-inventory-service";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function fail(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  return NextResponse.json({ error: "Asset inventory request failed." }, {
    status: 500, headers,
  });
}
async function scopeFor(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
function filters(request: NextRequest) {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of request.nextUrl.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(raw, key))
      throw new WorkInputError("INVALID", "Duplicate inventory query parameter.");
    if (key === "offset" || key === "limit") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value)))
        throw new WorkInputError("INVALID", "Invalid inventory pagination.");
      raw[key] = Number(value);
    } else if (key === "includeRetired") {
      if (value !== "true" && value !== "false")
        throw new WorkInputError("INVALID", "Invalid inventory boolean.");
      raw[key] = value === "true";
    } else {
      if (value.length > 150)
        throw new WorkInputError("INVALID", "Inventory filter too long.");
      raw[key] = value;
    }
  }
  return raw;
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const scope = await scopeFor((await params).slug);
    return NextResponse.json(await listAssetInventoryDevices(scope, filters(request)), { headers });
  } catch (error) {
    return fail(error);
  }
}
