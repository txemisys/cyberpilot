import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  inspectOsvRotationOperations,
  inspectRotationInventory, parseKeyRotationPolicy,
} from "../../../../../../lib/assets-osv-key-rotation";
import {
  configuredDispatchKeys,
} from "../../../../../../lib/assets-osv-signed-dispatch";
import { WorkInputError, canManageWork } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      code: cause.code, error: cause.message,
    }, {
      status: {
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[cause.code], headers,
    });
  return NextResponse.json({
    error: "OSV key rotation analysis is unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { session, membership } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
async function body(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID",
      "Key rotation requests must be JSON.");
  const declared = request.headers.get("content-length");
  if (declared && (!/^[0-9]+$/.test(declared) ||
      Number(declared) > 8192))
    throw new WorkInputError("INVALID",
      "Key rotation request exceeds 8 KiB.");
  const value = await request.text();
  if (Buffer.byteLength(value, "utf8") > 8192)
    throw new WorkInputError("INVALID",
      "Key rotation request exceeds 8 KiB.");
  try { return JSON.parse(value) as unknown; }
  catch { throw new WorkInputError("INVALID",
    "Key rotation JSON is invalid."); }
}
export async function GET(_request: NextRequest, { params }: Context) {
  try {
    const tenant = await scope((await params).slug);
    if (!canManageWork(tenant.role))
      throw new WorkInputError("FORBIDDEN",
        "Key rotation inventory requires admin access.");
    const report = inspectRotationInventory(
      configuredDispatchKeys(), tenant.organizationId,
      new Date(), parseKeyRotationPolicy({}));
    return NextResponse.json(report, { headers });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const tenant = await scope((await params).slug);
    const report = await inspectOsvRotationOperations(
      tenant, await body(request));
    return NextResponse.json(report, { headers });
  } catch (cause) { return failure(cause); }
}
