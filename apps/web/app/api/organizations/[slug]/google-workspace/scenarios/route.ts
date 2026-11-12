import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  executeGoogleScenarioRun, googleScenarioCatalog,
  inspectSanitizedGoogleRun,
} from "../../../../../../lib/google-lab-scenario-service";
import { GoogleLabError } from
  "@cyberpilot/integrations/google-workspace";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(cause: unknown) {
  if (cause instanceof GoogleLabError)
    return NextResponse.json({
      error: cause.message, code: cause.code,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409, EXPIRED: 410,
    }[cause.code], headers });
  return NextResponse.json({
    error: "Synthetic Google scenario execution unavailable.",
    code: "UNAVAILABLE",
  }, { status: 503, headers });
}
export async function GET(_request: NextRequest, context: Context) {
  try {
    await requireOrganizationAccess((await context.params).slug);
    return NextResponse.json({
      schema: "cyberpilot.google.lab.scenarios.catalog.v1",
      scenarios: googleScenarioCatalog(),
      externalProviderValidated: false,
      realAdminConsentRequiredForLive: true,
      source: "SYNTHETIC_FIXTURE",
    }, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
export async function POST(request: NextRequest, context: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug);
    if (request.headers.get("content-type")?.split(";")[0]
      ?.trim().toLowerCase() !== "application/json")
      throw new GoogleLabError("INVALID", "Expected JSON request.");
    const claimedLength = request.headers.get("content-length");
    if (claimedLength &&
        (!/^\d+$/.test(claimedLength) ||
         Number(claimedLength) > 16384))
      throw new GoogleLabError("INVALID",
        "Synthetic scenario request exceeds 16 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 16384)
      throw new GoogleLabError("INVALID",
        "Synthetic scenario request exceeds 16 KiB.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch {
      throw new GoogleLabError("INVALID", "Malformed scenario JSON.");
    }
    const result = await executeGoogleScenarioRun({
      organizationId: membership.organization.id,
      actorUserId: session.user.id, role: membership.role,
    }, input);
    if (!inspectSanitizedGoogleRun(result).valid)
      throw new GoogleLabError("CONFLICT",
        "Scenario result failed no-LIVE/no-PII checks.");
    return NextResponse.json(result, { headers });
  } catch (cause) {
    return errorResponse(cause);
  }
}
export async function DELETE() {
  return NextResponse.json({
    error: "Google fixture API does not delete customer accounts.",
  }, { status: 405, headers });
}
