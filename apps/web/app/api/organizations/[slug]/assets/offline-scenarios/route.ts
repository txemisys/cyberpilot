import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { canManageWork, WorkInputError } from "../../../../../../lib/remediation-work-input";
import {
  parseScenarioMatrixOptions, runOfflineScenarioMatrix,
  verifyOfflineScenarioMatrix,
} from "../../../../../../lib/assets-offline-scenario-matrix";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      error: cause.message, code: cause.code,
    }, {
      status: {
        INVALID: 400, MISSING: 404,
        CONFLICT: 409, FORBIDDEN: 403,
      }[cause.code], headers,
    });
  return NextResponse.json({
    error: "Offline acceptance reference matrix failed.",
  }, { status: 503, headers });
}
async function verifyOperator(slug: string) {
  const { membership } = await requireOrganizationAccess(slug);
  if (!canManageWork(membership.role))
    throw new WorkInputError("FORBIDDEN",
      "Only tenant administrators can run the offline acceptance matrix.");
}
async function parseBody(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID",
      "Scenario evaluation requires JSON.");
  const length = request.headers.get("content-length");
  if (length && (!/^[0-9]+$/.test(length) ||
      Number(length) > 8192))
    throw new WorkInputError("INVALID",
      "Scenario request exceeds 8 KiB.");
  const source = await request.text();
  if (Buffer.byteLength(source, "utf8") > 8192)
    throw new WorkInputError("INVALID",
      "Scenario request exceeds 8 KiB.");
  try { return JSON.parse(source) as unknown; }
  catch { throw new WorkInputError("INVALID",
    "Invalid scenario JSON."); }
}
function evaluate(input: unknown) {
  const policy = parseScenarioMatrixOptions(input);
  const report = runOfflineScenarioMatrix(policy);
  const verification = verifyOfflineScenarioMatrix(report);
  if (!verification.valid)
    throw new WorkInputError("CONFLICT",
      "Scenario reference report failed its structural integrity gate.");
  return NextResponse.json({ ...report, verification }, { headers });
}
export async function GET(_request: NextRequest, { params }: Context) {
  try {
    await verifyOperator((await params).slug);
    return evaluate({});
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    await verifyOperator((await params).slug);
    return evaluate(await parseBody(request));
  } catch (cause) { return failure(cause); }
}
