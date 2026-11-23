import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import {
  CaseActionHandoffError,
  handoffDecisionCaseToRiskAction,
  type CaseActionHandoffInput,
} from "../../../../../lib/case-action-handoff-service";

type Context = { params: Promise<{ slug: string }> };
const securityHeaders = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const reject = (code: string, status: number) => NextResponse.json({
  code, providerWrites: 0, independentlyVerifiedRemediation: false,
  customerConsentEstablished: false, cyberScoreV1Writes: 0,
}, { status, headers: securityHeaders });
const allowed = new Set([
  "caseId", "expectedRevision", "riskKey", "priority",
  "ownerUserId", "dueAt", "rationale",
]);
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function inputFrom(value: Record<string, unknown>): CaseActionHandoffInput | null {
  if (Object.keys(value).length !== allowed.size ||
      Object.keys(value).some(key => !allowed.has(key)) ||
      [...allowed].some(key => !Object.hasOwn(value, key)))
    return null;
  if (typeof value.caseId !== "string" ||
      typeof value.expectedRevision !== "number" ||
      typeof value.riskKey !== "string" ||
      typeof value.priority !== "string" ||
      !(value.ownerUserId === null || typeof value.ownerUserId === "string") ||
      !(value.dueAt === null || typeof value.dueAt === "string") ||
      !(value.rationale === null || typeof value.rationale === "string"))
    return null;
  return value as CaseActionHandoffInput;
}
function sameOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}
export async function POST(request: NextRequest, context: Context) {
  if (!sameOrigin(request)) return reject("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return reject("JSON_REQUIRED", 415);
  const claimed = request.headers.get("content-length");
  if (claimed && (!/^\d+$/.test(claimed) || Number(claimed) > 8192))
    return reject("BODY_TOO_LARGE", 413);
  let raw: string;
  try { raw = await request.text(); }
  catch { return reject("BODY_UNREADABLE", 400); }
  if (Buffer.byteLength(raw) > 8192)
    return reject("BODY_TOO_LARGE", 413);
  let parsed: unknown;
  try { parsed = JSON.parse(raw); }
  catch { return reject("JSON_INVALID", 400); }
  if (!object(parsed)) return reject("COMMAND_INVALID", 400);
  const input = inputFrom(parsed);
  if (!input) return reject("COMMAND_FIELDS_INVALID", 400);
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug,
    );
    if (!["OWNER", "ADMIN"].includes(membership.role))
      return reject("CASE_ACTION_PERMISSION_REQUIRED", 403);
    const result = await handoffDecisionCaseToRiskAction({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, input);
    return NextResponse.json({
      data: result,
      providerWrites: 0,
      independentlyVerifiedRemediation: false,
      customerConsentEstablished: false,
      cyberScoreV1Writes: 0,
    }, { headers: securityHeaders });
  } catch (error) {
    if (error instanceof CaseActionHandoffError) {
      const code = error.code;
      const forbidden = /PERMISSION|MEMBERSHIP|CROSS_TENANT/.test(code);
      return reject(code, forbidden ? 403 : 409);
    }
    return reject("CASE_ACTION_HANDOFF_UNAVAILABLE", 503);
  }
}
export async function GET() { return reject("POST_REQUIRED", 405); }
export async function PUT() { return reject("POST_REQUIRED", 405); }
export async function PATCH() { return reject("POST_REQUIRED", 405); }
export async function DELETE() { return reject("AUDIT_IMMUTABLE", 405); }
