import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  prepareIncidentEscalationPlan, admitIncidentEscalationDispatch,
  exportIncidentEscalationPlan, IncidentEscalationServiceError,
} from "../../../../../../lib/incident-escalation-dispatch-service";
import type { EscalationPolicy } from
  "../../../../../../lib/incident-escalation-dispatch-domain";

type Context = { params: Promise<{ slug: string }> };
const responseHeaders = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const deny = (code: string, status: number) => NextResponse.json({
  code, providerWrites: 0, notificationsDispatched: 0,
}, { status, headers: responseHeaders });
function record(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}
async function actor(ctx: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await ctx.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
async function readBody(req: NextRequest) {
  if (req.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json") throw Error("ESCALATION_JSON_REQUIRED");
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin)
    throw Error("ESCALATION_CROSS_ORIGIN_DENIED");
  const length = req.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 16000))
    throw Error("ESCALATION_REQUEST_TOO_LARGE");
  const text = await req.text();
  if (Buffer.byteLength(text) > 16000)
    throw Error("ESCALATION_REQUEST_TOO_LARGE");
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw Error("ESCALATION_JSON_INVALID"); }
  if (!record(value) || Object.keys(value).some(k =>
      !["incidentId", "policy", "mode", "format",
        "idempotencyKey", "boardDigest", "expectedIncidentRevision"]
        .includes(k)) ||
      typeof value.incidentId !== "string" ||
      !record(value.policy))
    throw Error("ESCALATION_REQUEST_INVALID");
  return {
    incidentId: value.incidentId,
    policy: value.policy as EscalationPolicy,
    mode: value.mode ?? "PLAN",
    format: value.format ?? "json",
    idempotencyKey: value.idempotencyKey,
    boardDigest: value.boardDigest,
    expectedIncidentRevision: value.expectedIncidentRevision,
  };
}
export async function POST(req: NextRequest, ctx: Context) {
  try {
    const user = await actor(ctx);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(user.role))
      return deny("ESCALATION_ROLE_DENIED", 403);
    const value = await readBody(req);
    if (value.mode === "PLAN") {
      return NextResponse.json(
        await prepareIncidentEscalationPlan(
          user, value.incidentId, value.policy),
        { headers: responseHeaders });
    }
    if (value.mode === "EXPORT") {
      if (!["json", "csv"].includes(String(value.format)))
        return deny("ESCALATION_FORMAT_INVALID", 400);
      const result = await exportIncidentEscalationPlan(
        user, value.incidentId, value.policy,
        value.format as "csv" | "json");
      return new NextResponse(result.content, {
        headers: { ...responseHeaders,
          "Content-Type": result.contentType,
          "X-Escalation-Plan-Digest": result.digest },
      });
    }
    if (value.mode === "ADMIT") {
      if (!["OWNER", "ADMIN"].includes(user.role))
        return deny("ESCALATION_WRITER_REQUIRED", 403);
      if (typeof value.idempotencyKey !== "string" ||
          typeof value.boardDigest !== "string" ||
          !Number.isSafeInteger(value.expectedIncidentRevision))
        return deny("ESCALATION_ADMISSION_FIELDS_REQUIRED", 400);
      return NextResponse.json(
        await admitIncidentEscalationDispatch(user, value.incidentId,
          value.policy, {
            idempotencyKey: value.idempotencyKey,
            boardDigest: value.boardDigest,
            expectedIncidentRevision: value.expectedIncidentRevision as number,
          }), { headers: responseHeaders });
    }
    return deny("ESCALATION_MODE_INVALID", 400);
  } catch (e) {
    const code = e instanceof IncidentEscalationServiceError ? e.code :
      e instanceof Error && e.message.startsWith("ESCALATION_") ?
        e.message : "ESCALATION_SERVICE_UNAVAILABLE";
    const status = /ROLE|MEMBERSHIP|REVOKED|WRITER/.test(code) ? 403 :
      /NOT_FOUND/.test(code) ? 404 :
      /CAS|CONFLICT|INTEGRITY|TAMPER/.test(code) ? 409 :
      /UNAVAILABLE/.test(code) ? 503 : 400;
    return deny(code, status);
  }
}
export async function GET() { return deny("ESCALATION_POST_REQUIRED", 405); }
export async function PATCH() { return deny("ESCALATION_POST_REQUIRED", 405); }
export async function PUT() { return deny("ESCALATION_POST_REQUIRED", 405); }
export async function DELETE() { return deny("ESCALATION_DELETE_DENIED", 405); }
