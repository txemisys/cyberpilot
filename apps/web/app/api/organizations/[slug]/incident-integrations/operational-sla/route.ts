import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { IncidentSlaServiceError,
  readIncidentOperationalSla, exportIncidentOperationalSla,
} from "../../../../../../lib/incident-operational-sla-service";
import type { OperationalSlaPolicy } from
  "../../../../../../lib/incident-operational-sla-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const denied = (code: string, status: number) =>
  NextResponse.json({ code, providerWrites: 0,
    externalServiceGuarantee: false }, { status, headers });
function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
async function getActor(ctx: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await ctx.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
async function parse(req: NextRequest) {
  if (req.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json") throw Error("SLA_JSON_REQUIRED");
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin)
    throw Error("SLA_CROSS_ORIGIN_REQUEST");
  const length = req.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 16000))
    throw Error("SLA_REQUEST_TOO_LARGE");
  const body = await req.text();
  if (Buffer.byteLength(body) > 16000)
    throw Error("SLA_REQUEST_TOO_LARGE");
  let parsed: unknown;
  try { parsed = JSON.parse(body); }
  catch { throw Error("SLA_JSON_INVALID"); }
  if (!isRecord(parsed) || Object.keys(parsed).some(k =>
      !["incidentId", "policy", "from", "to", "mode", "maxPages"]
        .includes(k))) throw Error("SLA_REQUEST_INVALID");
  if (typeof parsed.incidentId !== "string" ||
      !isRecord(parsed.policy) ||
      typeof parsed.policy.policyId !== "string")
    throw Error("SLA_FIELDS_REQUIRED");
  if (parsed.mode !== undefined &&
      !["report", "audit"].includes(String(parsed.mode)))
    throw Error("SLA_MODE_UNSUPPORTED");
  if (parsed.maxPages !== undefined &&
      (!Number.isSafeInteger(parsed.maxPages) ||
        Number(parsed.maxPages) < 1 || Number(parsed.maxPages) > 30))
    throw Error("SLA_PAGE_BUDGET_INVALID");
  return {
    incidentId: parsed.incidentId,
    policy: parsed.policy as OperationalSlaPolicy,
    from: parsed.from as string | undefined,
    to: parsed.to as string | undefined,
    maxPages: parsed.maxPages as number | undefined,
    mode: parsed.mode as "report" | "audit" | undefined,
  };
}
export async function POST(req: NextRequest, ctx: Context) {
  try {
    const actor = await getActor(ctx);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
      return denied("SLA_REVIEWER_REQUIRED", 403);
    const args = await parse(req);
    if (args.mode === "audit") {
      const exported = await exportIncidentOperationalSla(
        actor, args.incidentId, args.policy, "audit");
      return new NextResponse(exported.content, {
        headers: { ...headers,
          "Content-Type": exported.contentType,
          "X-SLA-Digest": exported.digest },
      });
    }
    return NextResponse.json(
      await readIncidentOperationalSla(
        actor, args.incidentId, args.policy,
        { ...(args.from !== undefined ? { from: args.from } : {}),
          ...(args.to !== undefined ? { to: args.to } : {}),
          ...(args.maxPages !== undefined ?
            { maxPages: args.maxPages } : {}) }),
      { headers });
  } catch (error) {
    const code = error instanceof IncidentSlaServiceError ? error.code :
      error instanceof Error && error.message.startsWith("SLA_") ?
        error.message : "SLA_SERVICE_UNAVAILABLE";
    const status = /REVIEWER|MEMBERSHIP/.test(code) ? 403 :
      /NOT_FOUND/.test(code) ? 404 :
      /TAMPERED|CONFLICT/.test(code) ? 409 :
      /UNAVAILABLE/.test(code) ? 503 : 400;
    return denied(code, status);
  }
}
export async function GET() { return denied("SLA_POST_REQUIRED", 405); }
export async function PUT() { return denied("SLA_READ_ONLY", 405); }
export async function PATCH() { return denied("SLA_READ_ONLY", 405); }
export async function DELETE() { return denied("SLA_READ_ONLY", 405); }
