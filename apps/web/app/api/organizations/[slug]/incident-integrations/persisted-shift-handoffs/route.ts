import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../../lib/organizations";
import {
  createPersistedShiftHandoff, mutatePersistedShiftHandoff,
  readPersistedShiftHandoff, listPersistedShiftHandoffs,
  exportPersistedShiftHandoffAudit,
} from "../../../../../../lib/incident-persisted-shift-handoff-service";
import type { ShiftHandoffAction } from
  "../../../../../../lib/incident-persisted-shift-handoff-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
function deny(code: string, status: number) {
  return NextResponse.json({ code, externalWrites: 0,
    providerOutcomeVerified: false }, { status, headers });
}
function failure(e: unknown) {
  const code = e instanceof Error &&
    /^(COORDINATION_|SHIFT_)/.test(e.message) ?
    e.message : "SHIFT_HANDOFF_SERVICE_UNAVAILABLE";
  const status = /DENIED|PARTICIPANT|MEMBERSHIP|ROLE|AUTHORIZED/.test(code) ?
      403 : /NOT_FOUND/.test(code) ? 404 :
    /STALE|CAS|CONFLICT|CHANGED|REPLAY|CORRUPT/.test(code) ? 409 :
    /UNAVAILABLE/.test(code) ? 503 : 400;
  return deny(code, status);
}
async function currentActor(context: Context) {
  const { session, membership } = await requireOrganizationAccess(
    (await context.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function parseQuery(req: NextRequest) {
  const q = req.nextUrl.searchParams;
  if ([...q.keys()].some(k => !["recordId", "incidentId",
      "offset", "limit", "audit"].includes(k)) ||
      [...new Set(q.keys())].some(k => q.getAll(k).length !== 1))
    throw Error("SHIFT_HANDOFF_QUERY_INVALID");
  const recordId = q.get("recordId");
  const incidentId = q.get("incidentId");
  if (Boolean(recordId) === Boolean(incidentId))
    throw Error("SHIFT_HANDOFF_SELECTION_INVALID");
  const offset = q.get("offset") ?? "0";
  const limit = q.get("limit") ?? "30";
  if (!/^\d{1,5}$/.test(offset) || !/^\d{1,3}$/.test(limit) ||
      q.has("audit") && q.get("audit") !== "1")
    throw Error("SHIFT_HANDOFF_PAGE_INVALID");
  return { recordId, incidentId, audit: q.get("audit") === "1",
    offset: Number(offset), limit: Number(limit) };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const actor = await currentActor(context);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
      return deny("SHIFT_HANDOFF_ROLE_DENIED", 403);
    const q = parseQuery(req);
    if (q.recordId && q.audit) {
      const result = await exportPersistedShiftHandoffAudit(
        actor, q.recordId);
      return new NextResponse(JSON.stringify(result), {
        headers: { ...headers, "Content-Type": "application/json",
          "Content-Disposition":
            'attachment; filename="cyberpilot-shift-handoff-audit.json"' },
      });
    }
    if (q.recordId)
      return NextResponse.json(await readPersistedShiftHandoff(
        actor, q.recordId), { headers });
    if (q.audit) return deny("SHIFT_HANDOFF_AUDIT_ID_MISSING", 400);
    return NextResponse.json(await listPersistedShiftHandoffs(
      actor, q.incidentId!, q.offset, q.limit), { headers });
  } catch (e) { return failure(e); }
}
export async function POST(req: NextRequest, context: Context) {
  try {
    const actor = await currentActor(context);
    if (!["OWNER", "ADMIN"].includes(actor.role))
      return deny("SHIFT_HANDOFF_ROLE_DENIED", 403);
    const body = await req.json() as {
      operation?: string; recordId?: string; commandId?: string;
      incidentId?: string; shiftId?: string;
      incomingUserId?: string; startsAt?: string; endsAt?: string;
      expectedRevision?: number; action?: ShiftHandoffAction;
    };
    if (!body || !["CREATE", "MUTATE"].includes(body.operation ?? "") ||
        typeof body.recordId !== "string" ||
        typeof body.commandId !== "string")
      return deny("SHIFT_HANDOFF_COMMAND_INVALID", 400);
    if (body.operation === "CREATE") {
      if (![body.incidentId, body.shiftId, body.incomingUserId,
          body.startsAt, body.endsAt].every(x => typeof x === "string"))
        return deny("SHIFT_HANDOFF_CREATE_INVALID", 400);
      const result = await createPersistedShiftHandoff(actor, {
        recordId: body.recordId, commandId: body.commandId,
        incidentId: body.incidentId!, shiftId: body.shiftId!,
        incomingUserId: body.incomingUserId!,
        startsAt: body.startsAt!, endsAt: body.endsAt!,
      });
      return NextResponse.json(result, { status: 201, headers });
    }
    if (!Number.isSafeInteger(body.expectedRevision) || !body.action)
      return deny("SHIFT_HANDOFF_MUTATION_INVALID", 400);
    return NextResponse.json(await mutatePersistedShiftHandoff(actor, {
      recordId: body.recordId, commandId: body.commandId,
      expectedRevision: body.expectedRevision as number,
      action: body.action,
    }), { headers });
  } catch (e) { return failure(e); }
}
export async function PATCH() { return deny("SHIFT_HANDOFF_POST_ONLY", 405); }
export async function PUT() { return deny("SHIFT_HANDOFF_POST_ONLY", 405); }
export async function DELETE() { return deny("SHIFT_HANDOFF_DELETE_DENIED", 405); }
