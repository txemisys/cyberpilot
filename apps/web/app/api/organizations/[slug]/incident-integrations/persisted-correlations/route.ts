import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../../lib/organizations";
import {
  createCorrelationBoard, mutateCorrelationBoard,
  readCorrelationBoard, listCorrelationBoards, exportCorrelationBoardAudit,
} from "../../../../../../lib/incident-persisted-correlation-service";
import type { CorrelationBoardAction } from
  "../../../../../../lib/incident-persisted-correlation-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
function denied(code: string, status: number) {
  return NextResponse.json({
    code, externalActions: 0, identityVerified: false,
  }, { status, headers });
}
function errorResponse(error: unknown) {
  const code = error instanceof Error &&
    /^(COORDINATION_|CORRELATION_)/.test(error.message) ?
      error.message : "CORRELATION_REVIEW_UNAVAILABLE";
  const status = /DENIED|MEMBERSHIP|ROLE|AUTHORIZED/.test(code) ? 403 :
    /NOT_FOUND/.test(code) ? 404 :
    /CAS|CONFLICT|CHANGED|CORRUPT|REPLAY/.test(code) ? 409 :
    /UNAVAILABLE/.test(code) ? 503 : 400;
  return denied(code, status);
}
async function currentActor(context: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await context.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
function query(req: NextRequest) {
  const q = req.nextUrl.searchParams;
  if ([...q.keys()].some(k => !["recordId", "incidentId",
      "offset", "limit", "audit"].includes(k)) ||
      [...new Set(q.keys())].some(k => q.getAll(k).length !== 1))
    throw Error("CORRELATION_REVIEW_QUERY_INVALID");
  const recordId = q.get("recordId");
  const incidentId = q.get("incidentId");
  if (Boolean(recordId) === Boolean(incidentId))
    throw Error("CORRELATION_REVIEW_SELECTION_INVALID");
  if (q.has("audit") && q.get("audit") !== "1")
    throw Error("CORRELATION_REVIEW_AUDIT_FORMAT_INVALID");
  const offset = q.get("offset") ?? "0";
  const limit = q.get("limit") ?? "30";
  if (!/^\d{1,5}$/.test(offset) || !/^\d{1,3}$/.test(limit))
    throw Error("CORRELATION_REVIEW_PAGING_INVALID");
  return { recordId, incidentId, audit: q.has("audit"),
    offset: Number(offset), limit: Number(limit) };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const actor = await currentActor(context);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
      return denied("CORRELATION_REVIEW_ROLE_DENIED", 403);
    const q = query(req);
    if (q.recordId && q.audit) {
      const data = await exportCorrelationBoardAudit(actor, q.recordId);
      return new NextResponse(JSON.stringify(data), {
        headers: { ...headers, "Content-Type": "application/json",
          "Content-Disposition":
            'attachment; filename="cyberpilot-correlation-audit.json"' },
      });
    }
    if (q.recordId)
      return NextResponse.json(await readCorrelationBoard(actor, q.recordId),
        { headers });
    if (q.audit) return denied("CORRELATION_AUDIT_ID_REQUIRED", 400);
    return NextResponse.json(await listCorrelationBoards(
      actor, q.incidentId!, q.offset, q.limit), { headers });
  } catch (e) { return errorResponse(e); }
}
export async function POST(req: NextRequest, context: Context) {
  try {
    const actor = await currentActor(context);
    if (!["OWNER", "ADMIN"].includes(actor.role))
      return denied("CORRELATION_REVIEW_ROLE_DENIED", 403);
    const body = await req.json() as {
      operation?: string; recordId?: string; commandId?: string;
      selectedIncidentIds?: string[]; expectedRevision?: number;
      action?: CorrelationBoardAction;
    };
    if (!body || !["CREATE", "MUTATE"].includes(body.operation ?? "") ||
        typeof body.recordId !== "string" ||
        typeof body.commandId !== "string")
      return denied("CORRELATION_REVIEW_COMMAND_INVALID", 400);
    if (body.operation === "CREATE") {
      if (!Array.isArray(body.selectedIncidentIds))
        return denied("CORRELATION_REVIEW_SELECTION_INVALID", 400);
      const result = await createCorrelationBoard(
        actor, body.recordId, body.commandId, body.selectedIncidentIds);
      return NextResponse.json(result, { status: 201, headers });
    }
    if (!Number.isSafeInteger(body.expectedRevision) || !body.action)
      return denied("CORRELATION_REVIEW_MUTATION_INVALID", 400);
    return NextResponse.json(await mutateCorrelationBoard(actor, {
      recordId: body.recordId, commandId: body.commandId,
      expectedRevision: body.expectedRevision as number, action: body.action,
    }), { headers });
  } catch (e) { return errorResponse(e); }
}
export async function PUT() { return denied("CORRELATION_REVIEW_READ_ONLY", 405); }
export async function PATCH() { return denied("CORRELATION_REVIEW_POST_ONLY", 405); }
export async function DELETE() { return denied("CORRELATION_REVIEW_DELETE_DENIED", 405); }
