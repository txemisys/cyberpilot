import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../../lib/organizations";
import {
  createInvestigationRecord, updateInvestigationRecord,
  readInvestigationRecord, listInvestigationRecords,
  exportInvestigationAudit,
} from "../../../../../../lib/incident-persisted-investigation-service";
import type { InvestigationReviewCommandAction } from
  "../../../../../../lib/incident-persisted-investigation-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer" };
function denied(code: string, status: number) {
  return NextResponse.json({ code, providerWrites: 0,
    providerOutcomeVerified: false }, { status, headers });
}
function failure(error: unknown) {
  const code = error instanceof Error &&
    /^(COORDINATION_|INVESTIGATION_)/.test(error.message) ?
      error.message : "INVESTIGATION_SERVICE_UNAVAILABLE";
  const status = /ROLE|MEMBERSHIP|DENIED/.test(code) ? 403 :
    /NOT_FOUND/.test(code) ? 404 :
    /CAS|DRIFT|CORRUPT|CONFLICT|REPLAY|CHANGED/.test(code) ? 409 :
    /UNAVAILABLE/.test(code) ? 503 : 400;
  return denied(code, status);
}
async function actor(context: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await context.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function parsedQuery(req: NextRequest) {
  const q = req.nextUrl.searchParams;
  if ([...q.keys()].some(x => !["recordId", "incidentId",
      "offset", "limit", "format"].includes(x)) ||
      [...new Set(q.keys())].some(x => q.getAll(x).length !== 1))
    throw Error("INVESTIGATION_QUERY_INVALID");
  const recordId = q.get("recordId");
  const incidentId = q.get("incidentId");
  if (!recordId && !incidentId || recordId && incidentId)
    throw Error("INVESTIGATION_QUERY_SELECTION_INVALID");
  const offset = q.get("offset") ?? "0";
  const limit = q.get("limit") ?? "30";
  if (!/^\d{1,5}$/.test(offset) || !/^\d{1,3}$/.test(limit))
    throw Error("INVESTIGATION_PAGING_INVALID");
  const format = q.get("format") ?? "page";
  if (!["page", "audit"].includes(format))
    throw Error("INVESTIGATION_FORMAT_INVALID");
  return { recordId, incidentId, offset: Number(offset),
    limit: Number(limit), format };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const user = await actor(context);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(user.role))
      return denied("INVESTIGATION_ROLE_DENIED", 403);
    const query = parsedQuery(req);
    if (query.recordId) {
      if (query.format === "audit") {
        const result = await exportInvestigationAudit(user, query.recordId);
        return new NextResponse(JSON.stringify(result), {
          headers: { ...headers, "Content-Type": "application/json",
            "Content-Disposition":
              'attachment; filename="cyberpilot-investigation-audit.json"' },
        });
      }
      return NextResponse.json(
        await readInvestigationRecord(user, query.recordId), { headers });
    }
    if (query.format !== "page")
      return denied("INVESTIGATION_FORMAT_INVALID", 400);
    return NextResponse.json(await listInvestigationRecords(
      user, query.incidentId!, query.offset, query.limit), { headers });
  } catch (e) { return failure(e); }
}
export async function POST(req: NextRequest, context: Context) {
  try {
    const user = await actor(context);
    if (!["OWNER", "ADMIN"].includes(user.role))
      return denied("INVESTIGATION_ROLE_DENIED", 403);
    const data = await req.json() as {
      operation?: unknown; recordId?: unknown; incidentId?: unknown;
      commandId?: unknown; expectedRevision?: unknown;
      action?: InvestigationReviewCommandAction;
    };
    if (!data || !["CREATE", "MUTATE"].includes(String(data.operation)) ||
        typeof data.recordId !== "string" ||
        typeof data.commandId !== "string")
      return denied("INVESTIGATION_COMMAND_INVALID", 400);
    if (data.operation === "CREATE") {
      if (typeof data.incidentId !== "string")
        return denied("INVESTIGATION_INCIDENT_INVALID", 400);
      return NextResponse.json(await createInvestigationRecord(
        user, data.recordId, data.commandId, data.incidentId),
        { status: 201, headers });
    }
    if (!Number.isSafeInteger(data.expectedRevision) || !data.action)
      return denied("INVESTIGATION_MUTATION_INVALID", 400);
    return NextResponse.json(await updateInvestigationRecord(user, {
      recordId: data.recordId, commandId: data.commandId,
      expectedRevision: data.expectedRevision as number,
      action: data.action,
    }), { headers });
  } catch (e) { return failure(e); }
}
export async function PATCH() { return denied("INVESTIGATION_POST_ONLY", 405); }
export async function PUT() { return denied("INVESTIGATION_POST_ONLY", 405); }
export async function DELETE() { return denied("INVESTIGATION_DELETE_DENIED", 405); }
