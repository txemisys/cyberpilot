import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { reviewIncidentRemediationIntegration,
  discoverIncidentRemediationReferences, readIncidentRemediationChecklist,
  IncidentRemediationIntegrationError }
  from "../../../../../lib/incident-integrated-remediation-service";
import { exportRemediationIntegration, planRemediationHandoffs,
  summarizeRemediationReadiness, buildIncidentRemediationDecisions }
  from "../../../../../lib/incident-integrated-remediation-operations";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
function deny(code: string, status: number) {
  return NextResponse.json({ code, providerWrites: 0,
    liveExecutionAuthorized: false }, { status, headers });
}
async function reviewer(ctx: Context) {
  const { membership, session } = await requireOrganizationAccess((await ctx.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function failed(e: unknown) {
  if (e instanceof IncidentRemediationIntegrationError)
    return deny(e.code, /TENANT|ROLE|MEMBERSHIP/.test(e.code) ? 403 : 400);
  return deny("REMEDIATION_INTEGRATION_UNAVAILABLE", 503);
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const actor = await reviewer(context);
    if (actor.role === "MEMBER") return deny("REVIEWER_ROLE_REQUIRED", 403);
    const q = new URL(request.url).searchParams;
    if ([...q.keys()].some(k => !["mode", "incidentId",
      "offset", "limit"].includes(k)))
      return deny("UNKNOWN_FIELD", 400);
    const mode = q.get("mode") ?? "inventory";
    if (mode === "checklist") {
      const id = q.get("incidentId");
      if (!id) return deny("INCIDENT_REQUIRED", 400);
      return NextResponse.json({ data: await readIncidentRemediationChecklist(actor, id),
        providerWrites: 0 }, { headers });
    }
    if (mode !== "inventory") return deny("MODE_INVALID", 400);
    const offset = q.get("offset"), limit = q.get("limit");
    if (offset && !/^\d{1,5}$/.test(offset) ||
        limit && !/^\d{1,3}$/.test(limit))
      return deny("PAGING_INVALID", 400);
    return NextResponse.json({
      data: await discoverIncidentRemediationReferences(actor, {
        ...(offset !== null ? { offset: Number(offset) } : {}),
        ...(limit !== null ? { limit: Number(limit) } : {}),
      }), providerWrites: 0,
    }, { headers });
  } catch (e) { return failed(e); }
}
export async function POST(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return deny("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json")
    return deny("JSON_REQUIRED", 415);
  const size = request.headers.get("content-length");
  if (size && (!/^\d+$/.test(size) || Number(size) > 16000))
    return deny("BODY_TOO_LARGE", 413);
  try {
    const actor = await reviewer(context);
    if (actor.role === "MEMBER") return deny("REVIEWER_ROLE_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 16000) return deny("BODY_TOO_LARGE", 413);
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return deny("JSON_INVALID", 400); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return deny("BODY_INVALID", 400);
    const command = parsed as Record<string, unknown>;
    if (Object.keys(command).some(k =>
      !["incidentId", "expectedIncidentRevision", "remediationIds",
        "findingIds", "workItemIds", "approvalMaxAgeHours", "format"].includes(k)) ||
        typeof command.incidentId !== "string" ||
        !Number.isSafeInteger(command.expectedIncidentRevision) ||
        !Array.isArray(command.remediationIds) ||
        !Array.isArray(command.findingIds) ||
        !Array.isArray(command.workItemIds))
      return deny("REMEDIATION_SELECTION_INVALID", 400);
    const format = command.format;
    if (format !== undefined && !["JSON", "CSV", "MARKDOWN"].includes(String(format)))
      return deny("EXPORT_FORMAT_INVALID", 400);
    const result = await reviewIncidentRemediationIntegration(actor, {
      incidentId: command.incidentId,
      expectedIncidentRevision: command.expectedIncidentRevision as number,
      remediationIds: command.remediationIds as string[],
      findingIds: command.findingIds as string[],
      workItemIds: command.workItemIds as string[],
      ...(command.approvalMaxAgeHours !== undefined ?
        { approvalMaxAgeHours: command.approvalMaxAgeHours as number } : {}),
    });
    const readiness = result.readiness;
    return NextResponse.json({ data: {
      ...result, plan: planRemediationHandoffs(readiness),
      matrix: summarizeRemediationReadiness(readiness),
      decisions: buildIncidentRemediationDecisions(readiness),
      artifact: format ? exportRemediationIntegration(readiness,
        format as "JSON" | "CSV" | "MARKDOWN") : null,
    }, providerWrites: 0, remediationExecutorCalled: false }, { headers });
  } catch (e) { return failed(e); }
}
export async function PUT() { return deny("NO_EXECUTOR_ON_THIS_ROUTE", 405); }
export async function PATCH() { return deny("NO_EXECUTOR_ON_THIS_ROUTE", 405); }
export async function DELETE() { return deny("NO_EXECUTOR_ON_THIS_ROUTE", 405); }
