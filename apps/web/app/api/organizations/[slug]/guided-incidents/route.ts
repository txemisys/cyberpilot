import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { createGuidedIncident, updateGuidedIncident, readGuidedIncidents,
  readGuidedIncidentDossier, readGuidedIncidentPortfolio,
  IncidentServiceError } from "../../../../../lib/incident-case-service";
import { INCIDENT_TYPES, type IncidentType } from "../../../../../lib/incident-playbook-catalog";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff" };
function denied(code: string, status: number) {
  return NextResponse.json({ code, providerWrites: 0,
    containmentVerified: false }, { status, headers });
}
async function actor(ctx: Context) {
  const { session, membership } = await requireOrganizationAccess((await ctx.params).slug);
  return { organizationId: membership.organization.id, userId: session.user.id,
    role: membership.role };
}
function originOk(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}
function id(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function error(e: unknown, write = false) {
  if (e instanceof IncidentServiceError) {
    const status = /CONCURRENT|REVISION|NOT_STARTABLE|NOT_REPORTABLE|STEP_|PROOF_|APPROVAL_/.test(e.code) ?
      409 : /ROLE|MEMBERSHIP|TENANT|DENIED/.test(e.code) ? 403 : 400;
    return denied(e.code, status);
  }
  return denied(write ? "INCIDENT_WRITE_UNAVAILABLE" : "INCIDENT_READ_UNAVAILABLE", 503);
}
export async function GET(request: NextRequest, context: Context) {
  if (!originOk(request)) return denied("CROSS_ORIGIN", 403);
  try {
    const current = await actor(context);
    if (current.role === "MEMBER") return denied("INCIDENT_REVIEW_ROLE_REQUIRED", 403);
    const params = new URL(request.url).searchParams;
    if (params.get("portfolio") === "true") {
      return NextResponse.json({ data: await readGuidedIncidentPortfolio(current),
        providerWrites: 0 }, { headers });
    }
    const incidentId = params.get("incidentId");
    if (incidentId) {
      const format = params.get("format") ?? "JSON";
      if (!id(incidentId) || !["JSON", "CSV", "MARKDOWN"].includes(format))
        return denied("INCIDENT_DOSSIER_INPUT_INVALID", 400);
      return NextResponse.json({
        data: await readGuidedIncidentDossier(current, incidentId,
          format as "JSON" | "CSV" | "MARKDOWN"), providerWrites: 0,
      }, { headers });
    }
    const type = params.get("type"), limit = params.get("limit"),
      offset = params.get("offset");
    if (type && !INCIDENT_TYPES.includes(type as IncidentType) ||
        limit !== null && !/^\d+$/.test(limit) ||
        offset !== null && !/^\d+$/.test(offset))
      return denied("INCIDENT_FILTER_INVALID", 400);
    const data = await readGuidedIncidents(current, {
      ...(type ? { type: type as IncidentType } : {}),
      ...(limit !== null ? { limit: Number(limit) } : {}),
      ...(offset !== null ? { offset: Number(offset) } : {}),
      includeHistory: params.get("history") === "true",
    });
    return NextResponse.json({ data, providerWrites: 0 }, { headers });
  } catch (e) { return error(e); }
}
export async function POST(request: NextRequest, context: Context) {
  if (!originOk(request)) return denied("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json")
    return denied("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 16000))
    return denied("INCIDENT_BODY_TOO_LARGE", 413);
  try {
    const current = await actor(context);
    if (!["OWNER", "ADMIN"].includes(current.role))
      return denied("INCIDENT_MANAGER_ROLE_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 16000) return denied("INCIDENT_BODY_TOO_LARGE", 413);
    let parsed: unknown;
    try { parsed = JSON.parse(raw); }
    catch { return denied("INCIDENT_INVALID_JSON", 400); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return denied("INCIDENT_COMMAND_INVALID", 400);
    const cmd = parsed as Record<string, unknown>;
    if (cmd.operation === "CREATE") {
      if (Object.keys(cmd).some(k => !["operation", "type", "title",
        "subjectReference", "ownerUserId", "relatedDecisionCaseId"].includes(k)))
        return denied("INCIDENT_UNKNOWN_FIELD", 400);
      if (!INCIDENT_TYPES.includes(cmd.type as IncidentType) ||
          typeof cmd.title !== "string" ||
          typeof cmd.subjectReference !== "string" ||
          cmd.ownerUserId !== null && !id(cmd.ownerUserId) ||
          cmd.relatedDecisionCaseId !== null && !id(cmd.relatedDecisionCaseId))
        return denied("INCIDENT_CREATE_INPUT_INVALID", 400);
      return NextResponse.json({ data: await createGuidedIncident(current, {
        type: cmd.type as IncidentType, title: cmd.title,
        subjectReference: cmd.subjectReference,
        ownerUserId: cmd.ownerUserId as string | null,
        relatedDecisionCaseId: cmd.relatedDecisionCaseId as string | null,
      }), providerWrites: 0 }, { status: 201, headers });
    }
    if (cmd.operation !== "UPDATE" || Object.keys(cmd).some(k =>
      !["operation", "incidentId", "expectedRevision", "kind", "stepId",
        "reason", "ownerUserId", "evidence", "approval"].includes(k)))
      return denied("INCIDENT_COMMAND_INVALID", 400);
    if (!id(cmd.incidentId) || !Number.isSafeInteger(cmd.expectedRevision) ||
        typeof cmd.kind !== "string")
      return denied("INCIDENT_UPDATE_INPUT_INVALID", 400);
    return NextResponse.json({ data: await updateGuidedIncident(current, {
      incidentId: cmd.incidentId, expectedRevision: cmd.expectedRevision as number,
      kind: cmd.kind as Parameters<typeof updateGuidedIncident>[1]["kind"],
      ...(Object.hasOwn(cmd, "stepId") ? { stepId: cmd.stepId as string } : {}),
      ...(Object.hasOwn(cmd, "reason") ? { reason: cmd.reason as string } : {}),
      ...(Object.hasOwn(cmd, "ownerUserId") ?
        { ownerUserId: cmd.ownerUserId as string | null } : {}),
      ...(Object.hasOwn(cmd, "evidence") ?
        { evidence: cmd.evidence as NonNullable<Parameters<typeof updateGuidedIncident>[1]["evidence"]> } : {}),
      ...(Object.hasOwn(cmd, "approval") ?
        { approval: cmd.approval as NonNullable<Parameters<typeof updateGuidedIncident>[1]["approval"]> } : {}),
    }), providerWrites: 0 }, { headers });
  } catch (e) { return error(e, true); }
}
export async function PUT() { return denied("INCIDENT_METHOD_NOT_ALLOWED", 405); }
export async function DELETE() { return denied("INCIDENT_HISTORY_IMMUTABLE", 405); }
