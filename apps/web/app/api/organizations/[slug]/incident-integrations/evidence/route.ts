import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { reviewIncidentIntegratedEvidence, reviewIncidentLinkedDecision,
  inspectIncidentDecisionCase, readIncidentEvidenceInventory,
  IncidentIntegrationError } from "../../../../../../lib/incident-integrated-evidence-service";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
function denied(code: string, status: number) {
  return NextResponse.json({ code, providerWrites: 0,
    securityOutcomeProven: false }, { status, headers });
}
function scope(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}
async function reviewer(context: Context) {
  const { membership, session } = await requireOrganizationAccess((await context.params).slug);
  return { organizationId: membership.organization.id, userId: session.user.id,
    role: membership.role };
}
function failure(e: unknown) {
  if (e instanceof IncidentIntegrationError)
    return denied(e.code, /TENANT|ROLE|MEMBERSHIP/.test(e.code) ? 403 : 400);
  return denied("INCIDENT_INTEGRATED_EVIDENCE_UNAVAILABLE", 503);
}
export async function GET(request: NextRequest, context: Context) {
  if (!scope(request)) return denied("CROSS_ORIGIN", 403);
  try {
    const actor = await reviewer(context);
    if (actor.role === "MEMBER") return denied("REVIEWER_ROLE_REQUIRED", 403);
    const query = new URL(request.url).searchParams;
    if ([...query.keys()].some(k =>
      !["mode", "incidentId", "kind", "offset", "limit"].includes(k)))
      return denied("UNKNOWN_QUERY_FIELD", 400);
    const mode = query.get("mode") ?? "inventory";
    const incidentId = query.get("incidentId");
    if (mode === "decision" || mode === "linked") {
      if (!incidentId) return denied("INCIDENT_ID_REQUIRED", 400);
      const data = mode === "decision" ?
        await inspectIncidentDecisionCase(actor, incidentId) :
        await reviewIncidentLinkedDecision(actor, incidentId);
      return NextResponse.json({ data, providerWrites: 0 }, { headers });
    }
    if (mode !== "inventory") return denied("MODE_INVALID", 400);
    const kind = query.get("kind");
    if (kind && !["EVIDENCE", "FINDING", "DECISION"].includes(kind))
      return denied("SOURCE_KIND_INVALID", 400);
    const limit = query.get("limit"), offset = query.get("offset");
    if (limit && !/^\d{1,3}$/.test(limit) ||
        offset && !/^\d{1,5}$/.test(offset))
      return denied("SOURCE_PAGING_INVALID", 400);
    const data = await readIncidentEvidenceInventory(actor, {
      ...(kind ? { kind: kind as "EVIDENCE" | "FINDING" | "DECISION" } : {}),
      ...(limit !== null ? { limit: Number(limit) } : {}),
      ...(offset !== null ? { offset: Number(offset) } : {}),
    });
    return NextResponse.json({ data, providerWrites: 0 }, { headers });
  } catch (e) { return failure(e); }
}
export async function POST(request: NextRequest, context: Context) {
  if (!scope(request)) return denied("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json")
    return denied("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 12000))
    return denied("BODY_TOO_LARGE", 413);
  try {
    const actor = await reviewer(context);
    if (actor.role === "MEMBER") return denied("REVIEWER_ROLE_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 12000) return denied("BODY_TOO_LARGE", 413);
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return denied("JSON_INVALID", 400); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return denied("REQUEST_INVALID", 400);
    const data = parsed as Record<string, unknown>;
    if (Object.keys(data).some(k =>
      !["incidentId", "evidenceIds", "findingIds", "decisionIds",
        "maxAgeHours"].includes(k)) ||
        typeof data.incidentId !== "string" ||
        !Array.isArray(data.evidenceIds) || !Array.isArray(data.findingIds) ||
        !Array.isArray(data.decisionIds))
      return denied("SELECTION_INVALID", 400);
    const result = await reviewIncidentIntegratedEvidence(actor, {
      incidentId: data.incidentId,
      evidenceIds: data.evidenceIds as string[],
      findingIds: data.findingIds as string[],
      decisionIds: data.decisionIds as string[],
      ...(data.maxAgeHours !== undefined ?
        { maxAgeHours: data.maxAgeHours as number } : {}),
    });
    return NextResponse.json({ data: result, providerWrites: 0,
      evidenceLinkedToCase: false }, { headers });
  } catch (e) { return failure(e); }
}
export async function PUT() { return denied("READ_ONLY_INTEGRATION", 405); }
export async function DELETE() { return denied("READ_ONLY_INTEGRATION", 405); }
