import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { OperationalTimelineError, readOperationalTimeline,
  exportOperationalTimeline } from "../../../../../../lib/incident-operational-timeline-service";
import { validateTimelineQuery, type TimelineQuery,
  type TimelineSource, type TimelineIntegrity } from "../../../../../../lib/incident-operational-timeline-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer" };
function denied(code: string, status: number) {
  return NextResponse.json({
    code, externalActions: 0, providerOutcomesVerified: false,
  }, { status, headers });
}
async function getActor(context: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await context.params).slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
function maybeCsv(req: NextRequest, value: string, digest: string,
  mime: string) {
  const disposition = req.nextUrl.searchParams.get("download") === "1" ?
    'attachment; filename="cyberpilot-incident-timeline.csv"' :
    'inline; filename="cyberpilot-incident-timeline.csv"';
  return new NextResponse(value, {
    headers: { ...headers, "Content-Type": mime,
      "Content-Disposition": disposition, "X-Timeline-Digest": digest },
  });
}
function parseQuery(params: URLSearchParams): {
  incidentId: string; query: TimelineQuery;
  format: "json" | "csv" | "page";
} {
  const permitted = ["incidentId", "source", "actorUserId",
    "from", "to", "operation", "integrity", "limit", "cursor",
    "format", "download"];
  if ([...params.keys()].some(k => !permitted.includes(k)))
    throw Error("TIMELINE_QUERY_FIELD_UNKNOWN");
  if ([...new Set([...params.keys()])].some(k =>
    params.getAll(k).length !== 1 &&
    !["source", "integrity"].includes(k)))
    throw Error("TIMELINE_QUERY_DUPLICATE_FIELD");
  const incidentId = params.get("incidentId");
  if (!incidentId) throw Error("TIMELINE_INCIDENT_REQUIRED");
  const format = params.get("format") ?? "page";
  if (!["page", "json", "csv"].includes(format))
    throw Error("TIMELINE_FORMAT_INVALID");
  const rawLimit = params.get("limit");
  if (rawLimit !== null && !/^\d{1,3}$/.test(rawLimit))
    throw Error("TIMELINE_LIMIT_INVALID");
  const query: TimelineQuery = {};
  const sources = params.getAll("source");
  if (sources.length) query.sources = sources as TimelineSource[];
  const integrity = params.getAll("integrity");
  if (integrity.length) query.integrity = integrity as TimelineIntegrity[];
  const actor = params.get("actorUserId");
  if (actor) query.actorUserId = actor;
  const from = params.get("from");
  if (from) query.from = from;
  const to = params.get("to");
  if (to) query.to = to;
  const operation = params.get("operation");
  if (operation) query.operation = operation;
  if (rawLimit !== null) query.limit = Number(rawLimit);
  const cursor = params.get("cursor");
  if (cursor) query.cursor = cursor;
  validateTimelineQuery(query);
  return { incidentId, query, format: format as "page" | "csv" | "json" };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const actor = await getActor(context);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
      return denied("TIMELINE_ROLE_DENIED", 403);
    const { incidentId, query, format } = parseQuery(
      new URL(req.url).searchParams);
    if (format === "csv" || format === "json") {
      const exported = await exportOperationalTimeline(
        actor, incidentId, query, format);
      return maybeCsv(req, exported.content, exported.digest, exported.mime);
    }
    return NextResponse.json(
      await readOperationalTimeline(actor, incidentId, query), { headers });
  } catch (error) {
    const code = error instanceof OperationalTimelineError ? error.code :
      error instanceof Error && error.message.startsWith("TIMELINE_") ?
        error.message : "TIMELINE_SERVICE_UNAVAILABLE";
    const status = /ROLE|MEMBERSHIP/.test(code) ? 403 :
      /NOT_FOUND/.test(code) ? 404 :
      /CORRUPT|CONFLICT|STALE/.test(code) ? 409 :
      /UNAVAILABLE/.test(code) ? 503 : 400;
    return denied(code, status);
  }
}
export async function POST() {
  return denied("TIMELINE_READ_ONLY", 405);
}
export async function PATCH() {
  return denied("TIMELINE_READ_ONLY", 405);
}
export async function DELETE() {
  return denied("TIMELINE_READ_ONLY", 405);
}
export async function PUT() {
  return denied("TIMELINE_READ_ONLY", 405);
}
