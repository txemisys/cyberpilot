import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { readSiemAuditPage, readSiemAuditFacets,
  readSiemAuditHistogram, siemExportCapabilities,
  SiemAuditServiceError } from "../../../../../lib/siem-audit-service";
import type { SiemFormat } from "../../../../../lib/siem-audit-interchange-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store, max-age=0",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const denied = (code: string, status: number) => NextResponse.json({
  code, providerCalls: 0, transmittedToSiem: false,
}, { status, headers });
function error(e: unknown) {
  if (e instanceof SiemAuditServiceError) return denied(e.code,
    /ROLE|MEMBERSHIP|DENIED|ADMIN/.test(e.code) ? 403 : 400);
  return denied("SIEM_EXPORT_UNAVAILABLE", 503);
}
async function reviewer(context: Context) {
  const { session, membership } = await requireOrganizationAccess(
    (await context.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function safeInput(query: URLSearchParams) {
  const keys = ["since", "until", "limit", "action", "resourceType", "cursor",
    "format", "actorRefs", "resourceRefs", "mode", "days"];
  if ([...query.keys()].some(x => !keys.includes(x)))
    throw new SiemAuditServiceError("SIEM_UNKNOWN_FILTER");
  const number = query.get("limit"), days = query.get("days");
  if (number && !/^\d{1,3}$/.test(number) ||
      days && !/^\d{1,2}$/.test(days))
    throw new SiemAuditServiceError("SIEM_NUMERIC_FILTER_INVALID");
  for (const name of ["actorRefs", "resourceRefs"]) {
    const value = query.get(name);
    if (value !== null && value !== "true" && value !== "false")
      throw new SiemAuditServiceError("SIEM_REFERENCE_FLAG_INVALID");
  }
  const format = query.get("format");
  if (format && !["JSONL", "ECS", "CEF", "CSV"].includes(format))
    throw new SiemAuditServiceError("SIEM_FORMAT_UNKNOWN");
  for (const name of ["action", "resourceType", "cursor", "since", "until"]) {
    if ((query.get(name)?.length ?? 0) > (name === "cursor" ? 1200 : 200))
      throw new SiemAuditServiceError("SIEM_FILTER_LENGTH_LIMIT");
  }
  return { format: format as SiemFormat | null, limit: number ? Number(number) : undefined,
    days: days ? Number(days) : undefined };
}
export async function GET(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return denied("SIEM_ORIGIN_REJECTED", 403);
  try {
    const actor = await reviewer(context);
    if (actor.role === "MEMBER") return denied("SIEM_REVIEW_ROLE_REQUIRED", 403);
    const query = new URL(request.url).searchParams;
    const parsed = safeInput(query);
    if (query.get("mode") === "capabilities")
      return NextResponse.json({ data: await siemExportCapabilities(actor) }, { headers });
    if (query.get("mode") === "facets")
      return NextResponse.json({ data: await readSiemAuditFacets(actor) }, { headers });
    if (query.get("mode") === "histogram")
      return NextResponse.json({ data: await readSiemAuditHistogram(
        actor, parsed.days) }, { headers });
    if (query.get("mode") && query.get("mode") !== "page")
      return denied("SIEM_MODE_UNSUPPORTED", 400);
    const data = await readSiemAuditPage(actor, {
      ...(query.get("since") ? { since: query.get("since")! } : {}),
      ...(query.get("until") ? { until: query.get("until")! } : {}),
      ...(parsed.limit !== undefined ? { limit: parsed.limit } : {}),
      ...(query.get("action") ? { action: query.get("action")! } : {}),
      ...(query.get("resourceType") ?
        { resourceType: query.get("resourceType")! } : {}),
      ...(query.get("cursor") ? { cursor: query.get("cursor")! } : {}),
      ...(parsed.format ? { format: parsed.format } : {}),
      includeActorReference: query.get("actorRefs") === "true",
      includeResourceReference: query.get("resourceRefs") === "true",
    });
    return NextResponse.json({ data, providerCalls: 0,
      externallyDelivered: false, productionSiemEnabled: false }, { headers });
  } catch (e) { return error(e); }
}
export async function POST() { return denied("SIEM_WRITE_NOT_SUPPORTED", 405); }
export async function PUT() { return denied("SIEM_WRITE_NOT_SUPPORTED", 405); }
export async function DELETE() { return denied("SIEM_DELETE_NOT_SUPPORTED", 405); }
