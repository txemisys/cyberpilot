import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../../lib/organizations";
import {
  readSelectedIncidentCorrelations,
  exportSelectedIncidentCorrelations,
  CrosscaseCorrelationError,
} from "../../../../../../lib/incident-crosscase-correlation-service";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
function denied(code: string, status: number) {
  return NextResponse.json({
    code, providerWrites: 0, identityProven: false,
  }, { status, headers });
}
function parse(request: NextRequest) {
  const q = request.nextUrl.searchParams;
  if ([...q.keys()].some(k =>
      !["incidentId", "format", "download"].includes(k)))
    throw Error("CORRELATION_QUERY_UNKNOWN");
  if (q.getAll("format").length > 1 ||
      q.getAll("download").length > 1)
    throw Error("CORRELATION_QUERY_DUPLICATE");
  const incidentIds = q.getAll("incidentId");
  if (incidentIds.length < 2 || incidentIds.length > 12 ||
      incidentIds.some(v => !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v)) ||
      new Set(incidentIds).size !== incidentIds.length)
    throw Error("CORRELATION_SELECTION_INVALID");
  const format = q.get("format") ?? "page";
  if (!["page", "json", "csv"].includes(format))
    throw Error("CORRELATION_FORMAT_INVALID");
  if (q.has("download") && !["0", "1"].includes(q.get("download")!))
    throw Error("CORRELATION_DOWNLOAD_INVALID");
  return { incidentIds, format: format as "page" | "json" | "csv",
    download: q.get("download") === "1" };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(membership.role))
      return denied("CORRELATION_ROLE_DENIED", 403);
    const actor = {
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    };
    const { incidentIds, format, download } = parse(req);
    if (format !== "page") {
      const exported = await exportSelectedIncidentCorrelations(
        actor, incidentIds, format);
      return new NextResponse(exported.content, {
        headers: {
          ...headers, "Content-Type": exported.mime,
          "Content-Disposition": (download ? "attachment" : "inline") +
            '; filename="cyberpilot-selected-incident-correlations.' +
            format + '"',
          "X-Correlation-Digest": exported.digest,
        },
      });
    }
    return NextResponse.json(
      await readSelectedIncidentCorrelations(actor, incidentIds),
      { headers });
  } catch (error) {
    const code = error instanceof CrosscaseCorrelationError ?
      error.code : error instanceof Error &&
      error.message.startsWith("CORRELATION_") ?
        error.message : "CORRELATION_SERVICE_UNAVAILABLE";
    const status = /ROLE|ACTOR|MEMBERSHIP/.test(code) ? 403 :
      /NOT_FOUND/.test(code) ? 404 :
      /CHANGED|CONFLICT|CORRUPT/.test(code) ? 409 :
      /UNAVAILABLE/.test(code) ? 503 : 400;
    return denied(code, status);
  }
}
export async function POST() { return denied("CORRELATION_READ_ONLY", 405); }
export async function PUT() { return denied("CORRELATION_READ_ONLY", 405); }
export async function PATCH() { return denied("CORRELATION_READ_ONLY", 405); }
export async function DELETE() { return denied("CORRELATION_READ_ONLY", 405); }
