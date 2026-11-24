import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../../lib/organizations";
import {
  readIncidentShiftBriefing, exportIncidentShiftBriefing,
  ShiftBriefingServiceError,
} from "../../../../../../lib/incident-shift-briefing-service";
import type { ShiftWindow } from
  "../../../../../../lib/incident-shift-briefing-domain";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
function deny(code: string, status: number) {
  return NextResponse.json({
    code, accepted: false, externalWrites: 0,
    providerOutcomeVerified: false,
  }, { status, headers });
}
function parse(req: NextRequest): {
  incidentId: string;
  shiftId: string;
  startsAt: string;
  endsAt: string;
  incomingRole: "OWNER" | "ADMIN" | "AUDITOR";
  format: "page" | "json" | "csv" | "md";
  download: boolean;
} {
  const q = req.nextUrl.searchParams;
  const keys = [
    "incidentId", "shiftId", "startsAt", "endsAt",
    "incomingRole", "format", "download",
  ];
  if ([...q.keys()].some(k => !keys.includes(k)))
    throw Error("SHIFT_QUERY_FIELD_UNKNOWN");
  if (keys.some(k => q.getAll(k).length > 1))
    throw Error("SHIFT_QUERY_DUPLICATE_FIELD");
  const incidentId = q.get("incidentId") ?? "";
  const shiftId = q.get("shiftId") ?? "";
  if (![incidentId, shiftId].every(x =>
      /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x)))
    throw Error("SHIFT_QUERY_IDENTIFIER_INVALID");
  const startsAt = q.get("startsAt") ?? "";
  const endsAt = q.get("endsAt") ?? "";
  for (const date of [startsAt, endsAt]) {
    if (!Number.isFinite(Date.parse(date)) ||
        new Date(date).toISOString() !== date)
      throw Error("SHIFT_QUERY_TIMESTAMP_INVALID");
  }
  const incomingRole = q.get("incomingRole") ?? "OWNER";
  if (!["OWNER", "ADMIN", "AUDITOR"].includes(incomingRole))
    throw Error("SHIFT_QUERY_ROLE_INVALID");
  const format = q.get("format") ?? "page";
  if (!["page", "json", "csv", "md"].includes(format))
    throw Error("SHIFT_QUERY_FORMAT_INVALID");
  if (q.has("download") && !["0", "1"].includes(q.get("download")!))
    throw Error("SHIFT_QUERY_DOWNLOAD_INVALID");
  return {
    incidentId, shiftId, startsAt, endsAt,
    incomingRole: incomingRole as "OWNER" | "ADMIN" | "AUDITOR",
    format: format as "page" | "json" | "csv" | "md",
    download: q.get("download") === "1",
  };
}
export async function GET(req: NextRequest, context: Context) {
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug);
    if (!["OWNER", "ADMIN", "AUDITOR"].includes(membership.role))
      return deny("SHIFT_ROLE_DENIED", 403);
    const q = parse(req);
    const window: ShiftWindow = {
      shiftId: q.shiftId, startsAt: q.startsAt, endsAt: q.endsAt,
      evaluatedAt: new Date().toISOString(),
      outgoingRole: membership.role as ShiftWindow["outgoingRole"],
      incomingRole: q.incomingRole,
      outgoingUserId: session.user.id,
      incomingUserId: null,
      acknowledgedBy: null,
      acceptedAt: null,
    };
    const actor = {
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    };
    if (q.format !== "page") {
      const exported = await exportIncidentShiftBriefing(
        actor, q.incidentId, window, q.format);
      const ext = q.format === "md" ? "md" : q.format;
      return new NextResponse(exported.content, {
        headers: {
          ...headers,
          "Content-Type": exported.mime,
          "Content-Disposition": (q.download ? "attachment" : "inline") +
            '; filename="cyberpilot-internal-shift.' + ext + '"',
          "X-Shift-Digest": exported.digest,
        },
      });
    }
    return NextResponse.json(
      await readIncidentShiftBriefing(actor, q.incidentId, window),
      { headers });
  } catch (cause) {
    const code = cause instanceof ShiftBriefingServiceError ?
      cause.code : cause instanceof Error &&
      cause.message.startsWith("SHIFT_") ?
        cause.message : "SHIFT_SERVICE_UNAVAILABLE";
    const status = /ROLE|ACCESS|MEMBERSHIP/.test(code) ? 403 :
      /NOT_FOUND/.test(code) ? 404 :
      /CHANGED|STALE|CORRUPT/.test(code) ? 409 :
      /UNAVAILABLE/.test(code) ? 503 : 400;
    return deny(code, status);
  }
}
export async function POST() { return deny("SHIFT_READ_ONLY", 405); }
export async function PATCH() { return deny("SHIFT_READ_ONLY", 405); }
export async function PUT() { return deny("SHIFT_READ_ONLY", 405); }
export async function DELETE() { return deny("SHIFT_READ_ONLY", 405); }
