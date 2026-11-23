import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { readIncidentAssetImpact, discoverIncidentAssetReferences,
  reviewIncidentAssetExposure, IncidentAssetIntegrationError }
  from "../../../../../../lib/incident-integrated-assets-service";
type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const reject = (code: string, status: number) => NextResponse.json({
  code, providerWrites: 0, deviceIsolationVerified: false,
}, { status, headers });
async function actor(context: Context) {
  const { membership, session } = await requireOrganizationAccess(
    (await context.params).slug);
  return { userId: session.user.id,
    organizationId: membership.organization.id, role: membership.role };
}
function error(e: unknown) {
  if (e instanceof IncidentAssetIntegrationError)
    return reject(e.code, /ROLE|TENANT|MEMBERSHIP/.test(e.code) ? 403 : 400);
  return reject("INCIDENT_ASSET_READ_UNAVAILABLE", 503);
}
export async function GET(request: NextRequest, context: Context) {
  try {
    const current = await actor(context);
    if (current.role === "MEMBER") return reject("REVIEWER_REQUIRED", 403);
    const q = new URL(request.url).searchParams;
    if ([...q.keys()].some(x =>
      !["mode", "importId", "offset", "limit"].includes(x)))
      return reject("QUERY_FIELD_INVALID", 400);
    if (q.get("mode") && q.get("mode") !== "inventory")
      return reject("MODE_INVALID", 400);
    const offset = q.get("offset"), limit = q.get("limit");
    if (offset && !/^\d{1,5}$/.test(offset) ||
        limit && !/^\d{1,3}$/.test(limit))
      return reject("PAGING_INVALID", 400);
    const data = await discoverIncidentAssetReferences(current, {
      ...(q.get("importId") ? { importId: q.get("importId")! } : {}),
      ...(offset !== null ? { offset: Number(offset) } : {}),
      ...(limit !== null ? { limit: Number(limit) } : {}),
    });
    return NextResponse.json({ data, providerWrites: 0 }, { headers });
  } catch (e) { return error(e); }
}
export async function POST(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return reject("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json")
    return reject("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 16000))
    return reject("BODY_TOO_LARGE", 413);
  try {
    const current = await actor(context);
    if (current.role === "MEMBER") return reject("REVIEWER_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 16000) return reject("BODY_TOO_LARGE", 413);
    let body: unknown;
    try { body = JSON.parse(raw); } catch { return reject("JSON_INVALID", 400); }
    if (!body || typeof body !== "object" || Array.isArray(body))
      return reject("BODY_INVALID", 400);
    const data = body as Record<string, unknown>;
    if (Object.keys(data).some(x =>
      !["incidentId", "deviceIds", "importIds", "externalIds",
        "freshnessHours", "requireActiveImport", "exposure"].includes(x)) ||
        typeof data.incidentId !== "string" ||
        !Array.isArray(data.deviceIds) || !Array.isArray(data.importIds) ||
        !Array.isArray(data.externalIds))
      return reject("SELECTION_INVALID", 400);
    if (data.exposure === true) {
      if (data.importIds.length || data.externalIds.length)
        return reject("EXPOSURE_ONLY_EXACT_DEVICE_IDS", 400);
      const result = await reviewIncidentAssetExposure(
        current, data.incidentId, data.deviceIds as string[]);
      return NextResponse.json({ data: result }, { headers });
    }
    const result = await readIncidentAssetImpact(current, {
      incidentId: data.incidentId, deviceIds: data.deviceIds as string[],
      importIds: data.importIds as string[],
      externalIds: data.externalIds as string[],
      ...(data.freshnessHours !== undefined ?
        { freshnessHours: data.freshnessHours as number } : {}),
      ...(data.requireActiveImport !== undefined ?
        { requireActiveImport: data.requireActiveImport as boolean } : {}),
    });
    return NextResponse.json({ data: result, providerWrites: 0 }, { headers });
  } catch (e) { return error(e); }
}
export async function PUT() { return reject("INCIDENT_ASSETS_READ_ONLY", 405); }
export async function DELETE() { return reject("INCIDENT_ASSETS_READ_ONLY", 405); }
