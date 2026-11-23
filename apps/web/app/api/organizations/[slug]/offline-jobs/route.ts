import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { enqueueOfflineJob, claimOfflineJob, executeClaimedOfflineJob,
  heartbeatOfflineJob, cancelOfflineJob, recoverExpiredOfflineJob,
  readOfflineJobs, readOfflineJobAudit, offlineQueueMetrics, readOfflineQueueHealth,
  DurableJobError } from "../../../../../lib/durable-offline-job-service";
import { OFFLINE_JOB_TYPES, type OfflineJobType } from "../../../../../lib/durable-offline-job-domain";

type Context = { params: Promise<{ slug: string }> };
const headers = { "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff" };
const denied = (code: string, status: number) => NextResponse.json({
  code, providerWrites: 0, automaticProviderExecution: false,
}, { headers, status });
const validOrigin = (request: NextRequest) => {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
};
async function actor(ctx: Context) {
  const { membership, session } = await requireOrganizationAccess((await ctx.params).slug);
  return { organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role };
}
function status(e: unknown) {
  if (!(e instanceof DurableJobError)) return denied("OFFLINE_JOB_UNAVAILABLE", 503);
  const code = e.code;
  return denied(code, /REVISION|CONCURRENT|LEASE|NOT_CLAIMABLE|RETRY|FENCE|CONFLICT/.test(code)
    ? 409 : /ROLE|TENANT|MEMBERSHIP/.test(code) ? 403 : 400);
}
export async function GET(request: NextRequest, context: Context) {
  if (!validOrigin(request)) return denied("CROSS_ORIGIN", 403);
  try {
    const current = await actor(context);
    if (current.role === "MEMBER") return denied("OFFLINE_JOB_ROLE_REQUIRED", 403);
    const query = new URL(request.url).searchParams;
    if (query.get("health") === "true") {
      const format = query.get("format");
      if (format && !["JSON", "CSV", "MARKDOWN"].includes(format))
        return denied("OFFLINE_JOB_EXPORT_INVALID", 400);
      return NextResponse.json({ data: await readOfflineQueueHealth(current,
        format as "JSON" | "CSV" | "MARKDOWN" | undefined) }, { headers });
    }
    if (query.get("metrics") === "true")
      return NextResponse.json({ data: await offlineQueueMetrics(current) }, { headers });
    const jobId = query.get("jobId");
    if (jobId) return NextResponse.json({
      data: await readOfflineJobAudit(current, jobId),
    }, { headers });
    const limit = query.get("limit"), offset = query.get("offset");
    if (limit !== null && !/^\d+$/.test(limit) ||
        offset !== null && !/^\d+$/.test(offset))
      return denied("OFFLINE_JOB_PAGING_INVALID", 400);
    const type = query.get("type");
    if (type && !OFFLINE_JOB_TYPES.includes(type as OfflineJobType))
      return denied("OFFLINE_JOB_TYPE_INVALID", 400);
    const data = await readOfflineJobs(current, {
      ...(limit !== null ? { limit: Number(limit) } : {}),
      ...(offset !== null ? { offset: Number(offset) } : {}),
      ...(type !== null ? { type: type as OfflineJobType } : {}),
      ...(query.get("status") ? { status: query.get("status")! } : {}),
    });
    return NextResponse.json({ data }, { headers });
  } catch (e) { return status(e); }
}
export async function POST(request: NextRequest, context: Context) {
  if (!validOrigin(request)) return denied("CROSS_ORIGIN", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json")
    return denied("JSON_REQUIRED", 415);
  const size = request.headers.get("content-length");
  if (size && (!/^\d+$/.test(size) || Number(size) > 10000))
    return denied("OFFLINE_JOB_BODY_LIMIT", 413);
  try {
    const current = await actor(context);
    if (!["OWNER", "ADMIN"].includes(current.role))
      return denied("OFFLINE_JOB_MANAGER_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 10000) return denied("OFFLINE_JOB_BODY_LIMIT", 413);
    let payload: unknown;
    try { payload = JSON.parse(raw); }
    catch { return denied("JSON_INVALID", 400); }
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
      return denied("OFFLINE_JOB_COMMAND_INVALID", 400);
    const command = payload as Record<string, unknown>;
    const operation = command.operation;
    if (operation === "ENQUEUE") {
      if (Object.keys(command).some(x => !["operation", "type",
        "idempotencyKey", "payload", "delaySeconds"].includes(x)) ||
          !OFFLINE_JOB_TYPES.includes(command.type as OfflineJobType) ||
          typeof command.idempotencyKey !== "string" ||
          !command.payload || typeof command.payload !== "object" ||
          Array.isArray(command.payload))
        return denied("OFFLINE_JOB_ADMISSION_INVALID", 400);
      const data = await enqueueOfflineJob(current, {
        type: command.type as OfflineJobType, idempotencyKey: command.idempotencyKey,
        payload: command.payload as Record<string, unknown>,
        ...(command.delaySeconds !== undefined ?
          { delaySeconds: command.delaySeconds as number } : {}),
      });
      return NextResponse.json({ data }, { headers, status: data.created ? 201 : 200 });
    }
    if (Object.keys(command).some(x => !["operation", "jobId",
      "expectedRevision", "leaseToken"].includes(x)) ||
      typeof command.jobId !== "string" ||
      !Number.isSafeInteger(command.expectedRevision) ||
      !["CLAIM", "EXECUTE", "HEARTBEAT", "CANCEL", "RECOVER"].includes(String(operation)))
      return denied("OFFLINE_JOB_COMMAND_INVALID", 400);
    const jobId = command.jobId, revision = command.expectedRevision as number;
    const leaseToken = command.leaseToken;
    if (["EXECUTE", "HEARTBEAT"].includes(String(operation)) &&
        typeof leaseToken !== "string")
      return denied("OFFLINE_JOB_TOKEN_REQUIRED", 400);
    const data = operation === "CLAIM" ? await claimOfflineJob(current, jobId, revision) :
      operation === "EXECUTE" ? await executeClaimedOfflineJob(current,
        jobId, revision, leaseToken as string) :
      operation === "HEARTBEAT" ? await heartbeatOfflineJob(current,
        jobId, revision, leaseToken as string) :
      operation === "CANCEL" ? await cancelOfflineJob(current, jobId, revision) :
      await recoverExpiredOfflineJob(current, jobId, revision);
    return NextResponse.json({ data, providerWrites: 0,
      actualRemoteSync: false }, { headers });
  } catch (e) { return status(e); }
}
export async function PUT() { return denied("OFFLINE_JOB_METHOD_DISABLED", 405); }
export async function DELETE() { return denied("OFFLINE_JOB_AUDIT_IMMUTABLE", 405); }
