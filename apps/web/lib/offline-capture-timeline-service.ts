import { db, type Prisma } from "@cyberpilot/database";
import type { IntegratedReviewer } from "./integrated-risk-service";
import type { OfflineCapture, OfflineCaptureKind } from "./offline-report-capture-domain";
import {
  buildCaptureTimeline,
  exportCaptureTimeline,
  timelineFingerprint,
  validateTimelineQuery,
  type CaptureTimelineQuery,
} from "./offline-capture-timeline-domain";

/**
 * Reads only already persisted snapshots, never regenerates a report or
 * contacts a provider. PostgreSQL is the scope authority for pagination.
 */
export class PersistedTimelineError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "PersistedTimelineError";
  }
}
function fail(code: string): never {
  throw new PersistedTimelineError(code);
}
const identifier = (x: string) =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);

export type TimelineReadRequest = {
  kind?: OfflineCaptureKind;
  from?: string;
  until?: string;
  completeOnly?: boolean;
  offset?: number;
  limit?: number;
  format?: "JSON" | "CSV" | "MARKDOWN";
};
async function authorize(actor: IntegratedReviewer) {
  if (!identifier(actor.organizationId) || !identifier(actor.userId))
    fail("TIMELINE_ACTOR_INVALID");
  if (!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("TIMELINE_REVIEW_ROLE_REQUIRED");
  const member = await db.membership.findFirst({
    where: { organizationId:actor.organizationId, userId:actor.userId },
    select: {role:true},
  });
  if (!member || member.role !== actor.role)
    fail("TIMELINE_CURRENT_MEMBERSHIP_REQUIRED");
}
type CaptureRow = Awaited<ReturnType<
  typeof db.offlineReportCapture.findMany
>>[number];
function map(row: CaptureRow): OfflineCapture {
  return {
    id:row.id,organizationId:row.organizationId,
    kind:row.kind as OfflineCaptureKind,
    schemaVersion:row.schemaVersion,
    originalDigest:row.originalDigest,
    payloadDigest:row.payloadDigest,
    payload:row.payload as unknown as OfflineCapture["payload"],
    sourceComplete:row.sourceComplete,
    createdById:row.createdById,
    createdAt:row.createdAt.toISOString(),
    externalAttestation:false,
    customerCertification:false,
  };
}
function whereFor(organizationId:string,query:CaptureTimelineQuery) {
  return {
    organizationId,
    ...(query.kind ? {kind:query.kind} : {}),
    ...(query.completeOnly === true ? {sourceComplete:true} : {}),
    ...(query.from || query.until ? {
      createdAt:{
        ...(query.from ? {gte:new Date(query.from)} : {}),
        ...(query.until ? {lte:new Date(query.until)} : {}),
      },
    } : {}),
  };
}
export async function readPersistedCaptureTimeline(
  actor: IntegratedReviewer,
  request: TimelineReadRequest = {},
) {
  await authorize(actor);
  const query:CaptureTimelineQuery={
    organizationId:actor.organizationId,
    ...(request.kind!==undefined?{kind:request.kind}:{}),
    ...(request.from!==undefined?{from:request.from}:{}),
    ...(request.until!==undefined?{until:request.until}:{}),
    ...(request.completeOnly!==undefined?{completeOnly:request.completeOnly}:{}),
    offset:request.offset??0,
    limit:request.limit??100,
  };
  const issues=validateTimelineQuery(query);
  if (issues.length) fail(issues[0]!);
  if (request.format!==undefined &&
      !["JSON","CSV","MARKDOWN"].includes(request.format))
    fail("TIMELINE_EXPORT_FORMAT_INVALID");
  const where=whereFor(actor.organizationId,query);
  const rows=await db.offlineReportCapture.findMany({
    where,
    orderBy:[{createdAt:"asc"},{id:"asc"}],
    skip:query.offset,
    take:query.limit!+1,
  });
  if (rows.some(x=>x.organizationId!==actor.organizationId))
    fail("TIMELINE_DATABASE_SCOPE_VIOLATION");
  const page=rows.slice(0,query.limit).map(map);
  // One extra row is used only to establish a conservative next-page marker.
  const hasMore=rows.length>query.limit!;
  const report=buildCaptureTimeline(query,page,
    new Date().toISOString(),hasMore);
  const exportFile=request.format?
    exportCaptureTimeline(report,request.format):null;
  return {
    schema:"cyberpilot.offline.persisted.timeline.read.v1" as const,
    organizationId:actor.organizationId,
    report,
    exportFile,
    manifestDigest:timelineFingerprint(report),
    page:{offset:query.offset!,limit:query.limit!,
      returned:report.points.length,
      hasMore,nextOffset:report.nextOffset},
    source:"PERSISTED_POSTGRESQL_CAPTURE" as const,
    providerCalls:0 as const,
    sqlRestorePerformed:false as const,
    liveCustomerAcceptance:false as const,
    historicalScoreV1Writes:0 as const,
  };
}
export async function auditPersistedCaptureHistory(
  actor:IntegratedReviewer,request:TimelineReadRequest={},
) {
  const rows=await readPersistedCaptureTimeline(actor,{
    ...request,format:undefined,
  });
  const report=rows.report;
  const sourceGaps=report.changes.filter(x=>
    x.elapsedMilliseconds>30*24*60*60*1000);
  const schemaDrift=report.changes.filter(x=>
    x.reasons.includes("SCHEMA_VERSION_CHANGED"));
  const sourceDrift=report.changes.filter(x=>
    x.sourceClassesAdded.length||x.sourceClassesRemoved.length);
  const duplicateSources=report.points.filter(x=>x.duplicatedDigest);
  const incomplete=report.points.filter(x=>!x.sourceComplete);
  const corrupt=report.points.filter(x=>!x.integrityValid);
  return {
    schema:"cyberpilot.offline.capture.timeline.audit.v1" as const,
    organizationId:actor.organizationId,
    manifestDigest:rows.manifestDigest,
    evaluatedAt:report.evaluatedAt,
    sourceGaps:sourceGaps.map(x=>({
      kind:x.kind,earlierId:x.earlierId,laterId:x.laterId,
      elapsedMilliseconds:x.elapsedMilliseconds,
    })),
    schemaDrift:schemaDrift.map(x=>({
      kind:x.kind,earlierId:x.earlierId,laterId:x.laterId,
    })),
    sourceDrift:sourceDrift.map(x=>({
      kind:x.kind,earlierId:x.earlierId,laterId:x.laterId,
      added:x.sourceClassesAdded,removed:x.sourceClassesRemoved,
    })),
    duplicateSourceIds:duplicateSources.map(x=>x.id),
    incompleteIds:incomplete.map(x=>x.id),
    integrityFailures:corrupt.map(x=>x.id),
    truncated:report.truncated,
    completeHistoryAudited:!report.truncated&&
      incomplete.length===0&&corrupt.length===0,
    independentImprovementVerified:false as const,
    externalDataCollected:false as const,
  };
}
