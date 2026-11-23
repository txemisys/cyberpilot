import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import {
  PersistedTimelineError, readPersistedCaptureTimeline,
  auditPersistedCaptureHistory, type TimelineReadRequest,
} from "../../../../../lib/offline-capture-timeline-service";
import type { OfflineCaptureKind } from "../../../../../lib/offline-report-capture-domain";
type Context={params:Promise<{slug:string}>};
const headers={
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
};
const denied=(code:string,status:number)=>NextResponse.json({
  code,providerCalls:0,sqlRestorePerformed:false,
  liveCustomerAcceptance:false,historicalScoreV1Writes:0,
},{status,headers});
const params=new Set([
  "kind","from","until","completeOnly","offset","limit","format","view",
]);
function numberParam(s:string|null,defaultValue:number) {
  if(s===null)return defaultValue;
  if(!/^\d{1,6}$/.test(s))return NaN;
  return Number(s);
}
function decode(request:NextRequest) {
  const url=new URL(request.url);
  if([...url.searchParams.keys()].some(key=>!params.has(key)))
    throw Error("TIMELINE_QUERY_FIELD_INVALID");
  if([...params].some(x=>url.searchParams.getAll(x).length>1))
    throw Error("TIMELINE_REPEATED_QUERY_FIELD");
  const kind=url.searchParams.get("kind");
  const from=url.searchParams.get("from");
  const until=url.searchParams.get("until");
  const completeOnly=url.searchParams.get("completeOnly");
  const format=url.searchParams.get("format");
  const view=url.searchParams.get("view");
  if(kind!==null&&!["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
    "EXECUTIVE","LONGITUDINAL"].includes(kind))
    throw Error("TIMELINE_KIND_INVALID");
  if(completeOnly!==null&&completeOnly!=="true"&&completeOnly!=="false")
    throw Error("TIMELINE_COMPLETE_FILTER_INVALID");
  if(format!==null&&!["JSON","CSV","MARKDOWN"].includes(format))
    throw Error("TIMELINE_FORMAT_INVALID");
  if(view!==null&&view!=="timeline"&&view!=="audit")
    throw Error("TIMELINE_VIEW_INVALID");
  if(view==="audit"&&format!==null)
    throw Error("TIMELINE_AUDIT_EXPORT_UNSUPPORTED");
  const query:TimelineReadRequest={
    offset:numberParam(url.searchParams.get("offset"),0),
    limit:numberParam(url.searchParams.get("limit"),100),
  };
  if(kind!==null)query.kind=kind as OfflineCaptureKind;
  if(from!==null)query.from=from;
  if(until!==null)query.until=until;
  if(completeOnly!==null)query.completeOnly=completeOnly==="true";
  if(format!==null)query.format=format as "JSON"|"CSV"|"MARKDOWN";
  return {query,audit:view==="audit"};
}
export async function GET(request:NextRequest,context:Context) {
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)
    return denied("CROSS_ORIGIN",403);
  let decoded:ReturnType<typeof decode>;
  try {decoded=decode(request);}
  catch(error) {
    return denied(error instanceof Error?error.message:
      "TIMELINE_QUERY_INVALID",400);
  }
  try {
    const {membership,session}=await requireOrganizationAccess(
      (await context.params).slug,
    );
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return denied("TIMELINE_PERMISSION_REQUIRED",403);
    const actor={
      organizationId:membership.organization.id,
      userId:session.user.id,
      role:membership.role,
    };
    if(decoded.audit){
      const audit=await auditPersistedCaptureHistory(actor,decoded.query);
      return NextResponse.json({
        data:audit,providerCalls:0,sqlRestorePerformed:false,
        liveCustomerAcceptance:false,historicalScoreV1Writes:0,
      },{headers});
    }
    const result=await readPersistedCaptureTimeline(actor,decoded.query);
    return NextResponse.json({
      data:result,providerCalls:0,sqlRestorePerformed:false,
      liveCustomerAcceptance:false,historicalScoreV1Writes:0,
    },{headers});
  }catch(error){
    if(error instanceof PersistedTimelineError)
      return denied(error.code,400);
    return denied("TIMELINE_HISTORY_UNAVAILABLE",503);
  }
}
export async function POST(){return denied("CAPTURES_ARE_READ_ONLY",405);}
export async function PUT(){return denied("CAPTURES_ARE_READ_ONLY",405);}
export async function PATCH(){return denied("CAPTURES_ARE_READ_ONLY",405);}
export async function DELETE(){return denied("CAPTURES_ARE_IMMUTABLE",405);}
