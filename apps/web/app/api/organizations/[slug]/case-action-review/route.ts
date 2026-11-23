import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import {
  HandoffReviewError,readCaseActionHandoffReview,
} from "../../../../../lib/case-action-handoff-review-service";
import type { HandoffBoardQuery } from "../../../../../lib/case-action-handoff-domain";

type Context={params:Promise<{slug:string}>};
const headers={
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
};
function denied(code:string,status:number){
  return NextResponse.json({
    code,providerCalls:0,independentRemediationConfirmed:false,
    LIVEPermissionGranted:false,customerConsentCreated:false,
    cyberScoreV1Writes:0,
  },{status,headers});
}
const keys=new Set([
  "kind","search","owner","priority","offset","limit",
  "includeCandidates","format",
]);
function decode(request:NextRequest){
  const params=new URL(request.url).searchParams;
  if([...params.keys()].some(x=>!keys.has(x))||
    [...keys].some(x=>params.getAll(x).length>1))
    throw Error("HANDOFF_REVIEW_FIELDS_INVALID");
  const format=params.get("format");
  if(format!==null&&!["JSON","CSV","MARKDOWN"].includes(format))
    throw Error("HANDOFF_REVIEW_FORMAT_INVALID");
  const kind=params.get("kind");
  if(kind!==null&&!["ALL","READY","BLOCKED","LINKED","UNLINKED"].includes(kind))
    throw Error("HANDOFF_REVIEW_KIND_INVALID");
  const priority=params.get("priority");
  if(priority!==null&&!["P0","P1","P2","P3"].includes(priority))
    throw Error("HANDOFF_REVIEW_PRIORITY_INVALID");
  const include=params.get("includeCandidates");
  if(include!==null&&!["true","false"].includes(include))
    throw Error("HANDOFF_REVIEW_CANDIDATES_INVALID");
  const offset=params.get("offset"),limit=params.get("limit");
  if(offset!==null&&!/^\d{1,6}$/.test(offset))
    throw Error("HANDOFF_REVIEW_OFFSET_INVALID");
  if(limit!==null&&!/^\d{1,3}$/.test(limit))
    throw Error("HANDOFF_REVIEW_LIMIT_INVALID");
  const search=params.get("search"),owner=params.get("owner");
  if(search!==null&&search.length>200)
    throw Error("HANDOFF_REVIEW_SEARCH_TOO_LONG");
  if(owner!==null&&!/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(owner))
    throw Error("HANDOFF_REVIEW_OWNER_INVALID");
  const filters:HandoffBoardQuery={
    offset:offset===null?0:Number(offset),
    limit:limit===null?50:Number(limit),
  };
  if(kind!==null)filters.kind=kind as Exclude<HandoffBoardQuery["kind"],undefined>;
  if(priority!==null)filters.minPriority=priority as Exclude<HandoffBoardQuery["minPriority"],undefined>;
  if(search!==null)filters.search=search;
  if(owner!==null)filters.ownerUserId=owner;
  if(include!==null)filters.includeCandidates=include==="true";
  return{filters,format:format as "JSON"|"CSV"|"MARKDOWN"|null};
}
export async function GET(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)
    return denied("CROSS_ORIGIN",403);
  let parsed:ReturnType<typeof decode>;
  try{parsed=decode(request);}
  catch(error){return denied(error instanceof Error?error.message:
    "HANDOFF_REVIEW_QUERY_INVALID",400);}
  try{
    const{membership,session}=await requireOrganizationAccess(
      (await context.params).slug,
    );
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return denied("HANDOFF_REVIEW_PERMISSION_REQUIRED",403);
    const report=await readCaseActionHandoffReview({
      organizationId:membership.organization.id,
      userId:session.user.id,role:membership.role,
    },{
      filters:parsed.filters,
      ...(parsed.format?{format:parsed.format}:{}),
    });
    return NextResponse.json({
      data:report,providerCalls:0,
      independentRemediationConfirmed:false,
      LIVEPermissionGranted:false,
      customerConsentCreated:false,cyberScoreV1Writes:0,
    },{headers});
  }catch(error){
    if(error instanceof HandoffReviewError)
      return denied(error.code,409);
    return denied("HANDOFF_REVIEW_UNAVAILABLE",503);
  }
}
export async function POST(){return denied("REVIEW_READ_ONLY",405);}
export async function PATCH(){return denied("REVIEW_READ_ONLY",405);}
export async function PUT(){return denied("REVIEW_READ_ONLY",405);}
export async function DELETE(){return denied("REVIEW_READ_ONLY",405);}
