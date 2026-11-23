import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  createPersistedAssuranceHandoffBoard, mutatePersistedAssuranceHandoffBoard,
  readPersistedAssuranceHandoffBoard, listPersistedAssuranceHandoffBoards,
  reviewAssuranceHandoffTenantAssignments, AssuranceHandoffServiceError,
} from "../../../../../../lib/incident-assurance-handoff-service";
import type {AssuranceRequest}
  from "../../../../../../lib/incident-assurance-service";
import type {HandoffCommand}
  from "../../../../../../lib/incident-assurance-handoff-domain";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff"};
function denied(code:string,status:number){
  return NextResponse.json({code,providerWrites:0,
    notificationDispatches:0,liveProviderContainmentVerified:false},
    {status,headers});
}
async function actor(ctx:Context){
  const {membership,session}=await requireOrganizationAccess(
    (await ctx.params).slug);
  return{organizationId:membership.organization.id,
    userId:session.user.id,role:membership.role};
}
function errorResponse(error:unknown){
  if(error instanceof AssuranceHandoffServiceError){
    const status=/ROLE|MEMBERSHIP|DENIED|TENANT/.test(error.code)?403:
      /NOT_FOUND/.test(error.code)?404:
      /RACE|CAS|CONCURRENT|CONFLICT|CORRUPT/.test(error.code)?409:400;
    return denied(error.code,status);
  }
  return denied("HANDOFF_SERVICE_UNAVAILABLE",503);
}
function record(x:unknown):x is Record<string,unknown>{
  return typeof x==="object"&&x!==null&&!Array.isArray(x);
}
function only(x:Record<string,unknown>,allowed:string[]){
  return Object.keys(x).every(k=>allowed.includes(k));
}
async function readBody(req:NextRequest){
  if(req.headers.get("content-type")?.split(";")[0]?.trim()!==
      "application/json")throw Error("HANDOFF_JSON_REQUIRED");
  const origin=req.headers.get("origin");
  if(origin&&origin!==new URL(req.url).origin)
    throw Error("HANDOFF_CROSS_ORIGIN");
  const length=req.headers.get("content-length");
  if(length&&(!/^\d+$/.test(length)||Number(length)>16000))
    throw Error("HANDOFF_REQUEST_TOO_LARGE");
  const body=await req.text();
  if(Buffer.byteLength(body)>16000)
    throw Error("HANDOFF_REQUEST_TOO_LARGE");
  let value:unknown;
  try{value=JSON.parse(body);}
  catch{throw Error("HANDOFF_JSON_INVALID");}
  if(!record(value))throw Error("HANDOFF_BODY_INVALID");
  return value;
}
function validatedAssuranceRequest(value:unknown):AssuranceRequest{
  if(!record(value)||!only(value,["situation","policy","tabletop","format"])||
      !record(value.situation)||
      typeof value.situation.incidentId!=="string"||
      value.situation.consistency!=="FAIL_CLOSED"||
      !["evidence","assets","remediation"].every(k=>
        value.situation!==undefined&&
        (value.situation as Record<string,unknown>)[k]===null||
        record((value.situation as Record<string,unknown>)[k])))
    throw Error("HANDOFF_ASSURANCE_SELECTION_INVALID");
  return value as unknown as AssuranceRequest;
}
export async function GET(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(current.role==="MEMBER")return denied("HANDOFF_REVIEWER_REQUIRED",403);
    const query=new URL(req.url).searchParams;
    if([...query.keys()].some(k=>!["mode","boardId","incidentId","offset",
      "limit"].includes(k)))return denied("HANDOFF_QUERY_INVALID",400);
    const mode=query.get("mode")??"detail";
    if(mode==="index"){
      const incidentId=query.get("incidentId");
      if(!incidentId)return denied("HANDOFF_INCIDENT_REQUIRED",400);
      const offset=query.get("offset")??"0";
      const limit=query.get("limit")??"30";
      if(!/^\d{1,5}$/.test(offset)||!/^\d{1,3}$/.test(limit))
        return denied("HANDOFF_PAGING_INVALID",400);
      return NextResponse.json({data:await listPersistedAssuranceHandoffBoards(
        current,incidentId,Number(offset),Number(limit)),providerWrites:0},
        {headers});
    }
    const boardId=query.get("boardId");
    if(!boardId)return denied("HANDOFF_BOARD_REQUIRED",400);
    if(mode==="detail")return NextResponse.json({
      data:await readPersistedAssuranceHandoffBoard(current,boardId),
      providerWrites:0},{headers});
    if(mode==="members")return NextResponse.json({
      data:await reviewAssuranceHandoffTenantAssignments(current,boardId),
      providerWrites:0},{headers});
    return denied("HANDOFF_MODE_INVALID",400);
  }catch(e){return errorResponse(e);}
}
export async function POST(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(!["OWNER","ADMIN"].includes(current.role))
      return denied("HANDOFF_WRITER_REQUIRED",403);
    const value=await readBody(req);
    if(!only(value,["boardId","request"])||
        typeof value.boardId!=="string")
      return denied("HANDOFF_CREATE_INVALID",400);
    const data=await createPersistedAssuranceHandoffBoard(
      current,value.boardId,validatedAssuranceRequest(value.request));
    return NextResponse.json({data,providerWrites:0},{
      status:data.created?201:200,headers,
    });
  }catch(e){
    if(e instanceof Error&&e.message.startsWith("HANDOFF_"))
      return denied(e.message,400);
    return errorResponse(e);
  }
}
export async function PATCH(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(!["OWNER","ADMIN"].includes(current.role))
      return denied("HANDOFF_WRITER_REQUIRED",403);
    const value=await readBody(req);
    if(!only(value,["boardId","expectedRevision","commandId","action"])||
        typeof value.boardId!=="string"||
        typeof value.expectedRevision!=="number"||
        typeof value.commandId!=="string"||
        !record(value.action)||typeof value.action.reason!=="string"||
        !["ASSIGN","ACCEPT","NEEDS_EVIDENCE","ADD_NOTE","ADD_REFERENCE",
          "ESCALATE_INTERNAL","ACK_DEADLINE","COMPLETE_INTERNAL_REVIEW",
          "REOPEN","CLOSE_BOARD","SUPERSEDE_BOARD"]
        .includes(String(value.action.kind)))
      return denied("HANDOFF_MUTATION_INVALID",400);
    const data=await mutatePersistedAssuranceHandoffBoard(current,
      value as unknown as Omit<HandoffCommand,"organizationId"|"actorId"|"at">);
    return NextResponse.json({data,providerWrites:0},{headers});
  }catch(e){
    if(e instanceof Error&&e.message.startsWith("HANDOFF_"))
      return denied(e.message,400);
    return errorResponse(e);
  }
}
export async function PUT(){return denied("HANDOFF_METHOD_DENIED",405);}
export async function DELETE(){return denied("HANDOFF_DELETE_DENIED",405);}
