import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  createOrganizationTabletopSession, commandOrganizationTabletopSession,
  readOrganizationTabletopSession, listOrganizationTabletopSessions,
  inspectTabletopSessionParticipants, TabletopSessionServiceError,
} from "../../../../../../lib/incident-tabletop-session-service";
import type { SessionCommand }
  from "../../../../../../lib/incident-tabletop-session-domain";
import type { IncidentType } from "../../../../../../lib/incident-playbook-catalog";
import type { TabletopFault } from "../../../../../../lib/incident-tabletop-domain";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff"};
const deny=(code:string,status:number)=>NextResponse.json({
  code,externalProviderWrites:0,liveContainmentProven:false,
},{status,headers});
async function actor(ctx:Context){
  const {membership,session}=await requireOrganizationAccess(
    (await ctx.params).slug);
  return{organizationId:membership.organization.id,
    userId:session.user.id,role:membership.role};
}
function failed(error:unknown){
  if(error instanceof TabletopSessionServiceError){
    const status=/ROLE|MEMBERSHIP|ACCESS|SCOPE|DENIED/.test(error.code)?403:
      /NOT_FOUND/.test(error.code)?404:
      /CAS|CONFLICT|TAMPER|DIVERGENT/.test(error.code)?409:400;
    return deny(error.code,status);
  }
  return deny("SESSION_INTERNAL_FAILURE",503);
}
function obj(x:unknown):x is Record<string,unknown>{
  return typeof x==="object"&&x!==null&&!Array.isArray(x);
}
function keys(x:Record<string,unknown>,allowed:string[]){
  return Object.keys(x).every(k=>allowed.includes(k));
}
async function readJson(req:NextRequest){
  const origin=req.headers.get("origin");
  if(origin&&origin!==new URL(req.url).origin)
    throw Error("SESSION_CROSS_ORIGIN");
  if(req.headers.get("content-type")?.split(";")[0]?.trim()!==
      "application/json")
    throw Error("SESSION_JSON_REQUIRED");
  const len=req.headers.get("content-length");
  if(len&&(!/^\d+$/.test(len)||Number(len)>16000))
    throw Error("SESSION_BODY_TOO_LARGE");
  const raw=await req.text();
  if(Buffer.byteLength(raw)>16000)throw Error("SESSION_BODY_TOO_LARGE");
  let value:unknown;
  try{value=JSON.parse(raw);}catch{throw Error("SESSION_JSON_INVALID");}
  if(!obj(value))throw Error("SESSION_BODY_INVALID");
  return value;
}
export async function GET(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(current.role==="MEMBER")return deny("SESSION_REVIEWER_REQUIRED",403);
    const q=new URL(req.url).searchParams;
    if([...q.keys()].some(x=>!["mode","sessionId","offset","limit"].includes(x)))
      return deny("SESSION_QUERY_FIELD_INVALID",400);
    const mode=q.get("mode")??"index";
    if(mode==="index"){
      const o=q.get("offset")??"0",l=q.get("limit")??"30";
      if(!/^\d{1,5}$/.test(o)||!/^\d{1,3}$/.test(l))
        return deny("SESSION_PAGING_INVALID",400);
      return NextResponse.json({data:await listOrganizationTabletopSessions(
        current,Number(o),Number(l)),providerWrites:0},{headers});
    }
    const id=q.get("sessionId");
    if(!id)return deny("SESSION_ID_REQUIRED",400);
    if(mode==="detail")
      return NextResponse.json({
        data:await readOrganizationTabletopSession(current,id),
        providerWrites:0,
      },{headers});
    if(mode==="participants")
      return NextResponse.json({
        data:await inspectTabletopSessionParticipants(current,id),
        providerWrites:0,
      },{headers});
    return deny("SESSION_MODE_INVALID",400);
  }catch(e){return failed(e);}
}
export async function POST(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(!["OWNER","ADMIN"].includes(current.role))
      return deny("SESSION_WRITER_REQUIRED",403);
    const v=await readJson(req);
    if(!keys(v,["id","incidentId","type","title","seed",
      "faultCount","additionalFaults"])||
      typeof v.id!=="string"||
      !(v.incidentId===null||typeof v.incidentId==="string")||
      typeof v.type!=="string"||typeof v.title!=="string"||
      typeof v.seed!=="number"||typeof v.faultCount!=="number"||
      (v.additionalFaults!==undefined&&!Array.isArray(v.additionalFaults)))
      return deny("SESSION_CREATE_REQUEST_INVALID",400);
    const data=await createOrganizationTabletopSession(current,{
      id:v.id,incidentId:v.incidentId,type:v.type as IncidentType,
      title:v.title,seed:v.seed,faultCount:v.faultCount,
      additionalFaults:v.additionalFaults as TabletopFault[]|undefined,
    });
    return NextResponse.json({data,providerWrites:0},{
      status:data.created?201:200,headers,
    });
  }catch(e){
    if(e instanceof Error&&e.message.startsWith("SESSION_"))
      return deny(e.message,400);
    return failed(e);
  }
}
export async function PATCH(req:NextRequest,ctx:Context){
  try{
    const current=await actor(ctx);
    if(!["OWNER","ADMIN"].includes(current.role))
      return deny("SESSION_WRITER_REQUIRED",403);
    const v=await readJson(req);
    if(!keys(v,["sessionId","commandId","expectedRevision","action"])||
      typeof v.sessionId!=="string"||typeof v.commandId!=="string"||
      typeof v.expectedRevision!=="number"||!obj(v.action)||
      typeof v.action.userId!=="string"||
      !["ENROLL","REMOVE","TRANSFER_FACILITATOR","PAUSE","RESUME",
        "PLAY","NOTE","DEBRIEF","ARCHIVE","SUPERSEDE"]
        .includes(String(v.action.kind)))
      return deny("SESSION_MUTATION_REQUEST_INVALID",400);
    const command=v as unknown as Omit<SessionCommand,"organizationId"|"at">;
    const data=await commandOrganizationTabletopSession(current,command);
    return NextResponse.json({data,providerWrites:0},{headers});
  }catch(e){
    if(e instanceof Error&&e.message.startsWith("SESSION_"))
      return deny(e.message,400);
    return failed(e);
  }
}
export async function PUT(){return deny("SESSION_METHOD_DENIED",405);}
export async function DELETE(){return deny("SESSION_DELETE_DENIED",405);}
