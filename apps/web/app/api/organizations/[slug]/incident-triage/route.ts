import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { readIncidentTriageBoard,readIncidentTriageDossier,
  readIncidentTriageOwnerWorkload,IncidentTriageError }
  from "../../../../../lib/incident-triage-service";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"};
const denied=(code:string,status:number)=>NextResponse.json({
  code,providerWrites:0,actualContainment:false},{status,headers});
export async function GET(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)
    return denied("INCIDENT_TRIAGE_ORIGIN_DENIED",403);
  try{
    const {membership,session}=await requireOrganizationAccess((await context.params).slug);
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return denied("INCIDENT_TRIAGE_REVIEW_ROLE_REQUIRED",403);
    const actor={organizationId:membership.organization.id,
      userId:session.user.id,role:membership.role};
    const query=new URL(request.url).searchParams;
    if([...query.keys()].some(k=>!["mode","incidentId","format",
      "limit","offset"].includes(k)))
      return denied("INCIDENT_TRIAGE_UNKNOWN_FILTER",400);
    const mode=query.get("mode")??"board";
    if(mode==="workload")
      return NextResponse.json({data:await readIncidentTriageOwnerWorkload(actor),
        providerWrites:0},{headers});
    const format=query.get("format");
    if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
      return denied("INCIDENT_TRIAGE_EXPORT_INVALID",400);
    const fmt=format as "JSON"|"CSV"|"MARKDOWN"|null;
    if(mode==="dossier"){
      const incidentId=query.get("incidentId");
      if(!incidentId)return denied("INCIDENT_TRIAGE_ID_REQUIRED",400);
      return NextResponse.json({data:await readIncidentTriageDossier(actor,
        incidentId,fmt??undefined),providerWrites:0},{headers});
    }
    if(mode!=="board")return denied("INCIDENT_TRIAGE_MODE_INVALID",400);
    const l=query.get("limit"),o=query.get("offset");
    if(l&&!/^\d{1,3}$/.test(l)||o&&!/^\d{1,5}$/.test(o))
      return denied("INCIDENT_TRIAGE_PAGING_INVALID",400);
    const data=await readIncidentTriageBoard(actor,{
      ...(l!==null?{limit:Number(l)}:{}),
      ...(o!==null?{offset:Number(o)}:{}),
      ...(fmt?{format:fmt}:{})});
    return NextResponse.json({data,providerWrites:0},{headers});
  }catch(error){
    if(error instanceof IncidentTriageError)
      return denied(error.code,/ROLE|MEMBERSHIP|TENANT/.test(error.code)?403:400);
    return denied("INCIDENT_TRIAGE_READ_UNAVAILABLE",503);
  }
}
export async function POST(){return denied("INCIDENT_TRIAGE_READ_ONLY",405);}
export async function PUT(){return denied("INCIDENT_TRIAGE_READ_ONLY",405);}
export async function PATCH(){return denied("INCIDENT_TRIAGE_READ_ONLY",405);}
export async function DELETE(){return denied("INCIDENT_TRIAGE_READ_ONLY",405);}
