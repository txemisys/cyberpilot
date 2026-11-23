import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { readIncidentSituation, readIncidentSituationIndex,
  readIncidentSituationWithLinkedDecision, SituationServiceError }
  from "../../../../../../lib/incident-situation-service";
import { exportIncidentSituation, prepareIncidentBriefing,
  reconcileIncidentSituation, planIncidentShiftHandoff }
  from "../../../../../../lib/incident-situation-operations";
type Context = {params: Promise<{slug: string}>};
const headers = {"Cache-Control":"private, no-store",
  "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff"};
const denied = (code:string,status:number) => NextResponse.json({
  code,providerWrites:0,independentContainmentVerified:false
},{status,headers});
async function actor(context:Context) {
  const {membership,session} = await requireOrganizationAccess((await context.params).slug);
  return {organizationId:membership.organization.id,
    userId:session.user.id,role:membership.role};
}
function failure(error:unknown) {
  if(error instanceof SituationServiceError)
    return denied(error.code,/ROLE|TENANT|MEMBERSHIP/.test(error.code)?403:400);
  return denied("SITUATION_SOURCE_UNAVAILABLE",503);
}
export async function GET(request:NextRequest,context:Context) {
  try {
    const current=await actor(context);
    if(current.role==="MEMBER") return denied("REVIEWER_REQUIRED",403);
    const query=new URL(request.url).searchParams;
    if([...query.keys()].some(key=>!["mode","incidentId","limit","offset"].includes(key)))
      return denied("QUERY_FIELD_INVALID",400);
    const mode=query.get("mode")??"index";
    if(mode==="linked") {
      const id=query.get("incidentId");
      if(!id)return denied("INCIDENT_ID_REQUIRED",400);
      return NextResponse.json({data:await readIncidentSituationWithLinkedDecision(
        current,id),providerWrites:0},{headers});
    }
    if(mode!=="index")return denied("MODE_INVALID",400);
    const l=query.get("limit"),o=query.get("offset");
    if(l&&!/^\d{1,3}$/.test(l)||o&&!/^\d{1,5}$/.test(o))
      return denied("PAGING_INVALID",400);
    const data=await readIncidentSituationIndex(current,
      o?Number(o):0,l?Number(l):30);
    return NextResponse.json({data,providerWrites:0},{headers});
  }catch(e){return failure(e);}
}
export async function POST(request:NextRequest,context:Context) {
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)return denied("CROSS_ORIGIN",403);
  if(request.headers.get("content-type")?.split(";")[0]?.trim()!=="application/json")
    return denied("JSON_REQUIRED",415);
  const advertised=request.headers.get("content-length");
  if(advertised&&(!/^\d+$/.test(advertised)||Number(advertised)>16000))
    return denied("BODY_TOO_LARGE",413);
  try{
    const current=await actor(context);
    if(current.role==="MEMBER")return denied("REVIEWER_REQUIRED",403);
    const text=await request.text();
    if(Buffer.byteLength(text)>16000)return denied("BODY_TOO_LARGE",413);
    let data:unknown;
    try{data=JSON.parse(text);}catch{return denied("JSON_INVALID",400);}
    if(!data||typeof data!=="object"||Array.isArray(data))
      return denied("BODY_INVALID",400);
    const cmd=data as Record<string,unknown>;
    if(Object.keys(cmd).some(x=>!["incidentId","evidence","assets",
      "remediation","consistency","format"].includes(x))||
      typeof cmd.incidentId!=="string" ||
      !["FAIL_CLOSED","PARTIAL_READ"].includes(String(cmd.consistency)) ||
      (cmd.format!==undefined&&
        !["JSON","CSV","MARKDOWN"].includes(String(cmd.format))))
      return denied("SELECTION_INVALID",400);
    const selection={
      incidentId:cmd.incidentId,
      evidence:(cmd.evidence??null) as
        Parameters<typeof readIncidentSituation>[1]["evidence"],
      assets:(cmd.assets??null) as
        Parameters<typeof readIncidentSituation>[1]["assets"],
      remediation:(cmd.remediation??null) as
        Parameters<typeof readIncidentSituation>[1]["remediation"],
      consistency:cmd.consistency as "FAIL_CLOSED"|"PARTIAL_READ",
    };
    const result=await readIncidentSituation(current,selection);
    const report=result.situation;
    const format=cmd.format as "JSON"|"CSV"|"MARKDOWN"|undefined;
    return NextResponse.json({data:{
      ...result,briefing:prepareIncidentBriefing(report),
      reconciliation:reconcileIncidentSituation(report),
      handoff:planIncidentShiftHandoff(report),
      artifact:format?exportIncidentSituation(report,format):null,
    },providerWrites:0},{headers});
  }catch(e){return failure(e);}
}
export async function PUT(){return denied("SITUATION_READ_ONLY",405);}
export async function PATCH(){return denied("SITUATION_READ_ONLY",405);}
export async function DELETE(){return denied("SITUATION_READ_ONLY",405);}
