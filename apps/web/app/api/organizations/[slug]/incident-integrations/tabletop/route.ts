import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { readTabletopCatalog,runOrganizationTabletop,
  runTabletopScenarioMatrix,examineTabletopSafety,TabletopServiceError }
  from "../../../../../../lib/incident-tabletop-service";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"};
const deny=(code:string,status:number)=>NextResponse.json({
  code,providerWrites:0,productionChanges:0},{status,headers});
async function actor(context:Context){
  const {membership,session}=await requireOrganizationAccess((await context.params).slug);
  return{organizationId:membership.organization.id,
    userId:session.user.id,role:membership.role};
}
function failed(e:unknown){
  if(e instanceof TabletopServiceError)return deny(e.code,
    /MEMBERSHIP|ROLE|TENANT/.test(e.code)?403:400);
  if(e instanceof Error&&/^TABLETOP_/.test(e.message))
    return deny(e.message.split(":")[0]!,400);
  return deny("TABLETOP_RUN_UNAVAILABLE",503);
}
export async function GET(request:NextRequest,context:Context){
  try{
    const current=await actor(context);
    if(current.role==="MEMBER")return deny("REVIEWER_REQUIRED",403);
    const query=new URL(request.url).searchParams;
    if([...query.keys()].some(x=>!["mode","seed","at","type",
      "scenarioId","faultCount"].includes(x)))
      return deny("QUERY_FIELD_INVALID",400);
    const mode=query.get("mode")??"catalog";
    if(mode==="catalog")return NextResponse.json({
      data:await readTabletopCatalog(current),providerWrites:0},{headers});
    const rawSeed=query.get("seed")??"42";
    if(!/^\d{1,10}$/.test(rawSeed)||Number(rawSeed)>0xffffffff)
      return deny("SCENARIO_SEED_INVALID",400);
    const seed=Number(rawSeed);
    const at=query.get("at")??new Date().toISOString();
    if(mode==="matrix")return NextResponse.json({
      data:await runTabletopScenarioMatrix(current,seed,at),
      providerWrites:0},{headers});
    if(mode==="preflight"){
      const type=query.get("type"),scenarioId=query.get("scenarioId");
      const faultCount=Number(query.get("faultCount")??"3");
      if(!type||!scenarioId)return deny("PREFLIGHT_IDS_REQUIRED",400);
      const data=await examineTabletopSafety(current,{
        type:type as Parameters<typeof examineTabletopSafety>[1]["type"],
        scenarioId,seed,at,faultCount,
      });
      return NextResponse.json({data,providerWrites:0},{headers});
    }
    return deny("TABLETOP_MODE_UNKNOWN",400);
  }catch(e){return failed(e);}
}
export async function POST(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)return deny("CROSS_ORIGIN",403);
  if(request.headers.get("content-type")?.split(";")[0]?.trim()!=="application/json")
    return deny("JSON_REQUIRED",415);
  const length=request.headers.get("content-length");
  if(length&&(!/^\d+$/.test(length)||Number(length)>32000))
    return deny("BODY_TOO_LARGE",413);
  try{
    const current=await actor(context);
    if(current.role==="MEMBER")return deny("REVIEWER_REQUIRED",403);
    const raw=await request.text();
    if(Buffer.byteLength(raw)>32000)return deny("BODY_TOO_LARGE",413);
    let decoded:unknown;
    try{decoded=JSON.parse(raw);}catch{return deny("BODY_JSON_INVALID",400);}
    if(!decoded||typeof decoded!=="object"||Array.isArray(decoded))
      return deny("REQUEST_INVALID",400);
    const data=decoded as Record<string,unknown>;
    if(Object.keys(data).some(x=>!["scenarioId","type","title",
      "seed","at","faultCount","additionalFaults","moves",
      "reviewedAt","format"].includes(x))||
      !Array.isArray(data.moves)||!Array.isArray(data.additionalFaults)||
      typeof data.scenarioId!=="string"||typeof data.type!=="string"||
      typeof data.title!=="string"||typeof data.at!=="string"||
      typeof data.reviewedAt!=="string"||
      !Number.isSafeInteger(data.seed)||!Number.isSafeInteger(data.faultCount)||
      (data.format!==undefined&&
        !["JSON","CSV","MARKDOWN"].includes(String(data.format))))
      return deny("TABLETOP_INPUT_INVALID",400);
    const result=await runOrganizationTabletop(current,
      data as Parameters<typeof runOrganizationTabletop>[1]);
    return NextResponse.json({data:result,providerWrites:0},{headers});
  }catch(e){return failed(e);}
}
export async function PUT(){return deny("TABLETOP_IS_SIMULATION_ONLY",405);}
export async function PATCH(){return deny("TABLETOP_IS_SIMULATION_ONLY",405);}
export async function DELETE(){return deny("TABLETOP_IS_SIMULATION_ONLY",405);}
