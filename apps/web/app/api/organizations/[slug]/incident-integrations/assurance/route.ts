import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {reviewIncidentAssurance,readAssurancePolicyCatalog,
  collectAssuranceIndex,reviewAssuranceMultiCase,AssuranceServiceError}
  from "../../../../../../lib/incident-assurance-service";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"};
const deny=(code:string,status:number)=>NextResponse.json({
  code,providerWrites:0,securityCertification:false},{status,headers});
async function actor(context:Context){
  const {membership,session}=await requireOrganizationAccess((await context.params).slug);
  return{organizationId:membership.organization.id,
    userId:session.user.id,role:membership.role};
}
function failure(e:unknown){
  if(e instanceof AssuranceServiceError)
    return deny(e.code,/ROLE|MEMBERSHIP|TENANT/.test(e.code)?403:400);
  if(e instanceof Error&&/^(ASSURANCE_|SITUATION_|TABLETOP_)/.test(e.message))
    return deny(e.message.split(":")[0]!,400);
  return deny("ASSURANCE_SOURCE_UNAVAILABLE",503);
}
export async function GET(request:NextRequest,context:Context){
  try{
    const current=await actor(context);
    if(current.role==="MEMBER")return deny("REVIEWER_REQUIRED",403);
    const query=new URL(request.url).searchParams;
    if([...query.keys()].some(x=>!["mode","offset","limit"].includes(x)))
      return deny("QUERY_UNKNOWN",400);
    const mode=query.get("mode")??"policies";
    if(mode==="policies")return NextResponse.json({
      data:await readAssurancePolicyCatalog(current),providerWrites:0},{headers});
    if(mode!=="index")return deny("MODE_UNKNOWN",400);
    const o=query.get("offset"),l=query.get("limit");
    if(o&&!/^\d{1,5}$/.test(o)||l&&!/^\d{1,3}$/.test(l))
      return deny("PAGING_INVALID",400);
    const data=await collectAssuranceIndex(current,{
      ...(o!==null?{offset:Number(o)}:{}),
      ...(l!==null?{limit:Number(l)}:{}),
    });
    return NextResponse.json({data,providerWrites:0},{headers});
  }catch(e){return failure(e);}
}
export async function POST(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)
    return deny("CROSS_ORIGIN",403);
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
    let parsed:unknown;
    try{parsed=JSON.parse(raw);}catch{return deny("JSON_INVALID",400);}
    if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))
      return deny("REQUEST_INVALID",400);
    const data=parsed as Record<string,unknown>;
    if(Object.keys(data).some(x=>!["situation","policy","tabletop",
      "format","caseIds"].includes(x)))
      return deny("REQUEST_UNKNOWN_FIELDS",400);
    if(Array.isArray(data.caseIds)){
      if(Object.keys(data).some(k=>k!=="caseIds"))
        return deny("MULTI_CASE_FIELDS_INVALID",400);
      const result=await reviewAssuranceMultiCase(current,
        data.caseIds as string[]);
      return NextResponse.json({data:result,providerWrites:0},{headers});
    }
    if(!data.situation||typeof data.situation!=="object"||
      Array.isArray(data.situation))
      return deny("SITUATION_SELECTION_REQUIRED",400);
    const result=await reviewIncidentAssurance(current,
      data as Parameters<typeof reviewIncidentAssurance>[1]);
    return NextResponse.json({data:result,providerWrites:0,
      signoffGranted:false},{headers});
  }catch(e){return failure(e);}
}
export async function PUT(){return deny("ASSURANCE_REVIEW_READ_ONLY",405);}
export async function PATCH(){return deny("ASSURANCE_REVIEW_READ_ONLY",405);}
export async function DELETE(){return deny("ASSURANCE_REVIEW_READ_ONLY",405);}
