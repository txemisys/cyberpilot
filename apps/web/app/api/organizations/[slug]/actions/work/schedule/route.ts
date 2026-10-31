import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {
 loadWorkSchedule,scheduleCalendar
} from "../../../../../../../lib/remediation-work-schedule";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";

type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function failure(error:unknown){
 if(error instanceof WorkInputError)
  return NextResponse.json({error:error.message,code:error.code},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
 console.error("Work schedule",error instanceof Error?error.name:"unknown");
 return NextResponse.json({error:"Could not read work schedule."},{status:500,headers});
}
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const params=Object.fromEntries(request.nextUrl.searchParams);
  const scope={organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
  const referenceDate=typeof params.referenceDate==="string"?params.referenceDate:
   new Date().toISOString().slice(0,10);
  const options={
   range:params.range??"MONTH",scope:params.scope??"MINE",
   referenceDate,includeClosed:params.includeClosed==="true",
   priority:params.priority??"ALL",search:params.search??"",
   assigneeUserId:params.assigneeUserId??null,
  };
  const result=await loadWorkSchedule(scope,options);
  if(params.format==="ics"){
   const body=scheduleCalendar(result,slug);
   return new NextResponse(body,{headers:{
    ...headers,"Content-Type":"text/calendar; charset=utf-8",
    "Content-Disposition":'attachment; filename="cyberpilot-work-targets.ics"',
   }});
  }
  if(params.format!==undefined&&params.format!=="json")
   throw new WorkInputError("INVALID","Unknown schedule output format.");
  return NextResponse.json(result,{headers});
 }catch(error){return failure(error);}
}
